"""Unit tests for Orchestrator components.

Tests:
- JSON extraction and healing (sanitization, edge cases)
- Qwen thinking tag cleaning and unclosed tag recovery
- Reporter heuristic fallback extraction
- Large tool output truncation for context optimization
- Anti-loop enforcement
- Context window management (sliding window summarization)
- Config integration
"""

import json
import os
import sys

import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.client.orchestrator import (
    _extract_json,
    _sanitize_json_string,
    _summarize_old_messages,
    _normalize_tool_args,
    _fuzzy_match_tool_name,
    _extract_target_from_prompt,
    _normalize_semantic_target,
    _get_semantic_signature,
    _filter_hallucinated_findings,
    _cold_ingest_assessment_playbook,
    _clean_thinking_tags,
    _extract_reporter_fallback,
    _truncate_tool_output_for_llm,
    _get_tool_timeout,
    _retry_tool_call,
    _RE_THINK_TAGS,
    AuditLogger,
)
from src.client.report_state import ReportState, Finding, ToolStep


# ===== JSON Extraction Tests =====

class TestExtractJSON:
    def test_standard_json_fence(self):
        content = 'Some text\n```json\n{"action": "call_tool", "tool_name": "test"}\n```\nMore text'
        result = _extract_json(content)
        assert result["action"] == "call_tool"
        assert result["tool_name"] == "test"

    def test_generic_fence(self):
        content = '```\n{"action": "final_answer", "text": "done"}\n```'
        result = _extract_json(content)
        assert result["action"] == "final_answer"

    def test_raw_json(self):
        content = 'The result is {"action": "call_tool", "tool_name": "nmap"}'
        result = _extract_json(content)
        assert result["tool_name"] == "nmap"

    def test_no_json_raises(self):
        with pytest.raises(ValueError, match="No valid JSON"):
            _extract_json("This has no JSON at all")

    def test_json_with_comments(self):
        content = '```json\n{"action": "call_tool", // this is a comment\n"tool_name": "test"}\n```'
        result = _extract_json(content)
        assert result["tool_name"] == "test"

    def test_json_with_trailing_commas(self):
        content = '```json\n{"action": "call_tool", "tool_name": "test",}\n```'
        result = _extract_json(content)
        assert result["tool_name"] == "test"

    def test_json_with_control_chars(self):
        content = '```json\n{"action": "call_tool", "thought": "test\x08value", "tool_name": "nmap"}\n```'
        result = _extract_json(content)
        assert result["tool_name"] == "nmap"

    def test_json_with_vietnamese_multiline(self):
        """Regression test: Vietnamese diacritics in multi-line JSON must survive parsing."""
        content = (
            '```json\n'
            '{\n'
            '  "thought": "Bắt đầu quá trình khám phá toàn diện cho mục tiêu. '
            'Đầu tiên, tôi sẽ kiểm tra các cổng mở trên máy chủ.",\n'
            '  "action": "call_tool",\n'
            '  "tool_name": "docker_scan_ports_fast",\n'
            '  "arguments": {"target_ip": "192.168.1.1"}\n'
            '}\n'
            '```'
        )
        result = _extract_json(content)
        assert result["tool_name"] == "docker_scan_ports_fast"
        assert "Bắt đầu" in result["thought"]
        assert result["arguments"]["target_ip"] == "192.168.1.1"

    def test_bracket_matching_extraction(self):
        """Test that bracket-matched extraction works for nested JSON."""
        content = 'Some preamble text {"action": "call_tool", "arguments": {"target_ip": "10.0.0.1"}} trailing'
        result = _extract_json(content)
        assert result["action"] == "call_tool"
        assert result["arguments"]["target_ip"] == "10.0.0.1"


# ===== Sanitization Tests =====

class TestSanitizeJSON:
    def test_removes_single_line_comments(self):
        text = '{"key": "value"} // comment here'
        result = _sanitize_json_string(text)
        assert "//" not in result

    def test_removes_block_comments(self):
        text = '{"key": /* block comment */ "value"}'
        result = _sanitize_json_string(text)
        assert "/*" not in result

    def test_removes_trailing_commas(self):
        text = '{"key": "value",}'
        result = _sanitize_json_string(text)
        assert result.strip().endswith("}")

    def test_preserves_valid_json(self):
        text = '{"action": "call_tool", "tool_name": "nmap"}'
        result = _sanitize_json_string(text)
        parsed = json.loads(result)
        assert parsed["action"] == "call_tool"


# ===== Context Window Management Tests =====

class TestContextWindowManagement:
    def test_no_compression_when_small(self):
        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "user prompt"},
            {"role": "assistant", "content": "response 1"},
            {"role": "user", "content": "Tool 'nmap' result: {ports: [80]}"},
        ]
        result = _summarize_old_messages(messages, keep_last=30)
        assert len(result) == 4  # No compression needed

    def test_compression_when_large(self):
        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "user prompt"},
        ]
        # Add 40 messages
        for i in range(20):
            messages.append({"role": "assistant", "content": f'{{"tool_name": "tool_{i}"}}'})
            messages.append({"role": "user", "content": f"Tool 'tool_{i}' result: result_{i}"})

        result = _summarize_old_messages(messages, keep_last=10)
        # Should have: system + user + summary + last 10 messages = 13
        assert len(result) == 13
        # Summary message should exist
        summary = result[2]["content"]
        assert "CONTEXT SUMMARY" in summary

    def test_preserves_system_and_user(self):
        messages = [
            {"role": "system", "content": "SYSTEM"},
            {"role": "user", "content": "USER PROMPT"},
        ]
        for i in range(20):
            messages.append({"role": "assistant", "content": f"msg_{i}"})
            messages.append({"role": "user", "content": f"reply_{i}"})

        result = _summarize_old_messages(messages, keep_last=5)
        assert result[0]["content"] == "SYSTEM"
        assert result[1]["content"] == "USER PROMPT"

    def test_summary_contains_tool_info(self):
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "prompt"},
            {"role": "assistant", "content": '{"tool_name": "docker_scan_ports_fast"}'},
            {"role": "user", "content": "Tool 'docker_scan_ports_fast' result: {ports: [22, 80]}"},
        ]
        # Add more to trigger compression
        for i in range(30):
            messages.append({"role": "assistant", "content": f"filler_{i}"})
            messages.append({"role": "user", "content": f"response_{i}"})

        result = _summarize_old_messages(messages, keep_last=5)
        summary = result[2]["content"]
        assert "docker_scan_ports_fast" in summary


# ===== Config Integration Tests =====

class TestConfigIntegration:
    def test_config_loads(self):
        from src.utils.config import load_config, reload_config
        config = reload_config()
        assert "llm" in config
        assert "agent" in config
        assert config["llm"]["model"] == "huihui_ai/qwen3.5-abliterated:9b"

    def test_config_get(self):
        from src.utils.config import get as cfg_get, reload_config
        reload_config()
        assert cfg_get("llm.model") == "huihui_ai/qwen3.5-abliterated:9b"
        assert cfg_get("agent.max_iterations") == 25
        assert cfg_get("nonexistent.key", "default") == "default"

    def test_env_overrides_with_underscores(self, monkeypatch):
        from src.utils.config import reload_config, get as cfg_get
        monkeypatch.setenv("MLSEC_AGENT_MAX_ITERATIONS", "42")
        monkeypatch.setenv("MLSEC_TIMEOUTS_FAST_SCAN", "99")
        monkeypatch.setenv("MLSEC_REPORTS_COMPANY_NAME", "CyberSec Pro")
        reload_config()
        assert cfg_get("agent.max_iterations") == 42
        assert cfg_get("timeouts.fast_scan") == 99
        assert cfg_get("reports.company_name") == "CyberSec Pro"


# ===== Audit Logger Tests =====

class TestAuditLogger:
    def test_audit_logger_context_manager(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MLSEC_REPORTS_OUTPUT_DIR", str(tmp_path))
        from src.utils.config import reload_config
        reload_config()

        with AuditLogger("test-target.com") as logger:
            logger.log("test_event", {"status": "ok", "value": 123})
            audit_file = logger.path

        assert os.path.exists(audit_file)
        with open(audit_file, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 1
        assert lines[0]["event"] == "test_event"
        assert lines[0]["status"] == "ok"
        assert lines[0]["value"] == 123


# ===== Target Extraction Tests =====

class TestExtractTarget:
    def test_extract_target_acquired_header(self):
        info = _extract_target_from_prompt("TARGET ACQUIRED: http://testphp.vulnweb.com/login.php")
        assert info["raw"] == "http://testphp.vulnweb.com/login.php"
        assert info["hostname"] == "testphp.vulnweb.com"
        assert info["url"] == "http://testphp.vulnweb.com/login.php"

    def test_extract_target_fallback_url(self):
        info = _extract_target_from_prompt("Please run a recon scan on https://example.com/api/v1")
        assert info["raw"] == "https://example.com/api/v1"
        assert info["hostname"] == "example.com"
        assert info["url"] == "https://example.com/api/v1"

    def test_extract_target_fallback_domain(self):
        info = _extract_target_from_prompt("Scan scanme.nmap.org now")
        assert info["raw"] == "scanme.nmap.org"
        assert info["hostname"] == "scanme.nmap.org"
        assert info["url"] == "http://scanme.nmap.org"

    def test_extract_target_fallback_ip(self):
        info = _extract_target_from_prompt("Conduct network assessment against 192.168.1.50")
        assert info["raw"] == "192.168.1.50"
        assert info["hostname"] == "192.168.1.50"
        assert info["url"] == "http://192.168.1.50"


# ===== Tool Normalization & Fuzzy Matching Tests =====

class TestToolNormalization:
    def test_normalize_target_to_target_host(self):
        schema = [{
            "name": "docker_testssl",
            "input_schema": {"properties": {"target_host": {"type": "string"}}}
        }]
        args = {"target": "example.com"}
        normalized = _normalize_tool_args("docker_testssl", args, schema)
        assert normalized == {"target_host": "example.com"}

    def test_normalize_target_to_domain(self):
        schema = [{
            "name": "docker_subfinder",
            "input_schema": {"properties": {"domain": {"type": "string"}}}
        }]
        args = {"target": "example.com"}
        normalized = _normalize_tool_args("docker_subfinder", args, schema)
        assert normalized == {"domain": "example.com"}

    def test_normalize_target_ip_to_target(self):
        schema = [{
            "name": "docker_scan_ports_fast",
            "input_schema": {"properties": {"target": {"type": "string"}}}
        }]
        args = {"target_ip": "192.168.1.1"}
        normalized = _normalize_tool_args("docker_scan_ports_fast", args, schema)
        assert normalized == {"target": "192.168.1.1"}

    def test_fuzzy_match_tool_name(self):
        schema = [
            {"name": "docker_nikto_scan"},
            {"name": "docker_subfinder"},
            {"name": "docker_bruteforce"},
            {"name": "docker_scan_ports_fast"},
            {"name": "bruteforce_http_form"},
            {"name": "bruteforce_ssh"},
            {"name": "docker_crawl_web"},
            {"name": "docker_dirb_scan"},
        ]
        assert _fuzzy_match_tool_name("docker_nikto", schema) == "docker_nikto_scan"
        assert _fuzzy_match_tool_name("docker_sublist3r", schema) == "docker_subfinder"
        assert _fuzzy_match_tool_name("docker_brute_force", schema) == "docker_bruteforce"
        assert _fuzzy_match_tool_name("scan_ports", schema) == "docker_scan_ports_fast"
        # Crucial bug fixes from real pentest logs:
        assert _fuzzy_match_tool_name("docker_bruteforce_http_form", schema) == "bruteforce_http_form"
        assert _fuzzy_match_tool_name("docker_bruteforce_ssh", schema) == "bruteforce_ssh"
        assert _fuzzy_match_tool_name("hydra_http_form", schema) == "bruteforce_http_form"
        assert _fuzzy_match_tool_name("crawl_web", schema) == "docker_crawl_web"
        assert _fuzzy_match_tool_name("dirb_scan", schema) == "docker_dirb_scan"


class TestSemanticAntiLoop:
    def test_normalize_semantic_target(self):
        assert _normalize_semantic_target("http://www.nhadatxunghe.vn/") == "nhadatxunghe.vn"
        assert _normalize_semantic_target("https://nhadatxunghe.vn") == "nhadatxunghe.vn"
        assert _normalize_semantic_target("http://nhadatxunghe.vn:80") == "nhadatxunghe.vn"
        assert _normalize_semantic_target("https://www.nhadatxunghe.vn:443/") == "nhadatxunghe.vn"
        assert _normalize_semantic_target("http://www.nhadatxunghe.vn/login") == "nhadatxunghe.vn/login"
        assert _normalize_semantic_target("https://nhadatxunghe.vn/login/") == "nhadatxunghe.vn/login"

    def test_semantic_signature_equivalence(self):
        sig1 = _get_semantic_signature("docker_crawl_web", {"url": "http://nhadatxunghe.vn"})
        sig2 = _get_semantic_signature("docker_crawl_web", {"url": "https://www.nhadatxunghe.vn/"})
        assert sig1 == sig2

        sig3 = _get_semantic_signature("docker_nikto_scan", {"target": "http://www.domain.com:80/"})
        sig4 = _get_semantic_signature("docker_nikto_scan", {"target": "domain.com"})
        assert sig3 == sig4


class TestReporterHallucinationGuard:
    def test_filter_discards_docker_bruteforce_findings(self):
        findings = [
            {"title": "Đường dẫn /login không được bảo vệ", "severity": "LOW", "description": "Form bruteforce"}
        ]
        result = _filter_hallucinated_findings(findings, "docker_bruteforce", "Hydra container is operational.")
        assert result == []

    def test_filter_discards_capability_check_findings(self):
        findings = [
            {"title": "Weak password found", "severity": "HIGH", "description": "admin/admin"}
        ]
        tool_result = json.dumps({"status": "capability_check_only", "message": "Health check"})
        result = _filter_hallucinated_findings(findings, "some_tool", tool_result)
        assert result == []

    def test_filter_discards_hallucinated_credentials_on_failed_hydra(self):
        findings = [
            {"title": "Mật khẩu yếu trên SSH", "severity": "HIGH", "description": "root/password"}
        ]
        tool_result = json.dumps({"status": "NO_CREDENTIALS_FOUND", "results": []})
        result = _filter_hallucinated_findings(findings, "bruteforce_ssh", tool_result)
        assert result == []

    def test_filter_keeps_legitimate_findings(self):
        findings = [
            {"title": "Open Port 22 (SSH)", "severity": "INFO", "description": "SSH OpenSSH 8.9"}
        ]
        tool_result = json.dumps({"open_ports": [{"port": 22, "service": "ssh"}]})
        result = _filter_hallucinated_findings(findings, "docker_scan_ports_fast", tool_result)
        assert len(result) == 1
        assert result[0]["title"] == "Open Port 22 (SSH)"


class TestColdIngestAssessmentPlaybook:
    def test_cold_ingest_packages_and_stores_playbook(self):
        class MockVectorMemory:
            def __init__(self):
                self.stored = []
            def store_attack_pattern(self, pattern):
                self.stored.append(pattern)
                return "ap::killchain_playbook::CWE-89::test12345"

        rs = ReportState(target="http://example.com/shop")
        rs.add_finding(Finding(title="SQL Injection", severity="HIGH", cve_id="CWE-89", tool_source="docker_sqlmap_scan"))
        rs.add_step(ToolStep(step_number=1, tool_name="docker_whatweb", arguments={}, result_snippet="Apache/2.4", status="SUCCESS"))
        rs.add_step(ToolStep(step_number=2, tool_name="docker_sqlmap_scan", arguments={}, result_snippet="DB dump", status="SUCCESS"))
        rs.update_risk_score(8.5)

        v_mem = MockVectorMemory()
        _cold_ingest_assessment_playbook(v_mem, rs)

        assert len(v_mem.stored) == 1
        stored_pattern = v_mem.stored[0]
        assert stored_pattern["cwe_id"] == "CWE-89"
        assert stored_pattern["context"]["entry_point"] == "http://example.com/shop"
        assert "docker_whatweb -> docker_sqlmap_scan" in stored_pattern["successful_vector"]["tool_args_key"]
        assert len(rs.rag_stored_patterns) == 1
        assert rs.rag_stored_patterns[0]["stored_id"] == "ap::killchain_playbook::CWE-89::test12345"



class TestQwenThinkingTagCleaning:
    def test_clean_closed_think_tags(self):
        text = "<think>\nLet's evaluate the target port 80.\n</think>\n```json\n{\"action\": \"call_tool\", \"tool_name\": \"docker_whatweb\"}\n```"
        cleaned = _clean_thinking_tags(text)
        assert "<think>" not in cleaned
        assert "</think>" not in cleaned
        assert "docker_whatweb" in cleaned

    def test_clean_unclosed_trailing_think_tags(self):
        text = '{"action": "call_tool", "tool_name": "docker_whatweb"}\n<think>\nUnfinished thought that was cut off'
        cleaned = _clean_thinking_tags(text)
        assert "<think>" not in cleaned
        assert "Unfinished thought" not in cleaned
        assert "docker_whatweb" in cleaned

    def test_clean_unclosed_all_think_tags_with_json(self):
        # When output begins with <think> and never closes, but contains a JSON object
        text = '<think>\nI should call docker_whatweb now.\n{"action": "call_tool", "tool_name": "docker_whatweb"}'
        cleaned = _clean_thinking_tags(text)
        assert "<think>" not in cleaned
        assert "docker_whatweb" in cleaned
        # JSON should be parseable
        parsed = _extract_json(cleaned)
        assert parsed["action"] == "call_tool"
        assert parsed["tool_name"] == "docker_whatweb"

    def test_clean_pure_text_no_tags(self):
        text = '{"action": "final_answer", "text": "Hoàn tất đánh giá."}'
        cleaned = _clean_thinking_tags(text)
        assert cleaned == text


class TestReporterFallbackExtraction:
    def test_extract_reporter_fallback_on_malformed_json(self):
        # Malformed JSON with raw unescaped quotes in description
        malformed = """
        {
            "risk_score": 7.5,
            "suggestion_for_redteam": "Tiếp tục quét cổng 443 và kiểm tra SSL",
            "step_comment": "Phát hiện file cấu hình nhạy cảm",
            "objective_assessment": "Đang tiến triển tốt",
            "blocking_factor": "Chưa bypass được WAF",
            "new_findings": [
                {
                    "title": "Lộ file config.php",
                    "severity": "HIGH",
                    "description": "Tìm thấy file "config.php" chứa database password",
                    "cve_id": "CVE-2023-1234"
                }
            ]
        }
        """
        # Strict json.loads will fail on raw unescaped quote
        res = _extract_reporter_fallback(malformed)
        assert res["risk_score"] == 7.5
        assert "Tiếp tục quét cổng 443" in res["suggestion"]
        assert "Phát hiện file cấu hình" in res["step_comment"]
        assert res["objective_assessment"] == "Đang tiến triển tốt"
        assert res["blocking_factor"] == "Chưa bypass được WAF"

    def test_extract_reporter_fallback_empty_on_garbage(self):
        assert _extract_reporter_fallback("") == {}
        assert _extract_reporter_fallback("Just some completely random text without any keys") == {}


class TestToolOutputTruncation:
    def test_truncate_under_threshold(self):
        short_output = "Nmap scan report for 192.168.1.1\nHost is up.\nPORT 80/tcp open http"
        assert _truncate_tool_output_for_llm(short_output, max_chars=6000) == short_output

    def test_truncate_over_threshold(self):
        # 10,000 character output
        long_output = "HEAD_MARKER: Scan started on port 80.\n" + ("A" * 9900) + "\nTAIL_MARKER: Scan completed with 5 open ports."
        truncated = _truncate_tool_output_for_llm(long_output, max_chars=6000)
        assert len(truncated) < len(long_output)
        assert "HEAD_MARKER: Scan started on port 80." in truncated
        assert "TAIL_MARKER: Scan completed with 5 open ports." in truncated
        assert "Đã rút gọn" in truncated



class TestToolTimeoutAndRetry:
    def test_get_tool_timeout_resolves_configured(self):
        t_crawl = _get_tool_timeout("docker_crawl_web")
        assert t_crawl >= 75.0
        t_fast = _get_tool_timeout("docker_scan_ports_fast")
        assert t_fast >= 135.0
        t_unknown = _get_tool_timeout("unknown_custom_tool")
        assert t_unknown == 135.0  # 120 + 15 buffer

    @pytest.mark.asyncio
    async def test_retry_tool_call_timeout_handling(self):
        import asyncio
        class MockHangingSession:
            async def call_tool(self, name, args):
                await asyncio.sleep(5)
                return None

        session = MockHangingSession()
        res = await _retry_tool_call(session, "test_hang", {}, max_retries=1, delay=0.01, timeout=0.05)
        assert "timed out after" in res


class TestRealtimeBayesianGuidance:
    def test_get_current_summary_includes_bayesian_critical_path(self):
        rs = ReportState(target="http://example.com")
        rs.add_finding(Finding(title="SQL Injection", severity="HIGH", cve_id="CWE-89", tool_source="docker_sqlmap_scan"))
        summary = rs.get_current_summary()
        assert "Bayesian Kill-Chain" in summary

    def test_get_reporter_feedback_block_includes_bayesian_kill_chain(self):
        rs = ReportState(target="http://example.com")
        rs.add_finding(Finding(title="SQL Injection", severity="HIGH", cve_id="CWE-89", tool_source="docker_sqlmap_scan"))
        block = rs.get_reporter_feedback_block(latest_suggestion="Run dump")
        assert "Bayesian Kill-Chain" in block


class TestRealtimeResilienceAndArgumentHealing:
    """Tests for Real-time Argument Healing and Docker Daemon Offline resilience."""

    def test_url_healing_missing_scheme_default_http(self):
        args = {"target_url": "target.local:8080"}
        normalized = _normalize_tool_args("docker_crawl_web", args)
        assert normalized["target_url"] == "http://target.local:8080"

    def test_url_healing_port_443_uses_https(self):
        args = {"target_url": "target.local:443"}
        normalized = _normalize_tool_args("docker_sqlmap_scan", args)
        assert normalized["target_url"] == "https://target.local:443"

    def test_url_healing_from_alias_target(self):
        args = {"target": "target.local"}
        normalized = _normalize_tool_args("docker_nikto_scan", args)
        assert "target_url" in normalized
        assert normalized["target_url"] == "http://target.local"

    def test_host_healing_nmap_fast_strips_url_and_path(self):
        args = {"target": "http://192.168.1.1:8080/api"}
        normalized = _normalize_tool_args("docker_scan_ports_fast", args)
        assert normalized["target"] == "192.168.1.1"

    def test_host_healing_nmap_deep_extracts_port(self):
        args = {"target": "http://192.168.1.1:8080/api"}
        normalized = _normalize_tool_args("docker_scan_ports_deep", args)
        assert normalized["target"] == "192.168.1.1"
        assert normalized["ports"] == "8080"

    def test_host_healing_ssl_audit_extracts_int_port(self):
        args = {"target_host": "https://secure.example.com:8443/login"}
        normalized = _normalize_tool_args("docker_ssl_cert_audit", args)
        assert normalized["target_host"] == "secure.example.com"
        assert normalized["port"] == 8443
        assert isinstance(normalized["port"], int)

    def test_host_healing_resolve_dns(self):
        args = {"hostname": "https://internal.corp/dns"}
        normalized = _normalize_tool_args("docker_resolve_dns", args)
        assert normalized["hostname"] == "internal.corp"

    def test_targets_list_healing_httpx_probe(self):
        args = {"targets": ["http://a.com", "http://b.com"]}
        normalized = _normalize_tool_args("docker_httpx_probe", args)
        assert normalized["targets"] == "http://a.com,http://b.com"

    def test_targets_newline_healing_httpx_probe(self):
        args = {"targets": "http://a.com\nhttp://b.com"}
        normalized = _normalize_tool_args("docker_httpx_probe", args)
        assert normalized["targets"] == "http://a.com,http://b.com"

    def test_port_type_healing(self):
        args = {"target_host": "10.0.0.1", "port": "22"}
        normalized = _normalize_tool_args("bruteforce_ssh", args)
        assert normalized["port"] == 22
        assert isinstance(normalized["port"], int)

        args_deep = {"target": "10.0.0.1", "ports": [80, 443]}
        normalized_deep = _normalize_tool_args("docker_scan_ports_deep", args_deep)
        assert normalized_deep["ports"] == "80,443"

    @pytest.mark.asyncio
    async def test_retry_tool_call_docker_daemon_offline_result_fast_abort(self):
        class MockItem:
            def __init__(self, text):
                self.text = text

        class MockResult:
            def __init__(self, text):
                self.content = [MockItem(text)]

        class MockDockerOfflineSession:
            def __init__(self):
                self.call_count = 0

            async def call_tool(self, name, args):
                self.call_count += 1
                return MockResult(
                    '{"error": "docker: Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?."}'
                )

        session = MockDockerOfflineSession()
        res = await _retry_tool_call(
            session, "docker_scan_ports_fast", {"target": "127.0.0.1"},
            max_retries=3, delay=10.0,
        )
        assert session.call_count == 1  # Fast abort, didn't retry 3 times
        assert "Cannot connect to the Docker daemon" in res

    @pytest.mark.asyncio
    async def test_retry_tool_call_docker_daemon_offline_exception_fast_abort(self):
        class MockDockerExceptionSession:
            def __init__(self):
                self.call_count = 0

            async def call_tool(self, name, args):
                self.call_count += 1
                raise RuntimeError("Error during connect: this error indicates that the docker daemon is not running")

        session = MockDockerExceptionSession()
        res = await _retry_tool_call(
            session, "docker_scan_ports_fast", {"target": "127.0.0.1"},
            max_retries=3, delay=10.0,
        )
        assert session.call_count == 1  # Fast abort, didn't retry 3 times
        assert "Docker daemon is offline or unreachable" in res

    def test_waf_tamper_script_resolution(self):
        from src.client.orchestrator import _get_waf_tamper_script
        assert _get_waf_tamper_script("Cloudflare") == "between,space2comment,charencode"
        assert _get_waf_tamper_script("ModSecurity OWASP CRS") == "modsecurityversioned,modsecurityzeroversioned,space2hash"
        assert _get_waf_tamper_script("AWS WAF / CloudFront") == "between,randomcase,space2comment"
        assert _get_waf_tamper_script(None) is None

    def test_normalize_tool_args_waf_tamper_injection(self):
        from src.client.orchestrator import _normalize_tool_args
        args = {"target_url": "http://example.com/item?id=1"}
        normalized = _normalize_tool_args("docker_sqlmap_scan", args, detected_waf="Cloudflare")
        assert "tamper" in normalized
        assert normalized["tamper"] == "between,space2comment,charencode"

        # Explicit tamper provided by user should not be overridden
        args_explicit = {"target_url": "http://example.com/item?id=1", "tamper": "custom_script"}
        normalized_explicit = _normalize_tool_args("docker_sqlmap_scan", args_explicit, detected_waf="Cloudflare")
        assert normalized_explicit["tamper"] == "custom_script"

    def test_display_mission_dashboard_render(self):
        from src.client.orchestrator import _display_mission_dashboard
        from src.client.report_state import ReportState, Finding
        state = ReportState(target="http://testphp.vulnweb.com", scan_mode="full")
        state.attack_surface.open_ports[80] = {"service": "http"}
        state.attack_surface.detected_waf = {"primary_waf": "Cloudflare"}
        state.add_finding(Finding(
            title="Dashboard Test SQLi",
            severity="HIGH",
            description="d",
            impact="i",
            remediation="r",
            tool_source="docker_sqlmap_scan",
            raw_evidence="e",
        ))
        state.register_discovered_service(80, "http")

        # Must execute without errors
        _display_mission_dashboard(
            report_state=state,
            iteration=2,
            max_iterations=15,
            last_tool="docker_sqlmap_scan",
            last_duration=1.8,
            stagnation_counter=0,
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])




