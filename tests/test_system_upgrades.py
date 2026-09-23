"""Unit tests for v4.1 system upgrades and enhancements.

Covers:
- Enhanced config validation (timeouts, reports, wordlists, mcp, reporter).
- Expanded tool argument normalization (port/ports, domain/target_domain).
- JSON healing with unescaped newlines and Vietnamese diacritics.
- Mission objective extraction and pinning in orchestrator.
- Multi-format report export (JSON and Markdown) in ReportState.
- Extended Finding fields (cve_id, cvss_score).
- CLI enhancements (--version, --output-dir).
"""

import json
import os
import pathlib
import pytest
import tempfile
from unittest.mock import patch, MagicMock, AsyncMock

from src.utils.config import validate_config, reload_config, load_config
from src.client.report_state import ReportState, Finding, ToolStep
from src.client.orchestrator import (
    _normalize_tool_args,
    _escape_newlines_in_json_strings,
    _extract_json,
    _extract_mission_objective,
    _export_all_reports,
)
import main


class TestConfigValidationUpgrades:
    """Tests for extended config validation in src/utils/config.py."""

    def test_valid_default_config_passes(self):
        reload_config()
        is_valid, errors = validate_config()
        assert is_valid is True
        assert len(errors) == 0

    def test_invalid_timeouts_detected(self):
        bad_cfg = {
            "llm": {"host": "localhost", "port": 11434, "model": "test"},
            "agent": {"scan_mode": "recon", "max_iterations": 10},
            "timeouts": {"nmap_fast": -10, "tool_default": "invalid_int"},
        }
        is_valid, errors = validate_config(bad_cfg)
        assert is_valid is False
        assert any("nmap_fast must be a positive number" in err for err in errors)
        assert any("tool_default must be a positive number" in err for err in errors)

    def test_invalid_reports_section_detected(self):
        bad_cfg = {
            "llm": {"host": "localhost", "port": 11434, "model": "test"},
            "agent": {"scan_mode": "recon", "max_iterations": 10},
            "reports": {
                "generate_word": "not_a_bool",
                "generate_markdown": "not_a_bool",
                "generate_json": 12345,
            },
        }
        is_valid, errors = validate_config(bad_cfg)
        assert is_valid is False
        assert any("reports.generate_word must be a boolean" in err for err in errors)
        assert any("reports.generate_markdown must be a boolean" in err for err in errors)
        assert any("reports.generate_json must be a boolean" in err for err in errors)

    def test_invalid_reporter_skip_tools_detected(self):
        bad_cfg = {
            "llm": {"host": "localhost", "port": 11434, "model": "test"},
            "agent": {"scan_mode": "recon", "max_iterations": 10},
            "reporter": {"skip_tools": "should_be_list"},
        }
        is_valid, errors = validate_config(bad_cfg)
        assert is_valid is False
        assert any("reporter.skip_tools must be a list" in err for err in errors)

    def test_invalid_mcp_log_level_detected(self):
        bad_cfg = {
            "llm": {"host": "localhost", "port": 11434, "model": "test"},
            "agent": {"scan_mode": "recon", "max_iterations": 10},
            "mcp": {"log_level": "INVALID_LEVEL"},
        }
        is_valid, errors = validate_config(bad_cfg)
        assert is_valid is False
        assert any("mcp.log_level must be one of" in err for err in errors)


class TestToolNormalizationUpgrades:
    """Tests for expanded tool argument aliasing in orchestrator."""

    MOCK_SCHEMA = [
        {"name": "docker_scan_ports_deep", "input_schema": {"properties": {"target": {}, "ports": {}}}},
        {"name": "bruteforce_ssh", "input_schema": {"properties": {"target": {}, "port": {}}}},
        {"name": "docker_subfinder", "input_schema": {"properties": {"target_domain": {}}}},
        {"name": "docker_resolve_dns", "input_schema": {"properties": {"domain": {}}}},
    ]

    def test_normalize_port_to_ports(self):
        args = {"target": "10.0.0.1", "port": "80,443"}
        normalized = _normalize_tool_args("docker_scan_ports_deep", args, self.MOCK_SCHEMA)
        assert "ports" in normalized
        assert normalized["ports"] == "80,443"

    def test_normalize_ports_to_port(self):
        args = {"target": "10.0.0.1", "ports": 22}
        normalized = _normalize_tool_args("bruteforce_ssh", args, self.MOCK_SCHEMA)
        assert "port" in normalized
        assert normalized["port"] == 22

    def test_normalize_domain_to_target_domain(self):
        args = {"domain": "example.com"}
        normalized = _normalize_tool_args("docker_subfinder", args, self.MOCK_SCHEMA)
        assert "target_domain" in normalized
        assert normalized["target_domain"] == "example.com"

    def test_normalize_target_domain_to_domain(self):
        args = {"target_domain": "example.com"}
        normalized = _normalize_tool_args("docker_resolve_dns", args, self.MOCK_SCHEMA)
        assert "domain" in normalized
        assert normalized["domain"] == "example.com"


class TestJSONHealingUpgrades:
    """Tests for string newline escaping and Vietnamese JSON extraction."""

    def test_escape_newlines_in_json_strings(self):
        raw_json_with_newlines = '{\n  "thought": "Dong 1\nDong 2\nDong 3",\n  "action": "call_tool"\n}'
        healed = _escape_newlines_in_json_strings(raw_json_with_newlines)
        data = json.loads(healed)
        assert "Dong 1\nDong 2\nDong 3" == data["thought"]
        assert data["action"] == "call_tool"

    def test_extract_json_with_raw_newlines_and_vietnamese(self):
        raw_llm_output = (
            "Suy nghĩ của tôi:\n"
            "```json\n"
            "{\n"
            '  "thought": "Phát hiện cổng 80 đang mở.\nTiếp tục quét thu thập thông tin mục tiêu.",\n'
            '  "action": "call_tool",\n'
            '  "tool_name": "docker_crawl_web",\n'
            '  "arguments": {"target": "http://example.com"}\n'
            "}\n"
            "```"
        )
        parsed = _extract_json(raw_llm_output)
        assert parsed["action"] == "call_tool"
        assert parsed["tool_name"] == "docker_crawl_web"
        assert "Phát hiện cổng 80" in parsed["thought"]


class TestMissionObjectiveExtraction:
    """Tests for mission objective extraction in orchestrator."""

    def test_extract_explicit_mission(self):
        prompt = (
            "TARGET ACQUIRED: 192.168.1.50\n"
            "MISSION: Perform comprehensive reconnaissance and find all open web vulnerabilities. Report in Vietnamese."
        )
        objective = _extract_mission_objective(prompt)
        assert "Perform comprehensive reconnaissance and find all open web vulnerabilities." in objective

    def test_extract_fallback_objective(self):
        prompt = "Hãy quét mục tiêu testphp.vulnweb.com và tìm lỗ hổng SQL Injection"
        objective = _extract_mission_objective(prompt)
        assert "testphp.vulnweb.com" in objective
        assert len(objective) > 0


class TestReportStateUpgrades:
    """Tests for ReportState multi-format export and extended Finding fields."""

    def test_finding_cve_and_cvss(self):
        finding = Finding(
            title="Apache Log4j RCE",
            severity="CRITICAL",
            description="Remote code execution via JNDI lookup",
            cve_id="cve-2021-44228",
            cvss_score=10.0,
        )
        assert finding.cve_id == "CVE-2021-44228"
        assert finding.cvss_score == 10.0

    def test_export_json_and_markdown(self):
        state = ReportState(target="http://example.com", scan_mode="full", mission_objective="Find critical bugs")
        state.add_finding(Finding(
            title="SQL Injection",
            severity="HIGH",
            description="Blind SQLi in id parameter",
            cve_id="CVE-2024-1234",
            cvss_score=8.5,
        ))
        state.add_step(ToolStep(
            step_number=1,
            tool_name="docker_crawl_web",
            arguments={"target": "http://example.com"},
            result_snippet="Found /index.php?id=1",
            status="SUCCESS",
            duration_seconds=1.5,
        ))
        state.finalize(red_teamer_answer="Target has high risk vulnerability.")

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "report.json")
            md_path = os.path.join(tmpdir, "report.md")

            state.export_json(json_path)
            state.export_markdown(md_path)

            assert os.path.exists(json_path)
            assert os.path.exists(md_path)

            # Verify JSON content
            with open(json_path, "r", encoding="utf-8") as f:
                loaded_json = json.load(f)
            assert loaded_json["target"] == "http://example.com"
            assert loaded_json["mission_objective"] == "Find critical bugs"
            assert len(loaded_json["findings"]) == 1
            assert loaded_json["findings"][0]["cve_id"] == "CVE-2024-1234"
            assert loaded_json["findings"][0]["cvss_score"] == 8.5

            # Verify Markdown content
            with open(md_path, "r", encoding="utf-8") as f:
                md_text = f.read()
            assert "Mục tiêu yêu cầu" in md_text
            assert "Find critical bugs" in md_text
            assert "SQL Injection" in md_text
            assert "CVE-2024-1234" in md_text


class TestExportAllReports:
    """Tests for _export_all_reports helper."""

    def test_export_all_reports_creates_files(self):
        state = ReportState(target="192.168.1.100", scan_mode="recon", mission_objective="Reconnaissance")
        state.add_finding(Finding(
            title="Open Port 80",
            severity="LOW",
            description="HTTP service running",
        ))
        state.finalize(red_teamer_answer="Recon completed.")

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("src.client.orchestrator.cfg_get") as mock_cfg:
                # Mock cfg_get to return tmpdir for output_dir, False for generate_word to skip docx in unit test
                mock_cfg.side_effect = lambda key, default=None: {
                    "reports.output_dir": tmpdir,
                    "reports.generate_word": False,
                }.get(key, default)

                audit_path = os.path.join(tmpdir, "audit_trail_192.168.1.100_20260917.jsonl")
                with open(audit_path, "w", encoding="utf-8") as f:
                    f.write("{}\n")

                primary_path = _export_all_reports(state, audit_path, "192.168.1.100")
                assert os.path.exists(primary_path)

                files_in_tmp = os.listdir(tmpdir)
                md_files = [f for f in files_in_tmp if f.endswith(".md")]
                json_files = [f for f in files_in_tmp if f.endswith(".json")]
                assert len(md_files) >= 1
                assert len(json_files) >= 1


class TestMainCliUpgrades:
    """Tests for CLI upgrades in main.py."""

    def test_version_flag(self):
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["main.py", "--version"]):
                main._parse_args()
        assert exc_info.value.code == 0

    def test_output_dir_flag(self):
        with patch("sys.argv", ["main.py", "--output-dir", "custom_reports_dir"]):
            args = main._parse_args()
            assert args.output_dir == "custom_reports_dir"
