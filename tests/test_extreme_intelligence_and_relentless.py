"""Comprehensive Test Suite for Ultimate Cognitive Hyper-Intelligence and Relentless Pursuit Engine.

Validates:
1. 8-Vector Enterprise Compound Threat Correlation Matrix (all 8 scenarios).
2. Exhaustive Attack Surface Verifier (is_surface_exhausted).
3. Zero-Surrender Absolute Mission Gatekeeper (blocking up to 10 challenges).
4. Stagnation Auto-Resurrection (up to 5 rescue attempts).
5. 5-Vector Cognitive Dual-Loop Reasoning System Prompt.
"""

import pytest
from unittest.mock import MagicMock, patch

from src.client.report_state import ReportState, Finding, ToolStep
from src.client.orchestrator import _evaluate_mission_guard
from src.utils.config import load_config, validate_config, _default_config, get as cfg_get


class TestExpandedCompoundThreatMatrix:
    """Validate all 8 compound threat correlation scenarios in ReportState."""

    def test_chain1_admin_session_hijacking(self):
        state = ReportState(target="http://example.com")
        state.add_finding(Finding(title="Reflected XSS on /search", severity="HIGH", description="XSS"))
        state.attack_surface.cookie_issues = [{"name": "session", "missing_flags": ["HttpOnly"]}]
        state.attack_surface.hidden_discovered_paths = ["/admin/dashboard"]
        
        compound = state.correlate_compound_threats()
        assert any("Chiếm quyền điều khiển phiên Quản trị viên" in f.title for f in compound)
        c1 = next(f for f in state.findings if "Chiếm quyền điều khiển phiên Quản trị viên" in f.title)
        assert c1.severity == "CRITICAL"
        assert c1.cvss_score == 9.3

    def test_chain2_bec_and_database_credential_leakage(self):
        state = ReportState(target="http://example.com")
        state.attack_surface.dns_security_info = {"security_issues": ["Missing SPF and DMARC"]}
        state.attack_surface.exposed_sensitive_files = [{"path": "/.env", "risk_type": "Credentials"}]
        
        compound = state.correlate_compound_threats()
        assert any("Giả mạo định danh doanh nghiệp kết hợp lộ lọt" in f.title for f in compound)
        c2 = next(f for f in state.findings if "Giả mạo định danh doanh nghiệp kết hợp lộ lọt" in f.title)
        assert c2.severity == "HIGH"
        assert c2.cvss_score == 8.5

    def test_chain3_cross_origin_data_exfiltration(self):
        state = ReportState(target="http://example.com")
        state.attack_surface.cors_issues = [{"url": "http://example.com/api", "type": "Reflected Origin"}]
        state.attack_surface.cookie_issues = [{"name": "auth", "missing_flags": ["SameSite"]}]
        
        compound = state.correlate_compound_threats()
        assert any("Đánh cắp dữ liệu người dùng qua lỗ hổng phối hợp CORS" in f.title for f in compound)
        c3 = next(f for f in state.findings if "Đánh cắp dữ liệu người dùng qua lỗ hổng phối hợp CORS" in f.title)
        assert c3.severity == "HIGH"
        assert c3.cvss_score == 8.2

    def test_chain4_database_exposure_and_remote_compromise(self):
        state = ReportState(target="http://example.com")
        state.attack_surface.open_ports = {3306: {"service": "mysql"}}
        state.attack_surface.exposed_sensitive_files = [{"path": "/config/db.ini", "risk_type": "DB Password"}]
        
        compound = state.correlate_compound_threats()
        assert any("Nguy cơ chiếm đoạt cơ sở dữ liệu và truy xuất dữ liệu từ xa" in f.title for f in compound)
        c4 = next(f for f in state.findings if "Nguy cơ chiếm đoạt cơ sở dữ liệu và truy xuất dữ liệu từ xa" in f.title)
        assert c4.severity == "CRITICAL"
        assert c4.cvss_score == 9.4

    def test_chain5_subdomain_hijacking_and_shadow_it(self):
        state = ReportState(target="http://example.com")
        state.attack_surface.alive_subdomains = [{"url": "http://dev.example.com"}]
        state.attack_surface.dns_security_info = {"security_issues": ["No DNSSEC"]}
        
        compound = state.correlate_compound_threats()
        assert any("Nguy cơ chiếm đoạt tên miền phụ (Subdomain Takeover)" in f.title for f in compound)
        c5 = next(f for f in state.findings if "Nguy cơ chiếm đoạt tên miền phụ (Subdomain Takeover)" in f.title)
        assert c5.severity == "HIGH"
        assert c5.cvss_score == 8.4

    def test_chain6_ssrf_and_cloud_metadata_exfiltration(self):
        state = ReportState(target="http://example.com")
        state.attack_surface.parameterized_endpoints = {"http://example.com/proxy?url=http://target": {}}
        state.attack_surface.exposed_sensitive_files = [{"path": "/backup/app.tar.gz"}]
        
        compound = state.correlate_compound_threats()
        assert any("Nguy cơ tấn công SSRF truy xuất siêu dữ liệu Đám mây" in f.title for f in compound)
        c6 = next(f for f in state.findings if "Nguy cơ tấn công SSRF truy xuất siêu dữ liệu Đám mây" in f.title)
        assert c6.severity == "HIGH"
        assert c6.cvss_score == 8.6

    def test_chain7_admin_privilege_escalation_internal_interface(self):
        state = ReportState(target="http://example.com")
        state.attack_surface.hidden_discovered_paths = ["/admin/users"]
        state.attack_surface.login_forms = [{"url": "http://example.com/admin/login"}]
        
        compound = state.correlate_compound_threats()
        assert any("Nguy cơ leo thang đặc quyền quản trị qua giao diện nội bộ" in f.title for f in compound)
        c7 = next(f for f in state.findings if "Nguy cơ leo thang đặc quyền quản trị qua giao diện nội bộ" in f.title)
        assert c7.severity == "HIGH"
        assert c7.cvss_score == 8.3

    def test_chain8_web_server_framework_rce(self):
        state = ReportState(target="http://example.com")
        state.attack_surface.detected_technologies = ["Apache 2.4.49"]
        state.add_finding(Finding(title="CVE-2021-41773 Directory Traversal", severity="CRITICAL", description="Apache bug"))
        
        assert any("Nguy cơ thực thi mã từ xa RCE thông qua lỗ hổng máy chủ web" in f.title for f in state.findings)
        c8 = next(f for f in state.findings if "Nguy cơ thực thi mã từ xa RCE thông qua lỗ hổng máy chủ web" in f.title)
        assert c8.severity == "CRITICAL"
        assert c8.cvss_score == 9.8


class TestExhaustiveAttackSurfaceVerifier:
    """Validate is_surface_exhausted() verifier across attack surface dimensions."""

    def test_unexhausted_ports_and_sqli(self):
        state = ReportState(target="http://example.com", scan_mode="full")
        state.attack_surface.open_ports = {80: {"service": "http", "deep_scanned": False}}
        state.attack_surface.parameterized_endpoints = {"http://example.com/view?id=1": {"tested_sqli": False, "tested_xss": True}}
        
        is_exhausted, untested = state.is_surface_exhausted()
        assert is_exhausted is False
        assert any("docker_scan_ports_deep" in u for u in untested)
        assert any("docker_sqlmap_scan" in u for u in untested)

    def test_exhausted_when_tools_called(self):
        state = ReportState(target="http://example.com", scan_mode="full")
        state.attack_surface.open_ports = {80: {"service": "http", "deep_scanned": True}}
        state.attack_surface.parameterized_endpoints = {"http://example.com/view?id=1": {"tested_sqli": True, "tested_xss": True}}
        
        all_required_tools = {
            "docker_scan_ports_deep",
            "docker_sqlmap_scan",
            "docker_xss_scan",
            "docker_sensitive_files_scan",
            "docker_cookie_security_audit",
            "docker_dns_security_audit",
            "docker_security_txt_audit",
            "docker_http_headers_audit",
            "docker_waf_detect",
        }
        is_exhausted, untested = state.is_surface_exhausted(tools_called=all_required_tools)
        assert is_exhausted is True
        assert len(untested) == 0


class TestZeroSurrenderGatekeeperExtreme:
    """Validate that mission guard blocks early completion up to 10 times in relentless pursuit."""

    def test_blocks_up_to_10_attempts_in_relentless_mode(self):
        state = ReportState(target="http://example.com", scan_mode="full", mission_objective="Audit full website")
        # Keep 1 milestone pending
        state.milestones[0].status = "COMPLETED"
        state.milestones[1].status = "PENDING"
        
        # Test attempts 0 through 9: ALL must be blocked
        for attempt in range(10):
            should_guard, unfulfilled = _evaluate_mission_guard(
                report_state=state,
                tools_called={"docker_scan_ports_fast"},
                progress_pct=40,
                untapped_actions=[{"action": "docker_crawl_web", "priority": "CRITICAL"}],
                iteration=5,
                max_iterations=25,
                guard_attempts=attempt,
                relentless_pursuit=True,
                max_guard_attempts=10,
            )
            assert should_guard is True, f"Failed to guard on attempt {attempt}"
            assert len(unfulfilled) > 0

        # Attempt 10: budget reached, allow exit
        should_guard, unfulfilled = _evaluate_mission_guard(
            report_state=state,
            tools_called={"docker_scan_ports_fast"},
            progress_pct=40,
            untapped_actions=[{"action": "docker_crawl_web", "priority": "CRITICAL"}],
            iteration=5,
            max_iterations=25,
            guard_attempts=10,
            relentless_pursuit=True,
            max_guard_attempts=10,
        )
        assert should_guard is False
        assert len(unfulfilled) == 0


class TestConfigurationAndStagnationRescue:
    """Validate default configuration and stagnation rescue parameters."""

    def test_default_config_extreme_parameters(self):
        default_cfg = _default_config()
        assert default_cfg["agent"]["relentless_pursuit"] is True
        assert default_cfg["agent"]["compound_threat_correlation"] is True
        assert default_cfg["agent"]["max_guard_challenges"] == 10
        assert default_cfg["agent"]["stagnation_max_rescues"] == 5

    def test_validate_config_accepts_valid_stagnation_rescues(self):
        valid_cfg = {
            "llm": {"base_url": "http://localhost:11434/v1", "model": "test"},
            "agent": {
                "max_iterations": 25,
                "relentless_pursuit": True,
                "compound_threat_correlation": True,
                "max_guard_challenges": 10,
                "stagnation_max_rescues": 5,
            },
            "timeouts": {"fast_scan": 120},
            "hitl": {"destructive_tools": []},
        }
        is_valid, errors = validate_config(valid_cfg)
        assert is_valid is True
        assert errors == []

    def test_validate_config_rejects_invalid_stagnation_rescues(self):
        invalid_cfg = {
            "llm": {"base_url": "http://localhost:11434/v1", "model": "test"},
            "agent": {
                "max_iterations": 25,
                "stagnation_max_rescues": -1,
            },
            "timeouts": {"fast_scan": 120},
            "hitl": {"destructive_tools": []},
        }
        is_valid, errors = validate_config(invalid_cfg)
        assert is_valid is False
        assert any("stagnation_max_rescues" in e for e in errors)


class TestCognitiveDualLoopCoTFormat:
    """Validate the 5-vector Cognitive CoT structure required in system prompt."""

    def test_system_prompt_mandates_5_vectors(self):
        import inspect
        from src.client import orchestrator
        source = inspect.getsource(orchestrator.run_agent)
        
        assert "[TÌNH BÁO TỔNG HỢP]" in source
        assert "[GIẢ THUYẾT ĐỘT PHÁ]" in source
        assert "[ĐÒN ĐÁNH CỘT MỐC]" in source
        assert "[CHIẾN THUẬT NÉ TRÁNH PHÒNG THỦ]" in source
        assert "[DỰ PHÒNG TỨC THỜI]" in source
