"""Tests for Relentless Pursuit Mode and Cognitive Hyper-Intelligence Engine.

Verifies:
1. Deep Target Auto-Disambiguation (Instant port, endpoint, and path detection)
2. Vulnerability Correlation Engine (Kill-Chain Synthesis into Compound Attack Scenarios)
3. Adaptive Obstacle Pivot Matrix (Dynamic fallback on 403, WAF, empty crawler/ports, SQLi failure)
4. Zero-Surrender Mission Gatekeeper (Interception of premature final_answer in relentless mode)
5. Multi-Format Report Integration (Compound Attack Scenarios table in DOCX)
6. CLI Flag integration (--relentless)
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from src.client.report_state import ReportState, Finding, ToolStep
from src.client.orchestrator import _resolve_tactical_pivot, _evaluate_mission_guard
from src.utils.report_generator import generate_docx_report
import main


class TestDeepTargetAutoDisambiguation:
    """Test instant parsing of target URLs into attack surface components."""

    def test_disambiguate_complex_url(self):
        target = "http://target.local:8080/admin/dashboard?view=users&id=105"
        state = ReportState(target=target, scan_mode="recon")

        # Port 8080 should be registered
        assert 8080 in state.attack_surface.open_ports
        assert state.attack_surface.open_ports[8080]["service"] == "http"

        # Parameterized endpoint should be registered
        assert target in state.attack_surface.parameterized_endpoints
        assert state.attack_surface.parameterized_endpoints[target]["tested_sqli"] is False

        # Admin path should be detected
        assert "/admin/dashboard" in state.attack_surface.hidden_discovered_paths
        assert any(target in f["url"] for f in state.attack_surface.login_forms)

    def test_disambiguate_plain_root_url_preserves_clean_state(self):
        target = "http://example.com"
        state = ReportState(target=target, scan_mode="recon")
        # No explicit port or query, so attack surface remains clean for active scanning
        assert not state.attack_surface.has_attack_surface()

    def test_disambiguate_https_custom_port(self):
        target = "https://secure.corp.local:8443/api/v1/auth"
        state = ReportState(target=target, scan_mode="full")
        assert 8443 in state.attack_surface.open_ports
        assert state.attack_surface.open_ports[8443]["service"] == "https"
        assert "/api/v1/auth" in state.attack_surface.hidden_discovered_paths


class TestVulnerabilityCorrelationEngine:
    """Test multi-signal vulnerability chaining and compound attack synthesis."""

    def test_chain_admin_session_hijacking(self):
        state = ReportState(target="http://vuln.local", scan_mode="full")
        state.attack_surface.hidden_discovered_paths.append("/admin")
        state.attack_surface.cookie_issues.append({"name": "PHPSESSID", "missing_flags": ["HttpOnly", "Secure"]})

        xss_finding = Finding(
            title="Reflected XSS in search parameter",
            severity="HIGH",
            description="Payload reflected in search query",
            impact="Client-side script execution",
            remediation="Sanitize input and encode output",
            tool_source="docker_xss_scan",
        )
        state.add_finding(xss_finding)

        compound_findings = [f for f in state.findings if "[CHUỖI TẤN CÔNG]" in f.title]
        assert len(compound_findings) == 1
        c = compound_findings[0]
        assert "Chiếm quyền điều khiển phiên Quản trị viên" in c.title
        assert c.severity == "CRITICAL"
        assert c.cvss_score == 9.3
        assert c.tool_source == "Compound Threat Correlation Engine"
        assert state.risk_score >= 9.0

        data = state.to_dict()
        assert len(data["compound_threats"]) == 1

    def test_chain_dns_and_sensitive_files(self):
        state = ReportState(target="http://company.com", scan_mode="full")
        state.attack_surface.dns_security_info = {
            "security_issues": ["Thiếu bản ghi SPF bảo vệ thư tín điện tử", "Chính sách DMARC chưa được thiết lập"]
        }
        state.attack_surface.exposed_sensitive_files.append({
            "path": "/.env",
            "risk_type": "Database Credentials Leak",
        })

        new_chains = state.correlate_compound_threats()
        assert len(new_chains) == 1
        assert "Giả mạo định danh doanh nghiệp" in new_chains[0].title
        assert new_chains[0].severity == "HIGH"
        assert new_chains[0].cvss_score == 8.5

    def test_chain_cors_and_cookie_session(self):
        state = ReportState(target="http://portal.local", scan_mode="full")
        state.attack_surface.cors_issues.append({
            "issue": "Access-Control-Allow-Origin: arbitrary origin reflection",
            "severity": "HIGH",
        })
        state.attack_surface.cookie_issues.append({
            "name": "auth_token",
            "missing_flags": ["SameSite"],
        })

        new_chains = state.correlate_compound_threats()
        assert len(new_chains) == 1
        assert "CORS Misconfiguration" in new_chains[0].title
        assert new_chains[0].severity == "HIGH"
        assert new_chains[0].cvss_score == 8.2


class TestAdaptiveObstaclePivotMatrix:
    """Test dynamic tactical pivots when encountering roadblocks."""

    def test_pivot_on_crawler_empty(self):
        state = ReportState(target="http://spa.local")
        empty_crawl_res = json.dumps({"endpoints": [], "status": "crawled 0 pages"})
        pivot = _resolve_tactical_pivot("docker_crawl_web", empty_crawl_res, state)

        assert pivot is not None
        assert pivot["pivot_tool"] == "docker_security_txt_audit"
        assert "Crawler không tìm thấy endpoint" in pivot["obstacle"]

    def test_pivot_on_waf_403_forbidden(self):
        state = ReportState(target="http://protected.gov")
        waf_res = "HTTP/1.1 403 Forbidden - Request blocked by Cloudflare WAF"
        pivot = _resolve_tactical_pivot("docker_crawl_web", waf_res, state)

        assert pivot is not None
        assert pivot["pivot_tool"] in ("docker_security_txt_audit", "docker_dns_security_audit")
        assert "WAF" in pivot["obstacle"]

    def test_pivot_on_sqlmap_no_vulnerability(self):
        state = ReportState(target="http://app.local")
        state.attack_surface.parameterized_endpoints["http://app.local/item?id=1"] = {"tested_sqli": True, "tested_xss": False}
        sqlmap_res = "all tested parameters do not appear to be injectable. 0 vulnerabilities found."

        pivot = _resolve_tactical_pivot("docker_sqlmap_scan", sqlmap_res, state)
        assert pivot is not None
        assert pivot["pivot_tool"] == "docker_xss_scan"
        assert "XSS" in pivot["reason"]

    def test_pivot_on_wpscan_non_wordpress(self):
        state = ReportState(target="http://custom-app.local")
        wpscan_res = "The remote website does not seem to be running WordPress."
        pivot = _resolve_tactical_pivot("docker_wpscan", wpscan_res, state)

        assert pivot is not None
        assert pivot["pivot_tool"] == "docker_whatweb"


class TestZeroSurrenderMissionGatekeeper:
    """Test relentless mission guard blocking premature exits."""

    def test_relentless_guard_blocks_when_milestone_pending(self):
        state = ReportState(target="http://test.local", scan_mode="full", mission_objective="Audit full infrastructure and web")
        assert state.milestones[1].status == "PENDING"

        should_guard, unfulfilled = _evaluate_mission_guard(
            report_state=state,
            tools_called={"docker_scan_ports_fast", "docker_crawl_web"},
            progress_pct=50,
            untapped_actions=[{"action": "docker_ssl_cert_audit", "priority": "HIGH", "recommendation": "Check cert"}],
            iteration=4,
            max_iterations=20,
            guard_attempts=3,
            relentless_pursuit=True,
            max_guard_attempts=5,
        )

        assert should_guard is True
        assert any("Chế độ Cực Đoan" in u for u in unfulfilled)

    def test_relentless_guard_permits_exit_when_exhausted(self):
        state = ReportState(target="http://test.local", scan_mode="recon")
        for m in state.milestones:
            m.status = "COMPLETED"
            m.progress_pct = 100

        should_guard, unfulfilled = _evaluate_mission_guard(
            report_state=state,
            tools_called={"docker_scan_ports_fast", "docker_crawl_web", "docker_ssl_cert_audit", "docker_dns_security_audit"},
            progress_pct=100,
            untapped_actions=[],
            iteration=10,
            max_iterations=20,
            guard_attempts=0,
            relentless_pursuit=True,
            max_guard_attempts=5,
        )

        assert should_guard is False
        assert len(unfulfilled) == 0


class TestDocxReportCompoundScenarios:
    """Test DOCX report generation includes the Compound Attack Scenarios table."""

    def test_docx_generates_with_compound_scenarios(self, tmp_path):
        state = ReportState(target="http://bank.local", scan_mode="full")
        state.attack_surface.hidden_discovered_paths.append("/admin")
        state.attack_surface.cookie_issues.append({"name": "session", "missing_flags": ["HttpOnly"]})
        state.add_finding(Finding(
            title="Stored XSS in admin comments",
            severity="HIGH",
            description="Stored XSS payload",
            impact="Admin account takeover",
            tool_source="docker_xss_scan",
        ))
        state.finalize(red_teamer_answer="Assessment finalized.")

        report_data = state.to_dict()
        assert len(report_data["compound_threats"]) >= 1

        with patch("src.utils.report_generator.cfg_get", side_effect=lambda k, d=None: str(tmp_path) if "output_dir" in k else d):
            docx_path = generate_docx_report(report_data)
            assert os.path.exists(docx_path)
            assert docx_path.endswith(".docx")
            assert os.path.getsize(docx_path) > 1000


class TestCliRelentlessFlag:
    """Test CLI argument parsing and environment variable handling."""

    def test_relentless_flag_parsed(self):
        with patch("sys.argv", ["main.py", "--target", "example.com", "--relentless"]):
            args = main._parse_args()
            assert args.relentless is True

    def test_relentless_flag_default_false(self):
        with patch("sys.argv", ["main.py", "--target", "example.com"]):
            args = main._parse_args()
            assert args.relentless is False