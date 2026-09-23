"""Tests for Big Update 2.0:
- 4 New Security Tools: docker_ssl_cert_audit, docker_dns_security_audit,
  docker_security_txt_audit, docker_cookie_security_audit
- Objective Milestone Engine (M1..M4 tracking, progress %, roadmap elevation)
- Orchestrator Distillation, Fuzzy Matching, and Mission Guard for new tools
- ReportState Attack Surface expansion & DOCX generation
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from src.servers import docker_arsenal
from src.client.report_state import ReportState, ObjectiveMilestone, AttackSurfaceGraph
from src.client.orchestrator import (
    _fuzzy_match_tool_name,
    _distill_tool_intelligence,
    _evaluate_mission_guard,
)
from src.utils.report_generator import generate_docx_report


# ===========================================================================
# 1. Tests for docker_ssl_cert_audit
# ===========================================================================

class TestSSLCertAudit:
    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_ssl_cert_audit_success(self, mock_ssl_ctx, mock_socket_conn):
        mock_sock = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_sock
        mock_ssock = MagicMock()
        mock_ssl_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "DigiCert Inc"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "api.example.com"), ("DNS", "admin.example.com")),
        }

        res_str = docker_arsenal.docker_ssl_cert_audit("example.com")
        data = json.loads(res_str)

        assert data["status"] == "success"
        assert data["hostname"] == "example.com"
        assert data["subject_cn"] == "example.com"
        assert data["issuer_org"] == "DigiCert Inc"
        assert data["tls_version"] == "TLSv1.3"
        assert data["key_bits"] == 256
        assert "api.example.com" in data["subject_alternative_names"]
        assert len(data["subject_alternative_names"]) == 3

    @patch("socket.create_connection", side_effect=Exception("Connection refused"))
    def test_ssl_cert_audit_connection_error(self, mock_socket_conn):
        res_str = docker_arsenal.docker_ssl_cert_audit("offline-host.local")
        data = json.loads(res_str)
        assert data["status"] == "error"
        assert "Connection refused" in data["error"]


# ===========================================================================
# 2. Tests for docker_dns_security_audit
# ===========================================================================

class TestDNSSecurityAudit:
    @patch("requests.get")
    def test_dns_security_audit_with_valid_spf_and_dmarc(self, mock_get):
        def mock_side_effect(url, **kwargs):
            m = MagicMock()
            m.status_code = 200
            if "name=example.com" in url and "type=TXT" in url:
                m.json.return_value = {
                    "Status": 0,
                    "Answer": [{"data": '"v=spf1 include:_spf.google.com ~all"'}]
                }
            elif "name=_dmarc.example.com" in url and "type=TXT" in url:
                m.json.return_value = {
                    "Status": 0,
                    "Answer": [{"data": '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'}]
                }
            elif "name=example.com" in url and "type=MX" in url:
                m.json.return_value = {
                    "Status": 0,
                    "Answer": [{"data": "10 mail.example.com."}]
                }
            elif "name=example.com" in url and "type=DNSKEY" in url:
                m.json.return_value = {
                    "Status": 0,
                    "AD": True,
                    "Answer": [{"data": "257 3 13 ..."}]
                }
            else:
                m.json.return_value = {"Status": 0, "Answer": []}
            return m

        mock_get.side_effect = mock_side_effect
        res_str = docker_arsenal.docker_dns_security_audit("example.com")
        data = json.loads(res_str)

        assert data["status"] == "success"
        assert data["spf"]["status"] == "valid"
        assert data["dmarc"]["status"] == "valid"
        assert data["dmarc"]["policy"] == "reject"
        assert data["dnssec"]["dnssec_enabled"] is True
        assert len(data["mx_records"]) == 1

    @patch("requests.get")
    def test_dns_security_audit_missing_spf_and_dmarc(self, mock_get):
        m = MagicMock()
        m.status_code = 200
        m.json.return_value = {"Status": 0, "Answer": []}
        mock_get.return_value = m

        res_str = docker_arsenal.docker_dns_security_audit("insecure-site.org")
        data = json.loads(res_str)

        assert data["status"] == "success"
        assert data["spf"]["status"] == "missing"
        assert data["dmarc"]["status"] == "missing"
        assert any("SPF" in iss for iss in data["security_issues"])
        assert any("DMARC" in iss for iss in data["security_issues"])


# ===========================================================================
# 3. Tests for docker_security_txt_audit
# ===========================================================================

class TestSecurityTxtAudit:
    @patch("requests.get")
    def test_security_txt_audit_findings(self, mock_get):
        def mock_side_effect(url, **kwargs):
            m = MagicMock()
            if "/.well-known/security.txt" in url:
                m.status_code = 200
                m.text = "Contact: mailto:security@target.com\nExpires: 2027-01-01T00:00:00.000Z\n"
            elif "/robots.txt" in url:
                m.status_code = 200
                m.text = "User-agent: *\nDisallow: /admin\nDisallow: /internal-api/\nDisallow: /backup.zip\n"
            elif "/sitemap.xml" in url:
                m.status_code = 200
                m.text = "<urlset><url><loc>http://target.com/secret-portal</loc></url></urlset>"
            else:
                m.status_code = 404
                m.text = "Not Found"
            return m

        mock_get.side_effect = mock_side_effect
        res_str = docker_arsenal.docker_security_txt_audit("http://target.com")
        data = json.loads(res_str)

        assert data["status"] == "success"
        assert data["security_txt"]["found"] is True
        assert "mailto:security@target.com" in data["security_txt"]["contact"]
        assert data["robots_txt"]["found"] is True
        assert len(data["robots_txt"]["disallowed_paths"]) == 3
        assert any("/admin" in p for p in data["interesting_paths_found"])
        assert any("/backup.zip" in p for p in data["interesting_paths_found"])


# ===========================================================================
# 4. Tests for docker_cookie_security_audit
# ===========================================================================

class TestCookieSecurityAudit:
    @patch("requests.get")
    def test_cookie_security_missing_flags(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        # Mock a session cookie missing Secure and HttpOnly
        mock_cookie = MagicMock()
        mock_cookie.name = "session_id"
        mock_cookie.secure = False
        mock_cookie.has_nonstandard_attr = lambda attr: False
        mock_cookie._rest = {}
        mock_resp.cookies = [mock_cookie]
        mock_resp.headers = {"set-cookie": "session_id=12345; Path=/"}
        mock_resp.url = "http://testapp.local"

        mock_get.return_value = mock_resp
        res_str = docker_arsenal.docker_cookie_security_audit("http://testapp.local")
        data = json.loads(res_str)

        assert data["status"] == "success"
        assert data["total_cookies_found"] == 1
        assert len(data["issues"]) > 0
        issue = data["issues"][0]
        assert issue["name"] == "session_id"
        assert "Secure" in issue["missing_flags"]
        assert "HttpOnly" in issue["missing_flags"]
        assert issue["severity"] == "HIGH"


# ===========================================================================
# 5. Tests for Objective Milestone Engine & ReportState
# ===========================================================================

class TestObjectiveMilestoneEngine:
    def test_initial_milestones_created(self):
        rs = ReportState(target="http://example.com", mission_objective="Tìm lỗ hổng SQL Injection và mật khẩu")
        assert len(rs.milestones) == 4
        m1 = rs.milestones[0]
        assert m1.id == "m1_recon"
        assert m1.status == "PENDING"
        assert m1.progress_pct == 0

    def test_milestone_progress_and_completion_flow(self):
        from src.client.report_state import ToolStep
        rs = ReportState(target="http://example.com", mission_objective="Rà quét toàn diện")
        # Step 1: Recon tool
        crawl_res = "Discovered 5 endpoints: http://example.com/item?id=1"
        rs.add_step(ToolStep(
            step_number=1,
            tool_name="docker_crawl_web",
            arguments={"target": "http://example.com"},
            result_snippet=crawl_res,
            reporter_comment="Crawl completed",
            status="SUCCESS",
        ))
        rs.update_attack_surface("docker_crawl_web", {"target": "http://example.com"}, crawl_res)
        assert rs.milestones[0].status in ("IN_PROGRESS", "COMPLETED")
        assert rs.milestones[0].progress_pct > 0

        # Step 2: Infra & Policy audit tools
        ssl_res = json.dumps({"status": "success", "subject_cn": "example.com", "days_until_expiry": 100, "san_domains": ["api.example.com"]})
        rs.add_step(ToolStep(
            step_number=2,
            tool_name="docker_ssl_cert_audit",
            arguments={"target": "example.com"},
            result_snippet=ssl_res,
            reporter_comment="SSL audit OK",
            status="SUCCESS",
        ))
        rs.update_attack_surface("docker_ssl_cert_audit", {"target": "example.com"}, ssl_res)
        assert rs.milestones[1].status == "IN_PROGRESS"
        # Check SANs added to subdomains automatically
        assert "api.example.com" in rs.attack_surface.subdomains

    def test_reporter_feedback_block_shows_milestones(self):
        rs = ReportState(target="http://example.com", mission_objective="Audit toàn bộ")
        feedback = rs.get_reporter_feedback_block()
        assert "Mốc sứ mệnh:" in feedback
        assert "Trinh Sát & Thu Thập Bề Mặt" in feedback
        assert "Kiểm Toán Cấu Hình & Hạ Tầng" in feedback
        assert "Tổng Hợp Rủi Ro & Khuyến Nghị Phòng Thủ" in feedback

    def test_tactical_roadmap_elevates_active_milestone(self):
        rs = ReportState(target="http://example.com", scan_mode="full", mission_objective="Kiểm tra bảo mật SQL và XSS")
        rs.attack_surface.parameterized_endpoints["http://example.com/search?q=test"] = {
            "params": ["q"],
            "tested_sqli": False,
            "tested_xss": False,
        }
        roadmap = rs.get_tactical_roadmap()
        # Should contain items from roadmap
        assert "untested_actions" in roadmap
        untested = roadmap["untested_actions"]
        assert len(untested) > 0
        tool_names = [r["tool"] for r in untested]
        assert "docker_sqlmap_scan" in tool_names or "docker_xss_scan" in tool_names


# ===========================================================================
# 6. Tests for Orchestrator Integrations (Fuzzy match, Distill, Mission Guard)
# ===========================================================================

class TestOrchestratorIntegrations:
    def test_fuzzy_match_tool_aliases_for_new_tools(self):
        schema = [
            {"name": "docker_ssl_cert_audit"},
            {"name": "docker_dns_security_audit"},
            {"name": "docker_security_txt_audit"},
            {"name": "docker_cookie_security_audit"},
        ]
        assert _fuzzy_match_tool_name("ssl_cert", schema) == "docker_ssl_cert_audit"
        assert _fuzzy_match_tool_name("cert_audit", schema) == "docker_ssl_cert_audit"
        assert _fuzzy_match_tool_name("dns_security", schema) == "docker_dns_security_audit"
        assert _fuzzy_match_tool_name("spf_audit", schema) == "docker_dns_security_audit"
        assert _fuzzy_match_tool_name("security_txt", schema) == "docker_security_txt_audit"
        assert _fuzzy_match_tool_name("robots_txt", schema) == "docker_security_txt_audit"
        assert _fuzzy_match_tool_name("cookie_security", schema) == "docker_cookie_security_audit"
        assert _fuzzy_match_tool_name("cookie_audit", schema) == "docker_cookie_security_audit"

    def test_distill_tool_intelligence_new_tools(self):
        # SSL
        ssl_res = json.dumps({"status": "success", "days_until_expiry": 45, "subject_alternative_names": ["a.com", "b.com"], "issues": []})
        intel = _distill_tool_intelligence("docker_ssl_cert_audit", ssl_res)
        assert "45 ngày" in intel["summary"]
        assert "2 SANs" in intel["summary"]

        # DNS
        dns_res = json.dumps({"status": "success", "spf": {"status": "valid"}, "dmarc": {"status": "valid"}, "dnssec": {"dnssec_enabled": True}, "security_issues": []})
        intel = _distill_tool_intelligence("docker_dns_security_audit", dns_res)
        assert "SPF=valid" in intel["summary"]
        assert "DNSSEC=bật" in intel["summary"]

        # Cookie
        cookie_res = json.dumps({"status": "success", "total_cookies_found": 3, "issues": [{"name": "auth"}]})
        intel = _distill_tool_intelligence("docker_cookie_security_audit", cookie_res)
        assert "3 cookie" in intel["summary"]

    def test_mission_guard_blocks_untested_ssl_objective(self):
        rs = ReportState(target="https://target.com", mission_objective="Đánh giá chứng chỉ SSL và chứng thư")
        tools_called = {"docker_scan_ports_fast"}
        should_guard, unfulfilled = _evaluate_mission_guard(
            report_state=rs,
            tools_called=tools_called,
            progress_pct=80,
            untapped_actions=[],
            iteration=3,
            max_iterations=20,
            guard_attempts=0,
        )
        assert should_guard is True
        assert any("docker_ssl_cert_audit" in u for u in unfulfilled)

    def test_mission_guard_blocks_untested_dns_objective(self):
        rs = ReportState(target="target.com", mission_objective="Kiểm tra cấu hình SPF và DMARC chống giả mạo email")
        tools_called = {"docker_scan_ports_fast"}
        should_guard, unfulfilled = _evaluate_mission_guard(
            report_state=rs,
            tools_called=tools_called,
            progress_pct=80,
            untapped_actions=[],
            iteration=3,
            max_iterations=20,
            guard_attempts=0,
        )
        assert should_guard is True
        assert any("docker_dns_security_audit" in u for u in unfulfilled)


# ===========================================================================
# 7. Tests for DOCX Generation with Expanded Attack Surface
# ===========================================================================

class TestDocxReportGenerationWithNewSections:
    def test_docx_renders_all_new_attack_surface_tables(self):
        rs = ReportState(target="https://enterprise.local", scan_mode="full", mission_objective="Toàn diện hệ thống")
        # Populate new attack surface fields
        rs.attack_surface.ssl_cert_info = {
            "subject_cn": "enterprise.local",
            "issuer_org": "Enterprise CA",
            "valid_to": "2027-01-01",
            "days_until_expiry": 280,
            "tls_version": "TLSv1.3",
            "key_bits": 2048,
            "subject_alternative_names": ["api.enterprise.local", "mail.enterprise.local"],
            "issues": ["Thiếu HSTS"],
        }
        rs.attack_surface.dns_security_info = {
            "spf": {"status": "missing", "details": "No SPF TXT record found"},
            "dmarc": {"status": "missing", "details": "No DMARC record"},
            "dnssec": {"dnssec_enabled": False},
            "security_issues": ["Domain vulnerable to email spoofing"],
        }
        rs.attack_surface.hidden_discovered_paths = [
            "/admin", "/backup.tar.gz", "/.well-known/security.txt"
        ]
        rs.attack_surface.cookie_issues = [
            {
                "name": "session_token",
                "missing_flags": ["Secure", "HttpOnly"],
                "severity": "HIGH",
                "risk": "Nguy cơ đánh cắp phiên qua XSS",
            }
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_file = os.path.join(tmp_dir, "audit.jsonl")
            with open(audit_file, "w", encoding="utf-8") as f:
                f.write('{"event": "test"}\n')

            with patch("src.utils.config.get", return_value=tmp_dir):
                docx_path = generate_docx_report(rs.to_dict(), audit_file)
                assert os.path.exists(docx_path)
                assert os.path.getsize(docx_path) > 5000
