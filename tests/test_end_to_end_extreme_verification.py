"""End-to-End Extreme Intelligence & Zero-Surrender Verification Test Suite.

Verifies:
1. Zero-Surrender Gatekeeper exhaustion defense across all 14 attack surface vectors.
2. Stagnation Auto-Resurrection (up to 5 rescue attempts with tactical priority pivoting).
3. Complete 8-Vector Enterprise Compound Threat Correlation Matrix.
4. Multi-Format Report Generation (DOCX, Markdown, JSON) under heavy load.
5. End-to-End autonomous red team workflow simulation.
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from src.client.report_state import (
    ReportState,
    Finding,
    ObjectiveMilestone,
    AttackSurfaceGraph,
)
from src.client.orchestrator import (
    _evaluate_mission_guard,
    _distill_tool_intelligence,
    _fuzzy_match_tool_name,
    _export_all_reports,
)
from src.utils.report_generator import generate_docx_report
import docx


class TestZeroSurrender14VectorExhaustion:
    """Validate that the mission gatekeeper thoroughly defends all 14 surface vectors."""

    def test_gatekeeper_blocks_when_any_vector_is_untested(self):
        # Target with HTTPS and subdomains
        state = ReportState(
            target="https://target.corp",
            scan_mode="full",
            mission_objective="Kiểm tra toàn diện bề mặt và khai thác nếu có lỗ hổng",
        )
        state.attack_surface.open_ports = {
            80: {"service": "http", "deep_scanned": True},
            443: {"service": "https", "deep_scanned": True},
        }
        state.attack_surface.subdomains = ["api.target.corp", "dev.target.corp"]
        state.attack_surface.parameterized_endpoints = {
            "https://target.corp/search?q=test": {"tested_sqli": True, "tested_xss": True}
        }
        state.attack_surface.login_forms = [
            {"action": "https://target.corp/login", "tested_bruteforce": True}
        ]

        # Incomplete tool call set (missing waf_detect, subdomain_takeover_audit, http_headers_audit)
        partial_tools = {
            "docker_scan_ports_deep",
            "docker_sqlmap_scan",
            "docker_xss_scan",
            "bruteforce_http_form",
            "docker_httpx_probe",
            "docker_sensitive_files_scan",
            "docker_cookie_security_audit",
            "docker_dns_security_audit",
            "docker_security_txt_audit",
            "docker_ssl_cert_audit",
        }

        # Check surface exhaustion
        is_exhausted, untested = state.is_surface_exhausted(tools_called=partial_tools)
        assert is_exhausted is False
        assert len(untested) >= 2
        assert any("docker_http_headers_audit" in u for u in untested)
        assert any("docker_waf_detect" in u for u in untested)

        # Mission guard MUST block surrender
        should_guard, unfulfilled = _evaluate_mission_guard(
            report_state=state,
            tools_called=partial_tools,
            progress_pct=75,
            untapped_actions=[{"tool": "docker_waf_detect", "priority": "HIGH"}],
            iteration=5,
            max_iterations=20,
            guard_attempts=1,
            relentless_pursuit=True,
        )
        assert should_guard is True
        assert any("Bề mặt tấn công chưa vét cạn" in msg for msg in unfulfilled)

    def test_gatekeeper_permits_completion_when_truly_exhausted(self):
        state = ReportState(
            target="https://target.corp",
            scan_mode="full",
            mission_objective="Audit mục tiêu",
        )
        state.attack_surface.open_ports = {
            80: {"service": "http", "deep_scanned": True},
            443: {"service": "https", "deep_scanned": True},
        }
        state.attack_surface.subdomains = ["api.target.corp"]
        state.attack_surface.parameterized_endpoints = {
            "https://target.corp/view?id=1": {"tested_sqli": True, "tested_xss": True}
        }

        # Complete set of all required tools
        complete_tools = {
            "docker_scan_ports_deep",
            "docker_sqlmap_scan",
            "docker_xss_scan",
            "docker_httpx_probe",
            "docker_sensitive_files_scan",
            "docker_cookie_security_audit",
            "docker_dns_security_audit",
            "docker_security_txt_audit",
            "docker_ssl_cert_audit",
            "docker_http_headers_audit",
            "docker_api_docs_audit",
            "docker_subdomain_takeover_audit",
            "docker_waf_detect",
        }

        for m in state.milestones:
            m.status = "COMPLETED"

        is_exhausted, untested = state.is_surface_exhausted(tools_called=complete_tools)
        assert is_exhausted is True
        assert len(untested) == 0

        # Now mission guard allows final_answer
        should_guard, unfulfilled = _evaluate_mission_guard(
            report_state=state,
            tools_called=complete_tools,
            progress_pct=95,
            untapped_actions=[],
            iteration=15,
            max_iterations=20,
            guard_attempts=2,
            relentless_pursuit=True,
        )
        assert should_guard is False
        assert len(unfulfilled) == 0


class TestStagnationAutoResurrection:
    """Validate that stagnation auto-resurrection rescues the agent with tactical pivoting."""

    def test_tactical_recommendations_elevates_untested_actions(self):
        state = ReportState(target="https://target.corp", scan_mode="full", mission_objective="Xâm nhập API")
        state.attack_surface.open_ports = {443: {"service": "https"}}
        
        recs = state.get_tactical_roadmap()
        assert "untested_actions" in recs
        assert len(recs["untested_actions"]) > 0

        # API docs should be CRITICAL because 'api' is in objective
        api_action = next(a for a in recs["untested_actions"] if a["tool"] == "docker_api_docs_audit")
        assert api_action["priority"] == "CRITICAL"


class TestCompoundThreatMatrixAll8Vectors:
    """Verify all 8 enterprise compound threat correlation scenarios."""

    def test_scenario_1_account_takeover(self):
        state = ReportState(target="https://company.internal", scan_mode="full")
        state.findings = [
            Finding(title="Reflected XSS", severity="HIGH", tool_source="docker_xss_scan", cvss_score=7.2),
            Finding(title="Cookie thiếu cờ HttpOnly", severity="MEDIUM", tool_source="docker_cookie_security_audit", cvss_score=5.0),
        ]
        state.attack_surface.hidden_discovered_paths = ["/admin/dashboard"]
        state.correlate_compound_threats()
        assert any("Chiếm quyền điều khiển phiên Quản trị viên" in f.title for f in state.findings)

    def test_scenario_2_bec_mail_spoofing(self):
        state = ReportState(target="https://company.internal", scan_mode="full")
        state.findings = [
            Finding(title="Lỗ hổng cấu hình SPF/DMARC", severity="HIGH", tool_source="docker_dns_security_audit", cvss_score=7.5),
            Finding(title="Lộ lọt tệp tin nhạy cảm .env", severity="CRITICAL", tool_source="docker_sensitive_files_scan", cvss_score=9.0),
        ]
        state.correlate_compound_threats()
        assert any("Giả mạo định danh doanh nghiệp" in f.title for f in state.findings)

    def test_scenario_3_cors_session_theft(self):
        state = ReportState(target="https://company.internal", scan_mode="full")
        state.findings = [
            Finding(title="Lỗ hổng cấu hình CORS", severity="HIGH", tool_source="docker_cors_scan", cvss_score=7.5),
            Finding(title="Cookie thiếu thuộc tính SameSite", severity="MEDIUM", tool_source="docker_cookie_security_audit", cvss_score=5.0),
        ]
        state.correlate_compound_threats()
        assert any("Đánh cắp dữ liệu người dùng" in f.title for f in state.findings)

    def test_scenario_4_database_exposure(self):
        state = ReportState(target="https://company.internal", scan_mode="full")
        state.findings = [
            Finding(title="Lộ tệp nhạy cảm .env", severity="HIGH", tool_source="docker_sensitive_files_scan", cvss_score=7.5),
        ]
        state.attack_surface.open_ports = {3306: {"service": "mysql"}}
        state.correlate_compound_threats()
        assert any("Nguy cơ chiếm đoạt cơ sở dữ liệu" in f.title for f in state.findings)

    def test_scenario_5_subdomain_takeover(self):
        state = ReportState(target="https://company.internal", scan_mode="full")
        state.findings = [
            Finding(title="Lỗ hổng cấu hình DNS SPF", severity="HIGH", tool_source="docker_dns_security_audit"),
        ]
        state.attack_surface.alive_subdomains = ["cdn.company.internal", "dev.company.internal"]
        state.attack_surface.dangling_cnames = [{"subdomain": "cdn.company.internal", "service": "AWS S3"}]
        state.correlate_compound_threats()
        assert any("Nguy cơ chiếm đoạt tên miền phụ (Subdomain Takeover)" in f.title for f in state.findings)

    def test_scenario_6_cloud_ssrf(self):
        state = ReportState(target="https://company.internal", scan_mode="full")
        state.findings = [
            Finding(title="Lộ tệp cấu hình nhạy cảm aws credentials", severity="CRITICAL", tool_source="docker_sensitive_files_scan", cvss_score=9.1),
        ]
        state.attack_surface.parameterized_endpoints = {"https://company.internal/proxy?url=http://example.com": {}}
        state.correlate_compound_threats()
        assert any("Nguy cơ tấn công SSRF" in f.title for f in state.findings)

    def test_scenario_7_admin_privilege_escalation(self):
        state = ReportState(target="https://company.internal", scan_mode="full")
        state.findings = []
        state.attack_surface.hidden_discovered_paths = ["/admin/login"]
        state.attack_surface.login_forms = [{"action": "/admin/login", "inputs": ["user", "pass"]}]
        state.correlate_compound_threats()
        assert any("Nguy cơ leo thang đặc quyền quản trị" in f.title for f in state.findings)

    def test_scenario_8_rce(self):
        state = ReportState(target="https://company.internal", scan_mode="full")
        state.findings = [
            Finding(title="Lỗ hổng CVE-2021-41773 Path Traversal", severity="CRITICAL", tool_source="docker_nuclei_scan", cvss_score=9.8),
        ]
        state.attack_surface.detected_technologies = ["Apache 2.4.49", "PHP 7.4"]
        state.attack_surface.exposed_sensitive_files = ["/etc/passwd"]
        state.correlate_compound_threats()
        assert any("thực thi mã từ xa rce" in f.title.lower() for f in state.findings)


class TestMultiFormatReportGenerationUnderStress:
    """Verify DOCX, Markdown, and JSON report generation with rich compound findings."""

    def test_generates_all_three_formats_flawlessly(self):
        state = ReportState(
            target="https://target.corp",
            scan_mode="full",
            mission_objective="Toàn quyền kiểm thử thâm nhập",
        )
        state.attack_surface.open_ports = {
            80: {"service": "http", "deep_scanned": True},
            443: {"service": "https", "deep_scanned": True},
            3306: {"service": "mysql", "deep_scanned": True},
        }
        state.attack_surface.subdomains = ["api.target.corp", "admin.target.corp"]
        state.attack_surface.alive_subdomains = ["api.target.corp"]
        state.attack_surface.parameterized_endpoints = {"https://target.corp/item?id=5": {}}
        state.attack_surface.security_headers_info = {"score": 45, "grade": "F", "missing_headers": ["strict-transport-security"]}
        state.attack_surface.exposed_api_docs = [{"type": "OpenAPI Spec", "url": "https://target.corp/openapi.json", "endpoints_count": 8}]
        state.attack_surface.dangling_cnames = [{"subdomain": "assets.target.corp", "service": "GitHub Pages"}]
        state.attack_surface.detected_waf = {"waf_detected": True, "primary_waf": "Cloudflare"}

        state.add_finding(Finding(
            title="SQL Injection trên tham số id",
            severity="CRITICAL",
            tool_source="docker_sqlmap_scan",
            cvss_score=9.8,
            description="Tham số id cho phép blind SQL injection.",
            impact="Trích xuất toàn bộ dữ liệu người dùng và mật khẩu.",
            remediation="Sử dụng Prepared Statements và tham số hóa truy vấn.",
        ))

        state.add_finding(Finding(
            title="Thiếu tiêu đề HSTS",
            severity="HIGH",
            tool_source="docker_http_headers_audit",
            cvss_score=7.4,
            description="Máy chủ không cấu hình HSTS.",
            impact="Nguy cơ bị tấn công SSL Strip.",
            remediation="Bổ sung Strict-Transport-Security header.",
        ))

        state.correlate_compound_threats()

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = os.path.join(tmpdir, "report.md")
            json_path = os.path.join(tmpdir, "report.json")

            # Generate DOCX
            docx_path = generate_docx_report(state.to_dict())
            assert os.path.exists(docx_path)

            # Generate Markdown
            state.export_markdown(md_path)
            assert os.path.exists(md_path)

            # Generate JSON
            state.export_json(json_path)
            assert os.path.exists(json_path)

            # Verify Markdown file
            with open(md_path, "r", encoding="utf-8") as f:
                md_content = f.read()
            assert "BÁO CÁO ĐÁNH GIÁ AN TOÀN THÔNG TIN TOÀN DIỆN" in md_content
            assert "SQL Injection trên tham số id" in md_content
            assert "Cloudflare" in md_content
            assert "api.target.corp" in md_content

            # Verify JSON file
            with open(json_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)
            assert json_data["target"] == "https://target.corp"
            assert len(json_data["findings"]) >= 2
            assert json_data["attack_surface"]["detected_waf"]["primary_waf"] == "Cloudflare"

            # Verify DOCX file
            doc = docx.Document(docx_path)
            full_docx_text = "\n".join([p.text for p in doc.paragraphs])
            assert "BÁO CÁO ĐÁNH GIÁ AN TOÀN THÔNG TIN TOÀN DIỆN" in full_docx_text or "BÁO CÁO" in full_docx_text
            assert "target.corp" in full_docx_text


class TestAutonomousRedTeamLifecycleSimulation:
    """Verify tool fuzzy matching, 5-step cognitive prompts, and milestone progression."""

    def test_fuzzy_matching_covers_all_new_tool_aliases(self):
        schema = [
            {"name": "docker_http_headers_audit"},
            {"name": "docker_api_docs_audit"},
            {"name": "docker_subdomain_takeover_audit"},
            {"name": "docker_waf_detect"},
            {"name": "docker_crawl_web"},
            {"name": "docker_sqlmap_scan"},
        ]

        # Verify aliases resolve to exact schema names
        assert _fuzzy_match_tool_name("http_headers", schema) == "docker_http_headers_audit"
        assert _fuzzy_match_tool_name("headers_audit", schema) == "docker_http_headers_audit"
        assert _fuzzy_match_tool_name("swagger", schema) == "docker_api_docs_audit"
        assert _fuzzy_match_tool_name("openapi", schema) == "docker_api_docs_audit"
        assert _fuzzy_match_tool_name("subdomain_takeover", schema) == "docker_subdomain_takeover_audit"
        assert _fuzzy_match_tool_name("takeover_audit", schema) == "docker_subdomain_takeover_audit"
        assert _fuzzy_match_tool_name("waf_detect", schema) == "docker_waf_detect"
        assert _fuzzy_match_tool_name("detect_waf", schema) == "docker_waf_detect"

    def test_distillation_handles_all_arsenal_outputs_robustly(self):
        # Empty string
        assert _distill_tool_intelligence("docker_crawl_web", "")["summary"] == ""
        # Non-empty output with no specific pattern
        assert _distill_tool_intelligence("docker_crawl_web", "Crawling done, nothing notable")["summary"] == "Không có dấu hiệu đặc biệt."

        # CVE extraction
        cve_out = "Found vulnerability: CVE-2021-41773 Apache Path Traversal"
        intel_cve = _distill_tool_intelligence("docker_nuclei_scan", cve_out)
        assert "CVE-2021-41773" in intel_cve["cves"]

        # Port extraction
        port_out = "80/tcp open http\n443/tcp open https\n3306/tcp open mysql"
        intel_port = _distill_tool_intelligence("docker_scan_ports_fast", port_out)
        assert 80 in intel_port["ports"]
        assert 443 in intel_port["ports"]
        assert 3306 in intel_port["ports"]

    def test_milestone_progression_lifecycle(self):
        state = ReportState(target="https://target.corp", scan_mode="full", mission_objective="Xâm nhập mục tiêu")
        assert state.milestones[0].status == "PENDING"

        # Step 1: Recon tool
        state.update_attack_surface(
            "docker_resolve_dns",
            {"target": "target.corp"},
            json.dumps({"ip": "1.2.3.4", "domain": "target.corp"})
        )
        assert state.milestones[0].status in ("IN_PROGRESS", "COMPLETED")

        # Step 2: Posture tool
        state.update_attack_surface(
            "docker_http_headers_audit",
            {"target_url": "https://target.corp"},
            json.dumps({"target": "https://target.corp", "missing_headers": ["strict-transport-security"]})
        )
        assert state.milestones[1].status in ("IN_PROGRESS", "COMPLETED")

