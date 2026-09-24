"""Unit tests for Next-Gen MLSecOps Upgrades:
- Automated CVE & Threat Intelligence Enrichment Engine (EPSS + CVSS + CISA KEV)
- Automated Actionable Remediation Code Generator
- Interactive Standalone HTML Cyber Executive Dashboard Generator
- Technology-Aware Adaptive Wordlist Selector
"""

import os
import pytest
from src.utils.cve_enricher import extract_cve_ids, enrich_cve_intel, KNOWN_CVE_INTEL
from src.utils.remediation_engine import generate_remediation_snippet
from src.utils.html_report_generator import generate_html_report
from src.utils.wordlist_selector import resolve_technology_wordlist
from src.client.report_state import ReportState, Finding
from src.client.orchestrator import _normalize_tool_args


class TestCVEEnrichmentEngine:
    def test_extract_cve_ids(self):
        text = "Vulnerability detected: cve-2021-44228 and also CVE-2022-22965. Repeated CVE-2021-44228 should dedup."
        cves = extract_cve_ids(text)
        assert cves == ["CVE-2021-44228", "CVE-2022-22965"]

    def test_enrich_known_cve_log4shell(self):
        intel = enrich_cve_intel("CVE-2021-44228")
        assert intel["is_known_threat"] is True
        assert intel["cvss_score"] == 10.0
        assert "CVSS:3.1" in intel["cvss_vector"]
        assert intel["epss_score"] >= 0.95
        assert intel["cisa_kev"] is True

    def test_enrich_heuristic_cve(self):
        intel = enrich_cve_intel("CVE-2023-99999", current_severity="CRITICAL")
        assert intel["is_known_threat"] is False
        assert intel["cvss_score"] == 9.8
        assert "CVSS:3.1" in intel["cvss_vector"]
        assert 0.0 < intel["epss_score"] < 1.0

    def test_finding_auto_enrichment(self):
        f = Finding(
            title="Apache Log4j Vulnerability Detected",
            severity="CRITICAL",
            description="Remote code execution via Log4j",
            cve_id="CVE-2021-44228",
        )
        assert f.cvss_score == 10.0
        assert f.cisa_kev is True
        assert f.epss_score >= 0.95
        assert "CVSS:3.1" in f.cvss_vector
        assert len(f.remediation_code) > 0


class TestRemediationEngine:
    def test_sql_injection_remediation(self):
        res = generate_remediation_snippet("Blind SQL Injection on login endpoint")
        assert res["category"] == "SQL Injection"
        assert "PDO" in res["code"]
        assert "prepare" in res["code"]

    def test_xss_remediation(self):
        res = generate_remediation_snippet("Reflected XSS on search parameter")
        assert res["category"] == "Cross-Site Scripting"
        assert "htmlspecialchars" in res["code"]
        assert "Content-Security-Policy" in res["code"]

    def test_cors_remediation(self):
        res = generate_remediation_snippet("Insecure CORS Wildcard Header")
        assert res["category"] == "CORS Misconfiguration"
        assert "Access-Control-Allow-Origin" in res["code"]

    def test_security_headers_remediation(self):
        res = generate_remediation_snippet("Missing Security Headers on web server")
        assert res["category"] == "Security Headers"
        assert "X-Frame-Options" in res["code"]
        assert "Strict-Transport-Security" in res["code"]


class TestHtmlReportGenerator:
    def test_generate_html_report_standalone(self, tmp_path):
        state = ReportState(
            target="http://vulnweb.test",
            scan_mode="full",
            mission_objective="Thẩm định toàn diện hệ thống",
        )
        state.attack_surface.open_ports[80] = {"service": "http"}
        state.attack_surface.detected_technologies = ["PHP", "Apache", "WordPress"]
        state.attack_surface.detected_waf = {"primary_waf": "Cloudflare"}
        state.add_finding(Finding(
            title="SQL Injection on login.php",
            severity="CRITICAL",
            description="Parameter id is injectable",
            impact="Full database takeover",
            remediation="Use PDO Prepared Statements",
            tool_source="docker_sqlmap_scan",
            cve_id="CVE-2021-44228",
            raw_evidence="SELECT * FROM users WHERE id='admin'",
        ))

        html_out = str(tmp_path / "dashboard.html")
        html_content = generate_html_report(state.to_dict(), html_out)

        assert os.path.exists(html_out)
        assert "<!DOCTYPE html>" in html_content
        assert "http://vulnweb.test" in html_content
        assert "SQL Injection on login.php" in html_content
        assert "CVE-2021-44228" in html_content
        assert "Cloudflare" in html_content
        assert "filterFindings" in html_content
        assert "copySnippet" in html_content

    def test_report_state_export_html(self, tmp_path):
        state = ReportState(target="http://example.com", scan_mode="recon")
        html_path = str(tmp_path / "report.html")
        res_path = state.export_html(html_path)
        assert os.path.exists(res_path)
        assert os.path.getsize(res_path) > 1000


class TestTechnologyAwareWordlistSelector:
    def test_resolve_technology_wordlist(self):
        wp_wl = resolve_technology_wordlist(["WordPress 6.2", "Nginx"])
        assert wp_wl is not None
        assert "wordpress.txt" in wp_wl

        php_wl = resolve_technology_wordlist(["PHP/8.1", "Apache"])
        assert php_wl is not None
        assert "php.txt" in php_wl or "wordpress.txt" in php_wl

        spring_wl = resolve_technology_wordlist(["Spring Boot Actuator"])
        assert spring_wl is not None
        assert "spring.txt" in spring_wl

    def test_normalize_tool_args_adaptive_wordlist(self):
        args = {"target_url": "http://example.com", "wordlist": "dirb_common.txt"}
        normalized = _normalize_tool_args(
            "docker_dirb_scan",
            args,
            detected_technologies=["WordPress"],
        )
        assert "wordlist" in normalized
        assert "wordpress.txt" in normalized["wordlist"]
