"""Comprehensive test suite for Bayesian Attack Graph & Threat Modeling Engine."""

import os
import pytest
from src.client.report_state import Finding, ReportState
from src.utils.attack_graph import AttackEdge, AttackNode, AttackPath, BayesianAttackGraph
from src.utils.report_generator import generate_docx_report


class TestBayesianProbability:
    """Test Bayesian exploit likelihood calculations."""

    def test_probability_by_severity(self):
        assert BayesianAttackGraph.calculate_probability("CRITICAL") == 0.92
        assert BayesianAttackGraph.calculate_probability("HIGH") == 0.80
        assert BayesianAttackGraph.calculate_probability("MEDIUM") == 0.55
        assert BayesianAttackGraph.calculate_probability("LOW") == 0.30
        assert BayesianAttackGraph.calculate_probability("INFO") == 0.15
        assert BayesianAttackGraph.calculate_probability("unknown") == 0.50

    def test_probability_by_cvss_score(self):
        # CVSS 9.8 should be capped at 0.95
        assert BayesianAttackGraph.calculate_probability("CRITICAL", cvss_score=9.8) == 0.95
        # CVSS 7.5 maps to 0.75
        assert BayesianAttackGraph.calculate_probability("HIGH", cvss_score=7.5) == 0.75
        # CVSS 0.5 maps to minimum 0.10
        assert BayesianAttackGraph.calculate_probability("LOW", cvss_score=0.5) == 0.10


class TestFrameworkAutomapping:
    """Test automatic mapping to OWASP Top 10 (2021) and MITRE ATT&CK Matrix."""

    def test_sqli_mapping(self):
        f = Finding(title="SQL Injection on /api/users", description="Union based SQLi")
        assert f.owasp_category == "A03:2021 - Injection"
        assert "Initial Access" in f.mitre_tactics
        assert any("T1190" in t for t in f.mitre_techniques)

    def test_xss_mapping(self):
        f = Finding(title="Reflected XSS in search query", description="q param reflected unescaped")
        assert f.owasp_category == "A03:2021 - Injection"
        assert any("T1059" in t for t in f.mitre_techniques)

    def test_rce_mapping(self):
        f = Finding(title="Command Execution RCE in ping utility", description="Arbitrary shell commands executed")
        assert f.owasp_category == "A03:2021 - Injection"
        assert "Execution" in f.mitre_tactics
        assert any("T1059" in t for t in f.mitre_techniques)

    def test_bruteforce_mapping(self):
        f = Finding(title="Hydra SSH password guessing", description="Weak credentials root:password")
        assert f.owasp_category == "A07:2021 - Identification and Authentication Failures"
        assert "Credential Access" in f.mitre_tactics
        assert any("T1110" in t for t in f.mitre_techniques)

    def test_ssrf_mapping(self):
        f = Finding(title="Server-Side Request Forgery", description="Internal metadata service exposed via SSRF")
        assert f.owasp_category == "A10:2021 - Server-Side Request Forgery (SSRF)"
        assert any("T1090" in t for t in f.mitre_techniques)

    def test_cors_cookie_mapping(self):
        f = Finding(title="CORS Arbitrary Origin reflection", description="Access-Control-Allow-Credentials true")
        assert f.owasp_category == "A01:2021 - Broken Access Control"
        assert any("T1539" in t or "T1557" in t for t in f.mitre_techniques)

    def test_ssl_tls_mapping(self):
        f = Finding(title="Weak SSL/TLS Cipher Suites Supported", description="RC4 enabled on port 443")
        assert f.owasp_category == "A02:2021 - Cryptographic Failures"
        assert any("T1557" in t or "T1040" in t for t in f.mitre_techniques)

    def test_outdated_component_mapping(self):
        f = Finding(title="Outdated Apache CVE-2021-41773", description="Path traversal in Apache 2.4.49")
        assert f.owasp_category == "A06:2021 - Vulnerable and Outdated Components"
        assert any("T1190" in t for t in f.mitre_techniques)

    def test_sensitive_file_mapping(self):
        f = Finding(title="Exposed .env environment configuration file", description="DB passwords leaked")
        assert f.owasp_category == "A05:2021 - Security Misconfiguration"
        assert any("T1552" in t for t in f.mitre_techniques)

    def test_custom_mapping_preserved(self):
        f = Finding(
            title="Custom Vendor Vulnerability",
            owasp_category="A04:2021 - Insecure Design",
            mitre_tactics=["Privilege Escalation"],
            mitre_techniques=["T1068 - Exploitation for Privilege Escalation"],
        )
        assert f.owasp_category == "A04:2021 - Insecure Design"
        assert f.mitre_tactics == ["Privilege Escalation"]
        assert f.mitre_techniques == ["T1068 - Exploitation for Privilege Escalation"]


class TestAttackGraphConstruction:
    """Test building Bayesian Attack Graph from report state."""

    @pytest.fixture
    def populated_report_state(self):
        state = ReportState(target="https://target.corp")
        state.attack_surface.open_ports = {
            22: {"service": "ssh"},
            80: {"service": "http"},
            3306: {"service": "mysql"},
        }
        state.attack_surface.subdomains = ["api.target.corp", "dev.target.corp"]

        # Findings establishing multi-hop attack vectors
        state.add_finding(
            Finding(
                title="SQL Injection on /api/login",
                severity="CRITICAL",
                cvss_score=9.5,
                tool_source="docker_sqlmap_scan",
                description="SQL injection allows database dump",
            )
        )
        state.add_finding(
            Finding(
                title="Sensitive Database Backup Dump backup.sql exposed",
                severity="HIGH",
                cvss_score=8.0,
                tool_source="docker_sensitive_files_scan",
                description="Exposed database backup",
            )
        )
        state.add_finding(
            Finding(
                title="Hydra SSH password guessing success",
                severity="HIGH",
                cvss_score=8.5,
                tool_source="bruteforce_ssh",
                description="Valid credentials root:toor",
            )
        )
        return state

    def test_graph_nodes_and_edges(self, populated_report_state):
        graph = BayesianAttackGraph.build_from_report_state(populated_report_state)

        # Baseline nodes
        assert "INTERNET" in graph.nodes
        assert "WEB_APPLICATION" in graph.nodes
        assert "DATABASE_TIER" in graph.nodes
        assert "ADMIN_INTERFACE" in graph.nodes
        assert "HOST_SYSTEM" in graph.nodes
        assert "SSH_SERVICE" in graph.nodes
        assert "SUB_api_target_corp" in graph.nodes

        # Verify edge creation
        assert len(graph.edges) > 0
        edge_targets = [e.target for e in graph.edges]
        assert "DATABASE_TIER" in edge_targets
        assert "HOST_SYSTEM" in edge_targets

    def test_path_discovery_and_probabilities(self, populated_report_state):
        graph = BayesianAttackGraph.build_from_report_state(populated_report_state)
        paths = graph.find_all_attack_paths()

        assert len(paths) > 0
        crit_path = graph.get_critical_path()
        assert crit_path is not None
        assert crit_path.cumulative_probability > 0.0
        assert crit_path.node_ids[0] == "INTERNET"
        assert crit_path.target_crown_jewel in ("DATABASE_TIER", "ADMIN_INTERFACE", "HOST_SYSTEM")

        # Summary string check
        summary = crit_path.to_summary()
        assert "Xác suất" in summary
        assert "➔" in summary

    def test_mermaid_export(self, populated_report_state):
        graph = BayesianAttackGraph.build_from_report_state(populated_report_state)
        mermaid = graph.to_mermaid()

        assert "```mermaid" in mermaid
        assert "flowchart TD" in mermaid
        assert "classDef crown" in mermaid
        assert "INTERNET" in mermaid
        assert "-->|" in mermaid

    def test_summary_dict(self, populated_report_state):
        graph = BayesianAttackGraph.build_from_report_state(populated_report_state)
        summary = graph.to_summary_dict()

        assert summary["total_nodes"] >= 5
        assert summary["total_attack_vectors"] >= 2
        assert summary["total_viable_paths"] >= 1
        assert summary["critical_path_probability"] > 0.0
        assert "➔" in summary["critical_path_chain"]


class TestReportStateIntegration:
    """Test ReportState methods and reporting integration."""

    def test_owasp_and_mitre_breakdowns(self):
        state = ReportState(target="https://app.local")
        state.add_finding(Finding(title="SQL Injection in auth", severity="CRITICAL"))
        state.add_finding(Finding(title="Reflected XSS in search", severity="HIGH"))
        state.add_finding(Finding(title="Hydra password brute force", severity="HIGH"))

        owasp = state.get_owasp_breakdown()
        assert "A03:2021 - Injection" in owasp
        assert owasp["A03:2021 - Injection"] == 2
        assert "A07:2021 - Identification and Authentication Failures" in owasp

        mitre = state.get_mitre_breakdown()
        assert len(mitre) >= 2

    def test_to_dict_includes_threat_modeling(self):
        state = ReportState(target="https://app.local")
        state.add_finding(Finding(title="SQL Injection in auth", severity="CRITICAL"))
        d = state.to_dict()

        assert "owasp_breakdown" in d
        assert "mitre_breakdown" in d
        assert "attack_graph_summary" in d
        assert "attack_graph_mermaid" in d
        assert "A03:2021 - Injection" in d["owasp_breakdown"]

    def test_to_markdown_includes_section_4(self):
        state = ReportState(target="https://app.local")
        state.add_finding(Finding(title="SQL Injection in auth", severity="CRITICAL"))
        md = state.to_markdown()

        assert "## 4. KỊCH BẢN KHAI THÁC PHỨC HỢP & MÔ HÌNH HÓA ĐỒ THỊ TẤN CÔNG BAYESIAN" in md
        assert "```mermaid" in md
        assert "flowchart TD" in md
        assert "A03:2021 - Injection" in md
        assert "Autonomous MLSecOps Agent" in md

    def test_generate_docx_with_threat_modeling(self, tmp_path):
        state = ReportState(target="https://app.local")
        state.add_finding(Finding(title="SQL Injection in auth", severity="CRITICAL"))
        state.attack_surface.open_ports = {80: {"service": "http"}}

        report_data = state.to_dict()
        docx_file = generate_docx_report(report_data, audit_path="")
        assert os.path.exists(docx_file)
        assert os.path.getsize(docx_file) > 1000
