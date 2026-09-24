"""Comprehensive Unit Tests for Superhuman Cyber Defense & Graph Interdiction.

Validates:
1. Multi-Platform Blue Team Defense Rule Synthesizer (ModSecurity, Suricata, Sigma, Cloudflare)
2. Critical Chokepoint & Attack Path Graph Interdiction Engine (Bayesian graph cuts)
3. SPA & Client-Side Dynamic State Transition Crawler (Webpack/Vite bundle analysis)
4. Autonomous Session State & Resilient Re-Authentication Guardian (JWT & token recovery)
5. ReportState Finding integration with virtual_patch_rules
"""

import time
import pytest
from src.utils.defense_rule_synthesizer import (
    DefenseRuleSynthesizer,
    DefenseRuleSet,
)
from src.utils.chokepoint_analyzer import (
    ChokepointAnalyzer,
    ChokepointCandidate,
    ChokepointReport,
)
from src.utils.spa_state_crawler import (
    SPAStateCrawler,
    SPARoute,
    SPACrawlResult,
)
from src.utils.session_guardian import (
    SessionGuardian,
    SessionState,
)
from src.utils.attack_graph import (
    BayesianAttackGraph,
    AttackNode,
    AttackEdge,
)
from src.client.report_state import Finding, ReportState


# ===========================================================================
# 1. Tests for DefenseRuleSynthesizer
# ===========================================================================
class TestDefenseRuleSynthesizer:
    def test_synthesize_sqli_rules(self):
        synth = DefenseRuleSynthesizer()
        rules = synth.synthesize_rules(
            finding_title="SQL Injection in user search",
            description="Union-based parameter manipulation",
            cve_id="CVE-2023-1234",
        )
        assert isinstance(rules, DefenseRuleSet)
        assert rules.category == "SQL Injection"
        assert "SecRule" in rules.modsecurity_rule
        assert "union" in rules.modsecurity_rule.lower()
        assert "alert http" in rules.suricata_rule
        assert "CVE-2023-1234" in rules.suricata_rule
        assert "title: Potential SQL Injection" in rules.sigma_rule
        assert "http.request.uri.query contains" in rules.cloudflare_rule

        block = rules.format_block()
        assert "VIRTUAL PATCH" in block
        assert "ModSecurity" in block

    def test_synthesize_rce_rules(self):
        synth = DefenseRuleSynthesizer()
        rules = synth.synthesize_rules(
            finding_title="Remote Command Injection in Diagnostics",
            description="Command chaining through ping host parameter",
        )
        assert rules.category == "Command Injection"
        assert "whoami" in rules.modsecurity_rule
        assert "classtype:attempted-admin" in rules.suricata_rule
        assert "Command Injection Shell Invocation" in rules.sigma_rule

    def test_synthesize_xss_rules(self):
        synth = DefenseRuleSynthesizer()
        rules = synth.synthesize_rules(
            finding_title="Stored XSS in user bio",
            description="Script injection through profile editor",
        )
        assert rules.category == "Cross-Site Scripting"
        assert "onerror" in rules.modsecurity_rule
        assert "attack-xss" in rules.modsecurity_rule

    def test_synthesize_ssrf_rules(self):
        synth = DefenseRuleSynthesizer()
        rules = synth.synthesize_rules(
            finding_title="Server-Side Request Forgery",
            description="Access to internal metadata service",
            evidence="target=http://169.254.169.254/latest/",
        )
        assert rules.category == "SSRF"
        assert "169\\.254" in rules.modsecurity_rule
        assert "169.254.169.254" in rules.suricata_rule

    def test_synthesize_path_traversal_rules(self):
        synth = DefenseRuleSynthesizer()
        rules = synth.synthesize_rules(
            finding_title="Arbitrary File Read via Path Traversal",
            description="Climbing directory paths with ../",
        )
        assert rules.category == "Path Traversal"
        assert "/etc/passwd" in rules.modsecurity_rule
        assert "attack-traversal" in rules.modsecurity_rule


# ===========================================================================
# 2. Tests for ChokepointAnalyzer
# ===========================================================================
class TestChokepointAnalyzer:
    def test_chokepoint_analysis_identifies_top_cut(self):
        graph = BayesianAttackGraph()
        # Build multi-hop graph: INTERNET -> WEB -> DB and INTERNET -> WEB -> ADMIN -> DB
        graph.add_node(AttackNode(id="WEB", name="Web Application", category="SERVICE"))
        graph.add_node(AttackNode(id="DATABASE_TIER", name="Database Server", category="DATA"))
        graph.add_node(AttackNode(id="ADMIN", name="Admin Portal", category="ADMIN"))

        graph.add_edge(AttackEdge(source="INTERNET", target="WEB", finding_title="Open Port 80", probability=0.9))
        graph.add_edge(AttackEdge(source="WEB", target="DATABASE_TIER", finding_title="SQL Injection", probability=0.85))
        graph.add_edge(AttackEdge(source="WEB", target="ADMIN", finding_title="XSS Session Hijack", probability=0.7))
        graph.add_edge(AttackEdge(source="ADMIN", target="DATABASE_TIER", finding_title="Admin DB Dump", probability=0.9))

        analyzer = ChokepointAnalyzer()
        report = analyzer.analyze(graph)

        assert isinstance(report, ChokepointReport)
        assert report.total_attack_paths_count >= 1
        assert report.baseline_risk_score > 0
        assert len(report.chokepoints) >= 1
        assert report.risk_reduction_pct > 0

        top_cp = report.chokepoints[0]
        assert top_cp.element_type == "EDGE"
        assert "DATABASE_TIER" in top_cp.target_crown_jewel or "ADMIN" in top_cp.target_crown_jewel

        block = report.format_block()
        assert "CHIẾN LƯỢC CAN THIỆP ĐIỂM NGHẼN" in block
        assert "Tử Huyệt Phòng Thủ" in block

    def test_chokepoint_analysis_handles_empty_graph(self):
        graph = BayesianAttackGraph()
        analyzer = ChokepointAnalyzer()
        report = analyzer.analyze(graph)
        assert report.total_attack_paths_count == 0
        assert report.baseline_risk_score == 0.0
        assert len(report.chokepoints) == 0


# ===========================================================================
# 3. Tests for SPAStateCrawler
# ===========================================================================
class TestSPAStateCrawler:
    def test_crawl_bundle_recovers_routes_and_storage(self):
        crawler = SPAStateCrawler()
        sample_bundle = """
        import React from 'react';
        import { createBrowserRouter } from 'react-router-dom';
        
        const routes = [
            { path: '/dashboard', element: <Dashboard /> },
            { path: '/admin/billing', element: <Billing /> },
            { path: '/settings/security', element: <SecuritySettings /> },
            { path: '/api/internal/stats', element: <Stats /> }
        ];

        function onLogin(token) {
            localStorage.setItem('auth_token', token);
            sessionStorage.setItem('user_session', JSON.stringify({ id: 1 }));
            fetch('/api/v1/user/profile');
        }

        const FIREBASE_CONFIG = {
            apiKey: "AIzaSyD-X_1234567890abcdefghijklmnopq",
            authDomain: "mycorp.firebaseapp.com"
        };
        const API_KEY = process.env.REACT_APP_STRIPE_PUBLIC_KEY = "pk_live_12345";
        """

        result = crawler.crawl_bundle(sample_bundle)
        assert isinstance(result, SPACrawlResult)
        assert len(result.discovered_routes) >= 3

        route_paths = [r.path for r in result.discovered_routes]
        assert "/dashboard" in route_paths
        assert "/admin/billing" in route_paths
        assert any(r.is_admin_route for r in result.discovered_routes if r.path == "/admin/billing")

        # Insecure storage
        assert len(result.insecure_storage_findings) >= 1
        assert any("auth_token" in s for s in result.insecure_storage_findings)

        # Embedded API
        assert any("/api/v1/user/profile" in a for a in result.api_endpoints)

        # Environment configs & Firebase API key
        assert "FIREBASE_API_KEY" in result.hardcoded_env_configs
        assert result.hardcoded_env_configs["FIREBASE_API_KEY"].startswith("AIza")

        block = result.format_block()
        assert "BÓC TÁCH BUNDLE SPA" in block
        assert "/admin/billing" in block


# ===========================================================================
# 4. Tests for SessionGuardian
# ===========================================================================
class TestSessionGuardian:
    def test_detect_session_death_on_401_and_expired_msg(self):
        guardian = SessionGuardian()
        guardian.set_active_session(token="sample_token_123", user="admin")
        assert guardian.state.is_authenticated is True

        # Status 401
        assert guardian.detect_session_death(401, "Unauthorized") is True

        # Status 403 with expired message
        assert guardian.detect_session_death(403, '{"error": "jwt expired"}') is True

        # Status 200 normal
        assert guardian.detect_session_death(200, '{"data": "profile details"}') is False

    def test_session_recovery_with_backup_tokens(self):
        guardian = SessionGuardian()
        guardian.set_active_session(token="old_dead_token", user="test")

        backup_tokens = ["new_valid_token_abc123"]
        backup_creds = [{"user": "superadmin", "password": "Pass"}]

        recovered, msg = guardian.recover_session(backup_tokens, backup_creds)
        assert recovered is True
        assert guardian.state.active_token == "new_valid_token_abc123"
        assert guardian.state.refresh_count == 1
        assert "Tự phục hồi phiên thành công" in msg

    def test_inject_session_arguments(self):
        guardian = SessionGuardian()
        guardian.set_active_session(token="jwt_token_secret_xyz", cookies={"sess_id": "999"})

        args = {"url": "http://target.local/api/data"}
        injected = guardian.inject_session_arguments("docker_curl", args)
        assert "headers" in injected
        assert injected["headers"]["Authorization"] == "Bearer jwt_token_secret_xyz"
        assert injected["cookie"] == "sess_id=999"

    def test_format_status_block(self):
        guardian = SessionGuardian()
        guardian.set_active_session(token="sample_token", user="auditor")
        block = guardian.format_status_block()
        assert "TRẠNG THÁI PHIÊN XÁC THỰC" in block
        assert "auditor" in block


# ===========================================================================
# 5. Integration: Finding Auto-Generates Virtual Patch Rules
# ===========================================================================
class TestFindingVirtualPatchIntegration:
    def test_finding_auto_generates_virtual_patch_rules(self):
        finding = Finding(
            title="SQL Injection on Products Search",
            severity="CRITICAL",
            description="Union extraction",
        )
        assert bool(finding.virtual_patch_rules) is True
        assert "modsecurity_rule" in finding.virtual_patch_rules
        assert "suricata_rule" in finding.virtual_patch_rules
        assert "sigma_rule" in finding.virtual_patch_rules
        assert "SecRule" in finding.virtual_patch_rules["modsecurity_rule"]
