"""Comprehensive Test Suite for Phase 3: Apex Autonomous Cyber Operations Platform.

Validates all 4 core engines:
1. ClosedLoopRemediationVerifier & Differential Fuzzing.
2. ActiveDeceptionEngine & Canary Honeytoken Topology.
3. ThreatActorProfiler & MITRE ATT&CK Enterprise Attribution.
4. WargameArena & In-Silico Adversarial Hardening.
5. End-to-end integration into Finding & ReportState.
"""

import pytest
from src.utils.remediation_verifier import (
    ClosedLoopRemediationVerifier,
    VerificationVerdict,
    VerificationReport,
    FuzzTestCase,
)
from src.utils.active_deception_engine import (
    ActiveDeceptionEngine,
    DeceptionAssetType,
    DeceptionTopology,
)
from src.utils.threat_actor_profiler import (
    ThreatActorProfiler,
    CampaignAttributionReport,
    ThreatAttributionMatch,
)
from src.utils.wargame_arena import (
    WargameArena,
    WargameConvergenceStatus,
    HardenedDefenseResult,
)
from src.utils.defense_rule_synthesizer import DefenseRuleSynthesizer
from src.client.report_state import Finding, ReportState


# ===========================================================================
# 1. ClosedLoopRemediationVerifier Tests
# ===========================================================================
class TestClosedLoopRemediationVerifier:
    def test_generate_sqli_fuzz_suite(self):
        verifier = ClosedLoopRemediationVerifier()
        suite = verifier.generate_fuzz_suite(
            finding_title="SQL Injection in Login Endpoint",
            base_exploit_payload="' OR '1'='1",
            category="SQL Injection",
        )
        assert len(suite) >= 8
        malicious = [t for t in suite if t.is_malicious]
        benign = [t for t in suite if not t.is_malicious]
        assert len(malicious) >= 4
        assert len(benign) >= 3
        # Check specific mutations
        names = [t.name for t in suite]
        assert "Direct Exploit Replay" in names
        assert "URL Encoded Evasion" in names
        assert "Inline Comment Obfuscation" in names
        assert "Benign Alphanumeric Query" in names

    def test_generate_xss_fuzz_suite(self):
        verifier = ClosedLoopRemediationVerifier()
        suite = verifier.generate_fuzz_suite(
            finding_title="Cross-Site Scripting",
            base_exploit_payload="<script>alert(1)</script>",
            category="XSS",
        )
        malicious = [t for t in suite if t.is_malicious]
        benign = [t for t in suite if not t.is_malicious]
        assert len(malicious) >= 4
        assert len(benign) >= 3
        names = [t.name for t in suite]
        assert "Event Handler Injection" in names
        assert "Benign Math Expression" in names

    def test_verify_remediation_approves_robust_rule(self):
        verifier = ClosedLoopRemediationVerifier()
        synth = DefenseRuleSynthesizer()
        rules = synth.synthesize_rules(
            finding_title="SQL Injection in id parameter",
            description="Extracting user hashes",
            evidence="id=1' UNION SELECT null, username, password FROM users--",
        )
        report = verifier.verify_remediation(
            finding_title="SQL Injection in id parameter",
            category="SQL Injection",
            base_exploit_payload="1' UNION SELECT null, username, password FROM users--",
            rule_definition=rules.modsecurity_rule,
        )
        assert report.exploit_neutralized is True
        assert report.evasion_resilience_rate >= 0.75
        assert report.false_positive_rate == 0.0
        assert report.confidence_score >= 0.85
        assert report.verdict == VerificationVerdict.APPROVED_FOR_PRODUCTION
        assert "Virtual patch approved" in report.remediation_summary

    def test_verify_remediation_flags_leaky_rule(self):
        verifier = ClosedLoopRemediationVerifier()
        # A flawed rule that only catches exact lowercase 'admin'
        flawed_rule = 'SecRule ARGS "@streq admin" "id:1001,phase:2,deny,status:403"'
        report = verifier.verify_remediation(
            finding_title="SQL Injection",
            category="SQL Injection",
            base_exploit_payload="' OR '1'='1",
            rule_definition=flawed_rule,
        )
        assert report.exploit_neutralized is False
        assert report.verdict == VerificationVerdict.REJECTED


# ===========================================================================
# 2. ActiveDeceptionEngine Tests
# ===========================================================================
class TestActiveDeceptionEngine:
    def test_generate_aws_honeytoken(self):
        engine = ActiveDeceptionEngine(callback_host="canary.corp.net")
        token = engine.generate_aws_honeytoken("api.corp.net")
        assert token.token_type == DeceptionAssetType.CANARY_AWS_KEY
        assert "AWS_ACCESS_KEY_ID=AKIA" in token.token_value
        assert "AWS_SECRET_ACCESS_KEY=" in token.token_value
        assert "https://canary.corp.net/api/v1/trigger/" in token.webhook_callback_url

    def test_generate_jwt_honeytoken(self):
        engine = ActiveDeceptionEngine()
        token = engine.generate_jwt_honeytoken("auth.corp.net")
        assert token.token_type == DeceptionAssetType.CANARY_JWT
        assert token.token_value.startswith("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.")
        assert token.target_placement != ""

    def test_generate_decoy_route_traps(self):
        engine = ActiveDeceptionEngine()
        traps = engine.generate_decoy_route_traps("portal.example.com")
        assert len(traps) >= 3
        paths = [t.path for t in traps]
        assert "/api/v1/internal/admin-debug" in paths
        assert "/.env.staging.bak" in paths
        for trap in traps:
            assert trap.severity == "EMERGENCY"
            assert "TRIPWIRE DECEPTION" in trap.tripwire_alert_rule

    def test_synthesize_deception_topology(self):
        engine = ActiveDeceptionEngine()
        topo = engine.synthesize_deception_topology("target.internal.io")
        assert topo.target_domain == "target.internal.io"
        assert len(topo.canary_tokens) >= 3
        assert len(topo.decoy_traps) >= 3
        assert len(topo.tripwire_waf_rules) >= 4
        assert topo.total_assets >= 6
        d = topo.to_dict()
        assert d["total_assets"] >= 6
        assert len(d["canary_tokens"]) >= 3


# ===========================================================================
# 3. ThreatActorProfiler Tests
# ===========================================================================
class TestThreatActorProfiler:
    def test_map_evidence_to_ttps(self):
        profiler = ThreatActorProfiler()
        ttps = profiler.map_evidence_to_ttps(
            finding_titles=["SQL Injection in login", "Arbitrary Command Execution RCE"],
            tool_names=["docker_nmap_fast", "docker_subfinder"],
        )
        tech_ids = {t.technique_id for t in ttps}
        assert "T1190" in tech_ids  # Exploit Public-Facing Application
        assert "T1059" in tech_ids  # Command and Scripting Interpreter
        assert "T1595" in tech_ids  # Active Scanning
        assert "T1590" in tech_ids  # Gather Victim Network Information

    def test_attribute_campaign_state_actor(self):
        profiler = ThreatActorProfiler()
        report = profiler.attribute_campaign(
            finding_titles=[
                "SQL Injection in financial transaction ledger",
                "Remote Code Execution via Web Shell",
                "Weak SSH Credentials Brute Forced",
                "Unsecured Cloud Metadata SSRF",
            ],
            tool_names=["docker_sqlmap_scan", "docker_hydra_ssh", "docker_metasploit_exploit"],
        )
        assert len(report.top_matched_actors) >= 3
        top = report.top_matched_actors[0]
        assert top.similarity_score > 0.35
        # APT28, Lazarus, or FIN7 should be top candidates
        actor_names = [a.actor_name for a in report.top_matched_actors]
        assert any(name in ["APT28", "Lazarus Group", "FIN7"] for name in actor_names)
        assert len(top.predicted_next_steps) >= 1
        assert "CISO" in report.ciso_briefing or len(report.ciso_briefing) > 50

    def test_attribution_report_serialization(self):
        profiler = ThreatActorProfiler()
        report = profiler.attribute_campaign(["Path Traversal in /etc/passwd"])
        d = report.to_dict()
        assert "observed_techniques" in d
        assert "top_matched_actors" in d
        assert "ciso_briefing" in d


# ===========================================================================
# 4. WargameArena Tests
# ===========================================================================
class TestWargameArena:
    def test_wargame_arena_hardens_rule(self):
        arena = WargameArena(max_rounds=5)
        # Start with a simple SecRule that lacks URL-decoding transforms
        initial_rule = (
            'SecRule ARGS "@rx (?i)(?:union\\s+select|select\\s+.*\\s+from)" \\\n'
            '    "id:200001,phase:2,t:none,deny,status:403,msg:\'SQLi Test\'"'
        )
        result = arena.run_wargame(
            finding_title="SQL Injection in search",
            category="SQL Injection",
            base_payload="UNION SELECT null, username, password FROM users",
            initial_rule=initial_rule,
        )
        assert result.rounds_executed == 5
        assert result.bypasses_thwarted >= 1
        assert result.resilience_score >= 0.80
        # Check that 't:urlDecodeUni' or 't:urlDecode' was injected into the hardened rule
        assert "t:urlDecode" in result.hardened_rule
        assert result.status in [
            WargameConvergenceStatus.CONVERGED_IMPREGNABLE,
            WargameConvergenceStatus.PARTIALLY_HARDENED,
        ]

    def test_wargame_result_serialization(self):
        arena = WargameArena(max_rounds=3)
        synth = DefenseRuleSynthesizer()
        rules = synth.synthesize_rules("XSS in comment", "Script injection", "<script>alert(1)</script>")
        result = arena.run_wargame(
            finding_title="XSS in comment",
            category="Cross-Site Scripting",
            base_payload="<script>alert(1)</script>",
            initial_rule=rules.modsecurity_rule,
        )
        d = result.to_dict()
        assert "status" in d
        assert "hardened_rule" in d
        assert "resilience_score" in d
        assert len(d["rounds"]) == 3


# ===========================================================================
# 5. Integration into Finding & ReportState
# ===========================================================================
class TestReportStateApexIntegration:
    def test_finding_auto_generates_remediation_verification(self):
        f = Finding(
            title="SQL Injection in Authentication Bypass",
            severity="CRITICAL",
            description="Vulnerable parameter 'username' allows boolean-based SQL injection.",
            raw_evidence="admin' OR '1'='1",
        )
        # Verify virtual_patch_rules synthesized
        assert f.virtual_patch_rules != {}
        assert "modsecurity_rule" in f.virtual_patch_rules
        # Verify remediation_verification auto-synthesized
        assert f.remediation_verification != {}
        assert f.remediation_verification["exploit_neutralized"] is True
        assert f.remediation_verification["confidence_score"] >= 0.70
        assert f.remediation_verification["verdict"] in [
            "APPROVED_FOR_PRODUCTION",
            "REQUIRES_TUNING",
        ]
