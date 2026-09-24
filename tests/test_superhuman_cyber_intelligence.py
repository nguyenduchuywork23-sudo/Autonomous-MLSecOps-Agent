"""Comprehensive Unit Test Suite for Superhuman Autonomous Cyber Intelligence Engines.

Validates:
1. Monte Carlo Tree Search (MCTS) Cyber Lookahead Simulator (src/utils/mcts_simulator.py)
2. Grammar-Based Business Logic & API Schema Fuzzer (src/utils/api_logic_fuzzer.py)
3. Dynamic Defense Fingerprinting & WAF Rule Decompiler (src/utils/waf_fingerprinter.py)
4. Autonomous Patch Synthesizer & Code-Level Hotfix Sandbox (src/utils/patch_sandbox.py)
5. ReportState Finding auto-patch synthesis integration
"""

import json
import pytest
from src.utils.mcts_simulator import MCTSCyberSimulator, MCTSNode, MCTSSimulationResult
from src.utils.api_logic_fuzzer import (
    APILogicFuzzer,
    APISchemaEndpoint,
    APILogicFuzzTarget,
)
from src.utils.waf_fingerprinter import WAFFingerprinter, BlockedTokenAnalysis
from src.utils.patch_sandbox import (
    PatchSynthesizer,
    HotfixSandboxVerifier,
    PatchDiffResult,
)
from src.client.report_state import Finding, ReportState


# ===========================================================================
# 1. Tests for MCTSCyberSimulator
# ===========================================================================
class TestMCTSCyberSimulator:
    def test_node_uct_score_calculation(self):
        root = MCTSNode(tool_name="root", visits=10, total_reward=20.0)
        child = MCTSNode(
            tool_name="docker_whatweb",
            parent=root,
            visits=2,
            total_reward=6.0,
            prior_prob=1.5,
        )
        # Value = 6.0 / 2 = 3.0
        # Exploration = 1.414 * 1.5 * sqrt(ln(10) / (1 + 2))
        score = child.uct_score(c_param=1.414)
        assert score > 3.0
        assert child.best_child() is None

    def test_simulation_recommends_web_recon_for_http_target(self):
        sim = MCTSCyberSimulator(rng_seed=42)
        state = {
            "open_ports": [80, 443],
            "detected_tech": ["nginx", "php"],
            "active_waf": None,
            "harvested_creds": [],
            "executed_tools": [],
            "target": "http://test-corp.local",
        }
        available_tools = [
            "docker_whatweb",
            "docker_httpx",
            "docker_nuclei_scan",
            "bruteforce_ssh",
        ]
        result = sim.simulate(available_tools, state, num_simulations=30, max_depth=3)
        assert isinstance(result, MCTSSimulationResult)
        assert result.best_tool in ("docker_whatweb", "docker_httpx", "docker_nuclei_scan")
        assert len(result.projected_sequence) >= 2
        assert result.expected_gain > 0
        assert result.stealth_risk < 0.6
        block = result.format_block()
        assert "BỘ MÔ PHỎNG CHIẾN THUẬT MCTS LOOKAHEAD" in block
        assert result.best_tool in block

    def test_simulation_penalizes_loud_tools_under_active_waf(self):
        sim = MCTSCyberSimulator(rng_seed=42)
        state = {
            "open_ports": [80],
            "detected_tech": ["cloudflare"],
            "active_waf": "Cloudflare",
            "harvested_creds": [],
            "executed_tools": [],
            "target": "https://protected-target.com",
        }
        available_tools = [
            "docker_whatweb",
            "docker_sqlmap_dump",
            "docker_hydra_attack",
        ]
        result = sim.simulate(available_tools, state, num_simulations=30, max_depth=2)
        # WhatWeb has low noise (0.1) whereas sqlmap_dump and hydra have noise >= 0.85
        assert result.best_tool == "docker_whatweb"
        assert result.stealth_risk > 0

    def test_simulation_prioritizes_ssh_bruteforce_when_credentials_exist(self):
        sim = MCTSCyberSimulator(rng_seed=42)
        state = {
            "open_ports": [22],
            "detected_tech": ["OpenSSH 8.9"],
            "active_waf": None,
            "harvested_creds": [{"user": "admin", "password": "SecretPassword123!"}],
            "executed_tools": ["docker_whatweb"],
            "target": "10.0.0.50",
        }
        available_tools = ["bruteforce_ssh", "docker_whatweb", "docker_resolve_dns"]
        result = sim.simulate(available_tools, state, num_simulations=30, max_depth=2)
        assert result.best_tool == "bruteforce_ssh"
        assert "tài khoản/khóa bí mật" in result.rationale


# ===========================================================================
# 2. Tests for APILogicFuzzer
# ===========================================================================
class TestAPILogicFuzzer:
    def test_parse_openapi_spec(self):
        fuzzer = APILogicFuzzer()
        sample_spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/v1/users/{user_id}": {
                    "get": {
                        "summary": "Get user profile",
                        "parameters": [{"name": "user_id", "in": "path"}],
                    },
                    "put": {
                        "summary": "Update user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                    },
                },
                "/api/v1/orders": {
                    "post": {
                        "summary": "Create order",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                    }
                },
            },
        }
        endpoints = fuzzer.parse_openapi_spec(sample_spec)
        assert len(endpoints) == 3
        paths = [ep.path for ep in endpoints]
        assert "/api/v1/users/{user_id}" in paths
        assert "/api/v1/orders" in paths

    def test_infer_endpoints_from_raw_html_js(self):
        fuzzer = APILogicFuzzer()
        raw_js = """
        const res = await fetch('/api/v2/accounts/{account_id}/transfer', { method: 'POST' });
        axios.get('/api/orders');
        fetch('/graphql');
        """
        endpoints = fuzzer.infer_endpoints_from_text(raw_js)
        assert len(endpoints) >= 2
        paths = [ep.path for ep in endpoints]
        assert any("/api/v2/accounts" in p for p in paths)
        assert any("/graphql" in p for p in paths)

    def test_generate_fuzz_plan_bola_and_mass_assignment(self):
        fuzzer = APILogicFuzzer()
        ep = APISchemaEndpoint(
            path="/api/v1/users/{user_id}",
            method="POST",
            parameters=[{"name": "user_id"}],
            request_body_schema={"type": "object"},
        )
        plan = fuzzer.generate_fuzz_plan([ep])
        types = [t.fuzz_type for t in plan]

        assert "BOLA_IDOR" in types
        assert "MASS_ASSIGNMENT" in types
        assert "TYPE_CONFUSION" in types
        assert "VERB_TAMPERING" in types

        # Check BOLA substitutions
        bola_paths = [t.url_path for t in plan if t.fuzz_type == "BOLA_IDOR"]
        assert "/api/v1/users/1" in bola_paths
        assert "/api/v1/users/0" in bola_paths
        assert "/api/v1/users/-1" in bola_paths

        # Check Mass Assignment payload
        mass_targets = [t for t in plan if t.fuzz_type == "MASS_ASSIGNMENT"]
        assert len(mass_targets) > 0
        assert mass_targets[0].json_body.get("is_admin") is True
        assert mass_targets[0].json_body.get("role") == "admin"

    def test_graphql_introspection_target_generation(self):
        fuzzer = APILogicFuzzer()
        ep = APISchemaEndpoint(path="/graphql", method="POST")
        plan = fuzzer.generate_fuzz_plan([ep])
        gql_targets = [t for t in plan if t.fuzz_type == "GRAPHQL_INTROSPECTION"]
        assert len(gql_targets) == 2
        assert any("__schema" in t.json_body.get("query", "") for t in gql_targets)

    def test_format_fuzz_directive(self):
        fuzzer = APILogicFuzzer()
        targets = [
            APILogicFuzzTarget(
                fuzz_type="BOLA_IDOR",
                method="GET",
                url_path="/api/v1/users/0",
                description="Test admin profile",
            )
        ]
        directive = fuzzer.format_fuzz_directive(targets)
        assert "BỘ TẠO ĐỘT BIẾN NGỮ PHÁP API" in directive
        assert "GET /api/v1/users/0" in directive


# ===========================================================================
# 3. Tests for WAFFingerprinter
# ===========================================================================
class TestWAFFingerprinter:
    def test_fingerprint_cloudflare_headers(self):
        waf = WAFFingerprinter()
        headers = {"cf-ray": "84849202029-SJC", "server": "cloudflare"}
        vendor = waf.fingerprint(status_code=403, headers=headers, body="error 1020 access denied")
        assert vendor == "Cloudflare"

    def test_fingerprint_modsecurity(self):
        waf = WAFFingerprinter()
        headers = {"server": "Apache"}
        body = "406 Not Acceptable. This error was generated by Mod_Security."
        vendor = waf.fingerprint(status_code=406, headers=headers, body=body)
        assert vendor == "ModSecurity / OWASP CRS"

    def test_fingerprint_aws_waf(self):
        waf = WAFFingerprinter()
        headers = {"x-amzn-requestid": "12345", "x-amz-cf-id": "abcd"}
        vendor = waf.fingerprint(status_code=403, headers=headers, body="403 Forbidden")
        assert vendor == "AWS WAF"

    def test_decompile_sqli_union_blocked_payload(self):
        waf = WAFFingerprinter()
        payload = "' UNION SELECT 1, table_name FROM information_schema.tables --"
        analysis = waf.decompile_blocked_payload(payload, detected_waf="ModSecurity / OWASP CRS")
        assert isinstance(analysis, BlockedTokenAnalysis)
        assert "UNION SELECT" in analysis.blocked_tokens
        assert "942100" in analysis.probable_rule_id
        assert any("UNION/**/SELECT" in e for e in analysis.recommended_evasions)
        assert any("uNiOn/**/sElEcT" in m for m in analysis.mutated_alternatives)

    def test_decompile_sqli_tautology_blocked_payload(self):
        waf = WAFFingerprinter()
        payload = "admin' OR '1'='1"
        analysis = waf.decompile_blocked_payload(payload)
        assert any("OR 1=1" in t for t in analysis.blocked_tokens)
        assert "942140" in analysis.probable_rule_id

    def test_decompile_xss_script_tag(self):
        waf = WAFFingerprinter()
        payload = "<script>alert(document.domain)</script>"
        analysis = waf.decompile_blocked_payload(payload)
        assert "<script>" in analysis.blocked_tokens
        assert "941100" in analysis.probable_rule_id
        assert any("<img src=x onerror=alert(1)>" in m for m in analysis.mutated_alternatives)

    def test_format_block(self):
        waf = WAFFingerprinter()
        payload = "; cat /etc/passwd"
        analysis = waf.decompile_blocked_payload(payload, detected_waf="Cloudflare")
        block = analysis.format_block()
        assert "GIẢI MÃ QUY TẮC PHÒNG THỦ WAF" in block
        assert "Cloudflare" in block
        assert "932100" in analysis.probable_rule_id


# ===========================================================================
# 4. Tests for PatchSynthesizer & HotfixSandboxVerifier
# ===========================================================================
class TestPatchSynthesizerAndSandbox:
    def test_synthesize_sqli_patch_and_verify(self):
        synth = PatchSynthesizer()
        res = synth.synthesize_patch(
            finding_title="SQL Injection in user search endpoint",
            description="Raw query concatenation allows UNION extraction",
            evidence="GET /users?id=1' UNION SELECT...",
        )
        assert isinstance(res, PatchDiffResult)
        assert res.sandbox_verified is True
        assert "--- a/app/repositories/user_repo.py" in res.unified_diff
        assert "+++ b/app/repositories/user_repo.py" in res.unified_diff
        assert "Prepared Statements" in res.unified_diff
        assert "cursor.execute(query, (user_id, 'active',))" in res.unified_diff
        assert "Thành công" in res.verification_proof

    def test_synthesize_rce_patch_and_verify(self):
        synth = PatchSynthesizer()
        res = synth.synthesize_patch(
            finding_title="Remote Code Execution via ping diagnostic",
            description="Command injection through unsanitized host parameter",
            evidence="host=127.0.0.1; whoami",
        )
        assert res.sandbox_verified is True
        assert "shell=False" in res.unified_diff
        assert "subprocess.check_output" in res.unified_diff

    def test_synthesize_path_traversal_patch_and_verify(self):
        synth = PatchSynthesizer()
        res = synth.synthesize_patch(
            finding_title="Arbitrary File Read via Path Traversal",
            description="Directory climbing allows reading /etc/passwd",
            evidence="filename=../../../../etc/passwd",
        )
        assert res.sandbox_verified is True
        assert "os.path.realpath" in res.unified_diff
        assert "startswith" in res.unified_diff

    def test_synthesize_ssrf_patch_and_verify(self):
        synth = PatchSynthesizer()
        res = synth.synthesize_patch(
            finding_title="Server-Side Request Forgery in webhook url",
            description="Allows querying cloud metadata service 169.254.169.254",
            evidence="url=http://169.254.169.254/latest/meta-data/",
        )
        assert res.sandbox_verified is True
        assert "is_private" in res.unified_diff
        assert "is_loopback" in res.unified_diff

    def test_verifier_rejects_unsafe_patch_additions(self):
        verifier = HotfixSandboxVerifier()
        bad_diff = (
            "--- a/test.py\n"
            "+++ b/test.py\n"
            "@@ -1,2 +1,3 @@\n"
            "+import subprocess\n"
            "+output = subprocess.check_output(cmd, shell=True)\n"
        )
        verified, proof = verifier.verify_patch("rce", bad_diff, language="python")
        assert verified is False
        assert "shell" in proof


# ===========================================================================
# 5. Integration Test: Finding Auto-Patch Synthesis in ReportState
# ===========================================================================
class TestFindingPatchIntegration:
    def test_finding_auto_generates_verified_patch(self):
        finding = Finding(
            title="SQL Injection on Login Form",
            severity="CRITICAL",
            description="Authentication bypass with tautology ' OR 1=1",
            raw_evidence="admin' OR '1'='1",
        )
        assert finding.patch_diff != ""
        assert "--- a/" in finding.patch_diff
        assert "+++ b/" in finding.patch_diff
        assert finding.sandbox_verified is True

    def test_report_state_serializes_and_deserializes_patch_diff(self):
        state = ReportState(target="https://target.local")
        f = Finding(
            title="Remote Code Execution in Upload",
            severity="CRITICAL",
            description="Arbitrary shell execution",
        )
        state.add_finding(f)
        state_dict = state.to_dict()

        restored = ReportState.from_dict(state_dict)
        assert len(restored.findings) == 1
        restored_f = restored.findings[0]
        assert restored_f.title == "Remote Code Execution in Upload"
        assert restored_f.patch_diff != ""
        assert restored_f.sandbox_verified is True
