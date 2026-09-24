"""
Unit Tests for Frontier Cognitive Reasoning Architecture
=========================================================
Tests for Claude 3.7 & GPT-5 Style System-2 Reasoning Components:
1. CognitiveScratchpad (Persistent Working Memory)
2. TreeOfThoughtEngine & Autonomous Backtracking
3. CognitiveCritic (Anti-Hallucination & Soft-404 Skeptic)
4. DefenseEvasionEngine (Anti-WAF Tactical Resiliency)
"""

import pytest
from src.utils.cognitive_scratchpad import CognitiveScratchpad
from src.utils.tree_of_thought import (
    TreeOfThoughtEngine,
    AttackVectorNode,
    VectorStatus,
    BacktrackEvent,
)
from src.utils.cognitive_critic import CognitiveCritic, CriticVerdict
from src.utils.defense_evasion import DefenseEvasionEngine


class TestCognitiveScratchpad:
    """Tests for persistent working memory and anti-amnesia scratchpad."""

    def test_initialization_and_profile_update(self):
        pad = CognitiveScratchpad(target="http://example.com")
        assert pad.target == "http://example.com"
        assert pad.target_profile["os"] == "Unknown"

        pad.update_target_profile("web_server", "Nginx/1.24.0")
        pad.update_target_profile("technologies", ["PHP", "WordPress"])
        pad.update_target_profile("technologies", ["WordPress", "MySQL"])  # duplicate merge

        assert pad.target_profile["web_server"] == "Nginx/1.24.0"
        assert set(pad.target_profile["technologies"]) == {"PHP", "WordPress", "MySQL"}

    def test_verified_facts_and_refuted_paths(self):
        pad = CognitiveScratchpad(target="http://example.com")
        pad.add_verified_fact("Auth", "Admin login located at /admin/login.php", confidence=0.95)
        pad.add_verified_fact("Auth", "Admin login located at /admin/login.php", confidence=0.99)  # confidence update

        assert len(pad.verified_facts) == 1
        assert pad.verified_facts[0]["confidence"] == 0.99

        pad.add_refuted_path("/wp-admin", "404 Not Found")
        assert pad.is_path_refuted("/wp-admin")
        assert pad.is_path_refuted("http://example.com/wp-admin/test")
        assert not pad.is_path_refuted("/api/v1")

    def test_update_from_tool_result(self):
        pad = CognitiveScratchpad(target="http://example.com")

        # Port scan tool output
        pad.update_from_tool_result(
            "docker_scan_ports_fast",
            {"target": "example.com"},
            "PORT   STATE SERVICE\n80/tcp open  http\n443/tcp open https",
        )
        assert 80 in pad.target_profile["open_ports"]
        assert 443 in pad.target_profile["open_ports"]

        # Dirb scan 404
        pad.update_from_tool_result(
            "docker_dirb_scan",
            {"target_url": "http://example.com/backup.zip"},
            "CODE: 404 Not Found | Error 404",
        )
        assert pad.is_path_refuted("http://example.com/backup.zip")

        # WAF 403 signal
        pad.update_from_tool_result(
            "docker_sqlmap_scan",
            {"target_url": "http://example.com/item?id=1"},
            "HTTP 403 Forbidden - Request blocked by WAF (Cloudflare)",
        )
        assert "WAF" in pad.target_profile["waf"]
        assert pad.evasion_directives["stealth_mode"] is True

    def test_format_scratchpad_block(self):
        pad = CognitiveScratchpad(target="http://example.com")
        pad.add_verified_fact("Network", "Port 80/tcp open", 0.9)
        pad.add_refuted_path("/admin", "404 Not Found")
        pad.set_active_hypotheses([{"id": "H1", "title": "SQLi on ?id=", "confidence": 0.85}])

        block = pad.format_scratchpad_block()
        assert "FRONTIER COGNITIVE SCRATCHPAD" in block
        assert "Port 80/tcp open" in block
        assert "/admin" in block
        assert "H1" in block

    def test_serialization_roundtrip(self):
        pad = CognitiveScratchpad(target="http://example.com")
        pad.add_verified_fact("Test", "Fact 1", 0.8)
        pad.add_refuted_path("/test", "Refuted")

        data = pad.to_dict()
        restored = CognitiveScratchpad.from_dict(data)

        assert restored.target == pad.target
        assert len(restored.verified_facts) == 1
        assert restored.is_path_refuted("/test")


class TestTreeOfThoughtEngine:
    """Tests for attack vector branching and autonomous backtracking."""

    def test_seeding_from_technologies(self):
        tot = TreeOfThoughtEngine(target="http://example.com")
        tot.seed_from_target_and_tech(
            target="http://example.com",
            tech_stack=["WordPress", "PHP", "Spring"],
            open_ports=[22, 80, 443],
        )

        assert "VEC-RECON-SURFACE" in tot.nodes
        assert "VEC-CMS-WORDPRESS" in tot.nodes
        assert "VEC-API-SPRING-ACTUATOR" in tot.nodes
        assert "VEC-WEB-PHP-ENDPOINTS" in tot.nodes
        assert "VEC-AUTH-SSH" in tot.nodes
        assert "VEC-WEB-SQLI" in tot.nodes

        active = tot.get_active_vector()
        assert active is not None
        assert active.node_id == "VEC-RECON-SURFACE"

    def test_best_unexplored_vector(self):
        tot = TreeOfThoughtEngine(target="http://example.com")
        tot.seed_from_target_and_tech(
            target="http://example.com",
            tech_stack=["WordPress"],
            open_ports=[80],
        )

        best = tot.get_best_unexplored_vector()
        assert best is not None
        # WordPress priority is 0.92, should be selected above standard SQLi (0.85)
        assert best.node_id == "VEC-CMS-WORDPRESS"

    def test_autonomous_backtracking(self):
        tot = TreeOfThoughtEngine(target="http://example.com")
        tot.seed_from_target_and_tech(
            target="http://example.com",
            tech_stack=["WordPress"],
            open_ports=[80],
        )

        # Active is VEC-RECON-SURFACE. Trigger backtrack:
        event = tot.trigger_backtrack("VEC-RECON-SURFACE", "Recon complete, pivoting to exploit")
        assert event is not None
        assert event.abandoned_node_id == "VEC-RECON-SURFACE"
        assert event.next_node_id == "VEC-CMS-WORDPRESS"
        assert tot.nodes["VEC-RECON-SURFACE"].status == VectorStatus.DEAD_END
        assert tot.nodes["VEC-CMS-WORDPRESS"].status == VectorStatus.ACTIVE
        assert tot.active_node_id == "VEC-CMS-WORDPRESS"

        # Check guidance message
        msg = event.guidance_message
        assert "TREE-OF-THOUGHT BACKTRACK" in msg
        assert "VEC-CMS-WORDPRESS" in msg

    def test_format_tot_block(self):
        tot = TreeOfThoughtEngine(target="http://example.com")
        tot.seed_from_target_and_tech("http://example.com")
        tot.mark_vector_confirmed("VEC-RECON-SURFACE", "Web endpoints discovered")

        block = tot.format_tot_block()
        assert "TREE-OF-THOUGHT HYPOTHESIS TREE" in block
        assert "Đã Xác Nhận Đột Phá" in block


class TestCognitiveCritic:
    """Tests for the skeptic critic filtering false positives."""

    def test_soft_404_detection(self):
        verdict = CognitiveCritic.evaluate_finding(
            title="Exposed Admin Portal",
            description="Found sensitive admin path /admin",
            tool_source="docker_dirb_scan",
            raw_evidence="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>404 Not Found - Page Not Found</body></html>",
        )
        assert verdict.is_valid is False
        assert verdict.is_false_positive is True
        assert "Soft-404" in verdict.reason

    def test_html_escaped_xss_detection(self):
        verdict = CognitiveCritic.evaluate_finding(
            title="Reflected XSS on parameter q",
            description="Payload reflected in body",
            tool_source="docker_xss_scan",
            raw_evidence="Search results for: &lt;script&gt;alert(1)&lt;/script&gt;",
        )
        assert verdict.is_valid is False
        assert verdict.is_false_positive is True
        assert "HTML-encode" in verdict.reason

    def test_valid_unescaped_xss(self):
        verdict = CognitiveCritic.evaluate_finding(
            title="Reflected XSS on parameter q",
            description="Payload reflected unescaped",
            tool_source="docker_xss_scan",
            raw_evidence="Search results for: <script>alert(1)</script>",
        )
        assert verdict.is_valid is True
        assert verdict.is_false_positive is False

    def test_generic_500_sqli_skepticism(self):
        verdict = CognitiveCritic.evaluate_finding(
            title="SQL Injection on login",
            description="Server crashed with 500",
            tool_source="docker_crawl_web",
            raw_evidence="HTTP/1.1 500 Internal Server Error\nAn unexpected error occurred.",
        )
        assert verdict.is_valid is False
        assert verdict.is_false_positive is True
        assert "chữ ký cú pháp SQL" in verdict.reason

    def test_true_sqli_syntax_error(self):
        verdict = CognitiveCritic.evaluate_finding(
            title="SQL Injection on login",
            description="Database error exposed",
            tool_source="docker_crawl_web",
            raw_evidence="Warning: mysql_fetch_array(): You have an error in your SQL syntax near '' at line 1",
        )
        assert verdict.is_valid is True
        assert verdict.is_false_positive is False


class TestDefenseEvasionEngine:
    """Tests for WAF detection and argument tampering."""

    def test_waf_detection_cloudflare(self):
        engine = DefenseEvasionEngine()
        detected = engine.analyze_response_for_defense(
            "docker_crawl_web",
            "HTTP/1.1 403 Forbidden\ncf-ray: 8645a2789-SJC\nServer: cloudflare\nAttention Required! | Cloudflare",
        )
        assert detected == "cloudflare"
        assert engine.stealth_level == "STEALTH"
        assert engine.recommended_delay == 1.0
        assert "space2comment" in engine.tamper_scripts

    def test_waf_detection_rate_limit(self):
        engine = DefenseEvasionEngine()
        detected = engine.analyze_response_for_defense(
            "docker_dirb_scan",
            "HTTP/1.1 429 Too Many Requests - Rate limit exceeded. Try again in 60s.",
        )
        assert detected == "rate_limit"
        assert engine.stealth_level == "DEEP_STEALTH"
        assert engine.recommended_delay == 2.0

    def test_adapt_tool_arguments_for_sqlmap(self):
        engine = DefenseEvasionEngine()
        engine.analyze_response_for_defense("docker_crawl_web", "mod_security block 403")

        initial_args = {"target_url": "http://example.com?id=1"}
        adapted = engine.adapt_tool_arguments("docker_sqlmap_scan", initial_args)

        assert "tamper" in adapted
        assert "space2comment" in adapted["tamper"]
        assert adapted["random_agent"] is True
        assert adapted["delay"] == 1

    def test_format_evasion_block(self):
        engine = DefenseEvasionEngine()
        engine.analyze_response_for_defense("docker_crawl_web", "cloudflare 403")
        block = engine.format_evasion_block()

        assert "CHỈ THỊ NÉ TRÁNH PHÒNG THỦ" in block
        assert "CLOUDFLARE" in block
