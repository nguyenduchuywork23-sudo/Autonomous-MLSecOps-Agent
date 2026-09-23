"""Unit and integration tests for Tactical Policy Engine (Q-Learning & UCB1)."""

import json
import os
import tempfile
import threading
import pytest

from src.client.report_state import ReportState, Finding
from src.utils.tactical_policy import (
    AttackStateExtractor,
    TacticalRewardEngine,
    TacticalPolicyManager,
    TacticalRecommendation,
    BASE_TOOL_PRIORS,
)


class TestAttackStateExtractor:
    """Tests for discrete environment state extraction."""

    def test_empty_or_none_state(self):
        """None or uninitialized state should return default initial state."""
        assert AttackStateExtractor.extract_state_key(None, []) == (
            "phase:init|web:none|params:0|forms:0|ssh:0|cms:none|waf:0"
        )

    def test_extract_web_and_ports(self):
        """Should detect HTTP/HTTPS, SSH port 22, and recon phase."""
        state = ReportState(target="https://example.com:8443", scan_mode="full")
        state.attack_surface.open_ports = [443, 22]

        key = AttackStateExtractor.extract_state_key(state, ["docker_scan_ports_fast"])
        assert "web:https" in key
        assert "ssh:1" in key
        assert "phase:recon" in key

    def test_extract_parameters_and_login_forms(self):
        """Should detect parameterized endpoints and login forms."""
        state = ReportState(target="http://testphp.vulnweb.com", scan_mode="full")
        state.attack_surface.parameterized_endpoints["http://testphp.vulnweb.com/listproducts.php?cat=1"] = ["cat"]
        state.attack_surface.login_forms.append("http://testphp.vulnweb.com/login.php")

        key = AttackStateExtractor.extract_state_key(state, ["docker_crawl_web", "docker_whatweb", "docker_httpx_probe"])
        assert "params:1" in key
        assert "forms:1" in key
        assert "phase:probe" in key

    def test_extract_cms_and_waf(self):
        """Should detect WordPress CMS and WAF presence."""
        state = ReportState(target="http://wp.local", scan_mode="full")
        state.attack_surface.detected_technologies.append("WordPress 6.2")
        state.attack_surface.detected_waf = {"has_waf": True, "primary_waf": "Cloudflare"}

        key = AttackStateExtractor.extract_state_key(state, ["tool1"] * 10)
        assert "cms:wp" in key
        assert "waf:1" in key
        assert "phase:exploit" in key

    def test_phase_transition_on_findings(self):
        """Having at least one finding should transition directly to exploit phase."""
        state = ReportState(target="http://example.com", scan_mode="full")
        state.add_finding(Finding(
            title="SQLi Detected", severity="HIGH", description="SQL injection",
            impact="Data leak", remediation="Sanitize", tool_source="docker_sqlmap_scan",
            raw_evidence="1' OR 1=1--",
        ))
        key = AttackStateExtractor.extract_state_key(state, ["docker_sqlmap_scan"])
        assert "phase:exploit" in key


class TestTacticalRewardEngine:
    """Tests for scalar reward computation."""

    def setup_method(self):
        self.engine = TacticalRewardEngine()

    def test_duplicate_call_penalty(self):
        """Duplicate tool calls should receive a flat negative reward."""
        r = self.engine.compute_reward(
            tool_name="docker_scan_ports_fast",
            pre_findings_count=0,
            post_findings_count=0,
            is_duplicate_call=True,
        )
        assert r == -2.5

    def test_tool_failure_penalties(self):
        """Failed, timeout, or blocked executions should yield negative rewards."""
        r_fail = self.engine.compute_reward("tool", 0, 0, tool_status="FAILED")
        assert r_fail < 0

        r_timeout = self.engine.compute_reward("tool", 0, 0, tool_status="TIMEOUT")
        assert r_timeout < r_fail

        r_blocked = self.engine.compute_reward("tool", 0, 0, tool_status="BLOCKED")
        assert r_blocked < r_timeout

    def test_surface_discovery_rewards(self):
        """Discovering new open ports and endpoints should yield positive scalar rewards."""
        r = self.engine.compute_reward(
            tool_name="docker_crawl_web",
            pre_findings_count=0,
            post_findings_count=0,
            new_ports_discovered=2,
            new_endpoints_discovered=3,
            tool_status="SUCCESS",
        )
        # 2 ports * 2.0 = 4.0, 3 endpoints * 1.5 = 4.5 => total = 8.5
        assert r >= 8.5

    def test_finding_severities_reward(self):
        """Critical and High findings should yield large positive reinforcement."""
        r_crit = self.engine.compute_reward(
            tool_name="docker_sqlmap_scan",
            pre_findings_count=0,
            post_findings_count=1,
            new_severities=["CRITICAL"],
        )
        assert r_crit >= 25.0

        r_high = self.engine.compute_reward(
            tool_name="docker_xss_scan",
            pre_findings_count=0,
            post_findings_count=1,
            new_severities=["HIGH"],
        )
        assert r_high == 15.0

    def test_neutral_successful_step(self):
        """A successful tool step with no new findings should yield a small positive baseline."""
        r = self.engine.compute_reward(
            tool_name="docker_whatweb",
            pre_findings_count=0,
            post_findings_count=0,
            tool_status="SUCCESS",
        )
        assert r == 0.5


class TestTacticalPolicyManager:
    """Tests for Q-learning updates, UCB1 action ranking, and persistence."""

    def test_initial_q_priors(self):
        """Manager should return domain priors for unseen states."""
        mgr = TacticalPolicyManager(policy_file="", enabled=True)
        q = mgr.get_q_value("phase:recon|web:https|params:0|forms:0|ssh:0|cms:none|waf:0", "docker_scan_ports_fast")
        assert q == BASE_TOOL_PRIORS.get("docker_scan_ports_fast")

    def test_recommend_actions_ucb1_and_exclusions(self):
        """UCB1 recommendation should respect exclusions and return top_k ranked actions."""
        mgr = TacticalPolicyManager(policy_file="", enabled=True)
        state_key = "phase:recon|web:http|params:1|forms:1|ssh:0|cms:wp|waf:0"

        recs = mgr.recommend_actions(state_key=state_key, top_k=3, exclude_tools={"docker_resolve_dns"})
        assert len(recs) <= 3
        assert all(r.tool_name != "docker_resolve_dns" for r in recs)
        assert all(isinstance(r, TacticalRecommendation) for r in recs)
        assert all(r.rationale != "" for r in recs)

    def test_q_learning_td_update(self):
        """Q(s, a) should update according to the Temporal-Difference formula."""
        mgr = TacticalPolicyManager(policy_file="", learning_rate=0.2, discount_factor=0.9, enabled=True)
        s = "phase:recon|web:http|params:0|forms:0|ssh:0|cms:none|waf:0"
        s_next = "phase:probe|web:http|params:1|forms:0|ssh:0|cms:none|waf:0"
        a = "docker_crawl_web"

        initial_q = mgr.get_q_value(s, a)
        reward = 10.0

        updated_q = mgr.record_outcome(state_key=s, action=a, reward=reward, next_state_key=s_next)
        assert updated_q > initial_q
        assert mgr.get_visit_count(s, a) == 1
        assert mgr.total_updates == 1

        # Second update on same action
        updated_q_2 = mgr.record_outcome(state_key=s, action=a, reward=reward, next_state_key=s_next)
        assert mgr.get_visit_count(s, a) == 2
        assert mgr.total_updates == 2

    def test_atomic_persistence_save_and_load(self):
        """Policy should save atomically to JSON and be successfully restored."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            policy_file = os.path.join(tmp_dir, "test_policy.json")
            mgr = TacticalPolicyManager(policy_file=policy_file, enabled=True)

            s = "phase:exploit|web:https|params:1|forms:0|ssh:0|cms:none|waf:0"
            mgr.record_outcome(s, "docker_sqlmap_scan", 25.0)
            mgr.record_outcome(s, "docker_xss_scan", 15.0)
            mgr.save_policy()

            assert os.path.exists(policy_file)
            with open(policy_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                assert data["total_updates"] == 2
                assert s in data["q_table"]
                assert "docker_sqlmap_scan" in data["q_table"][s]

            # Create new manager pointing to same file -> verify restoration
            mgr_reloaded = TacticalPolicyManager(policy_file=policy_file, enabled=True)
            assert mgr_reloaded.total_updates == 2
            assert mgr_reloaded.get_visit_count(s, "docker_sqlmap_scan") == 1
            assert mgr_reloaded.get_q_value(s, "docker_sqlmap_scan") == mgr.get_q_value(s, "docker_sqlmap_scan")

    def test_thread_safety_concurrent_updates(self):
        """Concurrent updates from multiple threads should not corrupt Q-table."""
        mgr = TacticalPolicyManager(policy_file="", enabled=True)
        s = "state_concurrent"

        def worker(tool_name: str, n_times: int):
            for _ in range(n_times):
                mgr.record_outcome(s, tool_name, 5.0)

        threads = [
            threading.Thread(target=worker, args=(f"tool_{i}", 50))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert mgr.total_updates == 200
        for i in range(4):
            assert mgr.get_visit_count(s, f"tool_{i}") == 50
