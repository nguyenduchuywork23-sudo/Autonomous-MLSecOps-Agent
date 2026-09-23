"""Tactical Policy Engine (Neuro-Symbolic & Reinforcement Learning Hybrid).

Provides mathematical decision-making and continual learning for the autonomous agent:
1. AttackStateExtractor: Maps ReportState and AttackSurfaceGraph into discrete state representations.
2. TacticalRewardEngine: Computes objective scalar rewards for tool execution outcomes.
3. TacticalPolicyManager: Q-Learning & Contextual Multi-Armed Bandit with UCB1 exploration,
   persisting learned policies to disk (continual learning without full reliance on LLM).
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Canonical tool categories
TOOL_CATEGORIES = {
    # Reconnaissance (23)
    "docker_resolve_dns": "RECON",
    "docker_scan_ports_fast": "RECON",
    "docker_scan_ports_deep": "RECON",
    "docker_crawl_web": "RECON",
    "browse_webpage": "RECON",
    "docker_whatweb": "RECON",
    "docker_nikto_scan": "RECON",
    "docker_nuclei_scan": "PROBE",
    "docker_dirb_scan": "RECON",
    "docker_subfinder": "RECON",
    "docker_ffuf": "RECON",
    "docker_testssl": "RECON",
    "docker_sensitive_files_scan": "PROBE",
    "docker_cors_scan": "PROBE",
    "docker_httpx_probe": "RECON",
    "docker_ssl_cert_audit": "RECON",
    "docker_dns_security_audit": "RECON",
    "docker_security_txt_audit": "RECON",
    "docker_cookie_security_audit": "PROBE",
    "docker_http_headers_audit": "RECON",
    "docker_api_docs_audit": "PROBE",
    "docker_subdomain_takeover_audit": "PROBE",
    "docker_waf_detect": "RECON",
    # Exploitation & Cracking (8)
    "docker_sqlmap_scan": "EXPLOIT",
    "docker_sqlmap_dump": "EXPLOIT",
    "docker_bruteforce": "EXPLOIT",
    "bruteforce_ssh": "EXPLOIT",
    "bruteforce_http_form": "EXPLOIT",
    "docker_wpscan": "EXPLOIT",
    "docker_msf_search": "EXPLOIT",
    "docker_xss_scan": "EXPLOIT",
}

# Base prior weights for cold-start (before learning accumulates)
BASE_TOOL_PRIORS: dict[str, float] = {
    "docker_resolve_dns": 4.0,
    "docker_scan_ports_fast": 5.0,
    "docker_crawl_web": 4.5,
    "docker_whatweb": 4.0,
    "docker_httpx_probe": 3.5,
    "docker_subfinder": 3.5,
    "docker_nuclei_scan": 5.0,
    "docker_sensitive_files_scan": 4.0,
    "docker_http_headers_audit": 3.0,
    "docker_api_docs_audit": 3.5,
    "docker_sqlmap_scan": 6.0,
    "docker_xss_scan": 5.0,
    "docker_wpscan": 5.5,
    "bruteforce_ssh": 4.0,
    "bruteforce_http_form": 4.5,
    "docker_testssl": 3.0,
    "docker_cors_scan": 3.0,
    "docker_dirb_scan": 3.5,
    "docker_ffuf": 3.5,
    "docker_nikto_scan": 3.5,
    "docker_scan_ports_deep": 4.0,
    "docker_sqlmap_dump": 6.5,
    "docker_msf_search": 4.5,
    "docker_waf_detect": 3.0,
    "docker_ssl_cert_audit": 2.5,
    "docker_dns_security_audit": 2.5,
    "docker_security_txt_audit": 2.5,
    "docker_cookie_security_audit": 2.5,
    "docker_subdomain_takeover_audit": 3.0,
    "docker_bruteforce": 3.5,
    "browse_webpage": 2.5,
}


# ---------------------------------------------------------------------------
# 1. State Feature Extraction
# ---------------------------------------------------------------------------

class AttackStateExtractor:
    """Extracts discrete, normalized state keys from ReportState and AttackSurfaceGraph."""

    @staticmethod
    def extract_state_key(report_state: Any, tools_called: list[str]) -> str:
        """Extract a canonical discrete state key representing the engagement environment."""
        if not report_state or not hasattr(report_state, "attack_surface"):
            return "phase:init|web:none|params:0|forms:0|ssh:0|cms:none|waf:0"

        surface = report_state.attack_surface
        call_count = len(tools_called)

        # 1. Web presence
        has_http = False
        has_https = False
        open_ports = getattr(surface, "open_ports", {})
        for p in open_ports:
            try:
                p_int = int(p)
                if p_int in (80, 8080, 8000, 8888):
                    has_http = True
                elif p_int in (443, 8443):
                    has_https = True
            except (ValueError, TypeError):
                pass

        target_str = str(getattr(report_state, "target", "")).lower()
        if "https://" in target_str:
            has_https = True
        elif "http://" in target_str:
            has_http = True

        if has_https:
            web_mode = "https"
        elif has_http:
            web_mode = "http"
        else:
            web_mode = "none"

        # 2. Parameters & endpoints
        params = getattr(surface, "parameterized_endpoints", {})
        has_params = "1" if len(params) > 0 else "0"

        # 3. Login forms
        login_forms = getattr(surface, "login_forms", [])
        has_login = "1" if len(login_forms) > 0 else "0"

        # 4. SSH presence
        has_ssh = "1" if 22 in open_ports or "22" in open_ports else "0"

        # 5. CMS
        detected_tech = [str(t).lower() for t in getattr(surface, "detected_technologies", [])]
        cms = "none"
        if any("wordpress" in t for t in detected_tech):
            cms = "wp"
        elif any("joomla" in t for t in detected_tech):
            cms = "joomla"
        elif any("drupal" in t for t in detected_tech):
            cms = "drupal"

        # 6. WAF
        detected_waf = getattr(surface, "detected_waf", {})
        waf = "1" if bool(detected_waf and detected_waf.get("has_waf")) else "0"

        # 7. Phase
        findings_count = len(getattr(report_state, "findings", []))
        if findings_count > 0 or call_count >= 9:
            phase = "exploit"
        elif call_count < 3:
            phase = "recon"
        else:
            phase = "probe"

        return f"phase:{phase}|web:{web_mode}|params:{has_params}|forms:{has_login}|ssh:{has_ssh}|cms:{cms}|waf:{waf}"


# ---------------------------------------------------------------------------
# 2. Objective Reward Engine
# ---------------------------------------------------------------------------

class TacticalRewardEngine:
    """Computes mathematical scalar reward for an action given environmental feedback."""

    # Severity values
    SEVERITY_WEIGHTS = {
        "CRITICAL": 25.0,
        "HIGH": 15.0,
        "MEDIUM": 8.0,
        "LOW": 4.0,
        "INFO": 2.0,
    }

    def compute_reward(
        self,
        tool_name: str,
        pre_findings_count: int,
        post_findings_count: int,
        new_severities: list[str] | None = None,
        new_ports_discovered: int = 0,
        new_endpoints_discovered: int = 0,
        tool_status: str = "SUCCESS",
        is_duplicate_call: bool = False,
    ) -> float:
        """Calculate the scalar reward signal R."""
        reward = 0.0

        # Duplicate penalty
        if is_duplicate_call:
            return -2.5

        # Tool status penalties
        norm_status = (tool_status or "SUCCESS").upper()
        if norm_status == "FAILED":
            reward -= 2.0
        elif norm_status == "TIMEOUT":
            reward -= 3.0
        elif norm_status == "BLOCKED":
            reward -= 4.0

        # Attack surface discovery rewards
        if new_ports_discovered > 0:
            reward += min(10.0, new_ports_discovered * 2.0)

        if new_endpoints_discovered > 0:
            reward += min(12.0, new_endpoints_discovered * 1.5)

        # Finding rewards
        diff_findings = max(0, post_findings_count - pre_findings_count)
        if diff_findings > 0:
            if new_severities:
                for sev in new_severities:
                    sev_upper = str(sev).upper().strip()
                    reward += self.SEVERITY_WEIGHTS.get(sev_upper, 3.0)
            else:
                reward += diff_findings * 5.0
        else:
            # Neutral baseline for recon steps that ran successfully without errors
            if norm_status == "SUCCESS":
                reward += 0.5
            else:
                reward -= 1.0

        return round(reward, 2)


# ---------------------------------------------------------------------------
# 3. Tactical Policy Manager (Q-Learning + Contextual Bandit)
# ---------------------------------------------------------------------------

@dataclass
class TacticalRecommendation:
    """Action recommendation emitted by the Tactical Policy Engine."""
    tool_name: str
    q_value: float
    confidence: float
    visits: int
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "q_value": round(self.q_value, 3),
            "confidence": round(self.confidence, 3),
            "visits": self.visits,
            "rationale": self.rationale,
        }


class TacticalPolicyManager:
    """Manages Q-values, UCB1 action exploration, and continual learning persistence."""

    def __init__(
        self,
        policy_file: str = "data/tactical_policy.json",
        learning_rate: float = 0.15,
        discount_factor: float = 0.85,
        exploration_bonus: float = 1.2,
        enabled: bool = True,
    ) -> None:
        self.policy_file = policy_file
        self.alpha = float(learning_rate)
        self.gamma = float(discount_factor)
        self.c_ucb = float(exploration_bonus)
        self.enabled = bool(enabled)

        self._lock = threading.RLock()
        self.q_table: dict[str, dict[str, float]] = {}
        self.visit_counts: dict[str, dict[str, int]] = {}
        self.total_updates: int = 0

        self.reward_engine = TacticalRewardEngine()
        self._load_policy()

    def _load_policy(self) -> None:
        """Load persisted policy from JSON file if present."""
        if not self.policy_file or not os.path.exists(self.policy_file):
            return

        with self._lock:
            try:
                with open(self.policy_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.q_table = data.get("q_table", {})
                    self.visit_counts = data.get("visit_counts", {})
                    self.total_updates = int(data.get("total_updates", 0))
                    logger.info(
                        "Loaded tactical policy from %s (%d states, %d updates)",
                        self.policy_file,
                        len(self.q_table),
                        self.total_updates,
                    )
            except Exception as e:
                logger.warning("Failed to load tactical policy from %s: %s", self.policy_file, e)

    def save_policy(self) -> None:
        """Atomically persist policy to disk."""
        if not self.enabled or not self.policy_file:
            return

        with self._lock:
            try:
                parent_dir = os.path.dirname(os.path.abspath(self.policy_file))
                os.makedirs(parent_dir, exist_ok=True)
                tmp_file = f"{self.policy_file}.tmp"
                payload = {
                    "version": "1.0",
                    "total_updates": self.total_updates,
                    "state_count": len(self.q_table),
                    "q_table": self.q_table,
                    "visit_counts": self.visit_counts,
                }
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
                os.replace(tmp_file, self.policy_file)
                logger.debug("Successfully saved tactical policy to %s", self.policy_file)
            except Exception as e:
                logger.warning("Failed to save tactical policy to %s: %s", self.policy_file, e)

    def get_q_value(self, state_key: str, tool_name: str) -> float:
        """Get current Q(s, a) with fallback to domain priors."""
        with self._lock:
            state_q = self.q_table.get(state_key, {})
            if tool_name in state_q:
                return state_q[tool_name]
            return BASE_TOOL_PRIORS.get(tool_name, 2.0)

    def get_visit_count(self, state_key: str, tool_name: str) -> int:
        """Get number of times action a was chosen in state s."""
        with self._lock:
            return self.visit_counts.get(state_key, {}).get(tool_name, 0)

    def recommend_actions(
        self,
        state_key: str,
        top_k: int = 3,
        allowed_tools: list[str] | set[str] | None = None,
        exclude_tools: set[str] | None = None,
    ) -> list[TacticalRecommendation]:
        """Rank and recommend actions using UCB1 exploration and Q-values."""
        if not self.enabled:
            return []

        with self._lock:
            candidate_tools = list(allowed_tools or BASE_TOOL_PRIORS.keys())
            if exclude_tools:
                candidate_tools = [t for t in candidate_tools if t not in exclude_tools]

            if not candidate_tools:
                return []

            # Compute total visits for state s
            state_visits = sum(self.visit_counts.get(state_key, {}).values()) + 1
            scores: list[tuple[str, float, float, int, str]] = []

            for tool in candidate_tools:
                q = self.get_q_value(state_key, tool)
                n = self.get_visit_count(state_key, tool)

                # UCB1 exploration score
                ucb_bonus = self.c_ucb * math.sqrt(math.log(state_visits + 1) / (n + 0.05))
                total_score = q + ucb_bonus

                # Build intuitive technical rationale
                cat = TOOL_CATEGORIES.get(tool, "SECURITY")
                if "params:1" in state_key and tool in ("docker_sqlmap_scan", "docker_xss_scan"):
                    rationale = f"[{cat}] Mục tiêu có tham số URL; lịch sử thực nghiệm đánh giá hiệu quả cao"
                elif "forms:1" in state_key and tool == "bruteforce_http_form":
                    rationale = f"[{cat}] Đã nhận diện form đăng nhập; ưu tiên kiểm tra xác thực"
                elif "cms:wp" in state_key and tool == "docker_wpscan":
                    rationale = f"[{cat}] Hệ quản trị WordPress phát hiện; kích hoạt công cụ chuyên biệt"
                elif "ssh:1" in state_key and tool == "bruteforce_ssh":
                    rationale = f"[{cat}] Cổng SSH 22 mở; kiểm tra bảo mật cấu hình đăng nhập"
                elif n > 0 and q >= 5.0:
                    rationale = f"[{cat}] Tỷ lệ thành công cao qua {n} lần quét tương tự (Q={q:.1f})"
                elif n == 0:
                    rationale = f"[{cat}] Thăm dò vector mới theo thuật toán UCB1 (Chưa thử nghiệm)"
                else:
                    rationale = f"[{cat}] Chiến thuật phù hợp với giai đoạn hiện tại (Điểm: {total_score:.1f})"

                scores.append((tool, total_score, q, n, rationale))

            # Sort descending by total UCB1 score
            scores.sort(key=lambda x: x[1], reverse=True)

            recs = [
                TacticalRecommendation(
                    tool_name=t,
                    q_value=q,
                    confidence=min(1.0, max(0.1, q / 20.0)),
                    visits=n,
                    rationale=r,
                )
                for t, total_s, q, n, r in scores[:top_k]
            ]
            return recs

    def record_outcome(
        self,
        state_key: str,
        action: str,
        reward: float,
        next_state_key: str | None = None,
    ) -> float:
        """Update Q-table via temporal-difference learning Q(s, a)."""
        if not self.enabled or not state_key or not action:
            return 0.0

        with self._lock:
            if state_key not in self.q_table:
                self.q_table[state_key] = {}
            if state_key not in self.visit_counts:
                self.visit_counts[state_key] = {}

            current_q = self.q_table[state_key].get(action, BASE_TOOL_PRIORS.get(action, 2.0))
            current_n = self.visit_counts[state_key].get(action, 0)

            # Next state max Q estimation
            max_next_q = 0.0
            if next_state_key and next_state_key in self.q_table and self.q_table[next_state_key]:
                max_next_q = max(self.q_table[next_state_key].values())
            elif next_state_key:
                max_next_q = max(BASE_TOOL_PRIORS.values()) * 0.5

            # Temporal-Difference Update
            target = reward + self.gamma * max_next_q
            updated_q = current_q + self.alpha * (target - current_q)

            self.q_table[state_key][action] = round(updated_q, 4)
            self.visit_counts[state_key][action] = current_n + 1
            self.total_updates += 1

            return updated_q
