"""
Dynamic Cognitive Scratchpad & Persistent Working Memory
========================================================
Inspired by Claude 3.7 Sonnet Extended Thinking and GPT-5 class reasoning architectures.

Maintains a structured, high-density working memory buffer across the entire
engagement lifecycle. Solves context window truncation amnesia by preserving:
1. Target architecture profile (OS, server, framework, DB, WAF)
2. Verified ground-truth facts & discovered endpoints
3. Blacklist of refuted dead-ends and failed attack paths (Anti-Loop Guarantee)
4. Active hypotheses ranked by confidence
5. Defense evasion directives currently in effect
"""

from __future__ import annotations

import re
import json
import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class CognitiveScratchpad:
    """Working memory buffer that maintains cognitive state across agent iterations."""

    def __init__(self, target: str = "") -> None:
        self.target: str = target
        self.target_profile: Dict[str, Any] = {
            "target": target,
            "os": "Unknown",
            "web_server": "Unknown",
            "technologies": [],
            "open_ports": [],
            "endpoints": [],
            "waf": "None detected",
        }
        self.verified_facts: List[Dict[str, Any]] = []
        self.refuted_paths: Dict[str, str] = {}  # path/vector -> reason
        self.active_hypotheses: List[Dict[str, Any]] = []
        self.evasion_directives: Dict[str, Any] = {
            "stealth_mode": False,
            "custom_headers": {},
            "tamper_scripts": [],
            "recommended_ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        self.iteration_count: int = 0

    def update_target_profile(self, key: str, value: Any) -> None:
        """Update a specific field in the target profile."""
        if key in self.target_profile:
            if isinstance(self.target_profile[key], list) and isinstance(value, list):
                # Union merge for lists
                existing = set(self.target_profile[key])
                for v in value:
                    if v not in existing:
                        self.target_profile[key].append(v)
            else:
                self.target_profile[key] = value

    def add_verified_fact(
        self,
        category: str,
        fact: str,
        confidence: float = 1.0,
        source_tool: str = "",
    ) -> None:
        """Record a verified factual finding to prevent knowledge decay."""
        clean_fact = fact.strip()
        if not clean_fact:
            return

        # Check for duplicates or near-duplicates
        for item in self.verified_facts:
            if item.get("fact") == clean_fact:
                item["confidence"] = max(item["confidence"], confidence)
                return

        self.verified_facts.append({
            "category": category,
            "fact": clean_fact,
            "confidence": round(confidence, 2),
            "source": source_tool,
        })
        # Keep at most 25 high-priority facts
        if len(self.verified_facts) > 25:
            self.verified_facts.sort(key=lambda x: x.get("confidence", 0), reverse=True)
            self.verified_facts = self.verified_facts[:25]

    def add_refuted_path(self, path_or_vector: str, reason: str) -> None:
        """Record a dead-end path or payload that failed so it will never be retried."""
        clean_key = path_or_vector.strip().lower()
        if clean_key:
            self.refuted_paths[clean_key] = reason.strip()

    def is_path_refuted(self, path_or_vector: str) -> bool:
        """Check if an endpoint, port, or attack vector has already been proven dead."""
        clean_key = path_or_vector.strip().lower()
        if clean_key in self.refuted_paths:
            return True
        # Partial match for path
        for refuted in self.refuted_paths:
            if refuted in clean_key:
                return True
        return False

    def set_active_hypotheses(self, hypotheses: List[Dict[str, Any]]) -> None:
        """Set the active prioritized hypothesis list."""
        self.active_hypotheses = hypotheses[:5]

    def set_evasion_directive(self, key: str, value: Any) -> None:
        """Set a defense evasion directive."""
        self.evasion_directives[key] = value

    def update_from_tool_result(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        result_str: str,
    ) -> None:
        """
        Synthesize raw tool output into high-density facts and refuted paths.
        Detects 404s, open ports, server headers, and credentials automatically.
        """
        self.iteration_count += 1
        res_lower = result_str.lower()

        # 1. Detect open ports from port scanners
        if tool_name in ("docker_scan_ports_fast", "docker_scan_ports_deep"):
            open_port_matches = re.findall(r"(\d+)/(?:tcp|udp)\s+open\s+([^\s\r\n]+)", result_str, re.IGNORECASE)
            for port_str, service in open_port_matches:
                p_int = int(port_str)
                if p_int not in self.target_profile["open_ports"]:
                    self.target_profile["open_ports"].append(p_int)
                self.add_verified_fact(
                    "Network",
                    f"Port {p_int}/tcp open ({service})",
                    confidence=0.95,
                    source_tool=tool_name,
                )

        # 2. Detect web technologies & server headers
        if tool_name in ("docker_whatweb", "docker_http_headers_audit"):
            # Check server banner
            server_m = re.search(r"server:\s*([^\r\n,]+)", result_str, re.IGNORECASE)
            if server_m:
                srv = server_m.group(1).strip()
                self.target_profile["web_server"] = srv
                self.add_verified_fact("Tech", f"Web Server: {srv}", confidence=0.9, source_tool=tool_name)

        # 3. Detect 404 dead ends from dirb/ffuf/crawler
        target_path = arguments.get("url") or arguments.get("target_url") or arguments.get("path") or ""
        if target_path and any(k in res_lower for k in ("404 not found", "error 404", "does not exist", "status 404")):
            self.add_refuted_path(target_path, "404 Not Found")

        # 4. Detect SQLi negative confirmation from sqlmap
        if tool_name == "docker_sqlmap_scan":
            if "all tested parameters do not appear to be injectable" in res_lower:
                target_url = arguments.get("target_url") or arguments.get("url") or ""
                if target_url:
                    self.add_refuted_path(f"SQLi:{target_url}", "Not injectable across tested payloads")

        # 5. Detect WAF blocking
        if any(waf_signal in res_lower for waf_signal in ("403 forbidden", "access denied", "cloudflare", "mod_security", "blocked by waf", "request rejected")):
            target_url = arguments.get("target_url") or arguments.get("url") or self.target
            self.target_profile["waf"] = "Active WAF / Filter Detected"
            self.evasion_directives["stealth_mode"] = True
            self.add_verified_fact(
                "Defense",
                "WAF/Filter blocking aggressive requests (HTTP 403 / Access Denied)",
                confidence=0.9,
                source_tool=tool_name,
            )

    def format_scratchpad_block(self, max_tokens: int = 400) -> str:
        """
        Format the scratchpad into an ultra-dense, structured prompt block.
        Follows Claude 3.7 / GPT-5 cognitive working memory formatting.
        """
        lines = [
            "# 🧠 BỘ NHỚ LÀM VIỆC CAO CẤP (FRONTIER COGNITIVE SCRATCHPAD):",
        ]

        # Target Profile
        prof = self.target_profile
        ports_str = ", ".join(str(p) for p in sorted(prof.get("open_ports", []))) or "Chưa rõ"
        tech_str = ", ".join(prof.get("technologies", [])) or "Đang trinh sát"
        lines.append(
            f"• **Hồ sơ Mục tiêu**: Server: `{prof.get('web_server', 'Unknown')}` | "
            f"Ports Open: `[{ports_str}]` | WAF: `{prof.get('waf', 'None')}` | Tech: `{tech_str}`"
        )

        # Verified Facts (Top 4)
        if self.verified_facts:
            lines.append("• **Sự Thật Đã Xác Thực (Ground Truth)**:")
            for item in self.verified_facts[-4:]:
                lines.append(f"  - [{item['category']}] {item['fact']} (Độ tin cậy: {item['confidence'] * 100:.0f}%)")

        # Refuted Dead Ends (Top 3) - Anti-loop safeguard
        if self.refuted_paths:
            lines.append("• **Đường Bế Tắc Đã Bác Bỏ (TUYỆT ĐỐI KHÔNG TÁI THỬ NGHIỆM)**:")
            for path, reason in list(self.refuted_paths.items())[-3:]:
                lines.append(f"  - 🚫 `{path}` ➔ {reason}")

        # Active Hypotheses (Top 2)
        if self.active_hypotheses:
            lines.append("• **Giả Thuyết Tấn Công Ưu Tiên Đang Theo Đuổi**:")
            for hyp in self.active_hypotheses[:2]:
                hid = hyp.get("id", "H")
                title = hyp.get("title", "")
                conf = hyp.get("confidence", 0.8)
                lines.append(f"  - 🎯 [{hid}] {title} (Ưu tiên: {conf * 100:.0f}%)")

        # Evasion Directives
        if self.evasion_directives.get("stealth_mode"):
            lines.append("• **Chỉ Thị Né Tránh Phòng Thủ (WAF Active)**: Bật chế độ Stealth, dùng Header bypass và Payload tamper!")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize scratchpad to dictionary."""
        return {
            "target": self.target,
            "target_profile": self.target_profile,
            "verified_facts": self.verified_facts,
            "refuted_paths": self.refuted_paths,
            "active_hypotheses": self.active_hypotheses,
            "evasion_directives": self.evasion_directives,
            "iteration_count": self.iteration_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CognitiveScratchpad:
        """Instantiate scratchpad from serialized dictionary."""
        pad = cls(target=data.get("target", ""))
        pad.target_profile = data.get("target_profile", pad.target_profile)
        pad.verified_facts = data.get("verified_facts", [])
        pad.refuted_paths = data.get("refuted_paths", {})
        pad.active_hypotheses = data.get("active_hypotheses", [])
        pad.evasion_directives = data.get("evasion_directives", pad.evasion_directives)
        pad.iteration_count = data.get("iteration_count", 0)
        return pad
