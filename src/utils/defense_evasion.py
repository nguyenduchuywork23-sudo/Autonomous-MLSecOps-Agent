"""
Defense Evasion & Anti-WAF Tactical Resiliency Engine
====================================================
Inspired by Frontier Reasoning (Claude 3.7 / GPT-5 Astra).

Detects defensive countermeasures (Cloudflare, ModSecurity, AWS WAF, Rate Limits, 403 blocks)
in real time and adapts tool parameters with bypass techniques:
1. Header spoofing (X-Forwarded-For, X-Originating-IP, custom User-Agents)
2. SQLmap tamper script injection (space2comment, between, randomcase)
3. Request rate throttling and jitter
4. Payload obfuscation and encoding
"""

from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DefenseEvasionEngine:
    """Monitors defense barriers and dynamically injects evasion parameters."""

    WAF_SIGNATURES = {
        "cloudflare": [r"cloudflare", r"cf-ray", r"error\s+1015", r"attention\s+required!\s*\|\s*cloudflare"],
        "modsecurity": [r"mod_security", r"modsecurity", r"this\s+error\s+was\s+generated\s+by\s+mod_security"],
        "aws_waf": [r"awselb", r"x-amzn-errortype", r"aws\s+waf"],
        "wordfence": [r"generated\s+by\s+wordfence", r"blocked\s+by\s+wordfence"],
        "akamai": [r"akamai", r"reference\s*#[0-9a-f.]+"],
        "generic_waf": [r"403\s+forbidden", r"access\s+denied", r"request\s+blocked\s+by\s+security\s+policy"],
        "rate_limit": [r"429\s+too\s+many\s+requests", r"rate\s+limit\s+exceeded"],
    }

    EVASION_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "X-Forwarded-For": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Remote-Addr": "127.0.0.1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def __init__(self) -> None:
        self.active_waf: str = ""
        self.stealth_level: str = "NORMAL"  # NORMAL, STEALTH, DEEP_STEALTH
        self.rate_limited: bool = False
        self.tamper_scripts: List[str] = []
        self.recommended_delay: float = 0.0

    def analyze_response_for_defense(self, tool_name: str, result_str: str) -> Optional[str]:
        """
        Scan tool output for defensive signatures.
        Returns detected defense name or None.
        """
        res_lower = result_str.lower()
        for defense_name, patterns in self.WAF_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, res_lower):
                    self.active_waf = defense_name
                    if defense_name == "rate_limit":
                        self.rate_limited = True
                        self.stealth_level = "DEEP_STEALTH"
                        self.recommended_delay = 2.0
                    else:
                        self.stealth_level = "STEALTH"
                        self.recommended_delay = 1.0

                    self._configure_tamper_for_waf(defense_name)
                    logger.info("Defense detected [%s]. Activated %s mode.", defense_name, self.stealth_level)
                    return defense_name
        return None

    def _configure_tamper_for_waf(self, waf_name: str) -> None:
        """Select optimal tamper scripts based on specific WAF architecture."""
        if waf_name in ("cloudflare", "aws_waf"):
            self.tamper_scripts = ["between", "randomcase", "space2comment", "charencode"]
        elif waf_name in ("modsecurity", "wordfence"):
            self.tamper_scripts = ["space2comment", "modsecurityversioned", "randomcase"]
        else:
            self.tamper_scripts = ["space2comment", "randomcase"]

    def adapt_tool_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Enrich and tamper tool arguments if defense/WAF is active.
        """
        if self.stealth_level == "NORMAL":
            return arguments

        adapted = dict(arguments)

        # 1. SQLMap Evasion
        if tool_name == "docker_sqlmap_scan":
            existing_tamper = adapted.get("tamper", "")
            if not existing_tamper and self.tamper_scripts:
                adapted["tamper"] = ",".join(self.tamper_scripts[:2])
            if self.recommended_delay > 0 and "delay" not in adapted:
                adapted["delay"] = int(self.recommended_delay)
            if "random_agent" not in adapted:
                adapted["random_agent"] = True

        # 2. Fuzzing Evasion (Dirb / FFUF)
        if tool_name in ("docker_dirb_scan", "docker_ffuf"):
            if self.recommended_delay > 0:
                adapted["delay"] = self.recommended_delay
            # Inject custom stealth headers
            if "headers" not in adapted and self.EVASION_HEADERS:
                adapted["headers"] = f"X-Forwarded-For: 127.0.0.1\nX-Originating-IP: 127.0.0.1"

        return adapted

    def format_evasion_block(self) -> str:
        """Format defense evasion status for prompt injection."""
        if self.stealth_level == "NORMAL":
            return ""

        lines = [
            "# 🛡️ CHỈ THỊ NÉ TRÁNH PHÒNG THỦ & WAF BYPASS (DEFENSE EVASION):",
            f"• **Phát Hiện Rào Cản**: `{self.active_waf.upper()}` | Chế độ: `{self.stealth_level}`",
            f"• **Kỹ Thuật Né Tránh Áp Dụng**:",
            f"  - Giãn cách yêu cầu (Delay): `{self.recommended_delay}s` để tránh Rate-Limiter.",
            f"  - Tamper SQLi: `{', '.join(self.tamper_scripts)}`",
            f"  - Header Spoofing: `X-Forwarded-For: 127.0.0.1`, `X-Originating-IP: 127.0.0.1`.",
            f"  - LƯU Ý: Hãy sử dụng các payload được mã hóa (URL double encode / comment obfuscation) để xuyên thủng WAF!",
        ]
        return "\n".join(lines)
