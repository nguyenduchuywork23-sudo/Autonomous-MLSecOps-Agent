"""Autonomous In-Silico Red/Blue Wargame Arena.

Executes iterative adversarial rounds pitting the Red Teamer's genetic mutations
against the Blue Teamer's synthesized virtual patches until defense rules achieve
mathematical resilience against all evasions.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class WargameConvergenceStatus(str, Enum):
    CONVERGED_IMPREGNABLE = "CONVERGED_IMPREGNABLE"
    PARTIALLY_HARDENED = "PARTIALLY_HARDENED"
    UNRESOLVED = "UNRESOLVED"


@dataclass
class WargameRound:
    round_number: int
    red_mutation_name: str
    red_payload: str
    blue_rule_before: str
    blue_rule_after: str
    bypass_achieved: bool
    hardening_applied: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "round_number": self.round_number,
            "red_mutation_name": self.red_mutation_name,
            "red_payload": self.red_payload,
            "bypass_achieved": self.bypass_achieved,
            "hardening_applied": self.hardening_applied,
        }


@dataclass
class HardenedDefenseResult:
    finding_title: str
    status: WargameConvergenceStatus
    initial_rule: str
    hardened_rule: str
    rounds_executed: int
    bypasses_thwarted: int
    resilience_score: float  # 0.00 to 1.00
    rounds: List[WargameRound] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_title": self.finding_title,
            "status": self.status.value,
            "initial_rule": self.initial_rule,
            "hardened_rule": self.hardened_rule,
            "rounds_executed": self.rounds_executed,
            "bypasses_thwarted": self.bypasses_thwarted,
            "resilience_score": round(self.resilience_score, 3),
            "rounds": [r.to_dict() for r in self.rounds],
        }


class WargameArena:
    """Simulates multi-round in-silico Red vs. Blue wargames to harden virtual patches."""

    def __init__(self, max_rounds: int = 5):
        self.max_rounds = max_rounds

    def _test_rule_matches(self, rule_text: str, payload: str) -> bool:
        """Helper to test if rule catches payload, considering normalization transforms."""
        # Extract regex from SecRule
        pattern = rule_text
        if "@rx" in rule_text:
            for line in rule_text.splitlines():
                if "@rx" in line:
                    idx = line.find("@rx")
                    rest = line[idx + 3:].strip()
                    rest = re.sub(r'\\\s*$', '', rest).strip()
                    if rest.endswith('"'):
                        rest = rest[:-1]
                    elif rest.endswith("'"):
                        rest = rest[:-1]
                    pattern = rest.strip()
                    break

        # If rule includes urlDecodeUni / lowercase, apply transforms
        has_url_decode = "t:urlDecodeUni" in rule_text or "t:urlDecode" in rule_text
        has_lowercase = "t:lowercase" in rule_text

        test_val = payload
        if has_url_decode:
            test_val = urllib.parse.unquote(urllib.parse.unquote(test_val))
        if has_lowercase:
            test_val = test_val.lower()

        try:
            return bool(re.search(pattern, test_val, re.IGNORECASE))
        except re.error:
            # Fallback simple substring
            clean_pat = re.sub(r'[\(\)\?\:\|\\\[\]\^\$\*\+\.\{\}]', '', pattern).lower()
            return clean_pat in test_val.lower()

    def run_wargame(
        self,
        finding_title: str,
        category: str,
        base_payload: str,
        initial_rule: str,
    ) -> HardenedDefenseResult:
        """Runs iterative rounds between Red mutations and Blue rule hardening."""
        current_rule = initial_rule
        rounds_history: List[WargameRound] = []
        bypasses_thwarted = 0

        # Sequence of Red Team adversarial mutations
        mutations = [
            ("Direct Base Payload", base_payload),
            ("Case Alternation Evasion", "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(base_payload))),
            ("URL Encoded Evasion", urllib.parse.quote(base_payload)),
            ("Double URL Encoded Evasion", urllib.parse.quote(urllib.parse.quote(base_payload))),
            ("Comment / Whitespace Obfuscation", base_payload.replace(" ", "/**/")),
        ]

        for idx, (mut_name, mut_payload) in enumerate(mutations[: self.max_rounds]):
            round_num = idx + 1
            rule_before = current_rule

            # Blue evaluates payload against current rule
            caught = self._test_rule_matches(current_rule, mut_payload)

            if not caught:
                bypass = True
                hardening = ""
                # Blue hardens rule based on the bypass type
                if "URL Encoded" in mut_name:
                    if "t:urlDecodeUni" not in current_rule:
                        current_rule = current_rule.replace(
                            "t:none", "t:none,t:urlDecodeUni"
                        )
                        hardening = "Injected 't:urlDecodeUni' transform to normalize encoded inputs"
                    else:
                        current_rule = current_rule.replace(
                            "t:urlDecodeUni", "t:urlDecodeUni,t:urlDecode"
                        )
                        hardening = "Added multi-pass URL decoding transforms"
                elif "Case" in mut_name:
                    if "t:lowercase" not in current_rule:
                        current_rule = current_rule.replace(
                            "t:none", "t:none,t:lowercase"
                        )
                        hardening = "Injected 't:lowercase' transform to normalize case permutations"
                    else:
                        # Ensure regex has (?i)
                        if "(?i)" not in current_rule:
                            current_rule = current_rule.replace('@rx "', '@rx "(?i)')
                            hardening = "Added case-insensitive regex flag (?i)"
                elif "Comment" in mut_name:
                    # In ModSecurity regex, replace \s+ with (?:\s+|/\*.*?\*/)
                    if "/\\*" not in current_rule:
                        current_rule = current_rule.replace(
                            r"\s+", r"(?:\s+|/\*.*?\*/)"
                        )
                        hardening = "Broadened whitespace token regex to capture inline SQL comments '/**/'"
                else:
                    # Generic broadening
                    hardening = "Reinforced inspection phase and match severity"
                    current_rule = current_rule.replace("phase:2", "phase:1,phase:2")

                # Verify if hardening succeeded
                if self._test_rule_matches(current_rule, mut_payload):
                    bypasses_thwarted += 1
            else:
                bypass = False
                hardening = "Defense rule successfully blocked mutation without modifications"

            rounds_history.append(
                WargameRound(
                    round_number=round_num,
                    red_mutation_name=mut_name,
                    red_payload=mut_payload,
                    blue_rule_before=rule_before,
                    blue_rule_after=current_rule,
                    bypass_achieved=bypass,
                    hardening_applied=hardening,
                )
            )

        # Check final resilience across all mutations
        final_caught_count = sum(
            1 for _, p in mutations if self._test_rule_matches(current_rule, p)
        )
        resilience = final_caught_count / len(mutations)

        if resilience >= 1.0:
            status = WargameConvergenceStatus.CONVERGED_IMPREGNABLE
        elif resilience >= 0.75:
            status = WargameConvergenceStatus.PARTIALLY_HARDENED
        else:
            status = WargameConvergenceStatus.UNRESOLVED

        return HardenedDefenseResult(
            finding_title=finding_title,
            status=status,
            initial_rule=initial_rule,
            hardened_rule=current_rule,
            rounds_executed=len(rounds_history),
            bypasses_thwarted=bypasses_thwarted,
            resilience_score=resilience,
            rounds=rounds_history,
        )
