"""Closed-Loop Remediation Verifier & Differential Fuzzing Engine.

Performs active closed-loop verification of virtual patches, WAF rules, and code hotfixes:
1. Generates Direct Exploit Replay payloads.
2. Synthesizes Adversarial Evasion Variations (encodings, comments, casing, null-bytes).
3. Evaluates Legitimate Benign Baselines to guarantee zero false positives.
4. Computes empirical Verification Confidence Score (0.00 - 1.00) and certification verdict.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class VerificationVerdict(str, Enum):
    APPROVED_FOR_PRODUCTION = "APPROVED_FOR_PRODUCTION"
    REQUIRES_TUNING = "REQUIRES_TUNING"
    REJECTED = "REJECTED"


@dataclass
class FuzzTestCase:
    name: str
    payload: str
    is_malicious: bool
    description: str
    blocked: bool = False
    details: str = ""


@dataclass
class VerificationReport:
    finding_title: str
    verdict: VerificationVerdict
    confidence_score: float  # 0.00 to 1.00
    exploit_neutralized: bool
    evasion_resilience_rate: float  # 0.00 to 1.00
    false_positive_rate: float  # 0.00 to 1.00
    total_tests_run: int
    malicious_tests_blocked: int
    benign_tests_passed: int
    test_cases: List[FuzzTestCase] = field(default_factory=list)
    remediation_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_title": self.finding_title,
            "verdict": self.verdict.value,
            "confidence_score": round(self.confidence_score, 3),
            "exploit_neutralized": self.exploit_neutralized,
            "evasion_resilience_rate": round(self.evasion_resilience_rate, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "total_tests_run": self.total_tests_run,
            "malicious_tests_blocked": self.malicious_tests_blocked,
            "benign_tests_passed": self.benign_tests_passed,
            "test_cases": [
                {
                    "name": tc.name,
                    "payload": tc.payload,
                    "is_malicious": tc.is_malicious,
                    "blocked": tc.blocked,
                    "details": tc.details,
                }
                for tc in self.test_cases
            ],
            "remediation_summary": self.remediation_summary,
        }


class ClosedLoopRemediationVerifier:
    """Verifies that synthesized defense rules and patches eliminate exploits without breaking benign traffic."""

    def __init__(self):
        pass

    def generate_fuzz_suite(
        self,
        finding_title: str,
        base_exploit_payload: str,
        category: str = "SQL Injection",
    ) -> List[FuzzTestCase]:
        """Synthesizes a differential test suite containing base exploits, adversarial evasions, and benign baselines."""
        tests: List[FuzzTestCase] = []

        # 1. Direct Exploit Replay
        tests.append(
            FuzzTestCase(
                name="Direct Exploit Replay",
                payload=base_exploit_payload,
                is_malicious=True,
                description="The exact payload that successfully triggered the vulnerability.",
            )
        )

        cat_upper = category.upper()

        # 2. Adversarial Evasions
        if "SQL" in cat_upper:
            # SQLi mutations
            tests.extend(
                [
                    FuzzTestCase(
                        name="URL Encoded Evasion",
                        payload=urllib.parse.quote(base_exploit_payload),
                        is_malicious=True,
                        description="Single URL-encoded representation of exploit.",
                    ),
                    FuzzTestCase(
                        name="Double URL Encoded Evasion",
                        payload=urllib.parse.quote(urllib.parse.quote(base_exploit_payload)),
                        is_malicious=True,
                        description="Double URL-encoded representation to bypass single-pass decoders.",
                    ),
                    FuzzTestCase(
                        name="Inline Comment Obfuscation",
                        payload=base_exploit_payload.replace(" ", "/**/"),
                        is_malicious=True,
                        description="Whitespace substituted with SQL inline comments.",
                    ),
                    FuzzTestCase(
                        name="Mixed Case Evasion",
                        payload="".join(
                            c.upper() if i % 2 == 0 else c.lower()
                            for i, c in enumerate(base_exploit_payload)
                        ),
                        is_malicious=True,
                        description="Alternating upper/lower case to defeat case-sensitive filters.",
                    ),
                ]
            )
            # Benign baselines
            tests.extend(
                [
                    FuzzTestCase(
                        name="Benign Alphanumeric Query",
                        payload="JohnDoe123",
                        is_malicious=False,
                        description="Standard alphanumeric user input.",
                    ),
                    FuzzTestCase(
                        name="Benign O'Connor Name",
                        payload="O'Connor",
                        is_malicious=False,
                        description="Legitimate Irish name containing an apostrophe.",
                    ),
                    FuzzTestCase(
                        name="Benign Numeric Search",
                        payload="45092",
                        is_malicious=False,
                        description="Legitimate product or user ID search.",
                    ),
                    FuzzTestCase(
                        name="Benign Sentence with 'or'/'and'",
                        payload="Apples and oranges or bananas",
                        is_malicious=False,
                        description="Legitimate sentence with boolean words.",
                    ),
                ]
            )

        elif "XSS" in cat_upper or "CROSS-SITE" in cat_upper:
            # XSS mutations
            tests.extend(
                [
                    FuzzTestCase(
                        name="Mixed Case Tag Evasion",
                        payload=base_exploit_payload.replace("<script>", "<sCrIpt>").replace("alert", "aLeRt"),
                        is_malicious=True,
                        description="Alternating case in tag and function names.",
                    ),
                    FuzzTestCase(
                        name="Event Handler Injection",
                        payload='<img src=x onerror=alert(1)>',
                        is_malicious=True,
                        description="Non-script tag event handler reflection.",
                    ),
                    FuzzTestCase(
                        name="SVG Vector Evasion",
                        payload='<svg/onload=alert(1)>',
                        is_malicious=True,
                        description="SVG onload vector.",
                    ),
                    FuzzTestCase(
                        name="URL Encoded XSS",
                        payload=urllib.parse.quote(base_exploit_payload),
                        is_malicious=True,
                        description="URL-encoded payload.",
                    ),
                ]
            )
            # Benign baselines
            tests.extend(
                [
                    FuzzTestCase(
                        name="Benign Plain Text",
                        payload="Hello, World!",
                        is_malicious=False,
                        description="Standard greeting.",
                    ),
                    FuzzTestCase(
                        name="Benign Math Expression",
                        payload="3 < 5 and 7 > 2",
                        is_malicious=False,
                        description="Mathematical inequalities using angle brackets.",
                    ),
                    FuzzTestCase(
                        name="Benign Email Address",
                        payload="alice.smith@corporate.example.com",
                        is_malicious=False,
                        description="Standard valid email address.",
                    ),
                ]
            )

        elif "COMMAND" in cat_upper or "RCE" in cat_upper:
            # RCE mutations
            tests.extend(
                [
                    FuzzTestCase(
                        name="Semicolon Separation",
                        payload="; id;",
                        is_malicious=True,
                        description="Semicolon command chaining.",
                    ),
                    FuzzTestCase(
                        name="Pipe Operator Evasion",
                        payload="| whoami",
                        is_malicious=True,
                        description="Standard pipe command operator.",
                    ),
                    FuzzTestCase(
                        name="Backtick Command Substitution",
                        payload="`id`",
                        is_malicious=True,
                        description="POSIX backtick shell command execution.",
                    ),
                    FuzzTestCase(
                        name="Subshell Execution",
                        payload="$(whoami)",
                        is_malicious=True,
                        description="Subshell syntax execution.",
                    ),
                ]
            )
            # Benign baselines
            tests.extend(
                [
                    FuzzTestCase(
                        name="Benign Filename",
                        payload="report_2026_q1.pdf",
                        is_malicious=False,
                        description="Standard document file name.",
                    ),
                    FuzzTestCase(
                        name="Benign Hostname / IP",
                        payload="10.0.0.15",
                        is_malicious=False,
                        description="Ordinary IP address argument.",
                    ),
                    FuzzTestCase(
                        name="Benign Text with Dash",
                        payload="alpha-beta-test",
                        is_malicious=False,
                        description="Hyphenated parameter input.",
                    ),
                ]
            )

        elif "SSRF" in cat_upper:
            # SSRF mutations
            tests.extend(
                [
                    FuzzTestCase(
                        name="Localhost IP Evasion",
                        payload="http://127.0.0.1:8080/admin",
                        is_malicious=True,
                        description="Direct loopback connection.",
                    ),
                    FuzzTestCase(
                        name="AWS Metadata IP Evasion",
                        payload="http://169.254.169.254/latest/meta-data/",
                        is_malicious=True,
                        description="Cloud link-local metadata query.",
                    ),
                    FuzzTestCase(
                        name="Decimal IP Representation",
                        payload="http://2130706433/",  # 127.0.0.1 in decimal
                        is_malicious=True,
                        description="Dword/decimal encoded IP evasion.",
                    ),
                ]
            )
            # Benign baselines
            tests.extend(
                [
                    FuzzTestCase(
                        name="Benign Public Webhook URL",
                        payload="https://api.github.com/webhook",
                        is_malicious=False,
                        description="Standard public HTTPS webhook.",
                    ),
                    FuzzTestCase(
                        name="Benign Image CDN URL",
                        payload="https://images.unsplash.com/photo-101.jpg",
                        is_malicious=False,
                        description="Standard public image asset URL.",
                    ),
                ]
            )

        else:
            # Generic Web Evasions & Baselines
            tests.extend(
                [
                    FuzzTestCase(
                        name="Path Traversal Sequence",
                        payload="../../../../etc/passwd",
                        is_malicious=True,
                        description="Standard dot-dot-slash sequence.",
                    ),
                    FuzzTestCase(
                        name="Sensitive Env File",
                        payload="/.env",
                        is_malicious=True,
                        description="Root environment configuration access.",
                    ),
                    FuzzTestCase(
                        name="Benign Static Asset",
                        payload="/static/css/theme.css",
                        is_malicious=False,
                        description="Ordinary CSS stylesheet asset.",
                    ),
                    FuzzTestCase(
                        name="Benign User Profile Path",
                        payload="/users/profile/view?id=42",
                        is_malicious=False,
                        description="Ordinary user profile endpoint.",
                    ),
                ]
            )

        return tests

    def evaluate_rule_against_test(self, rule_regex: str, test: FuzzTestCase) -> bool:
        """Evaluates whether the given regular expression / rule pattern matches and blocks the test payload."""
        # Clean regex if it's ModSecurity SecRule syntax
        pattern = rule_regex
        if "@rx" in rule_regex:
            for line in rule_regex.splitlines():
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
        elif "content:" in rule_regex:
            # Suricata format extraction
            m_suricata = re.search(r'content:"([^"]+)"', rule_regex)
            if m_suricata:
                pattern = re.escape(m_suricata.group(1))

        # Check payload direct, url-decoded, and lowercase
        decoded = urllib.parse.unquote(test.payload)
        double_decoded = urllib.parse.unquote(decoded)

        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            blocked = bool(
                compiled.search(test.payload)
                or compiled.search(decoded)
                or compiled.search(double_decoded)
            )
        except re.error:
            # Fallback substring matching if regex syntax has specific engine extensions
            cleaned_pat = re.sub(r'[\(\)\?\:\|\\\[\]\^\$\*\+\.\{\}]', '', pattern).lower()
            blocked = bool(
                cleaned_pat
                and (
                    cleaned_pat in test.payload.lower()
                    or cleaned_pat in decoded.lower()
                )
            )

        test.blocked = blocked
        test.details = "Blocked by rule" if blocked else "Allowed through"
        return blocked

    def verify_remediation(
        self,
        finding_title: str,
        category: str,
        base_exploit_payload: str,
        rule_definition: str,
    ) -> VerificationReport:
        """Executes full differential verification suite against a synthesized rule or virtual patch."""
        suite = self.generate_fuzz_suite(
            finding_title=finding_title,
            base_exploit_payload=base_exploit_payload,
            category=category,
        )

        malicious_tests = [t for t in suite if t.is_malicious]
        benign_tests = [t for t in suite if not t.is_malicious]

        # Evaluate each test case
        for test in suite:
            self.evaluate_rule_against_test(rule_definition, test)

        # 1. Exploit Neutralized: Direct exploit replay MUST be blocked
        direct_replay = suite[0]
        exploit_neutralized = direct_replay.blocked

        # 2. Evasion Resilience: % of malicious variations blocked
        malicious_blocked = sum(1 for t in malicious_tests if t.blocked)
        evasion_resilience = malicious_blocked / len(malicious_tests) if malicious_tests else 1.0

        # 3. False Positive Rate: % of benign baselines blocked
        benign_blocked = sum(1 for t in benign_tests if t.blocked)
        benign_passed = len(benign_tests) - benign_blocked
        false_positive_rate = benign_blocked / len(benign_tests) if benign_tests else 0.0

        # Confidence formula:
        # 50% Exploit Neutralization + 30% Evasion Resilience + 20% (1.0 - False Positive Rate)
        base_score = 0.5 * (1.0 if exploit_neutralized else 0.0)
        evasion_score = 0.3 * evasion_resilience
        fp_score = 0.2 * (1.0 - false_positive_rate)
        confidence = round(base_score + evasion_score + fp_score, 3)

        # Verdict assignment
        if exploit_neutralized and evasion_resilience >= 0.75 and false_positive_rate == 0.0:
            verdict = VerificationVerdict.APPROVED_FOR_PRODUCTION
            summary = (
                f"Virtual patch approved with {confidence*100:.1f}% confidence. "
                f"100% exploit replay neutralized, {evasion_resilience*100:.1f}% evasion vectors blocked, "
                f"and 0.0% false positive disruption to benign traffic."
            )
        elif exploit_neutralized and false_positive_rate == 0.0:
            verdict = VerificationVerdict.REQUIRES_TUNING
            summary = (
                f"Exploit is neutralized, but evasion resilience ({evasion_resilience*100:.1f}%) "
                f"suggests rule may be bypassed with advanced encoding mutations."
            )
        else:
            verdict = VerificationVerdict.REJECTED
            summary = (
                f"Rule failed verification: "
                f"Exploit neutralized={exploit_neutralized}, False positive rate={false_positive_rate*100:.1f}%."
            )

        return VerificationReport(
            finding_title=finding_title,
            verdict=verdict,
            confidence_score=confidence,
            exploit_neutralized=exploit_neutralized,
            evasion_resilience_rate=round(evasion_resilience, 3),
            false_positive_rate=round(false_positive_rate, 3),
            total_tests_run=len(suite),
            malicious_tests_blocked=malicious_blocked,
            benign_tests_passed=benign_passed,
            test_cases=suite,
            remediation_summary=summary,
        )
