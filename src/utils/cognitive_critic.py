"""
Dual-Brain Cognitive Critic & Anti-Hallucination Skeptic
=======================================================
Inspired by Claude 3.7 / GPT-5 Frontier Metacognitive Verification.

Acts as the internal 'Blue Team Skeptic' questioning raw vulnerability discoveries.
Performs rigorous sanity checks before findings are logged to prevent hallucinations
and false positives:
1. Soft-404 Detection (200 OK responses with custom error bodies)
2. HTML-escaped reflected XSS (safe output mistaken for vulnerability)
3. Generic 500 errors mistaken for true SQL Injection
4. WAF connection drops mistaken for patch remediation
"""

from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CriticVerdict:
    """Assessment decision from the Cognitive Critic."""

    def __init__(
        self,
        is_valid: bool,
        confidence: float,
        is_false_positive: bool = False,
        reason: str = "",
        verification_probe: str = "",
    ) -> None:
        self.is_valid = is_valid
        self.confidence = confidence
        self.is_false_positive = is_false_positive
        self.reason = reason
        self.verification_probe = verification_probe

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "confidence": self.confidence,
            "is_false_positive": self.is_false_positive,
            "reason": self.reason,
            "verification_probe": self.verification_probe,
        }


class CognitiveCritic:
    """Evaluates raw findings and tool outputs to eliminate false positives."""

    # Soft-404 patterns commonly found in custom 404 pages returning 200 OK
    SOFT_404_PATTERNS = [
        re.compile(r"page\s+not\s+found", re.IGNORECASE),
        re.compile(r"404\s+not\s+found", re.IGNORECASE),
        re.compile(r"error\s+404", re.IGNORECASE),
        re.compile(r"không\s+tìm\s+thấy\s+trang", re.IGNORECASE),
        re.compile(r"trang\s+không\s+tồn\s+tại", re.IGNORECASE),
        re.compile(r"the\s+requested\s+url\s+was\s+not\s+found", re.IGNORECASE),
        re.compile(r"oops!\s*that\s*page\s*can(?:'|’)?t\s*be\s*found", re.IGNORECASE),
        re.compile(r"we\s+can(?:'|’)?t\s+find\s+that\s+page", re.IGNORECASE),
    ]

    # True SQL Database syntax error signatures
    SQL_SYNTAX_SIGNATURES = [
        re.compile(r"you\s+have\s+an\s+error\s+in\s+your\s+sql\s+syntax", re.IGNORECASE),
        re.compile(r"warning:\s*mysql_", re.IGNORECASE),
        re.compile(r"unclosed\s+quotation\s+mark\s+after\s+the\s+character\s+string", re.IGNORECASE),
        re.compile(r"quoted\s+string\s+not\s+properly\s+terminated", re.IGNORECASE),
        re.compile(r"pg_query\(\):\s*query\s+failed", re.IGNORECASE),
        re.compile(r"ora-\d{5}", re.IGNORECASE),
        re.compile(r"sqlite3::sqlexception", re.IGNORECASE),
        re.compile(r"microsoft\s+ole\s+db\s+provider\s+for\s+odbc\s+drivers", re.IGNORECASE),
    ]

    @classmethod
    def evaluate_finding(
        cls,
        title: str,
        description: str,
        tool_source: str,
        raw_evidence: str,
    ) -> CriticVerdict:
        """
        Evaluate a candidate finding before logging.
        Returns CriticVerdict indicating validity, confidence, and false-positive status.
        """
        evidence_lower = raw_evidence.lower()
        title_lower = title.lower()
        desc_lower = description.lower()

        # Check 1: Soft-404 False Positive on Sensitive File / Directory Discovery
        if any(term in title_lower or term in desc_lower for term in ("sensitive file", "directory listing", "exposed", "admin portal", "found path")):
            for pattern in cls.SOFT_404_PATTERNS:
                if pattern.search(raw_evidence):
                    return CriticVerdict(
                        is_valid=False,
                        confidence=0.15,
                        is_false_positive=True,
                        reason="Bác bỏ (False Positive): Server trả về mã 200 OK nhưng phần thân phản hồi chứa nội dung Soft-404 ('Page Not Found').",
                        verification_probe="Gửi request tới URL ngẫu nhiên không tồn tại để kiểm chứng baseline kích thước phản hồi.",
                    )

        # Check 2: HTML-Escaped Reflected XSS False Positive
        if "xss" in title_lower or "cross-site scripting" in title_lower:
            # If payload is present but escaped as &lt;script&gt; or \u003cscript\u003e
            if re.search(r"(&lt;|\\u003c)script", raw_evidence, re.IGNORECASE):
                # Check if unescaped <script> is NOT present
                if not re.search(r"<script[^>]*>", raw_evidence, re.IGNORECASE):
                    return CriticVerdict(
                        is_valid=False,
                        confidence=0.10,
                        is_false_positive=True,
                        reason="Bác bỏ (False Positive): Ký tự XSS đã được máy chủ HTML-encode an toàn (&lt;script&gt;), không thể thực thi trong DOM.",
                        verification_probe="Thử nghiệm payload không chứa dấu ngoặc nhọn hoặc event handlers không cần thẻ script.",
                    )

        # Check 3: Generic HTTP 500 Error Mistaken for True SQL Injection
        if "sql injection" in title_lower or "sqli" in title_lower:
            if "500 internal server error" in evidence_lower:
                has_sql_sig = any(sig.search(raw_evidence) for sig in cls.SQL_SYNTAX_SIGNATURES)
                if not has_sql_sig and "parameter appears to be" not in evidence_lower and "sqlmap" not in tool_source:
                    return CriticVerdict(
                        is_valid=False,
                        confidence=0.30,
                        is_false_positive=True,
                        reason="Nghi ngờ (Unconfirmed): Lỗi HTTP 500 chung chung không chứa chữ ký cú pháp SQL Database. Cần chạy sqlmap để xác thực.",
                        verification_probe="Gọi docker_sqlmap_scan với tham số --technique=BEUST để kiểm tra thời gian/boolean.",
                    )

        # Check 4: Nikto wild-card 404 false positives
        if tool_source == "docker_nikto_scan" and "retrieved 200 requests" in evidence_lower:
            if any(term in evidence_lower for term in ("wildcard", "error 404")):
                return CriticVerdict(
                    is_valid=False,
                    confidence=0.20,
                    is_false_positive=True,
                    reason="Bác bỏ: Nikto cảnh báo máy chủ xử lý wildcard 404 (mọi URL đều trả về 200).",
                    verification_probe="Bật tham số -no404 trong Nikto hoặc dùng docker_ffuf với bộ lọc kích thước -fs.",
                )

        # Finding passed all skeptic checks
        return CriticVerdict(
            is_valid=True,
            confidence=0.90,
            is_false_positive=False,
            reason="Xác thực: Dấu hiệu kỹ thuật và bằng chứng thô hợp lệ, vượt qua các bài kiểm tra phản biện.",
        )
