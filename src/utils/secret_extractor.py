"""
Semantic De-obfuscator & Entropy Secret Extractor
=================================================
Inspired by Claude Opus Deep Cognitive Signal Extraction.

Analyzes raw tool responses (HTML, JS, headers, JSON, source code) to discover:
1. High-entropy cryptographic secrets, API tokens, and private keys
2. AWS access keys, JWT tokens, Bearer tokens, DB connection strings
3. Internal network addresses (RFC 1918) and internal domain names
4. Developer comments and latent API endpoints that standard scanners miss
"""

from __future__ import annotations

import re
import math
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string (in bits per symbol)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class ExtractedIntelligence:
    """Structured latent intelligence extracted from raw tool outputs."""
    api_keys: List[str] = field(default_factory=list)
    jwt_tokens: List[str] = field(default_factory=list)
    credentials: List[Dict[str, str]] = field(default_factory=list)  # {"user": ..., "password": ...}
    internal_ips: List[str] = field(default_factory=list)
    internal_hostnames: List[str] = field(default_factory=list)
    developer_comments: List[str] = field(default_factory=list)
    hidden_endpoints: List[str] = field(default_factory=list)
    high_entropy_strings: List[str] = field(default_factory=list)

    @property
    def has_secrets(self) -> bool:
        return bool(
            self.api_keys or self.jwt_tokens or self.credentials
            or self.internal_ips or self.internal_hostnames
        )

    def format_summary(self) -> str:
        """Format extracted intelligence into an actionable prompt summary."""
        lines = []
        if self.api_keys:
            lines.append(f"• **API Keys ({len(self.api_keys)})**: " + ", ".join(f"`{k[:12]}...`" for k in self.api_keys[:3]))
        if self.jwt_tokens:
            lines.append(f"• **JWT Tokens ({len(self.jwt_tokens)})**: " + ", ".join(f"`{t[:20]}...`" for t in self.jwt_tokens[:2]))
        if self.credentials:
            creds_str = ", ".join(f"`{c.get('user', 'unknown')}:{c.get('password', '***')}`" for c in self.credentials[:3])
            lines.append(f"• **Thu Thập Thông Tin Xác Thực ({len(self.credentials)})**: {creds_str}")
        if self.internal_ips:
            lines.append(f"• **IP Mạng Nội Bộ (RFC 1918)**: " + ", ".join(f"`{ip}`" for ip in self.internal_ips[:4]))
        if self.internal_hostnames:
            lines.append(f"• **Domain Nội Bộ**: " + ", ".join(f"`{h}`" for h in self.internal_hostnames[:3]))
        if self.hidden_endpoints:
            lines.append(f"• **Endpoints Ẩn Phát Hiện Trong Mã Nguồn**: " + ", ".join(f"`{ep}`" for ep in self.hidden_endpoints[:4]))
        if self.developer_comments:
            lines.append(f"• **Ghi Chú Lập Trình Viên (Developer Comments)**: `{self.developer_comments[0][:80]}...`")
        return "\n".join(lines)


class SecretExtractor:
    """Extracts hidden secrets, internal topology, and developer comments."""

    # Pre-compiled high-precision regular expressions
    RE_AWS_KEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
    RE_JWT = re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")
    RE_BEARER = re.compile(r"(?:Bearer|token|auth_token)\s*[:=]\s*['\"]?([A-Za-z0-9_.\-~+/]{20,})['\"]?", re.IGNORECASE)
    RE_DB_CONN = re.compile(r"\b(?:mysql|postgres|postgresql|mongodb|redis)://([A-Za-z0-9_]+):([^@\s]+)@([^\s:/]+)", re.IGNORECASE)
    RE_INTERNAL_IPV4 = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    )
    RE_INTERNAL_HOST = re.compile(r"\b([a-zA-Z0-9.-]+\.(?:internal|corp|local|lan|priv|intra|private))\b", re.IGNORECASE)
    RE_DEV_COMMENTS = re.compile(r"<!--\s*(.*?(?:TODO|admin|fixme|endpoint|debug|auth|secret|cred).*?)\s*-->", re.IGNORECASE | re.DOTALL)
    RE_HIDDEN_ENDPOINTS = re.compile(r"['\"](/(?:api/v[0-9]|v[0-9]|admin/api|private|internal|graphql|swagger|oauth)[a-zA-Z0-9_\-/]*)['\"]")
    RE_GENERIC_CRED = re.compile(
        r"(?:password|passwd|user_password|db_pass|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*()_+=\-]{6,40})['\"]?",
        re.IGNORECASE,
    )

    @classmethod
    def extract(cls, text: str) -> ExtractedIntelligence:
        """Scan raw text and extract structured latent intelligence."""
        intel = ExtractedIntelligence()
        if not text:
            return intel

        # 1. AWS Access Keys
        for match in cls.RE_AWS_KEY.findall(text):
            if match not in intel.api_keys:
                intel.api_keys.append(match)

        # 2. JWT Tokens
        for match in cls.RE_JWT.findall(text):
            if match not in intel.jwt_tokens:
                intel.jwt_tokens.append(match)

        # 3. Bearer Tokens
        for match in cls.RE_BEARER.findall(text):
            if match not in intel.api_keys and match not in intel.jwt_tokens:
                intel.api_keys.append(match)

        # 4. Database Connection Strings (credentials & host)
        for match in cls.RE_DB_CONN.findall(text):
            user, pwd, host = match
            intel.credentials.append({"user": user, "password": pwd, "target": host})

        # 5. Generic Passwords
        for match in cls.RE_GENERIC_CRED.findall(text):
            pwd = match.strip()
            if not any(c.get("password") == pwd for c in intel.credentials):
                intel.credentials.append({"user": "auto_extracted", "password": pwd})

        # 6. Internal IPv4 Addresses (filter out common broadcast/mask)
        for match in cls.RE_INTERNAL_IPV4.findall(text):
            if match not in ("127.0.0.1", "0.0.0.0", "255.255.255.0") and match not in intel.internal_ips:
                intel.internal_ips.append(match)

        # 7. Internal Hostnames
        for match in cls.RE_INTERNAL_HOST.findall(text):
            m_lower = match.lower()
            if m_lower not in intel.internal_hostnames:
                intel.internal_hostnames.append(m_lower)

        # 8. Developer Comments
        for match in cls.RE_DEV_COMMENTS.findall(text):
            clean_c = " ".join(match.split())
            if clean_c and clean_c not in intel.developer_comments:
                intel.developer_comments.append(clean_c)

        # 9. Hidden API Endpoints
        for match in cls.RE_HIDDEN_ENDPOINTS.findall(text):
            if match not in intel.hidden_endpoints and len(match) < 100:
                intel.hidden_endpoints.append(match)

        # 10. High-Entropy Tokens (tokens of length >= 20 with Shannon entropy > 4.2)
        words = re.findall(r"\b[A-Za-z0-9+/=_-]{24,64}\b", text)
        for word in words:
            if word not in intel.api_keys and word not in intel.jwt_tokens:
                ent = calculate_shannon_entropy(word)
                if ent >= 4.2:
                    intel.high_entropy_strings.append(word)

        return intel
