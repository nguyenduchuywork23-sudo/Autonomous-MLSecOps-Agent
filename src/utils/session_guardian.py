"""Autonomous Session State & Resilient Re-Authentication Guardian.

Monitors active penetration testing sessions, detects JWT token expiration or
session invalidation, automatically rotates and refreshes authentication state
using harvested credentials, and injects active authentication headers into tool calls.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class SessionState:
    """Current authentication and session state of the agent."""

    auth_type: str = "NONE"  # BEARER_JWT, COOKIE_SESSION, API_KEY, NONE
    active_token: str = ""
    active_cookies: dict[str, str] = field(default_factory=dict)
    active_user: str = ""
    is_authenticated: bool = False
    last_refresh_time: float = field(default_factory=time.time)
    refresh_count: int = 0


class SessionGuardian:
    """Autonomous session lifecycle manager for offensive & audit operations."""

    EXPIRATION_PATTERNS = [
        "token expired",
        "jwt expired",
        "signature has expired",
        "session timed out",
        "session expired",
        "unauthorized",
        "authentication required",
        "invalid token",
        "please log in",
    ]

    def __init__(self) -> None:
        self.state = SessionState()

    def set_active_session(
        self,
        token: str = "",
        cookies: Optional[dict[str, str]] = None,
        user: str = "",
        auth_type: str = "BEARER_JWT",
    ) -> None:
        """Register a confirmed working authentication session."""
        self.state.active_token = token
        self.state.active_cookies = cookies or {}
        self.state.active_user = user
        self.state.auth_type = auth_type
        self.state.is_authenticated = bool(token or cookies)
        self.state.last_refresh_time = time.time()
        logger.info("SessionGuardian: Active session registered for user '%s' (%s)", user, auth_type)

    def is_jwt_expired(self, token: str) -> bool:
        """Decode JWT payload without cryptographic verification to check expiration timestamp."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False
            payload_b64 = parts[1]
            # Handle base64 padding
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            data = json.loads(payload_bytes.decode("utf-8"))
            exp = data.get("exp")
            if exp and isinstance(exp, (int, float)):
                return time.time() >= exp
        except Exception:
            pass
        return False

    def detect_session_death(
        self,
        status_code: int,
        response_text: str,
        headers: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Detect whether the current tool output indicates session invalidation."""
        if not self.state.is_authenticated:
            return False

        # Status 401 is an explicit session death signal
        if status_code == 401:
            return True

        resp_lower = (response_text or "").lower()
        if status_code in (403, 400) and any(pat in resp_lower for pat in self.EXPIRATION_PATTERNS):
            return True

        # Check for login redirects
        if headers:
            loc = str(headers.get("Location") or headers.get("location") or "")
            if any(login_p in loc.lower() for login_p in ("/login", "/signin", "/auth")):
                return True

        # Check if JWT expired by clock
        if self.state.active_token and self.is_jwt_expired(self.state.active_token):
            return True

        return False

    def recover_session(
        self,
        available_tokens: list[str],
        available_credentials: list[dict[str, Any]],
    ) -> tuple[bool, str]:
        """Attempt to restore authentication using alternate tokens or credentials."""
        # 1. Try unused valid JWT tokens
        for token in available_tokens:
            if token != self.state.active_token and not self.is_jwt_expired(token):
                self.state.active_token = token
                self.state.auth_type = "BEARER_JWT"
                self.state.is_authenticated = True
                self.state.refresh_count += 1
                self.state.last_refresh_time = time.time()
                return True, f"Tự phục hồi phiên thành công với JWT token dự phòng ({token[:15]}...)"

        # 2. Try harvested credentials
        if available_credentials:
            cred = available_credentials[0]
            self.state.active_user = cred.get("user", "admin")
            self.state.is_authenticated = True
            self.state.refresh_count += 1
            self.state.last_refresh_time = time.time()
            return True, f"Kích hoạt tái xác thực tự động với tài khoản thu hoạch `{self.state.active_user}`"

        self.state.is_authenticated = False
        return False, "Không còn token hoặc tài khoản khả dụng để tái xác thực phiên"

    def inject_session_arguments(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Automatically inject Authorization header or session cookies into tool call arguments."""
        if not self.state.is_authenticated:
            return arguments

        args_copy = dict(arguments)

        # For curl or HTTP scanning tools
        if self.state.active_token:
            auth_header = f"Authorization: Bearer {self.state.active_token}"
            if "headers" in args_copy:
                if isinstance(args_copy["headers"], dict):
                    args_copy["headers"]["Authorization"] = f"Bearer {self.state.active_token}"
                elif isinstance(args_copy["headers"], list):
                    args_copy["headers"].append(auth_header)
            elif tool_name in ("docker_curl", "docker_nuclei_scan", "docker_ffuf_scan", "docker_sqlmap_scan"):
                args_copy["headers"] = {"Authorization": f"Bearer {self.state.active_token}"}

        # For tools supporting cookies
        if self.state.active_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.state.active_cookies.items())
            if "cookie" not in args_copy:
                args_copy["cookie"] = cookie_str

        return args_copy

    def format_status_block(self) -> str:
        """Format current session health for the agent."""
        if not self.state.is_authenticated:
            return "🔐 [TRẠNG THÁI PHIÊN: CHƯA XÁC THỰC (ANONYMOUS)]"

        uptime_min = int((time.time() - self.state.last_refresh_time) / 60)
        user_str = f" | User: `{self.state.active_user}`" if self.state.active_user else ""
        return (
            f"🔐 [TRẠNG THÁI PHIÊN XÁC THỰC: ĐANG HOẠT ĐỘNG ({self.state.auth_type})]\n"
            f"• Thời gian phiên: {uptime_min} phút | Số lần tự phục hồi: {self.state.refresh_count}{user_str}\n"
            f"• Tự động đính kèm Authorization Header/Cookie vào các công cụ tiếp theo."
        )
