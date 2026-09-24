"""SPA & Client-Side Dynamic State Transition Crawler.

Dissects Single Page Application (React, Vue, Next.js, Angular) bundles to
recover unlinked client-side routes, inspect client-side state machines,
audit insecure token storage (localStorage/sessionStorage), and extract
embedded API credentials.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SPARoute:
    """A client-side route discovered inside JavaScript bundles."""

    path: str
    auth_required: bool = False
    source_component: str = ""
    is_admin_route: bool = False


@dataclass
class SPACrawlResult:
    """Analysis result of a Single Page Application bundle."""

    discovered_routes: list[SPARoute] = field(default_factory=list)
    insecure_storage_findings: list[str] = field(default_factory=list)
    hardcoded_env_configs: dict[str, str] = field(default_factory=dict)
    api_endpoints: list[str] = field(default_factory=list)

    def format_block(self) -> str:
        """Format SPA analysis into a tactical directive for the orchestrator."""
        routes_summary = ", ".join(f"`{r.path}`" for r in self.discovered_routes[:6])
        admin_routes = [r.path for r in self.discovered_routes if r.is_admin_route]
        admin_str = f"\n• Cảnh báo đường dẫn Quản trị (Admin Routes): {', '.join(f'`{a}`' for a in admin_routes)}" if admin_routes else ""

        storage_str = ""
        if self.insecure_storage_findings:
            storage_str = "\n• Phát hiện lưu trữ token thiếu an toàn: " + "; ".join(self.insecure_storage_findings)

        env_str = ""
        if self.hardcoded_env_configs:
            env_str = f"\n• Biến môi trường rò rỉ ({len(self.hardcoded_env_configs)}): " + ", ".join(f"`{k}`" for k in list(self.hardcoded_env_configs.keys())[:4])

        return (
            f"🌐 [BÓC TÁCH BUNDLE SPA & ROUTING PHÍA CLIENT ({len(self.discovered_routes)} ĐƯỜNG DẪN ẨN)]\n"
            f"• Tuyến đường khám phá: {routes_summary}{admin_str}{storage_str}{env_str}\n"
            f"➔ HÃY ĐƯA CÁC ĐƯỜNG DẪN TRÊN VÀO DANH SÁCH RÀ QUÉT CỦA `docker_httpx` VÀ `docker_nuclei_scan`."
        )


class SPAStateCrawler:
    """Analyzes modern frontend JavaScript bundles for security intelligence."""

    # Patterns for React Router, Vue Router, Angular, Next.js page definitions
    RE_ROUTER_PATH = re.compile(
        r"""(?:path|route|url)\s*[:=]\s*["'](/[a-zA-Z0-9_\-\./{}:]+)["']""",
        re.IGNORECASE,
    )
    RE_JSX_ROUTE = re.compile(
        r"""<Route\s+[^>]*path=["'](/[a-zA-Z0-9_\-\./{}:]+)["']""",
        re.IGNORECASE,
    )

    # Insecure storage patterns
    RE_STORAGE_ACCESS = re.compile(
        r"""(?:localStorage|sessionStorage)\.setItem\s*\(\s*["']([^"']+)["']""",
        re.IGNORECASE,
    )

    # API endpoints and environment config patterns
    RE_FETCH_API = re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["'](/[a-zA-Z0-9_\-\./?=&]+)["']""",
        re.IGNORECASE,
    )
    RE_ENV_VARS = re.compile(
        r"""(?:REACT_APP_|NEXT_PUBLIC_|VITE_)([A-Z0-9_]+)\s*[:=]\s*["']([^"']+)["']""",
        re.IGNORECASE,
    )
    RE_FIREBASE_CONFIG = re.compile(
        r"""apiKey\s*:\s*["'](AIza[0-9A-Za-z-_]{30,45})["']""",
        re.IGNORECASE,
    )

    def crawl_bundle(self, bundle_text: str, base_url: str = "") -> SPACrawlResult:
        """Scan JavaScript bundle text to extract routes, APIs, and storage leaks."""
        routes: list[SPARoute] = []
        seen_paths: set[str] = set()

        # 1. Extract Router paths
        raw_paths = self.RE_ROUTER_PATH.findall(bundle_text) + self.RE_JSX_ROUTE.findall(bundle_text)
        for p in raw_paths:
            clean_path = p.split("?")[0].strip()
            # Filter out non-web paths or asset file extensions
            if clean_path in seen_paths or clean_path in ("/", "") or any(clean_path.endswith(ext) for ext in (".png", ".svg", ".jpg", ".css", ".woff")):
                continue
            seen_paths.add(clean_path)

            is_admin = any(k in clean_path.lower() for k in ("admin", "superadmin", "manage", "billing", "audit", "console", "dashboard"))
            auth_req = is_admin or any(k in clean_path.lower() for k in ("profile", "account", "settings", "orders"))

            routes.append(
                SPARoute(
                    path=clean_path,
                    auth_required=auth_req,
                    is_admin_route=is_admin,
                )
            )

        # 2. Extract Insecure Storage calls
        storage_findings: list[str] = []
        storage_keys = self.RE_STORAGE_ACCESS.findall(bundle_text)
        for key in storage_keys:
            if any(token_k in key.lower() for token_k in ("token", "jwt", "auth", "access", "secret", "user", "cred")):
                storage_findings.append(f"Client lưu trữ khóa nhạy cảm `{key}` trong localStorage/sessionStorage (Dễ bị XSS đánh cắp)")

        # 3. Extract Embedded API calls
        api_endpoints: list[str] = []
        seen_apis = set()
        for api_p in self.RE_FETCH_API.findall(bundle_text):
            if api_p not in seen_apis:
                seen_apis.add(api_p)
                api_endpoints.append(api_p)

        # 4. Extract Leaked Environment Variables & Firebase configs
        env_configs: dict[str, str] = {}
        for var_name, var_val in self.RE_ENV_VARS.findall(bundle_text):
            env_configs[var_name] = var_val

        firebase_match = self.RE_FIREBASE_CONFIG.search(bundle_text)
        if firebase_match:
            env_configs["FIREBASE_API_KEY"] = firebase_match.group(1)

        return SPACrawlResult(
            discovered_routes=routes,
            insecure_storage_findings=list(dict.fromkeys(storage_findings)),
            hardcoded_env_configs=env_configs,
            api_endpoints=api_endpoints,
        )
