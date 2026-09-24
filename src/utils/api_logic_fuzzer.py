"""Grammar-Based Business Logic & API Schema Fuzzer.

Parses OpenAPI/Swagger, GraphQL schemas, and REST endpoints to synthesize deep
business logic test cases:
- BOLA / IDOR (Broken Object Level Authorization)
- Mass Assignment & Parameter Pollution
- Type Confusion & Boundary Value Anomalies
- HTTP Method Tampering & Verb Tunneling
- GraphQL Introspection & Deep Nesting Queries
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class APISchemaEndpoint:
    """Represents a discovered API route/endpoint."""

    path: str
    method: str = "GET"
    parameters: list[dict[str, Any]] = field(default_factory=list)
    request_body_schema: dict[str, Any] = field(default_factory=dict)
    auth_required: bool = False
    summary: str = ""


@dataclass
class APILogicFuzzTarget:
    """A concrete business logic or schema mutation test vector."""

    fuzz_type: str  # BOLA_IDOR, MASS_ASSIGNMENT, TYPE_CONFUSION, VERB_TAMPERING, GRAPHQL_INTROSPECTION
    method: str
    url_path: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    json_body: Optional[dict[str, Any]] = None
    severity_potential: str = "HIGH"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fuzz_type": self.fuzz_type,
            "method": self.method,
            "url_path": self.url_path,
            "headers": self.headers,
            "params": self.params,
            "json_body": self.json_body,
            "severity_potential": self.severity_potential,
            "description": self.description,
        }


class APILogicFuzzer:
    """Grammar-based fuzzer for API schemas and business logic vulnerabilities."""

    # Common privileged / administrative fields for Mass Assignment attacks
    MASS_ASSIGNMENT_FIELDS = {
        "is_admin": True,
        "isAdmin": True,
        "role": "admin",
        "roles": ["admin", "superuser"],
        "is_superuser": True,
        "verified": True,
        "is_verified": True,
        "balance": 999999,
        "credit": 1000000,
        "status": "active",
        "permissions": ["*"],
        "tier": "enterprise",
    }

    # BOLA / IDOR identification patterns
    RE_ID_PARAM = re.compile(
        r"\{?(?:user_?id|account_?id|order_?id|org_?id|invoice_?id|id|uuid|profile_?id)\}?",
        re.IGNORECASE,
    )
    RE_API_ROUTE = re.compile(
        r"""(?:"|')(/(?:api|v[1-9]|rest|graphql|internal)(?:/[a-zA-Z0-9_\-\./{}:]*)?)(?:"|')""",
        re.IGNORECASE,
    )

    def parse_openapi_spec(self, spec_data: dict[str, Any] | str) -> list[APISchemaEndpoint]:
        """Parse Swagger 2.0 or OpenAPI 3.0 dictionary into APISchemaEndpoint list."""
        if isinstance(spec_data, str):
            try:
                spec_data = json.loads(spec_data)
            except Exception:
                return []

        endpoints: list[APISchemaEndpoint] = []
        paths = spec_data.get("paths", {})
        if not isinstance(paths, dict):
            return endpoints

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method_raw, op_item in path_item.items():
                method = method_raw.upper()
                if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                    continue
                if not isinstance(op_item, dict):
                    continue

                params = op_item.get("parameters", [])
                summary = op_item.get("summary", "") or op_item.get("description", "")
                security = op_item.get("security", []) or spec_data.get("security", [])
                auth_req = bool(security)

                req_body = {}
                # OpenAPI 3.0 requestBody
                if "requestBody" in op_item:
                    content = op_item["requestBody"].get("content", {})
                    if "application/json" in content:
                        req_body = content["application/json"].get("schema", {})

                endpoints.append(
                    APISchemaEndpoint(
                        path=path,
                        method=method,
                        parameters=params,
                        request_body_schema=req_body,
                        auth_required=auth_req,
                        summary=summary,
                    )
                )

        return endpoints

    def infer_endpoints_from_text(self, text: str) -> list[APISchemaEndpoint]:
        """Scan raw HTML/JS or API docs to extract candidate API routes."""
        matches = self.RE_API_ROUTE.findall(text)
        endpoints: list[APISchemaEndpoint] = []
        seen = set()

        for route in matches:
            clean_route = route.split("?")[0].strip()
            if clean_route in seen or len(clean_route) < 4:
                continue
            seen.add(clean_route)

            # Heuristics for method & params
            has_id = bool(self.RE_ID_PARAM.search(clean_route))
            method = "GET"
            if any(verb in clean_route.lower() for verb in ("create", "add", "register", "submit")):
                method = "POST"
            elif any(verb in clean_route.lower() for verb in ("update", "edit")):
                method = "PUT"
            elif any(verb in clean_route.lower() for verb in ("delete", "remove")):
                method = "DELETE"

            endpoints.append(
                APISchemaEndpoint(
                    path=clean_route,
                    method=method,
                    summary=f"Discovered via regex pattern analysis ({'Parameterized' if has_id else 'Static'})",
                )
            )

        return endpoints

    def generate_fuzz_plan(
        self,
        endpoints: list[APISchemaEndpoint],
        base_url: str = "",
    ) -> list[APILogicFuzzTarget]:
        """Generate high-yield business logic and schema fuzz targets."""
        targets: list[APILogicFuzzTarget] = []

        for ep in endpoints:
            # 1. BOLA / IDOR Testing
            if self.RE_ID_PARAM.search(ep.path) or any(self.RE_ID_PARAM.search(p.get("name", "")) for p in ep.parameters):
                targets.extend(self._generate_bola_targets(ep))

            # 2. Mass Assignment Testing (POST, PUT, PATCH)
            if ep.method in ("POST", "PUT", "PATCH") or ep.request_body_schema:
                targets.extend(self._generate_mass_assignment_targets(ep))

            # 3. Type Confusion & Boundary Testing
            targets.extend(self._generate_type_confusion_targets(ep))

            # 4. HTTP Method Tampering & Verb Tunneling
            targets.extend(self._generate_verb_tampering_targets(ep))

            # 5. GraphQL Introspection if endpoint is graphql
            if "graphql" in ep.path.lower():
                targets.extend(self._generate_graphql_targets(ep))

        return targets

    def _generate_bola_targets(self, ep: APISchemaEndpoint) -> list[APILogicFuzzTarget]:
        """Generate Broken Object Level Authorization (IDOR) probes."""
        results: list[APILogicFuzzTarget] = []
        path = ep.path

        # Substitute ID placeholders with critical test values
        substitutions = [
            ("1", "Admin/System Account Probe (ID: 1)"),
            ("0", "Root/Default User Probe (ID: 0)"),
            ("-1", "Negative Index Bypass Probe (ID: -1)"),
            ("1002", "Horizontal Neighbor ID Tamper (ID: 1002)"),
            ("00000000-0000-0000-0000-000000000000", "Nil UUID Probe"),
            ("admin", "String Identifier Probe ('admin')"),
        ]

        for val, desc in substitutions:
            tampered_path = self.RE_ID_PARAM.sub(val, path)
            results.append(
                APILogicFuzzTarget(
                    fuzz_type="BOLA_IDOR",
                    method=ep.method,
                    url_path=tampered_path,
                    severity_potential="CRITICAL",
                    description=f"BOLA/IDOR: Thử truy cập tài nguyên của đối tượng khác qua {desc}",
                )
            )

        return results

    def _generate_mass_assignment_targets(self, ep: APISchemaEndpoint) -> list[APILogicFuzzTarget]:
        """Generate Mass Assignment & Privilege Escalation payload probes."""
        results: list[APILogicFuzzTarget] = []
        clean_path = self.RE_ID_PARAM.sub("1", ep.path)

        # Base body plus elevated properties
        injected_body = dict(self.MASS_ASSIGNMENT_FIELDS)
        injected_body["username"] = "testuser"
        injected_body["email"] = "testuser@sec-audit.local"

        results.append(
            APILogicFuzzTarget(
                fuzz_type="MASS_ASSIGNMENT",
                method=ep.method if ep.method in ("POST", "PUT", "PATCH") else "POST",
                url_path=clean_path,
                headers={"Content-Type": "application/json"},
                json_body=injected_body,
                severity_potential="HIGH",
                description="Mass Assignment: Bơm các trường đặc quyền (role: admin, isAdmin: true, balance: 999999)",
            )
        )

        return results

    def _generate_type_confusion_targets(self, ep: APISchemaEndpoint) -> list[APILogicFuzzTarget]:
        """Generate Type Confusion & Extreme Boundary inputs."""
        results: list[APILogicFuzzTarget] = []
        clean_path = self.RE_ID_PARAM.sub("2147483647", ep.path)

        # 32-bit integer overflow probe
        results.append(
            APILogicFuzzTarget(
                fuzz_type="TYPE_CONFUSION",
                method=ep.method,
                url_path=clean_path,
                severity_potential="MEDIUM",
                description="Type Confusion: Tràn số nguyên 32-bit (INT_MAX: 2147483647)",
            )
        )

        # Array injection for parameter pollution
        polluted_path = self.RE_ID_PARAM.sub("1,2", ep.path)
        results.append(
            APILogicFuzzTarget(
                fuzz_type="TYPE_CONFUSION",
                method=ep.method,
                url_path=polluted_path,
                severity_potential="MEDIUM",
                description="Parameter Pollution: Tiêm mảng dữ liệu (1,2) vào tham số đơn",
            )
        )

        return results

    def _generate_verb_tampering_targets(self, ep: APISchemaEndpoint) -> list[APILogicFuzzTarget]:
        """Generate HTTP Verb Tampering & Method Override headers."""
        results: list[APILogicFuzzTarget] = []
        clean_path = self.RE_ID_PARAM.sub("1", ep.path)

        # X-HTTP-Method-Override header bypass
        results.append(
            APILogicFuzzTarget(
                fuzz_type="VERB_TAMPERING",
                method="POST",
                url_path=clean_path,
                headers={"X-HTTP-Method-Override": "PUT"},
                severity_potential="MEDIUM",
                description="Verb Tunneling: Gửi POST kèm header X-HTTP-Method-Override: PUT để lách kiểm soát ACL",
            )
        )

        # X-Original-URL path rewrite
        results.append(
            APILogicFuzzTarget(
                fuzz_type="VERB_TAMPERING",
                method="GET",
                url_path=clean_path,
                headers={"X-Original-URL": "/admin"},
                severity_potential="HIGH",
                description="URL Rewrite Tunneling: Header X-Original-URL: /admin để vượt qua reverse proxy reverse-proxy",
            )
        )

        return results

    def _generate_graphql_targets(self, ep: APISchemaEndpoint) -> list[APILogicFuzzTarget]:
        """Generate GraphQL introspection and query complexity checks."""
        introspection_payload = {
            "query": (
                "query IntrospectionQuery { "
                "__schema { types { name fields { name type { name } } } } }"
            )
        }

        deep_nesting_payload = {
            "query": (
                "query NestedDoS { "
                "user { friends { friends { friends { friends { id name } } } } } }"
            )
        }

        return [
            APILogicFuzzTarget(
                fuzz_type="GRAPHQL_INTROSPECTION",
                method="POST",
                url_path=ep.path,
                headers={"Content-Type": "application/json"},
                json_body=introspection_payload,
                severity_potential="HIGH",
                description="GraphQL Introspection: Thu thập toàn bộ schema dữ liệu, types và mutations bí mật",
            ),
            APILogicFuzzTarget(
                fuzz_type="GRAPHQL_INTROSPECTION",
                method="POST",
                url_path=ep.path,
                headers={"Content-Type": "application/json"},
                json_body=deep_nesting_payload,
                severity_potential="MEDIUM",
                description="GraphQL Complexity: Kiểm tra giới hạn độ sâu truy vấn (Query Depth Limiting DoS)",
            ),
        ]

    def format_fuzz_directive(
        self,
        targets: list[APILogicFuzzTarget],
        max_count: int = 5,
    ) -> str:
        """Format a clear, actionable directive block for the ReAct orchestrator."""
        if not targets:
            return ""

        selected = targets[:max_count]
        lines = [
            f"⚡ [BỘ TẠO ĐỘT BIẾN NGỮ PHÁP API & LOGIC KINH DOANH ({len(targets)} KỊCH BẢN KHẢ THI)]",
            "Đã phân tích cấu trúc API và tạo các mẫu thử nghiệm khai thác logic chuyên sâu:",
        ]

        for i, t in enumerate(selected, start=1):
            body_preview = f" Body: `{json.dumps(t.json_body)}`" if t.json_body else ""
            lines.append(
                f" {i}. [{t.fuzz_type}][{t.severity_potential}] `{t.method} {t.url_path}`{body_preview}\n"
                f"    ➔ Mục tiêu: {t.description}"
            )

        lines.append("➔ HÃY THỰC THI CÁC VECTOR NÀY BẰNG `docker_curl` HOẶC `docker_ffuf_scan`.")
        return "\n".join(lines)
