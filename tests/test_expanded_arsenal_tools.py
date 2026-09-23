"""Tests for the 4 expanded security tools in Docker Arsenal:
1. docker_http_headers_audit
2. docker_api_docs_audit
3. docker_subdomain_takeover_audit
4. docker_waf_detect
plus ReportState & Orchestrator integrations.
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from src.servers.docker_arsenal import (
    docker_http_headers_audit,
    docker_api_docs_audit,
    docker_subdomain_takeover_audit,
    docker_waf_detect,
)
from src.client.report_state import ReportState
from src.client.orchestrator import (
    _distill_tool_intelligence,
    _fuzzy_match_tool_name,
    _evaluate_mission_guard,
)


class TestHttpHeadersAudit:
    """Test HTTP Security Headers & Server Banner audit."""

    @patch("src.servers.docker_arsenal.requests.get")
    def test_detects_missing_headers_and_server_leak(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "Content-Type": "text/html",
        }
        mock_get.return_value = mock_resp

        result_raw = docker_http_headers_audit("https://target.com")
        result = json.loads(result_raw)

        assert result["target"] == "https://target.com"
        assert result["score"] < 50
        assert result["grade"] in ("F", "D")
        assert len(result["missing_headers"]) >= 5
        assert "strict-transport-security" in result["missing_headers"]
        assert "content-security-policy" in result["missing_headers"]
        assert len(result["information_leaks"]) >= 2
        assert any(l["header"] == "server" for l in result["information_leaks"])
        assert any(l["header"] == "x-powered-by" for l in result["information_leaks"])

    @patch("src.servers.docker_arsenal.requests.get")
    def test_clean_secure_headers_give_high_score(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        mock_get.return_value = mock_resp

        result_raw = docker_http_headers_audit("https://secure.target.com")
        result = json.loads(result_raw)

        assert result["score"] == 100
        assert result["grade"] == "A"
        assert len(result["missing_headers"]) == 0
        assert len(result["information_leaks"]) == 0


class TestApiDocsAudit:
    """Test OpenAPI / Swagger / Redoc / GraphQL discovery."""

    @patch("src.servers.docker_arsenal.requests.get")
    @patch("src.servers.docker_arsenal.requests.post")
    def test_finds_swagger_json_and_endpoints(self, mock_post, mock_get):
        spec_data = {
            "swagger": "2.0",
            "info": {"title": "Test API", "version": "1.0"},
            "basePath": "/api/v1",
            "paths": {
                "/users": {"get": {}},
                "/orders": {"post": {}},
                "/admin/secret": {"delete": {}}
            }
        }

        # Setup mock for GET /swagger.json
        def get_side_effect(url, **kwargs):
            resp = MagicMock()
            if "swagger.json" in url:
                resp.status_code = 200
                resp.headers = {"Content-Type": "application/json"}
                resp.text = json.dumps(spec_data)
                resp.json.return_value = spec_data
                return resp
            resp.status_code = 404
            resp.text = "Not Found"
            return resp

        mock_get.side_effect = get_side_effect

        # Setup mock for GraphQL POST
        mock_graphql_resp = MagicMock()
        mock_graphql_resp.status_code = 404
        mock_graphql_resp.text = "Not Found"
        mock_post.return_value = mock_graphql_resp

        result_raw = docker_api_docs_audit("http://target.com")
        result = json.loads(result_raw)

        assert result["exposed_docs_count"] >= 1
        swagger_doc = next(d for d in result["exposed_docs"] if "Swagger" in d["type"] or "OpenAPI" in d["type"])
        assert swagger_doc["title"] == "Test API"
        assert swagger_doc["endpoints_count"] == 3
        assert "/users" in swagger_doc["sample_endpoints"]


class TestSubdomainTakeoverAudit:
    """Test dangling CNAME and Subdomain Takeover audit."""

    @patch("src.servers.docker_arsenal.requests.get")
    def test_detects_dangling_s3_bucket(self, mock_get):
        # Mock DoH response for CNAME query and HTTP request for bucket fingerprint
        def get_side_effect(url, **kwargs):
            resp = MagicMock()
            if "dns-query" in url:
                resp.status_code = 200
                resp.json.return_value = {
                    "Status": 0,
                    "Answer": [
                        {"type": 5, "data": "dangling-subdomain.s3.amazonaws.com."}
                    ]
                }
                return resp
            else:
                # Target HTTP request
                resp.status_code = 404
                resp.text = "The specified bucket does not exist: NoSuchBucket"
                return resp

        mock_get.side_effect = get_side_effect

        result_raw = docker_subdomain_takeover_audit("target.com", ["assets.target.com"])
        result = json.loads(result_raw)

        assert result["takeover_vulnerabilities_count"] >= 1
        vuln = result["vulnerabilities"][0]
        assert vuln["subdomain"] == "assets.target.com"
        assert vuln["service"] == "AWS S3 Bucket"
        assert vuln["severity"] == "HIGH"


class TestWafDetect:
    """Test Web Application Firewall & CDN detection."""

    @patch("src.servers.docker_arsenal.requests.get")
    def test_identifies_cloudflare_waf(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Server": "cloudflare",
            "cf-ray": "893740237402374-SJC",
            "Content-Type": "text/html",
        }
        mock_resp.text = "<html>Welcome</html>"
        mock_get.return_value = mock_resp

        result_raw = docker_waf_detect("http://protected.target.com")
        result = json.loads(result_raw)

        assert result["waf_detected"] is True
        assert result["primary_waf"] == "Cloudflare"
        assert "Cloudflare" in result["detected_wafs"]
        assert len(result["evasion_recommendations"]) > 0


class TestReportStateIntegration:
    """Verify that ReportState updates correctly from all 4 new tools."""

    def test_report_state_updates_from_new_tools(self):
        state = ReportState(target="https://target.com", scan_mode="full")

        # 1. Update from HTTP Headers Audit
        headers_payload = json.dumps({
            "target": "https://target.com",
            "score": 30,
            "grade": "F",
            "missing_headers": [
                "strict-transport-security",
                "content-security-policy",
            ],
            "information_leaks": [
                {"header": "server", "value": "Apache/2.4.41", "severity": "LOW"}
            ]
        })
        state.update_attack_surface("docker_http_headers_audit", {"target_url": "https://target.com"}, headers_payload)
        assert state.attack_surface.security_headers_info.get("grade") == "F"
        assert any("Strict-Transport-Security" in f.title for f in state.findings)
        assert any("Content-Security-Policy" in f.title for f in state.findings)
        assert any("Rò rỉ thông tin" in f.title for f in state.findings)

        # 2. Update from API Docs Audit
        api_payload = json.dumps({
            "target": "https://target.com",
            "exposed_count": 1,
            "exposed_docs": [
                {
                    "type": "OpenAPI / Swagger JSON Specification",
                    "path": "/swagger.json",
                    "url": "https://target.com/swagger.json",
                    "endpoints_count": 5,
                    "sample_endpoints": ["/api/v1/users"],
                    "severity": "HIGH",
                }
            ]
        })
        state.update_attack_surface("docker_api_docs_audit", {"target_url": "https://target.com"}, api_payload)
        assert len(state.attack_surface.exposed_api_docs) == 1
        assert "/api/v1/users" in state.attack_surface.hidden_discovered_paths
        assert any("Lộ lọt tài liệu API" in f.title for f in state.findings)

        # 3. Update from Subdomain Takeover Audit
        takeover_payload = json.dumps({
            "takeover_vulnerabilities_count": 1,
            "vulnerabilities": [
                {
                    "subdomain": "assets.target.com",
                    "cname": "target.s3.amazonaws.com",
                    "service": "AWS S3 Bucket",
                    "severity": "HIGH",
                    "risk": "Dangling S3 pointer",
                    "remediation": "Remove CNAME record",
                }
            ]
        })
        state.update_attack_surface("docker_subdomain_takeover_audit", {"domain": "target.com"}, takeover_payload)
        assert len(state.attack_surface.dangling_cnames) == 1
        assert any("Subdomain Takeover" in f.title for f in state.findings)

        # 4. Update from WAF Detect
        waf_payload = json.dumps({
            "waf_detected": True,
            "primary_waf": "Cloudflare",
            "detected_wafs": ["Cloudflare"],
            "signals": ["Server: cloudflare"],
        })
        state.update_attack_surface("docker_waf_detect", {"target_url": "https://target.com"}, waf_payload)
        assert state.attack_surface.detected_waf.get("primary_waf") == "Cloudflare"
        assert any("Tường lửa Ứng dụng Web" in f.title for f in state.findings)


class TestOrchestratorIntegration:
    """Verify distillation, fuzzy matching, and mission guard logic for new tools."""

    def test_distills_new_tool_outputs(self):
        # Distill HTTP headers
        h_json = json.dumps({"score": 25, "grade": "F", "missing_headers": ["strict-transport-security"], "information_leaks": [{"header": "server"}]})
        intel = _distill_tool_intelligence("docker_http_headers_audit", h_json)
        assert "HTTP Headers:" in intel["summary"]

        # Distill API docs
        a_json = json.dumps({"exposed_docs": [{"type": "Swagger", "endpoints_count": 12}]})
        intel_api = _distill_tool_intelligence("docker_api_docs_audit", a_json)
        assert "API Docs Exposed:" in intel_api["summary"]

        # Distill Subdomain takeover
        t_json = json.dumps({"vulnerabilities": [{"subdomain": "sub.target.com"}]})
        intel_takeover = _distill_tool_intelligence("docker_subdomain_takeover_audit", t_json)
        assert "Subdomain Takeover:" in intel_takeover["summary"]

        # Distill WAF detect
        w_json = json.dumps({"waf_detected": True, "primary_waf": "Cloudflare"})
        intel_waf = _distill_tool_intelligence("docker_waf_detect", w_json)
        assert "Cloudflare" in intel_waf["summary"]

    def test_fuzzy_match_aliases(self):
        schema = [
            {"name": "docker_http_headers_audit"},
            {"name": "docker_api_docs_audit"},
            {"name": "docker_subdomain_takeover_audit"},
            {"name": "docker_waf_detect"},
        ]
        assert _fuzzy_match_tool_name("http_headers", schema) == "docker_http_headers_audit"
        assert _fuzzy_match_tool_name("swagger", schema) == "docker_api_docs_audit"
        assert _fuzzy_match_tool_name("subdomain_takeover", schema) == "docker_subdomain_takeover_audit"
        assert _fuzzy_match_tool_name("waf_detect", schema) == "docker_waf_detect"

    def test_mission_guard_requires_new_tools_when_asked(self):
        state = ReportState(target="http://target.com", scan_mode="full", mission_objective="Kiểm tra bảo mật API và tiêu đề an ninh HTTP")
        should_guard, unfulfilled = _evaluate_mission_guard(
            report_state=state,
            tools_called={"docker_crawl_web"},
            progress_pct=50,
            untapped_actions=[],
            iteration=1,
            max_iterations=20,
            guard_attempts=0,
            relentless_pursuit=False,
        )
        assert should_guard is True
        assert any("docker_http_headers_audit" in msg for msg in unfulfilled)
        assert any("docker_api_docs_audit" in msg for msg in unfulfilled)
