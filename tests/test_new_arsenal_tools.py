"""Unit tests for the 4 new arsenal tools and tactical engine updates (v4.1 Big Update)."""

import json
from unittest.mock import patch, MagicMock
import pytest

from src.servers.docker_arsenal import (
    docker_sensitive_files_scan,
    docker_cors_scan,
    docker_xss_scan,
    docker_httpx_probe,
)
from src.client.report_state import ReportState, AttackSurfaceGraph
from src.client.orchestrator import (
    _distill_tool_intelligence,
    _fuzzy_match_tool_name,
    _normalize_tool_args,
)


# ===========================================================================
# 1. Tests for docker_sensitive_files_scan
# ===========================================================================

class TestSensitiveFilesScan:
    def test_detect_exposed_env_file(self):
        def mock_get(url, **kwargs):
            resp = MagicMock()
            if ".env" in url:
                resp.status_code = 200
                resp.text = "APP_NAME=SecOps\nDB_PASSWORD=SuperSecretPass123!\nKEY=xyz"
                resp.headers = {"Content-Type": "text/plain"}
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.headers = {}
            return resp

        with patch("requests.get", side_effect=mock_get):
            res_str = docker_sensitive_files_scan("http://target.local")
            res = json.loads(res_str)
            assert res["vulnerabilities_found"] >= 1
            exposed_paths = [f["path"] for f in res["exposed_files"]]
            assert "/.env" in exposed_paths

    def test_detect_git_head_exposure(self):
        def mock_get(url, **kwargs):
            resp = MagicMock()
            if ".git/HEAD" in url:
                resp.status_code = 200
                resp.text = "ref: refs/heads/main\n"
                resp.headers = {}
            else:
                resp.status_code = 404
                resp.text = "Not Found"
                resp.headers = {}
            return resp

        with patch("requests.get", side_effect=mock_get):
            res_str = docker_sensitive_files_scan("http://target.local")
            res = json.loads(res_str)
            assert res["vulnerabilities_found"] >= 1
            exposed_paths = [f["path"] for f in res["exposed_files"]]
            assert "/.git/HEAD" in exposed_paths

    def test_soft_404_ignored(self):
        # When non-existent probe returns 200 with HTML, soft 404 shouldn't trigger findings
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "<!DOCTYPE html><html><body>Custom 404 page</body></html>"
            resp.headers = {"Content-Type": "text/html"}
            return resp

        with patch("requests.get", side_effect=mock_get):
            res_str = docker_sensitive_files_scan("http://target.local")
            res = json.loads(res_str)
            assert res["vulnerabilities_found"] == 0
            assert len(res["exposed_files"]) == 0


# ===========================================================================
# 2. Tests for docker_cors_scan
# ===========================================================================

class TestCorsScan:
    def test_critical_cors_reflection_with_credentials(self):
        def mock_get(url, headers=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            headers = headers or {}
            origin = headers.get("Origin")
            resp.headers = {
                "Content-Type": "application/json",
            }
            if origin == "https://evil-attacker.com":
                resp.headers["Access-Control-Allow-Origin"] = "https://evil-attacker.com"
                resp.headers["Access-Control-Allow-Credentials"] = "true"
            return resp

        with patch("requests.get", side_effect=mock_get):
            res_str = docker_cors_scan("http://target.local/api")
            res = json.loads(res_str)
            assert res["vulnerabilities_found"] > 0
            crit_issues = [c for c in res["cors_misconfigurations"] if c["severity"] == "CRITICAL"]
            assert len(crit_issues) == 1
            assert crit_issues[0]["origin_tested"] == "https://evil-attacker.com"
            assert len(res["missing_security_headers"]) > 0

    def test_missing_security_headers_detection(self):
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Server": "Apache"}
            return resp

        with patch("requests.get", side_effect=mock_get):
            res_str = docker_cors_scan("http://target.local")
            res = json.loads(res_str)
            missing_names = [h["header"] for h in res["missing_security_headers"]]
            assert "Content-Security-Policy" in missing_names
            assert "X-Frame-Options" in missing_names


# ===========================================================================
# 3. Tests for docker_xss_scan
# ===========================================================================

class TestXssScan:
    def test_no_params_error_handling(self):
        res_str = docker_xss_scan("http://target.local/about")
        res = json.loads(res_str)
        assert res["vulnerabilities_found"] == 0
        assert "No query parameters" in res["error"]

    def test_detect_unescaped_html_reflection(self):
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            # Simulate reflecting parameter verbatim
            if "xss_probe_canary_tag" in url:
                resp.text = f"<html><body>Search results for: <xss_probe_canary_tag_9921></body></html>"
            else:
                resp.text = "<html><body>Clean</body></html>"
            return resp

        with patch("requests.get", side_effect=mock_get):
            res_str = docker_xss_scan("http://target.local/search?q=test&lang=en")
            res = json.loads(res_str)
            assert res["vulnerabilities_found"] >= 1
            vuln_param_names = [v["parameter"] for v in res["vulnerable_parameters"]]
            assert "q" in vuln_param_names or "lang" in vuln_param_names


# ===========================================================================
# 4. Tests for docker_httpx_probe
# ===========================================================================

class TestHttpxProbe:
    def test_probe_single_and_multiple_targets(self):
        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.url = url
            resp.content = b"<html><head><title>Admin Dashboard</title></head><body>OK</body></html>"
            resp.text = "<html><head><title>Admin Dashboard</title></head><body>OK</body></html>"
            resp.headers = {"Server": "nginx/1.24"}
            return resp

        with patch("requests.get", side_effect=mock_get):
            res_str = docker_httpx_probe("sub1.example.com, sub2.example.com")
            res = json.loads(res_str)
            assert res["total_probed"] == 2
            assert res["alive_count"] == 2
            assert res["alive_targets"][0]["title"] == "Admin Dashboard"
            assert "nginx" in res["alive_targets"][0]["server"]

    def test_empty_target_handling(self):
        res_str = docker_httpx_probe("")
        res = json.loads(res_str)
        assert res["alive_count"] == 0
        assert res["total_probed"] == 0


# ===========================================================================
# 5. Tests for AttackSurfaceGraph & Tactical Engine
# ===========================================================================

class TestAttackSurfaceIntegration:
    def test_attack_surface_updates_from_new_tools(self):
        state = ReportState(target="target.local", scan_mode="full")

        # 1. Update from sensitive files scan
        sens_res = json.dumps({
            "exposed_files": [{"path": "/.env", "type": "Credentials", "severity": "CRITICAL"}]
        })
        state.update_attack_surface("docker_sensitive_files_scan", {"target_url": "http://target.local"}, sens_res)
        assert len(state.attack_surface.exposed_sensitive_files) == 1
        assert state.attack_surface.has_attack_surface() is True

        # 2. Update from CORS scan
        cors_res = json.dumps({
            "cors_misconfigurations": [{"type": "Arbitrary Origin Reflection", "severity": "CRITICAL"}]
        })
        state.update_attack_surface("docker_cors_scan", {"target_url": "http://target.local"}, cors_res)
        assert len(state.attack_surface.cors_issues) == 1

        # 3. Update from XSS scan
        state.attack_surface.parameterized_endpoints["http://target.local/view?id=1"] = {
            "tested_sqli": False, "tested_xss": False
        }
        state.update_attack_surface("docker_xss_scan", {"target_url": "http://target.local/view?id=1"}, "{}")
        assert state.attack_surface.parameterized_endpoints["http://target.local/view?id=1"]["tested_xss"] is True

        # 4. Update from HTTPX probe
        httpx_res = json.dumps({
            "alive_targets": [{"url": "http://api.target.local", "alive": True, "title": "API Gateway"}]
        })
        state.update_attack_surface("docker_httpx_probe", {"targets": "api.target.local"}, httpx_res)
        assert len(state.attack_surface.alive_subdomains) == 1

    def test_tactical_roadmap_recommendations(self):
        state = ReportState(target="target.local", scan_mode="full")
        state.attack_surface.open_ports[80] = {"service": "http"}
        state.attack_surface.subdomains.append("sub1.target.local")
        state.attack_surface.parameterized_endpoints["http://target.local/search?q=test"] = {
            "tested_sqli": True, "tested_xss": False
        }

        roadmap = state.get_tactical_roadmap()
        recommended_tools = [a["tool"] for a in roadmap["untested_actions"]]

        assert "docker_xss_scan" in recommended_tools
        assert "docker_httpx_probe" in recommended_tools
        assert "docker_sensitive_files_scan" in recommended_tools
        assert "docker_cors_scan" in recommended_tools


# ===========================================================================
# 6. Tests for Orchestrator Distillation, Fuzzy Matching, and Normalization
# ===========================================================================

class TestOrchestratorIntegrations:
    def test_distill_intelligence_from_new_tools(self):
        sens_data = json.dumps({"exposed_files": [{"path": "/.env"}, {"path": "/.git/HEAD"}]})
        intel_sens = _distill_tool_intelligence("docker_sensitive_files_scan", sens_data)
        assert "Lộ tệp tin nhạy cảm" in intel_sens["summary"]

        cors_data = json.dumps({"cors_misconfigurations": [{"type": "Arbitrary Origin Reflection"}]})
        intel_cors = _distill_tool_intelligence("docker_cors_scan", cors_data)
        assert "Lỗ hổng CORS" in intel_cors["summary"]

        xss_data = json.dumps({"vulnerable_parameters": [{"parameter": "q"}]})
        intel_xss = _distill_tool_intelligence("docker_xss_scan", xss_data)
        assert "Lỗ hổng XSS" in intel_xss["summary"]

        httpx_data = json.dumps({"alive_targets": [{"url": "http://sub.target.local"}]})
        intel_httpx = _distill_tool_intelligence("docker_httpx_probe", httpx_data)
        assert "Máy chủ alive" in intel_httpx["summary"]

    def test_fuzzy_match_aliases(self):
        schema = [
            {"name": "docker_xss_scan"},
            {"name": "docker_cors_scan"},
            {"name": "docker_httpx_probe"},
            {"name": "docker_sensitive_files_scan"},
        ]
        assert _fuzzy_match_tool_name("xss", schema) == "docker_xss_scan"
        assert _fuzzy_match_tool_name("cors", schema) == "docker_cors_scan"
        assert _fuzzy_match_tool_name("httpx", schema) == "docker_httpx_probe"
        assert _fuzzy_match_tool_name("sensitive_files", schema) == "docker_sensitive_files_scan"

    def test_normalize_httpx_args(self):
        schema = [{
            "name": "docker_httpx_probe",
            "input_schema": {
                "type": "object",
                "properties": {
                    "targets": {"type": "string"}
                },
                "required": ["targets"]
            }
        }]
        args = {"target": "sub1.domain.com,sub2.domain.com"}
        normalized = _normalize_tool_args("docker_httpx_probe", args, schema)
        assert "targets" in normalized
        assert normalized["targets"] == "sub1.domain.com,sub2.domain.com"
