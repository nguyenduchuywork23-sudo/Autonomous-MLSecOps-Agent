"""Unit tests for Docker Arsenal MCP tools.

Tests tool functions with mocked subprocess calls to verify:
- JSON output format correctness
- Context Distillation (output parsing/filtering)
- Error handling (Docker not found, timeouts)
- Edge cases (empty output, no matches)
"""

import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

# Import tools under test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "servers"))
from docker_arsenal import (
    docker_resolve_dns,
    docker_scan_ports_fast,
    docker_scan_ports_deep,
    docker_nuclei_scan,
    docker_sqlmap_scan,
    docker_sqlmap_dump,
    docker_crawl_web,
    docker_bruteforce,
    bruteforce_ssh,
    bruteforce_http_form,
    docker_wpscan,
    docker_msf_search,
    browse_webpage,
    docker_whatweb,
    docker_nikto_scan,
    docker_dirb_scan,
    docker_subfinder,
    docker_ffuf,
    docker_testssl,
    _ensure_url_scheme,
    _resolve_wordlist,
    _normalize_target,
)


# ===== Nmap Fast Scan Tests =====

class TestNmapFastScan:
    @patch("docker_arsenal.subprocess.run")
    def test_open_ports_detected(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="PORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_scan_ports_fast("192.168.1.1"))
        assert result["target"] == "192.168.1.1"
        assert len(result["open_ports"]) == 3
        assert result["open_ports"][0]["port"] == 22
        assert result["open_ports"][0]["service"] == "ssh"

    @patch("docker_arsenal.subprocess.run")
    def test_no_open_ports(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="All 100 scanned ports are filtered\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_scan_ports_fast("192.168.1.1"))
        assert result["open_ports"] == []

    @patch("docker_arsenal.subprocess.run", side_effect=FileNotFoundError)
    def test_docker_not_found(self, mock_run):
        result = json.loads(docker_scan_ports_fast("192.168.1.1"))
        assert "error" in result
        assert "Docker" in result["error"]

    @patch("docker_arsenal.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 120))
    def test_timeout(self, mock_run):
        result = json.loads(docker_scan_ports_fast("192.168.1.1"))
        assert "error" in result
        assert "timed out" in result["error"]


# ===== Nmap Deep Scan Tests =====

class TestNmapDeepScan:
    @patch("docker_arsenal.subprocess.run")
    def test_service_detection(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "PORT   STATE SERVICE VERSION\n"
                "80/tcp open  http    Apache httpd 2.4.54\n"
                "| http-title: Test Page\n"
            ),
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_scan_ports_deep("192.168.1.1", "80"))
        assert result["target"] == "192.168.1.1"
        assert len(result["services"]) >= 1
        assert result["services"][0]["port"] == 80


# ===== Nuclei Tests =====

class TestNucleiScan:
    @patch("docker_arsenal.subprocess.run")
    def test_findings_parsed(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="[CVE-2021-44228] Log4Shell\n[CVE-2023-1234] Test vuln\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_nuclei_scan("http://target.com"))
        assert result["target"] == "http://target.com"
        assert len(result["findings"]) == 2

    @patch("docker_arsenal.subprocess.run")
    def test_no_findings(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        result = json.loads(docker_nuclei_scan("http://target.com"))
        assert "No critical/high findings" in result["findings"][0]


# ===== SQLmap Tests =====

class TestSQLmapScan:
    @patch("docker_arsenal.subprocess.run")
    def test_injectable_params(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "Parameter: id (GET)\n"
                "available databases [2]:\n"
                "[*] information_schema\n"
                "[*] testdb\n\n"
            ),
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_sqlmap_scan("http://target.com/page?id=1"))
        assert result["target"] == "http://target.com/page?id=1"
        assert "id" in result["injectable_params"]

    @patch("docker_arsenal.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 300))
    def test_timeout(self, mock_run):
        result = json.loads(docker_sqlmap_scan("http://target.com/page?id=1"))
        assert "timed out" in result["error"]


# ===== Crawler Tests =====

class TestCrawlWeb:
    @patch("docker_arsenal.subprocess.run")
    def test_param_urls_extracted(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="http://target.com/page?id=1\nhttp://target.com/search?q=test\nhttp://target.com/about\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_crawl_web("http://target.com"))
        assert result["status"] == "success"
        assert len(result["parameterized_endpoints"]) == 2


# ===== Subfinder Tests =====

class TestSubfinder:
    @patch("docker_arsenal.subprocess.run")
    def test_subdomains_found(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="mail.example.com\nwww.example.com\napi.example.com\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_subfinder("example.com"))
        assert result["domain"] == "example.com"
        assert result["total_subdomains"] == 3
        assert "api.example.com" in result["subdomains"]

    @patch("docker_arsenal.subprocess.run")
    def test_strip_protocol(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        docker_subfinder("https://example.com/")
        call_args = mock_run.call_args[0][0]
        assert "https://example.com/" not in call_args
        assert any("example.com" == arg for arg in call_args)


# ===== FFUF Tests =====

class TestFFUF:
    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="/fake/path.txt")
    def test_dir_mode(self, mock_wl, mock_run):
        mock_run.return_value = MagicMock(
            stdout="/admin\n/backup\n/api\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_ffuf("http://target.com"))
        assert result["total_found"] == 3
        assert "/admin" in result["discovered"]

    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="/fake/path.txt")
    def test_fuzz_keyword_appended(self, mock_wl, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        docker_ffuf("http://target.com")
        call_args = mock_run.call_args[0][0]
        url_arg_idx = call_args.index("-u") + 1
        assert "FUZZ" in call_args[url_arg_idx]

    @patch("docker_arsenal._resolve_wordlist", return_value=None)
    def test_wordlist_not_found(self, mock_wl):
        result = json.loads(docker_ffuf("http://target.com", wordlist="nonexistent.txt"))
        assert "error" in result


# ===== TestSSL Tests =====

class TestTestSSL:
    @patch("docker_arsenal.subprocess.run")
    def test_vulnerability_extraction(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "Testing protocols\n"
                " SSLv2      not offered (OK)\n"
                " SSLv3      not offered (OK)\n"
                " TLS 1      not offered\n"
                " TLS 1.1    not offered\n"
                " TLS 1.2    offered (OK)\n"
                " TLS 1.3    offered (OK)\n"
                "Heartbleed: not vulnerable (OK)\n"
                "POODLE: not vulnerable (OK)\n"
                "Certificate: CN=example.com\n"
                "Issuer: Let's Encrypt\n"
            ),
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_testssl("example.com"))
        assert result["target"] == "example.com"
        assert len(result["vulnerabilities"]) > 0
        assert len(result["protocols"]) > 0


# ===== WPScan Tests =====

class TestWPScan:
    @patch("docker_arsenal.subprocess.run")
    def test_wp_findings(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="[+] WordPress version 5.9.3\n[!] Outdated plugin: contact-form-7\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_wpscan("http://target.com"))
        assert len(result["findings"]) == 2


# ===== Browse Webpage Tests =====

class TestBrowseWebpage:
    @patch("docker_arsenal.requests.get")
    def test_successful_browse(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
        mock_get.return_value = mock_response
        result = json.loads(browse_webpage("http://example.com"))
        assert result["status_code"] == 200
        assert result["title"] == "Test"

    @patch("docker_arsenal.requests.get")
    def test_browse_without_scheme_auto_prepends_http(self, mock_get):
        """When user provides domain without scheme, it should auto-prepend http://."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><head><title>AutoScheme</title></head><body><p>OK</p></body></html>"
        mock_get.return_value = mock_response
        result = json.loads(browse_webpage("example.com"))
        assert result["status_code"] == 200
        assert result["title"] == "AutoScheme"
        mock_get.assert_called_with("http://example.com", headers=pytest.approx(mock_get.call_args[1]["headers"]), timeout=10, verify=False)


# ===== Arsenal Helpers Tests =====

class TestArsenalHelpers:
    def test_ensure_url_scheme(self):
        assert _ensure_url_scheme("example.com") == "http://example.com"
        assert _ensure_url_scheme("192.168.1.1") == "http://192.168.1.1"
        assert _ensure_url_scheme("https://secure.com") == "https://secure.com"
        assert _ensure_url_scheme("http://insecure.com") == "http://insecure.com"
        assert _ensure_url_scheme("example.com", "https") == "https://example.com"
        assert _ensure_url_scheme("") == ""

    def test_normalize_target(self):
        assert _normalize_target("https://example.com/path?id=1") == "example.com"
        assert _normalize_target("http://192.168.1.1:8080/admin") == "192.168.1.1"
        assert _normalize_target("target.com:443") == "target.com"
        assert _normalize_target("10.0.0.1") == "10.0.0.1"

    def test_resolve_wordlist_aliases(self):
        # Should resolve "common.txt" alias to "dirb_common.txt"
        path = _resolve_wordlist("common.txt")
        assert path is not None
        assert "dirb_common.txt" in path

        # Should resolve "rockyou" alias to "rockyou.txt"
        path = _resolve_wordlist("rockyou")
        assert path is not None
        assert "rockyou.txt" in path


# ===== Hydra Brute-Force Tests =====

class TestHydraSSH:
    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/rockyou.txt")
    def test_credentials_found(self, mock_wl, mock_run):
        mock_run.return_value = MagicMock(
            stdout="[22][ssh] host: 192.168.1.1   login: root   password: password123\n1 of 1 target successfully completed, 1 valid password found\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(bruteforce_ssh("192.168.1.1", "root", "rockyou.txt"))
        assert result["status"] == "CREDENTIALS_FOUND"
        assert len(result["results"]) >= 1
        assert "login: root" in result["results"][0]

    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/rockyou.txt")
    def test_no_credentials_found_not_false_positive(self, mock_wl, mock_run):
        """Ensure failed attacks do NOT produce false positive CREDENTIALS_FOUND."""
        mock_run.return_value = MagicMock(
            stdout="[DATA] attacking ssh://192.168.1.1:22/\n[STATUS] 100 tries completed\n0 of 1 target completed, 0 valid passwords found\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(bruteforce_ssh("192.168.1.1", "root", "rockyou.txt"))
        assert result["status"] == "NO_CREDENTIALS_FOUND"

    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/dirb_common.txt")
    def test_resolved_wordlist_passed_to_docker(self, mock_wl, mock_run):
        """Ensure the container receives the resolved filename rather than raw alias."""
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        bruteforce_ssh("192.168.1.1", "root", "common")
        call_args = mock_run.call_args[0][0]
        assert "-P" in call_args
        p_idx = call_args.index("-P") + 1
        assert call_args[p_idx] == "/wordlists/dirb_common.txt"

    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/rockyou.txt")
    def test_network_host_and_threads_in_command(self, mock_wl, mock_run):
        """Ensure --network host, -e nsr, -W 3, and custom threads are passed."""
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        bruteforce_ssh("192.168.1.1", "root", "rockyou.txt", threads=32)
        call_args = mock_run.call_args[0][0]
        # --network host must be present
        assert "--network" in call_args
        net_idx = call_args.index("--network") + 1
        assert call_args[net_idx] == "host"
        # -t must be 32
        t_idx = call_args.index("-t") + 1
        assert call_args[t_idx] == "32"
        # -e nsr must be present
        assert "-e" in call_args
        e_idx = call_args.index("-e") + 1
        assert call_args[e_idx] == "nsr"
        # -W 3 must be present
        assert "-W" in call_args
        w_idx = call_args.index("-W") + 1
        assert call_args[w_idx] == "3"

    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/rockyou.txt")
    def test_threads_clamped_to_max_64(self, mock_wl, mock_run):
        """Threads above 64 should be clamped to 64."""
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        bruteforce_ssh("192.168.1.1", threads=999)
        call_args = mock_run.call_args[0][0]
        t_idx = call_args.index("-t") + 1
        assert call_args[t_idx] == "64"

    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/rockyou.txt")
    def test_connection_refused_error(self, mock_wl, mock_run):
        """Hydra 'connection refused' should return CONNECTION_ERROR status."""
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="[ERROR] target 192.168.1.1 - Connection refused\n",
            returncode=1,
        )
        result = json.loads(bruteforce_ssh("192.168.1.1"))
        assert result["status"] == "CONNECTION_ERROR"
        assert "connection refused" in result["error"].lower()

    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/rockyou.txt")
    def test_raw_output_saved_field(self, mock_wl, mock_run):
        """Result should include raw_output_saved path."""
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        result = json.loads(bruteforce_ssh("192.168.1.1"))
        assert "raw_output_saved" in result

    def test_empty_target_returns_error(self):
        """Empty target should return error without calling Docker."""
        result = json.loads(bruteforce_ssh(""))
        assert "error" in result

    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/rockyou.txt")
    def test_progress_extracted(self, mock_wl, mock_run):
        """Progress summary should be extracted from Hydra output."""
        mock_run.return_value = MagicMock(
            stdout="[22][ssh] host: 192.168.1.1   login: root   password: toor\n1 of 1 target successfully completed, 1 valid password found\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(bruteforce_ssh("192.168.1.1"))
        assert result["status"] == "CREDENTIALS_FOUND"
        assert "valid password" in result["progress"].lower()

    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/rockyou.txt")
    def test_default_threads_is_16(self, mock_wl, mock_run):
        """Default thread count should be 16."""
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        bruteforce_ssh("192.168.1.1")
        call_args = mock_run.call_args[0][0]
        t_idx = call_args.index("-t") + 1
        assert call_args[t_idx] == "16"



class TestHydraHTTPForm:
    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/dirb_common.txt")
    def test_http_form_resolved_wordlist(self, mock_wl, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        bruteforce_http_form("http://target.com/login", wordlist="common")
        call_args = mock_run.call_args[0][0]
        p_idx = call_args.index("-P") + 1
        assert call_args[p_idx] == "/wordlists/dirb_common.txt"


# ===== Deep Scan Port Formatting Tests =====

class TestDeepScanPortFormatting:
    @patch("docker_arsenal.subprocess.run")
    def test_ports_as_integer(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        docker_scan_ports_deep("192.168.1.1", ports=80)
        call_args = mock_run.call_args[0][0]
        p_idx = call_args.index("-p") + 1
        assert call_args[p_idx] == "80"

    @patch("docker_arsenal.subprocess.run")
    def test_ports_as_list(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        docker_scan_ports_deep("192.168.1.1", ports=[80, 443, 8080])
        call_args = mock_run.call_args[0][0]
        p_idx = call_args.index("-p") + 1
        assert call_args[p_idx] == "80,443,8080"


# ===== Dirb Scan Wordlist Resolution Tests =====

class TestDirbScanWordlist:
    @patch("docker_arsenal.subprocess.run")
    @patch("docker_arsenal._resolve_wordlist", return_value="C:/wordlists/dirb_common.txt")
    def test_dirb_uses_resolved_wordlist(self, mock_wl, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        docker_dirb_scan("http://target.com", wordlist="common")
        call_args = mock_run.call_args[0][0]
        w_idx = call_args.index("-w") + 1
        assert call_args[w_idx] == "/wordlists/dirb_common.txt"


# ===== Docker Bruteforce (Capability Check) Tests =====

class TestDockerBruteforceCapabilityCheck:
    @patch("docker_arsenal.subprocess.run")
    def test_docker_bruteforce_capability_check_json(self, mock_run):
        mock_run.return_value = MagicMock(stdout="Hydra v9.5 help...", stderr="", returncode=0)
        raw_result = docker_bruteforce("example.com")
        result = json.loads(raw_result)
        assert result["status"] == "capability_check_only"
        assert result["hydra_available"] is True
        assert result["target"] == "example.com"
        assert "NO attack was performed" in result["message"]


# ===== DNS Resolution Tests =====

class TestResolveDNS:
    @patch("socket.getaddrinfo")
    def test_resolve_dns_success(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("93.184.216.35", 0)),
        ]
        result = json.loads(docker_resolve_dns("http://example.com/path"))
        assert result["hostname"] == "example.com"
        assert "93.184.216.34" in result["ip_addresses"]
        assert result["primary_ip"] == "93.184.216.34"

    def test_resolve_dns_empty(self):
        result = json.loads(docker_resolve_dns(""))
        assert "error" in result

    @patch("socket.getaddrinfo")
    def test_resolve_dns_failure(self, mock_getaddrinfo):
        import socket
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        result = json.loads(docker_resolve_dns("invalid-nonexistent-domain.xyz"))
        assert "error" in result
        assert "failed" in result["error"].lower()


# ===== WhatWeb Tests =====

class TestWhatWeb:
    @patch("docker_arsenal.subprocess.run")
    def test_whatweb_success(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="http://target.com [200 OK] Apache[2.4.50], HTTPServer[Ubuntu Linux], PHP[8.1.2]",
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_whatweb("http://target.com"))
        assert result["target"] == "http://target.com"
        assert len(result["technologies_detected"]) >= 1

    @patch("docker_arsenal.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 60))
    def test_whatweb_timeout(self, mock_run):
        result = json.loads(docker_whatweb("http://target.com"))
        assert "error" in result
        assert "timed out" in result["error"].lower()

    @patch("docker_arsenal.subprocess.run", side_effect=FileNotFoundError)
    def test_whatweb_docker_missing(self, mock_run):
        result = json.loads(docker_whatweb("http://target.com"))
        assert "error" in result
        assert "Docker" in result["error"]


# ===== Nikto Scan Tests =====

class TestNiktoScan:
    @patch("docker_arsenal.subprocess.run")
    def test_nikto_findings(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="+ Server: Apache/2.4.41\n+ OSVDB-3092: /admin/: Admin directory found\n+ /test.php: Contains sensitive data",
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_nikto_scan("http://target.com"))
        assert result["target"] == "http://target.com"
        assert len(result["findings"]) >= 2

    @patch("docker_arsenal.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 240))
    def test_nikto_timeout(self, mock_run):
        result = json.loads(docker_nikto_scan("http://target.com"))
        assert "error" in result
        assert "timed out" in result["error"].lower()


# ===== SQLmap Dump Tests =====

class TestSQLmapDump:
    @patch("docker_arsenal.subprocess.run")
    def test_dump_success(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "Database: users\n"
                "Table: accounts\n"
                "[2 entries]\n"
                "+----+-------+----------+\n"
                "| id | name  | password |\n"
                "+----+-------+----------+\n"
                "| 1  | admin | pass123  |\n"
                "| 2  | user  | secret   |\n"
                "+----+-------+----------+\n"
            ),
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_sqlmap_dump("http://target.com/page?id=1", "users", "accounts"))
        assert result["database"] == "users"
        assert result["table"] == "accounts"
        assert len(result["dumped_rows"]) >= 2

    def test_dump_invalid_params(self):
        result = json.loads(docker_sqlmap_dump("http://target.com", "", ""))
        assert "error" in result


# ===== Metasploit Search Tests =====

class TestMSFSearch:
    @patch("docker_arsenal.subprocess.run")
    def test_search_success(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "Matching Modules\n"
                "0  exploit/multi/http/log4shell_header_injection  2021-12-09  excellent  Log4Shell HTTP Header\n"
                "1  exploit/windows/smb/ms17_010_eternalblue       2017-03-14  average    EternalBlue SMB\n"
            ),
            stderr="",
            returncode=0,
        )
        result = json.loads(docker_msf_search("log4shell"))
        assert result["query"] == "log4shell"
        assert len(result["top_exploits"]) >= 1

    def test_search_empty(self):
        result = json.loads(docker_msf_search(""))
        assert "error" in result


# ===== Fast/Deep Scan Edge Cases =====

class TestScanEdgeCases:
    @patch("docker_arsenal.subprocess.run")
    def test_fast_scan_failed_code_returns_error(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="Failed to resolve host", returncode=1)
        result = json.loads(docker_scan_ports_fast("invalid_target"))
        assert "error" in result
        assert result["open_ports"] == []

    @patch("docker_arsenal.subprocess.run")
    def test_deep_scan_empty_ports_fallback(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        result = json.loads(docker_scan_ports_deep("192.168.1.1", ports=""))
        assert result["ports_scanned"] == "80,443,22,21,3306,8080"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

