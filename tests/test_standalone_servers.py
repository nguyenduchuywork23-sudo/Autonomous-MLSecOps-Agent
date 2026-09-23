"""Unit tests for standalone task servers and diagnostic tooling."""

import json
import os
import subprocess
import sys
from unittest.mock import patch, MagicMock

import pytest

# Ensure src/servers is importable
SERVERS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "servers"))
if SERVERS_DIR not in sys.path:
    sys.path.insert(0, SERVERS_DIR)

import nmap_server
import nuclei_server
import sqlmap_server
import hydra_server
import metasploit_server
import dummy_server
import unified_server


# ===== Nmap Standalone Server Tests =====

class TestNmapServer:
    @patch("nmap_server.subprocess.run")
    def test_fast_scan_success(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="22/tcp open ssh\n80/tcp open http\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(nmap_server.scan_ports_fast("127.0.0.1"))
        assert result["target"] == "127.0.0.1"
        assert 22 in result["open_ports"]
        assert 80 in result["open_ports"]

    def test_fast_scan_empty(self):
        result = json.loads(nmap_server.scan_ports_fast(""))
        assert "error" in result

    @patch("nmap_server.subprocess.run", side_effect=FileNotFoundError)
    def test_fast_scan_missing(self, mock_run):
        result = json.loads(nmap_server.scan_ports_fast("127.0.0.1"))
        assert "error" in result
        assert "Nmap is not installed" in result["error"]

    @patch("nmap_server.subprocess.run")
    def test_deep_scan_success(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            stdout="80/tcp open Apache httpd 2.4.50\n",
            stderr="",
            returncode=0,
        )
        with patch.object(nmap_server, "RAW_OUTPUTS_DIR", tmp_path):
            result = nmap_server.scan_port_deep("127.0.0.1", 80)
            assert "Port 80 is open" in result
            assert "Apache httpd" in result


# ===== Nuclei Standalone Server Tests =====

class TestNucleiServer:
    @patch("nuclei_server.subprocess.run")
    def test_nuclei_scan_success(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        jsonl_file = tmp_path / "nuclei_scan.jsonl"
        jsonl_file.write_text(
            json.dumps({"template-id": "cve-2021-44228", "info": {"name": "Log4j", "severity": "critical"}, "matched-at": "http://target.com"}) + "\n",
            encoding="utf-8",
        )

        with patch.object(nuclei_server, "RAW_OUTPUTS_DIR", tmp_path):
            with patch("re.sub", return_value="scan"):
                result = json.loads(nuclei_server.nuclei_scan("http://target.com"))
                assert result["target"] == "http://target.com"
                assert len(result["findings"]) == 1
                assert result["findings"][0]["template_id"] == "cve-2021-44228"

    @patch("nuclei_server.subprocess.run")
    def test_nuclei_tech_detection(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="nginx\nphp\nwordpress\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(nuclei_server.nuclei_scan_tech("http://target.com"))
        assert result["target"] == "http://target.com"
        assert "nginx" in result["technologies_detected"]


# ===== SQLmap Standalone Server Tests =====

class TestSQLmapServer:
    @patch("sqlmap_server.subprocess.run")
    def test_sqlmap_scan_success(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            stdout="Parameter: id (GET)\navailable databases [1]:\n[*] testdb\n\n",
            stderr="",
            returncode=0,
        )
        with patch.object(sqlmap_server, "RAW_OUTPUTS_DIR", tmp_path):
            result = json.loads(sqlmap_server.sqlmap_scan("http://target.com/page?id=1"))
            assert result["target"] == "http://target.com/page?id=1"
            assert "id" in result["injectable_params"]
            assert "testdb" in result["databases_found"]

    @patch("sqlmap_server.subprocess.run")
    def test_dump_table_success(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            stdout="| 1 | admin |\n| 2 | guest |\n",
            stderr="",
            returncode=0,
        )
        with patch.object(sqlmap_server, "RAW_OUTPUTS_DIR", tmp_path):
            result = json.loads(sqlmap_server.dump_table("http://target.com", "mydb", "users"))
            assert result["database"] == "mydb"
            assert result["table"] == "users"


# ===== Hydra Standalone Server Tests =====

class TestHydraServer:
    @patch("hydra_server.subprocess.run")
    def test_bruteforce_ssh(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            stdout="[ssh] host: 127.0.0.1 login: root password: secretpassword\n",
            stderr="",
            returncode=0,
        )
        with patch.object(hydra_server, "RAW_OUTPUTS_DIR", tmp_path):
            result = json.loads(hydra_server.bruteforce_ssh("127.0.0.1", "root"))
            assert result["target"] == "127.0.0.1"
            assert result["port"] == 22
            assert len(result["credentials_found"]) == 1
            assert result["credentials_found"][0]["password"] == "secretpassword"

    @patch("hydra_server.subprocess.run")
    def test_bruteforce_ssh_port_and_threads(self, mock_run, tmp_path):
        """Port and threads parameters should be passed to Hydra command."""
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        with patch.object(hydra_server, "RAW_OUTPUTS_DIR", tmp_path):
            hydra_server.bruteforce_ssh("127.0.0.1", port=2222, threads=32)
            call_args = mock_run.call_args[0][0]
            s_idx = call_args.index("-s") + 1
            assert call_args[s_idx] == "2222"
            t_idx = call_args.index("-t") + 1
            assert call_args[t_idx] == "32"
            assert "-e" in call_args
            e_idx = call_args.index("-e") + 1
            assert call_args[e_idx] == "nsr"
            assert "-W" in call_args
            w_idx = call_args.index("-W") + 1
            assert call_args[w_idx] == "3"

    @patch("hydra_server.subprocess.run")
    def test_bruteforce_ssh_connection_error(self, mock_run, tmp_path):
        """Connection refused should return CONNECTION_ERROR status."""
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="[ERROR] Connection refused on port 22\n",
            returncode=1,
        )
        with patch.object(hydra_server, "RAW_OUTPUTS_DIR", tmp_path):
            result = json.loads(hydra_server.bruteforce_ssh("127.0.0.1"))
            assert result["status"] == "CONNECTION_ERROR"
            assert "connection refused" in result["error"].lower()

    @patch("hydra_server.subprocess.run")
    def test_bruteforce_ssh_progress_extracted(self, mock_run, tmp_path):
        """Progress summary should be extracted from output."""
        mock_run.return_value = MagicMock(
            stdout="[ssh] host: 127.0.0.1 login: root password: test\n1 of 1 target successfully completed, 1 valid password found\n",
            stderr="",
            returncode=0,
        )
        with patch.object(hydra_server, "RAW_OUTPUTS_DIR", tmp_path):
            result = json.loads(hydra_server.bruteforce_ssh("127.0.0.1"))
            assert "valid password" in result["progress"].lower()


    @patch("hydra_server.subprocess.run")
    def test_bruteforce_http_form(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            stdout="[http-post-form] host: 127.0.0.1 login: admin password: pass\n",
            stderr="",
            returncode=0,
        )
        with patch.object(hydra_server, "RAW_OUTPUTS_DIR", tmp_path):
            result = json.loads(hydra_server.bruteforce_http_form(
                "http://127.0.0.1/login", "admin", "rockyou.txt", "user=^USER^&pass=^PASS^:F=Invalid"
            ))
            assert result["target"] == "http://127.0.0.1/login"
            assert len(result["credentials_found"]) == 1


# ===== Metasploit Standalone Server Tests =====

class TestMetasploitServer:
    @patch("metasploit_server.subprocess.run")
    def test_search_exploit(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            stdout="0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14  EternalBlue SMB\n",
            stderr="",
            returncode=0,
        )
        with patch.object(metasploit_server, "RAW_OUTPUTS_DIR", tmp_path):
            result = json.loads(metasploit_server.msf_search_exploit("eternalblue"))
            assert result["query"] == "eternalblue"
            assert len(result["modules"]) >= 1

    @patch("metasploit_server.subprocess.run")
    def test_fire_exploit(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            stdout="Meterpreter session 1 opened (127.0.0.1:4444 -> 127.0.0.1:49152)\n",
            stderr="",
            returncode=0,
        )
        with patch.object(metasploit_server, "RAW_OUTPUTS_DIR", tmp_path):
            result = json.loads(metasploit_server.fire_exploit("exploit/test", "127.0.0.1"))
            assert result["module"] == "exploit/test"
            assert len(result["sessions_opened"]) >= 1


# ===== Dummy / Diagnostic Server Tests =====

class TestDummyServer:
    def test_get_system_time(self):
        time_str = dummy_server.get_system_time()
        assert len(time_str) >= 19

    def test_get_system_info(self):
        info_json = dummy_server.get_system_info()
        info = json.loads(info_json)
        assert "system" in info
        assert "python_version" in info

    @patch("socket.socket")
    def test_ping_target_reachable(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        result = json.loads(dummy_server.ping_target("127.0.0.1", 80))
        assert result["reachable"] is True
        assert result["status"] == "OPEN"


# ===== Unified Server Tests =====

class TestUnifiedServer:
    def test_arsenal_status(self):
        status_json = unified_server.docker_arsenal_status()
        status = json.loads(status_json)
        assert status["status"] == "online"
        assert status["total_tools"] == 31
        assert status["recon_tools_count"] == 23
        assert status["exploit_tools_count"] == 8
