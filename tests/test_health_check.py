"""Unit tests for environment health check utility."""

from unittest.mock import patch, MagicMock
import pytest
from src.utils.config import check_environment


class TestHealthCheck:
    @patch("src.utils.config.load_config")
    @patch("requests.get")
    @patch("subprocess.run")
    def test_all_systems_pass(self, mock_subproc, mock_requests_get, mock_load_cfg, tmp_path):
        """When docker, ollama, models, and wordlists are ready, all_ok should be True."""
        # Mock docker info success
        mock_subproc.return_value = MagicMock(returncode=0, stdout="Docker running")

        # Mock ollama API response with both required models
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "models": [
                {"name": "huihui_ai/qwen3.5-abliterated:9b"},
                {"name": "huihui_ai/qwen3.5-abliterated:2B"},
            ]
        }
        mock_requests_get.return_value = mock_resp

        # Mock wordlists directory
        wl_dir = tmp_path / "wordlists"
        wl_dir.mkdir()
        (wl_dir / "dirb_common.txt").write_text("common")
        (wl_dir / "rockyou.txt").write_text("passwords")

        mock_load_cfg.return_value = {
            "llm": {
                "base_url": "http://localhost:11434/v1",
                "model": "huihui_ai/qwen3.5-abliterated:9b",
            },
            "reporter": {"model": "huihui_ai/qwen3.5-abliterated:2B"},
            "wordlists": {"directory": str(wl_dir)},
        }

        status = check_environment()
        assert status["docker"]["ok"] is True
        assert status["ollama"]["ok"] is True
        assert status["models"]["ok"] is True
        assert status["wordlists"]["ok"] is True
        assert status["all_ok"] is True

    @patch("src.utils.config.load_config")
    @patch("requests.get")
    @patch("subprocess.run")
    def test_docker_down_fails(self, mock_subproc, mock_requests_get, mock_load_cfg):
        """When docker is not running, docker.ok and all_ok should be False."""
        mock_subproc.return_value = MagicMock(returncode=1, stderr="Cannot connect")
        mock_requests_get.side_effect = Exception("Connection refused")
        mock_load_cfg.return_value = {
            "llm": {"base_url": "http://localhost:11434/v1", "model": "test"},
            "reporter": {"model": "test"},
            "wordlists": {"directory": "nonexistent"},
        }

        status = check_environment()
        assert status["docker"]["ok"] is False
        assert status["all_ok"] is False

    @patch("src.utils.config.load_config")
    @patch("requests.get")
    @patch("subprocess.run")
    def test_model_missing_detected(self, mock_subproc, mock_requests_get, mock_load_cfg):
        """When required model is missing from ollama list, models.ok should be False."""
        mock_subproc.return_value = MagicMock(returncode=0)
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"models": [{"name": "some-other-model:latest"}]}
        mock_requests_get.return_value = mock_resp

        mock_load_cfg.return_value = {
            "llm": {"base_url": "http://localhost:11434/v1", "model": "required-model:7b"},
            "reporter": {"model": "required-reporter:3b"},
            "wordlists": {"directory": "wordlists"},
        }

        status = check_environment()
        assert status["models"]["ok"] is False
        assert len(status["models"]["missing"]) > 0
        assert status["all_ok"] is False

    @patch("src.utils.config.load_config")
    @patch("requests.get")
    @patch("subprocess.run")
    def test_vectordb_health_check_passed(self, mock_subproc, mock_requests_get, mock_load_cfg, tmp_path):
        """When vectordb is enabled and nomic-embed-text is present, vectordb.ok should be True."""
        mock_subproc.return_value = MagicMock(returncode=0)
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "models": [
                {"name": "huihui_ai/qwen3.5-abliterated:9b"},
                {"name": "huihui_ai/qwen3.5-abliterated:2B"},
                {"name": "nomic-embed-text:latest"},
            ]
        }
        mock_requests_get.return_value = mock_resp

        wl_dir = tmp_path / "wordlists"
        wl_dir.mkdir()
        (wl_dir / "dirb_common.txt").write_text("common")
        (wl_dir / "rockyou.txt").write_text("passwords")

        vdb_dir = tmp_path / "data" / "chromadb"

        mock_load_cfg.return_value = {
            "llm": {"base_url": "http://localhost:11434/v1", "model": "huihui_ai/qwen3.5-abliterated:9b"},
            "reporter": {"model": "huihui_ai/qwen3.5-abliterated:2B"},
            "wordlists": {"directory": str(wl_dir)},
            "vectordb": {
                "enabled": True,
                "path": str(vdb_dir),
                "embedding_source": "ollama",
                "ollama_model": "nomic-embed-text",
            },
        }

        status = check_environment()
        assert "vectordb" in status
        assert status["vectordb"]["ok"] is True
        assert status["all_ok"] is True

    @patch("src.utils.config.load_config")
    @patch("requests.get")
    @patch("subprocess.run")
    def test_vectordb_model_missing_detected(self, mock_subproc, mock_requests_get, mock_load_cfg, tmp_path):
        """When vectordb is enabled but embedding model is missing, vectordb.ok should be False."""
        mock_subproc.return_value = MagicMock(returncode=0)
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "models": [
                {"name": "huihui_ai/qwen3.5-abliterated:9b"},
                {"name": "huihui_ai/qwen3.5-abliterated:2B"},
            ]
        }
        mock_requests_get.return_value = mock_resp

        wl_dir = tmp_path / "wordlists"
        wl_dir.mkdir()
        (wl_dir / "dirb_common.txt").write_text("common")
        (wl_dir / "rockyou.txt").write_text("passwords")

        mock_load_cfg.return_value = {
            "llm": {"base_url": "http://localhost:11434/v1", "model": "huihui_ai/qwen3.5-abliterated:9b"},
            "reporter": {"model": "huihui_ai/qwen3.5-abliterated:2B"},
            "wordlists": {"directory": str(wl_dir)},
            "vectordb": {
                "enabled": True,
                "path": str(tmp_path / "chromadb"),
                "embedding_source": "ollama",
                "ollama_model": "nomic-embed-text",
            },
        }

        status = check_environment()
        assert "vectordb" in status
        assert status["vectordb"]["ok"] is False
        assert "missing" in status["vectordb"]["message"].lower()
        assert status["all_ok"] is False
