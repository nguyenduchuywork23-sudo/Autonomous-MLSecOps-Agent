"""Unit tests for main CLI argument parser and execution dispatch."""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

# Add workspace to sys.path
import pathlib
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import main


class TestMainArgParsing:
    def test_default_args(self):
        with patch.object(sys, "argv", ["main.py"]):
            args = main._parse_args()
            assert args.target is None
            assert args.mode == "recon"
            assert args.no_hitl is False
            assert args.check is False
            assert args.list_tools is False
            assert args.validate_config is False

    def test_custom_target_and_mode(self):
        with patch.object(sys, "argv", ["main.py", "--target", "192.168.1.50", "--mode", "full"]):
            args = main._parse_args()
            assert args.target == "192.168.1.50"
            assert args.mode == "full"

    def test_flags_parsing(self):
        with patch.object(sys, "argv", ["main.py", "--no-hitl", "--list-tools", "--validate-config"]):
            args = main._parse_args()
            assert args.no_hitl is True
            assert args.list_tools is True
            assert args.validate_config is True

    def test_health_check_flag(self):
        with patch.object(sys, "argv", ["main.py", "--check"]):
            args = main._parse_args()
            assert args.check is True

        with patch.object(sys, "argv", ["main.py", "--health"]):
            args = main._parse_args()
            assert args.check is True

    def test_resume_flag(self):
        with patch.object(sys, "argv", ["main.py", "--resume", "sess_20260924_test"]):
            args = main._parse_args()
            assert args.resume == "sess_20260924_test"


class TestMainDispatch:
    @pytest.mark.asyncio
    @patch("main._parse_args")
    @patch("main._print_system_info")
    async def test_list_tools_flag(self, mock_info, mock_parse):
        mock_parse.return_value = MagicMock(
            list_tools=True,
            validate_config=False,
            check=False,
            no_hitl=False,
            target=None,
        )
        await main.main()
        mock_info.assert_called_once()

    @pytest.mark.asyncio
    @patch("main._parse_args")
    @patch("src.utils.config.validate_config")
    async def test_validate_config_flag_valid(self, mock_val, mock_parse):
        mock_parse.return_value = MagicMock(
            list_tools=False,
            validate_config=True,
            check=False,
            no_hitl=False,
            target=None,
        )
        mock_val.return_value = (True, [])
        await main.main()
        mock_val.assert_called_once()

    @pytest.mark.asyncio
    @patch("main._parse_args")
    @patch("src.utils.config.validate_config")
    async def test_validate_config_flag_invalid(self, mock_val, mock_parse):
        mock_parse.return_value = MagicMock(
            list_tools=False,
            validate_config=True,
            check=False,
            no_hitl=False,
            target=None,
        )
        mock_val.return_value = (False, ["Missing key 'llm'"])
        await main.main()
        mock_val.assert_called_once()

    @pytest.mark.asyncio
    @patch("main._parse_args")
    @patch("main._print_health_check")
    async def test_check_flag(self, mock_health, mock_parse):
        mock_parse.return_value = MagicMock(
            list_tools=False,
            validate_config=False,
            check=True,
            no_hitl=False,
            target=None,
        )
        await main.main()
        mock_health.assert_called_once()

    @pytest.mark.asyncio
    @patch("main._parse_args")
    @patch("main._single_shot_mode", new_callable=AsyncMock)
    @patch("main._print_health_check", return_value=True)
    async def test_target_single_shot(self, mock_health, mock_single, mock_parse):
        mock_parse.return_value = MagicMock(
            list_tools=False,
            validate_config=False,
            check=False,
            no_hitl=False,
            target="10.0.0.1, 10.0.0.2",
            mode="full",
        )
        await main.main()
        mock_single.assert_awaited_once_with(["10.0.0.1", "10.0.0.2"], "full")

    @pytest.mark.asyncio
    @patch("main._parse_args")
    @patch("main._single_shot_mode", new_callable=AsyncMock)
    @patch("main._print_health_check", return_value=True)
    @patch("src.utils.config.reload_config")
    async def test_no_hitl_flag_sets_env(self, mock_reload, mock_health, mock_single, mock_parse):
        mock_parse.return_value = MagicMock(
            list_tools=False,
            validate_config=False,
            check=False,
            no_hitl=True,
            target="127.0.0.1",
            mode="recon",
        )
        await main.main()
        assert os.environ.get("MLSEC_HITL_ENABLED") == "false"
        mock_reload.assert_called_once()
        mock_single.assert_awaited_once_with(["127.0.0.1"], "recon")


class TestMainSessionSummary:
    def test_print_session_summary(self):
        results = [
            {"target": "example.com", "mode": "recon", "result": "Scan completed successfully."}
        ]
        # Verify it executes without error
        main._print_session_summary(results)
