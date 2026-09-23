"""Unit tests for enterprise wordlists setup script."""

import gzip
import os
import pathlib
import sys
from unittest.mock import patch, MagicMock

# Add workspace to sys.path
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import setup_wordlists


class TestWordlistsDownload:
    def test_download_skips_existing(self, tmp_path):
        dest = tmp_path / "existing.txt"
        dest.write_text("A" * 200)

        with patch("urllib.request.urlopen") as mock_urlopen:
            setup_wordlists._download("http://example.com/test.txt", str(dest), "test_file", force=False)
            mock_urlopen.assert_not_called()

    def test_download_force_redownloads(self, tmp_path):
        dest = tmp_path / "existing.txt"
        dest.write_text("old content")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"new valid content" * 10
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            setup_wordlists._download("http://example.com/test.txt", str(dest), "test_file", force=True)
            assert dest.read_bytes() == b"new valid content" * 10

    def test_download_handles_404_content(self, tmp_path):
        dest = tmp_path / "nonexistent.txt"
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"404: Not Found"
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            setup_wordlists._download("http://example.com/missing.txt", str(dest), "missing_file")
            assert not dest.exists()

    def test_download_handles_exception_and_cleans_tmp(self, tmp_path):
        dest = tmp_path / "fail.txt"
        tmp_file = tmp_path / "fail.txt.tmp"
        tmp_file.write_text("incomplete")

        with patch("urllib.request.urlopen", side_effect=Exception("Network error")):
            setup_wordlists._download("http://example.com/fail.txt", str(dest), "fail_file")
            assert not dest.exists()
            assert not tmp_file.exists()


class TestSetupEnterpriseWordlists:
    def test_extract_rockyou_gz(self, tmp_path):
        # Create a fake rockyou.txt.gz
        base = tmp_path / "app"
        base.mkdir()
        gz_path = base / "rockyou.txt.gz"
        with gzip.open(gz_path, "wb") as f:
            f.write(b"password123\nadmin\n")

        with patch("setup_wordlists.os.path.abspath", return_value=str(base / "setup_wordlists.py")):
            with patch("setup_wordlists.os.path.dirname", return_value=str(base)):
                with patch("setup_wordlists._download"):
                    setup_wordlists.setup_enterprise_wordlists(force=False)
                    extracted = base / "wordlists" / "rockyou.txt"
                    assert extracted.exists()
                    assert extracted.read_text() == "password123\nadmin\n"

    def test_skips_rockyou_if_extracted(self, tmp_path):
        base = tmp_path / "app"
        wl_dir = base / "wordlists"
        wl_dir.mkdir(parents=True)
        txt_path = wl_dir / "rockyou.txt"
        txt_path.write_text("existing_passwords\n")

        with patch("setup_wordlists.os.path.abspath", return_value=str(base / "setup_wordlists.py")):
            with patch("setup_wordlists.os.path.dirname", return_value=str(base)):
                with patch("setup_wordlists._download"):
                    with patch("gzip.open") as mock_gzip:
                        setup_wordlists.setup_enterprise_wordlists(force=False)
                        mock_gzip.assert_not_called()
