"""MCP Server for Hydra brute-force testing with SSD/VRAM tiering.

Native execution alternative to Docker Arsenal, storing full attack logs to SSD tier
and returning compact summaries to protect LLM context window / VRAM.
"""

import json
import os
import pathlib
import re
import subprocess
import sys

try:
    from mcp.server.fastmcp import FastMCP
except (ModuleNotFoundError, ImportError):
    from mcp.server.mcpserver import MCPServer as FastMCP

mcp = FastMCP("HydraServer")

# SSD storage tier
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
RAW_OUTPUTS_DIR = BASE_DIR / "data" / "raw_outputs"
RAW_OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
WORDLISTS_DIR = BASE_DIR / "wordlists"

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def _get_timeout(key: str, default: int) -> int:
    try:
        from src.utils.config import get as cfg_get
        return int(cfg_get(f"timeouts.{key}", default))
    except Exception:
        return default


def _resolve_local_wordlist(path_str: str) -> str:
    """Resolve wordlist path to an existing file or return the original path."""
    p = pathlib.Path(path_str)
    if p.is_file():
        return str(p.resolve())
    candidate = WORDLISTS_DIR / p.name
    if candidate.is_file():
        return str(candidate.resolve())
    return path_str


@mcp.tool()
def bruteforce_ssh(
    target_ip: str,
    username: str = "root",
    wordlist: str = "rockyou.txt",
    port: int = 22,
    threads: int = 16,
) -> str:
    """[DESTRUCTIVE] Brute-force SSH login credentials on the target.

    WARNING: Active attack that generates significant traffic. Operator approval required.

    Uses -e nsr for quick empty/name/reverse password checks, configurable
    thread count, and connection wait for reliability.

    Args:
        target_ip: Target IP address or hostname.
        username: Username to attempt login with (default: root).
        wordlist: Path or filename of the password wordlist file.
        port: SSH port number (default: 22).
        threads: Number of parallel login threads (default: 16, max: 64).
    """
    clean_target = str(target_ip or "").strip()
    clean_user = str(username or "root").strip()
    if not clean_target:
        return json.dumps({"error": "Target IP/hostname cannot be empty."})

    resolved_wordlist = _resolve_local_wordlist(wordlist)
    safe_target = re.sub(r"[^\w.-]", "_", clean_target)
    output_file = RAW_OUTPUTS_DIR / f"hydra_ssh_{safe_target}.txt"
    safe_threads = max(1, min(int(threads), 64))

    timeout = _get_timeout("hydra", 600)
    cmd = [
        "hydra",
        "-l", clean_user,
        "-P", resolved_wordlist,
        "-s", str(port),
        "-t", str(safe_threads),
        "-W", "3",
        "-e", "nsr",
        "-f",
        "-o", str(output_file),
        clean_target, "ssh",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return json.dumps({"error": "Hydra is not installed on the system."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Hydra SSH brute-force timed out after {timeout}s.", "target": clean_target, "port": port})
    except Exception as e:
        return json.dumps({"error": f"Failed to execute Hydra SSH brute-force: {e}"})

    output = result.stdout + "\n" + result.stderr

    # Check for Hydra-level connection errors
    output_lower = output.lower()
    hydra_errors = []
    for err_pattern in ["connection refused", "could not connect", "can not connect",
                        "no address found", "invalid target", "connection timed out"]:
        if err_pattern in output_lower:
            hydra_errors.append(err_pattern)

    if hydra_errors and "valid password" not in output_lower:
        try:
            saved_path = str(output_file.relative_to(BASE_DIR))
        except ValueError:
            saved_path = str(output_file)
        return json.dumps({
            "target": clean_target, "port": port, "status": "CONNECTION_ERROR",
            "error": f"Hydra could not connect to target: {', '.join(hydra_errors)}",
            "raw_output_saved": saved_path,
        })

    # Context Distillation: extract successful credentials only
    creds = re.findall(
        r"\[ssh\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)",
        result.stdout,
    )

    # Extract progress summary
    progress_info = ""
    for ln in output.split("\n"):
        ln_stripped = ln.strip()
        if "valid password" in ln_stripped.lower() or "target successfully" in ln_stripped.lower():
            progress_info = ln_stripped
            break

    try:
        saved_path = str(output_file.relative_to(BASE_DIR))
    except ValueError:
        saved_path = str(output_file)

    return json.dumps({
        "target": clean_target,
        "port": port,
        "service": "ssh",
        "username": clean_user,
        "credentials_found": [
            {"login": c[0], "password": c[1]} for c in creds
        ],
        "progress": progress_info,
        "raw_output_saved": saved_path,
    })



@mcp.tool()
def bruteforce_http_form(
    target_url: str,
    username: str,
    wordlist: str,
    form_params: str,
) -> str:
    """[DESTRUCTIVE] Brute-force HTTP login form credentials.

    WARNING: Active attack against web authentication. Operator approval required.

    Args:
        target_url: URL of the login page (e.g., http://target.com/login).
        username: Username to attempt login with.
        wordlist: Path to the password wordlist file.
        form_params: Hydra http-post-form string
                     (e.g., '/login:user=^USER^&pass=^PASS^:F=Invalid').
    """
    clean_url = str(target_url or "").strip()
    clean_user = str(username or "admin").strip()
    if not clean_url:
        return json.dumps({"error": "Invalid target URL format."})

    safe_target = re.sub(r"[^\w.-]", "_", clean_url[:40])
    output_file = RAW_OUTPUTS_DIR / f"hydra_http_{safe_target}.txt"

    # Extract hostname from URL
    host_match = re.search(r"https?://([^/:]+)", clean_url)
    if not host_match:
        return json.dumps({"error": "Invalid target URL format."})
    host = host_match.group(1)

    resolved_wordlist = _resolve_local_wordlist(wordlist)
    timeout = _get_timeout("hydra", 600)
    cmd = [
        "hydra",
        "-l", clean_user,
        "-P", resolved_wordlist,
        "-t", "4",
        "-o", str(output_file),
        host, "http-post-form", form_params,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return json.dumps({"error": "Hydra is not installed on the system."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Hydra HTTP form brute-force timed out after {timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Failed to execute Hydra HTTP brute-force: {e}"})

    creds = re.findall(
        r"\[http.*?\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)",
        result.stdout,
    )

    try:
        saved_path = str(output_file.relative_to(BASE_DIR))
    except ValueError:
        saved_path = str(output_file)

    return json.dumps({
        "target": clean_url,
        "service": "http-post-form",
        "username": clean_user,
        "credentials_found": [
            {"login": c[0], "password": c[1]} for c in creds
        ],
        "raw_output_saved": saved_path,
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
