"""MCP Server for Metasploit Framework with SSD/VRAM tiering.

Native execution alternative to Docker Arsenal, storing full exploit logs to SSD tier
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

mcp = FastMCP("MetasploitServer")

# SSD storage tier
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
RAW_OUTPUTS_DIR = BASE_DIR / "data" / "raw_outputs"
RAW_OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def _get_timeout(key: str, default: int) -> int:
    try:
        from src.utils.config import get as cfg_get
        return int(cfg_get(f"timeouts.{key}", default))
    except Exception:
        return default


@mcp.tool()
def msf_search_exploit(query: str) -> str:
    """Search the Metasploit database for exploit modules matching a query.

    Returns a distilled list of matching modules capped at 15 to protect VRAM.

    Args:
        query: Search term (e.g., 'apache 2.4', 'ms17-010', 'eternalblue').
    """
    clean_query = re.sub(r'["\';&|`$]', '', str(query or "").strip())
    if not clean_query:
        return json.dumps({"error": "Search query cannot be empty."})

    timeout = _get_timeout("metasploit", 180)
    cmd = ["msfconsole", "-q", "-x", f"search {clean_query}; exit"]

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
        return json.dumps({"error": "Metasploit Framework (msfconsole) is not installed."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Metasploit search timed out after {timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Failed to search Metasploit: {e}"})

    # Context Distillation: parse table rows for module paths
    modules = []
    for line in result.stdout.split("\n"):
        match = re.match(
            r"\s*\d+\s+(exploit/\S+)\s+(\d{4}-\d{2}-\d{2})?\s*(.*)", line,
        )
        if match:
            modules.append({
                "module": match.group(1).strip(),
                "date": (match.group(2) or "").strip(),
                "description": match.group(3).strip(),
            })

    # Save raw output to SSD tier
    safe_query = re.sub(r"[^\w.-]", "_", clean_query[:40])
    raw_file = RAW_OUTPUTS_DIR / f"msf_search_{safe_query}.txt"
    try:
        raw_file.write_text(result.stdout, encoding="utf-8", errors="replace")
        try:
            saved_path = str(raw_file.relative_to(BASE_DIR))
        except ValueError:
            saved_path = str(raw_file)
    except Exception:
        saved_path = "save_failed"

    return json.dumps({
        "query": clean_query,
        "modules_found": len(modules),
        "modules": modules[:15],
        "raw_output_saved": saved_path,
    })


@mcp.tool()
def fire_exploit(
    module: str,
    rhosts: str,
    lhost: str = "127.0.0.1",
    payload: str = "",
) -> str:
    """[DESTRUCTIVE] Execute a Metasploit exploit module against a target.

    WARNING: This fires a live exploit. Operator approval is mandatory.

    Args:
        module: Metasploit module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue').
        rhosts: Target IP address or hostname.
        lhost: Local IP for reverse connections (default: 127.0.0.1).
        payload: Optional payload override (e.g., 'windows/x64/meterpreter/reverse_tcp').
    """
    clean_mod = re.sub(r'["\';&|`$]', '', str(module or "").strip())
    clean_rhosts = re.sub(r'["\';&|`$]', '', str(rhosts or "").strip())
    clean_lhost = re.sub(r'["\';&|`$]', '', str(lhost or "127.0.0.1").strip())
    clean_payload = re.sub(r'["\';&|`$]', '', str(payload or "").strip())

    if not clean_mod or not clean_rhosts:
        return json.dumps({"error": "Module and rhosts are required parameters."})

    msf_commands = f"use {clean_mod}; set RHOSTS {clean_rhosts}; set LHOST {clean_lhost};"
    if clean_payload:
        msf_commands += f" set PAYLOAD {clean_payload};"
    msf_commands += " run; exit"

    timeout = _get_timeout("metasploit", 300)
    cmd = ["msfconsole", "-q", "-x", msf_commands]

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
        return json.dumps({"error": "Metasploit Framework (msfconsole) is not installed."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Metasploit exploit execution timed out after {timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Failed to fire exploit: {e}"})

    # Save raw output to SSD tier
    safe_target = re.sub(r"[^\w.-]", "_", clean_rhosts)
    safe_module = re.sub(r"[^\w.-]", "_", clean_mod.split("/")[-1])
    raw_file = RAW_OUTPUTS_DIR / f"msf_exploit_{safe_module}_{safe_target}.txt"
    try:
        raw_file.write_text(
            result.stdout + "\n---STDERR---\n" + result.stderr, encoding="utf-8", errors="replace",
        )
        try:
            saved_path = str(raw_file.relative_to(BASE_DIR))
        except ValueError:
            saved_path = str(raw_file)
    except Exception:
        saved_path = "save_failed"

    # Context Distillation: detect opened sessions
    sessions = re.findall(
        r"(session \d+ opened|Meterpreter session \d+ opened)",
        result.stdout,
        re.IGNORECASE,
    )

    return json.dumps({
        "module": clean_mod,
        "target": clean_rhosts,
        "sessions_opened": sessions if sessions else [],
        "exploit_output_summary": (
            result.stdout[-500:] if len(result.stdout) > 500 else result.stdout
        ),
        "raw_output_saved": saved_path,
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
