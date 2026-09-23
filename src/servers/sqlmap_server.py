"""MCP Server for SQLmap SQL injection testing with SSD/VRAM tiering.

Native execution alternative to Docker Arsenal, storing full scan and dump outputs to SSD tier
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

mcp = FastMCP("SQLmapServer")

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
def sqlmap_scan(target_url: str, forms: bool = False) -> str:
    """Scan a target URL for SQL injection vulnerabilities.

    Runs SQLmap in batch mode with safe defaults and returns a distilled
    summary of injectable parameters and discovered databases.

    Args:
        target_url: The URL to test (e.g., http://target.com/page?id=1).
        forms: If True, also crawl and test HTML forms on the page.
    """
    clean_target = str(target_url or "").strip()
    if not clean_target:
        return json.dumps({"error": "Target URL cannot be empty."})

    timeout = _get_timeout("sqlmap", 300)
    cmd = ["sqlmap", "-u", clean_target, "--batch", "--level=2", "--risk=1"]
    if forms:
        cmd.append("--forms")

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
        return json.dumps({"error": "SQLmap is not installed on the system."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"SQLmap scan timed out after {timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Failed to execute SQLmap scan: {e}"})

    # Context Distillation: extract injectable parameters and databases
    injectable = re.findall(r"Parameter:\s+(.+?)\s+\(", result.stdout)
    databases = re.findall(
        r"available databases\s*\[.*?\]:\s*(.*?)(?:\n\n|\Z)",
        result.stdout,
        re.DOTALL,
    )

    # Save full output to SSD tier
    safe_target = re.sub(r"[^\w.-]", "_", clean_target[:60])
    raw_file = RAW_OUTPUTS_DIR / f"sqlmap_{safe_target}.txt"
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

    databases_list = [
        ln.strip().lstrip("[*] ").strip()
        for ln in databases[0].strip().split("\n")
        if ln.strip()
    ] if databases else []

    return json.dumps({
        "target": clean_target,
        "injectable_params": injectable if injectable else [],
        "databases_found": databases_list,
        "raw_output_saved": saved_path,
    })


@mcp.tool()
def dump_table(target_url: str, database: str, table: str) -> str:
    """[DESTRUCTIVE] Dump a specific database table via confirmed SQL injection.

    WARNING: This extracts live data from the target. Operator approval required.

    Args:
        target_url: The URL confirmed vulnerable to SQL injection.
        database: Name of the database to target.
        table: Name of the table to dump.
    """
    clean_target = str(target_url or "").strip()
    clean_db = re.sub(r"[^\w.-]", "", str(database or "").strip())
    clean_tbl = re.sub(r"[^\w.-]", "", str(table or "").strip())
    if not clean_target or not clean_db or not clean_tbl:
        return json.dumps({"error": "Target URL, database, and table are all required and must be valid."})

    timeout = _get_timeout("sqlmap", 600)
    cmd = [
        "sqlmap", "-u", clean_target, "--batch",
        "-D", clean_db, "-T", clean_tbl, "--dump",
        "--threads=2",
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
        return json.dumps({"error": "SQLmap is not installed on the system."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"SQLmap dump timed out after {timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Failed to dump table: {e}"})

    # Save raw dump to SSD tier
    safe_target = re.sub(r"[^\w.-]", "_", clean_target[:40])
    raw_file = RAW_OUTPUTS_DIR / f"sqlmap_dump_{safe_target}_{clean_db}_{clean_tbl}.txt"
    try:
        raw_file.write_text(result.stdout, encoding="utf-8", errors="replace")
        try:
            saved_path = str(raw_file.relative_to(BASE_DIR))
        except ValueError:
            saved_path = str(raw_file)
    except Exception:
        saved_path = "save_failed"

    # Context Distillation: count extracted rows
    row_count = len(re.findall(r"^\|", result.stdout, re.MULTILINE))

    return json.dumps({
        "target": clean_target,
        "database": clean_db,
        "table": clean_tbl,
        "rows_extracted": max(0, row_count - 2),
        "raw_dump_saved": saved_path,
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
