"""MCP Server for Nuclei vulnerability scanner with SSD/VRAM tiering.

Native execution alternative to Docker Arsenal, storing full JSONL scans to SSD tier
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

mcp = FastMCP("NucleiServer")

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
def nuclei_scan(target: str, severity: str = "critical,high,medium") -> str:
    """Scan a target for known CVEs and vulnerabilities using Nuclei templates.

    Returns a distilled summary of findings capped at 20 entries to protect VRAM.

    Args:
        target: Target URL or hostname to scan.
        severity: Comma-separated severity filter (critical,high,medium,low,info).
    """
    clean_target = str(target or "").strip()
    if not clean_target:
        return json.dumps({"error": "Target URL/hostname cannot be empty."})

    safe_target = re.sub(r"[^\w.-]", "_", clean_target[:60])
    json_output = RAW_OUTPUTS_DIR / f"nuclei_{safe_target}.jsonl"

    timeout = _get_timeout("nuclei", 300)
    cmd = [
        "nuclei", "-target", clean_target,
        "-severity", severity,
        "-jsonl", "-output", str(json_output),
        "-silent",
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
        return json.dumps({"error": "Nuclei is not installed on the system."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Nuclei scan timed out after {timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Failed to execute Nuclei scan: {e}"})

    # Context Distillation: parse JSONL findings
    findings = []
    if json_output.exists():
        try:
            for line in json_output.read_text(encoding="utf-8", errors="replace").strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    findings.append({
                        "template_id": entry.get("template-id", "unknown"),
                        "name": entry.get("info", {}).get("name", "unknown"),
                        "severity": entry.get("info", {}).get("severity", "unknown"),
                        "matched_at": entry.get("matched-at", ""),
                    })
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass

    try:
        saved_path = str(json_output.relative_to(BASE_DIR))
    except ValueError:
        saved_path = str(json_output)

    return json.dumps({
        "target": clean_target,
        "total_findings": len(findings),
        "findings": findings[:20],
        "raw_output_saved": saved_path,
    })


@mcp.tool()
def nuclei_scan_tech(target: str) -> str:
    """Detect technologies, frameworks, and services running on the target.

    Args:
        target: Target URL or hostname to fingerprint.
    """
    clean_target = str(target or "").strip()
    if not clean_target:
        return json.dumps({"error": "Target URL/hostname cannot be empty."})

    timeout = _get_timeout("whatweb", 120)
    cmd = [
        "nuclei", "-target", clean_target,
        "-tags", "tech",
        "-silent",
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
        return json.dumps({"error": "Nuclei is not installed on the system."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Nuclei tech detection timed out after {timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Failed to run tech detection: {e}"})

    techs = [
        line.strip()
        for line in result.stdout.strip().split("\n")
        if line.strip()
    ]

    return json.dumps({
        "target": clean_target,
        "technologies_detected": techs[:30],
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
