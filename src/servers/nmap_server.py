"""MCP Server for Nmap network security tooling with SSD/VRAM tiering.

Native execution alternative to Docker Arsenal, storing full XML scans to SSD tier
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

# Initialize FastMCP server
mcp = FastMCP("NmapServer")

# Ensure SSD storage tier directory exists
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
def scan_ports_fast(target_ip: str) -> str:
    """Perform a fast port scan on target_ip and return discovered open ports.
    
    Args:
        target_ip: The target hostname or IP address to scan.
    """
    clean_target = str(target_ip or "").strip()
    if not clean_target:
        return json.dumps({"error": "Target IP/hostname cannot be empty."})

    timeout = _get_timeout("fast_scan", 120)
    cmd = ["nmap", "-F", "-T4", clean_target]
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
        return json.dumps({"error": "Nmap is not installed on the system."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Nmap fast scan timed out after {timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Failed to execute fast scan: {e}"})

    # Context Distillation: parse stdout to extract open ports only (O(N) regex)
    open_ports = [
        int(match.group(1))
        for match in re.finditer(r"(\d+)/(?:tcp|udp)\s+open", result.stdout)
    ]

    return json.dumps({"target": clean_target, "open_ports": open_ports})


@mcp.tool()
def scan_port_deep(target_ip: str, port: int) -> str:
    """Perform a deep service and version scan on a single port.
    
    Dumps the raw XML output to the local SSD storage tier and returns
    only a distilled metadata summary to protect LLM context / VRAM.
    
    Args:
        target_ip: Target hostname or IP address.
        port: The specific port number to inspect.
    """
    clean_target = str(target_ip or "").strip()
    if not clean_target:
        return json.dumps({"error": "Target IP/hostname cannot be empty."})

    safe_target = re.sub(r"[^\w.-]", "_", clean_target)
    xml_output_file = RAW_OUTPUTS_DIR / f"nmap_{safe_target}_{port}.xml"

    timeout = _get_timeout("deep_scan", 180)
    cmd = [
        "nmap",
        "-sV",
        "-p",
        str(port),
        "-oX",
        str(xml_output_file),
        clean_target,
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
        return json.dumps({"error": "Nmap is not installed on the system."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Nmap deep scan timed out after {timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Failed to execute deep scan: {e}"})

    # Context Distillation: extract Service Name and Version from stdout
    service_match = re.search(
        rf"{port}/(?:tcp|udp)\s+open\s+([^\r\n]+)",
        result.stdout,
    )

    if service_match:
        extracted_string = service_match.group(1).strip()
    else:
        extracted_string = "Service/version details not identified or port closed."

    return (
        f"Port {port} is open. Service details: {extracted_string}. "
        f"Full raw XML saved to data/raw_outputs/"
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
