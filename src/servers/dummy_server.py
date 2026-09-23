"""Dummy / Diagnostic MCP Server for testing stdio communication, connectivity, and baseline tooling."""

from datetime import datetime
import json
import os
import platform
import socket
import sys

try:
    from mcp.server.fastmcp import FastMCP
except (ModuleNotFoundError, ImportError):
    from mcp.server.mcpserver import MCPServer as FastMCP

# Initialize FastMCP server
mcp = FastMCP("DummyServer")


@mcp.tool()
def get_system_time() -> str:
    """Get the current system date and time in ISO format."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@mcp.tool()
def get_system_info() -> str:
    """Retrieve host system information (OS platform, architecture, Python version)."""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
        "node_hostname": platform.node(),
        "cpu_count": os.cpu_count() or 1,
    }
    return json.dumps(info)


@mcp.tool()
def ping_target(host: str, port: int = 80, timeout_seconds: float = 3.0) -> str:
    """Perform a lightweight TCP connection check to test if a target host and port are reachable.

    Args:
        host: Target hostname or IP address.
        port: TCP port number to probe (default: 80).
        timeout_seconds: Timeout in seconds for connection attempt (default: 3.0).
    """
    clean_host = str(host or "").strip()
    if not clean_host:
        return json.dumps({"error": "Host cannot be empty."})
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(max(0.5, float(timeout_seconds)))
        result = sock.connect_ex((clean_host, int(port)))
        sock.close()
        is_open = (result == 0)
        return json.dumps({
            "host": clean_host,
            "port": int(port),
            "reachable": is_open,
            "status": "OPEN" if is_open else "CLOSED_OR_FILTERED",
        })
    except Exception as e:
        return json.dumps({"host": clean_host, "port": int(port), "reachable": False, "error": str(e)})


if __name__ == "__main__":
    mcp.run(transport="stdio")
