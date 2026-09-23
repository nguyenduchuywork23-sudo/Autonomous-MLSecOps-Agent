"""MCP Server: Docker Arsenal — Container-based Security Toolkit.

Every tool invokes a Docker container via subprocess, ensuring full
environment isolation and OPSEC. Context Distillation is applied to
all outputs so only compact summaries reach the LLM's context window.

Tools (31 total):
  Recon (23): docker_resolve_dns, docker_scan_ports_fast, docker_scan_ports_deep, docker_crawl_web,
              browse_webpage, docker_whatweb, docker_nikto_scan, docker_nuclei_scan,
              docker_dirb_scan, docker_subfinder, docker_ffuf, docker_testssl,
              docker_sensitive_files_scan, docker_cors_scan, docker_httpx_probe,
              docker_ssl_cert_audit, docker_dns_security_audit, docker_security_txt_audit,
              docker_cookie_security_audit, docker_http_headers_audit, docker_api_docs_audit,
              docker_subdomain_takeover_audit, docker_waf_detect
  Exploit (8): docker_sqlmap_scan, docker_sqlmap_dump, docker_bruteforce, bruteforce_ssh,
               bruteforce_http_form, docker_wpscan, docker_msf_search, docker_xss_scan
"""

import functools
import json
import os
import re
import socket
import ssl
import subprocess
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

try:
    from mcp.server.fastmcp import FastMCP
except (ModuleNotFoundError, ImportError):
    from mcp.server.mcpserver import MCPServer as FastMCP

mcp = FastMCP("DockerArsenal")

# Base path for wordlists (resolved relative to this file)
_WORDLISTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "wordlists"))
# Normalized path for Docker volume mounting on Windows/Linux
_WORDLISTS_MOUNT = _WORDLISTS_DIR.replace("\\", "/")

# SSD storage tier for raw attack outputs (forensics/audit)
_RAW_OUTPUTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "raw_outputs"))
os.makedirs(_RAW_OUTPUTS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# High-Performance Pre-compiled Regular Expressions
# ---------------------------------------------------------------------------
_RE_SQLMAP_PARAM = re.compile(r"Parameter:\s+(.+?)\s+\(")
_RE_SQLMAP_DB_SECTION = re.compile(r"available databases\s*\[.*?\]:\s*(.*?)(?:\n\n|\Z)", re.DOTALL)
_RE_CLEAN_ALPHANUM = re.compile(r"[^\w.-]")
_RE_SANITIZED_INPUT = re.compile(r'["\';&|`$]')
_RE_BRACKET_CONTENT = re.compile(r"\[([^\]]+)\]")
_RE_HTML_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_RE_DMARC_POLICY = re.compile(r'\bp=([a-zA-Z]+)')
_RE_SITEMAP_LOC = re.compile(r'<loc>(https?://[^<]+)</loc>', re.IGNORECASE)
_RE_HTTP_STATUS = re.compile(r"\[\+\]|\[!\]")
_RE_NMAP_PORT_SVC = re.compile(r"(\d+)/(?:tcp|udp)\s+open\s+(\S+)")
_RE_NMAP_PORT_FALLBACK = re.compile(r"(\d+)/(?:tcp|udp)\s+open")
_RE_NMAP_DEEP_PORT = re.compile(r"(\d+)/(?:tcp|udp)\s+open\s+(\S+)(?:[ \t]+([^\r\n]*))?")
_RE_NMAP_SCRIPT_LINE = re.compile(r"\|_?\s*(.+)")
_RE_DIRSEARCH_STATUS = re.compile(r"/.+\s+\(Status:\s*\d+\)")
_RE_GIT_HASH = re.compile(r"^[0-9a-f]{40}$")

WORDLIST_ALIASES = {
    "common.txt": "dirb_common.txt",
    "common": "dirb_common.txt",
    "dirb.txt": "dirb_common.txt",
    "dirb": "dirb_common.txt",
    "directory": "dirb_common.txt",
    "directory.txt": "dirb_common.txt",
    "default": "dirb_common.txt",
    "default.txt": "dirb_common.txt",
    "wordlist": "dirb_common.txt",
    "wordlist.txt": "dirb_common.txt",
    "dirb_common": "dirb_common.txt",
    "rockyou": "rockyou.txt",
    "rockyou.txt": "rockyou.txt",
    "passwords.txt": "rockyou.txt",
    "passwords": "rockyou.txt",
    "password": "rockyou.txt",
    "password.txt": "rockyou.txt",
    "fasttrack": "fasttrack.txt",
    "fasttrack.txt": "fasttrack.txt",
    "probable": "probable.txt",
    "probable.txt": "probable.txt",
    "subdomains.txt": "dnsmap.txt",
    "subdomains": "dnsmap.txt",
    "subdomain": "dnsmap.txt",
    "subdomain.txt": "dnsmap.txt",
    "dnsmap": "dnsmap.txt",
    "dnsmap.txt": "dnsmap.txt",
    "users.txt": "fasttrack.txt",
    "users": "fasttrack.txt",
    "user.txt": "fasttrack.txt",
    "user": "fasttrack.txt",
    "usernames.txt": "fasttrack.txt",
    "usernames": "fasttrack.txt",
    "logins.txt": "fasttrack.txt",
    "logins": "fasttrack.txt",
    "login.txt": "fasttrack.txt",
    "accounts.txt": "fasttrack.txt",
}


@functools.lru_cache(maxsize=256)
def _resolve_wordlist(name: str) -> str | None:
    """Return the absolute path to a wordlist file, supporting aliases, or None if missing."""
    clean_name = os.path.basename(name.strip())
    resolved_name = WORDLIST_ALIASES.get(clean_name.lower(), clean_name)
    path = os.path.join(_WORDLISTS_DIR, resolved_name)
    if os.path.isfile(path):
        return path
    # Try case-insensitive lookup
    if os.path.isdir(_WORDLISTS_DIR):
        for existing in os.listdir(_WORDLISTS_DIR):
            if existing.lower() == resolved_name.lower():
                return os.path.join(_WORDLISTS_DIR, existing)

    # On-demand extraction for rockyou.txt if rockyou.txt.gz exists
    if resolved_name.lower() == "rockyou.txt":
        project_root = os.path.abspath(os.path.join(_WORDLISTS_DIR, ".."))
        gz_candidates = [
            os.path.join(project_root, "rockyou.txt.gz"),
            os.path.join(_WORDLISTS_DIR, "rockyou.txt.gz"),
        ]
        for gz_path in gz_candidates:
            if os.path.isfile(gz_path):
                try:
                    import gzip
                    import shutil
                    target_txt = os.path.join(_WORDLISTS_DIR, "rockyou.txt")
                    os.makedirs(_WORDLISTS_DIR, exist_ok=True)
                    with gzip.open(gz_path, "rb") as f_in, open(target_txt, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                    if os.path.isfile(target_txt):
                        return target_txt
                except Exception:
                    pass

    return None


@functools.lru_cache(maxsize=128)
def _normalize_target(target: str) -> str:
    """Extract hostname or IP from a target string, stripping protocol, port, and path."""
    from urllib.parse import urlparse
    target = target.strip()
    if '://' in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    # Strip any trailing path first
    clean = target.split('/')[0]
    # IPv6 format [::1]:8080 or ::1
    if clean.startswith('[') and ']' in clean:
        return clean.split(']')[0].lstrip('[')
    # If it has a port (single colon, not IPv6)
    if clean.count(':') == 1:
        return clean.split(':')[0]
    return clean


def _ensure_url_scheme(url: str, default_scheme: str = "http") -> str:
    """Ensure a URL has http:// or https:// scheme for web-based security tools."""
    url = url.strip()
    if not url:
        return url
    if not (url.startswith("http://") or url.startswith("https://")):
        return f"{default_scheme}://{url}"
    return url


@functools.lru_cache(maxsize=128)
def _get_timeout(tool_key: str, default_seconds: int) -> int:
    """Read tool timeout from config.yaml with fallback to default_seconds."""
    try:
        import sys
        sys_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        if sys_path not in sys.path:
            sys.path.insert(0, sys_path)
        from src.utils.config import get as cfg_get
        val = cfg_get(f"timeouts.{tool_key}", default_seconds)
        return int(val)
    except Exception:
        return default_seconds


# ===========================================================================
# Tool 0: DNS Resolution Helper
# ===========================================================================

@mcp.tool()
def docker_resolve_dns(hostname: str) -> str:
    """Resolve a hostname/domain to IP address(es). Use FIRST when you need an IP for port scanning.

    Args:
        hostname: Domain name to resolve (e.g., 'example.com'). Accepts URLs too (http:// is auto-stripped).
    """
    import socket
    clean_host = _normalize_target(hostname)
    if not clean_host:
        return json.dumps({"error": "Empty or invalid hostname provided."})
    try:
        results = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC)
        ips = sorted(set(r[4][0] for r in results))
        return json.dumps({"hostname": clean_host, "ip_addresses": ips, "primary_ip": ips[0] if ips else None})
    except (socket.gaierror, OSError, Exception) as e:
        return json.dumps({"error": f"DNS resolution failed for '{clean_host}': {e}"})


# ===========================================================================
# Tool 1: Nmap Fast Port Scan (Docker)
# ===========================================================================

@mcp.tool()
def docker_scan_ports_fast(target: str) -> str:
    """Run a fast port scan on the target using the Nmap Docker container.

    Discovers open TCP ports with host-discovery disabled (-Pn) for speed.

    Args:
        target: Target IP, hostname, or URL (http:// is auto-stripped).
    """
    target = _normalize_target(target)
    if not target:
        return json.dumps({"error": "Empty or invalid target provided."})
    scan_timeout = _get_timeout("fast_scan", 120)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "instrumentisto/nmap",
             "-F", "-T4", "-Pn", target],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Nmap scan timed out after {scan_timeout}s."})

    # Context Distillation: extract open ports with service names
    open_ports = []
    for m in _RE_NMAP_PORT_SVC.finditer(result.stdout):
        open_ports.append({"port": int(m.group(1)), "service": m.group(2)})

    # Fallback: just port numbers
    if not open_ports:
        open_ports = [
            {"port": int(m.group(1)), "service": "unknown"}
            for m in _RE_NMAP_PORT_FALLBACK.finditer(result.stdout)
        ]

    # If scan returned non-zero code and no open ports, attach error snippet for LLM awareness
    if result.returncode != 0 and not open_ports:
        err_msg = (result.stderr or "").strip()[:300]
        if err_msg:
            return json.dumps({"target": target, "open_ports": [], "error": f"Nmap scan failed (exit code {result.returncode}): {err_msg}"})

    return json.dumps({"target": target, "open_ports": open_ports})


# ===========================================================================
# Tool 2: Nmap Deep Service Scan (Docker) — NEW
# ===========================================================================

@mcp.tool()
def docker_scan_ports_deep(target: str, ports: str = "80,443,22,21,3306,8080") -> str:
    """Deep-scan specific ports for service versions and OS detection using Nmap.

    Use this AFTER docker_scan_ports_fast to identify software versions
    on discovered open ports. Runs -sV -sC --version-intensity 5.

    Args:
        target: Target IP, hostname, or URL (http:// is auto-stripped).
        ports: Comma-separated list of ports to deep-scan (e.g., '80,443,22').
    """
    target = _normalize_target(target)
    if not target:
        return json.dumps({"error": "Empty or invalid target provided."})

    if not ports:
        ports = "80,443,22,21,3306,8080"
    if isinstance(ports, (list, tuple, set)):
        ports = ",".join(str(p).strip() for p in ports)
    elif not isinstance(ports, str):
        ports = str(ports).strip()
    ports = ports.replace(" ", "")
    if not ports:
        ports = "80,443,22,21,3306,8080"

    scan_timeout = _get_timeout("deep_scan", 300)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "instrumentisto/nmap",
             "-sV", "-sC", "--version-intensity", "5",
             "-Pn", "-p", ports, target],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Nmap deep scan timed out after {scan_timeout}s."})

    # Context Distillation: extract port/service/version lines
    services = []
    for m in _RE_NMAP_DEEP_PORT.finditer(result.stdout):
        services.append({
            "port": int(m.group(1)),
            "service": m.group(2),
            "version_info": (m.group(3) or "").strip()[:120],
        })

    # Extract any NSE script output (capped)
    script_output = []
    for m in _RE_NMAP_SCRIPT_LINE.finditer(result.stdout):
        line = m.group(1).strip()
        if line and len(script_output) < 15:
            script_output.append(line)

    if result.returncode != 0 and not services:
        err_msg = (result.stderr or "").strip()[:300]
        if err_msg:
            return json.dumps({"target": target, "ports_scanned": ports, "services": [], "error": f"Nmap deep scan failed (exit code {result.returncode}): {err_msg}"})

    return json.dumps({
        "target": target,
        "ports_scanned": ports,
        "services": services,
        "nse_scripts": script_output[:15],
    })


# ===========================================================================
# Tool 3: Nuclei Vulnerability Scan (Docker)
# ===========================================================================

@mcp.tool()
def docker_nuclei_scan(target_url: str) -> str:
    """Scan the target for known CVEs and vulnerabilities using Nuclei.

    Focuses on critical and high severity findings only.

    Args:
        target_url: Target URL to scan (e.g., http://192.168.1.1).
    """
    target_url = _ensure_url_scheme(target_url)
    scan_timeout = _get_timeout("nuclei", 300)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "projectdiscovery/nuclei",
             "-u", target_url, "-severity", "critical,high", "-silent"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Nuclei scan timed out after {scan_timeout}s."})

    lines = [ln.strip() for ln in result.stdout.strip().split("\n") if ln.strip()]
    if result.returncode != 0 and not lines:
        err_msg = (result.stderr or "").strip()[:300]
        return json.dumps({"target": target_url, "error": f"Nuclei scan failed (exit code {result.returncode}): {err_msg or 'unknown error'}"})

    summary = lines[:20] if lines else ["No critical/high findings detected."]

    return json.dumps({"target": target_url, "findings": summary})


# ===========================================================================
# Tool 4: SQLmap SQL Injection Scan (Docker)
# ===========================================================================

@mcp.tool()
def docker_sqlmap_scan(target_url: str) -> str:
    """Test the target URL for SQL injection vulnerabilities using SQLmap.

    Runs in full-auto beast mode: crawls 1 level deep, tests all forms,
    uses random User-Agent, level 2 / risk 2 for aggressive detection.

    Args:
        target_url: Target URL (e.g., http://target.com or http://target.com/page?id=1).
    """
    target_url = _ensure_url_scheme(target_url)
    scan_timeout = _get_timeout("sqlmap", 300)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "secsi/sqlmap",
             "-u", target_url,
             "--batch", "--random-agent",
             "--crawl=1", "--forms",
             "--level=2", "--risk=2",
             "--dbs"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"SQLmap scan timed out after {scan_timeout}s."})

    injectable = _RE_SQLMAP_PARAM.findall(result.stdout)
    db_section = _RE_SQLMAP_DB_SECTION.search(result.stdout)
    databases = []
    if db_section:
        databases = [
            ln.strip().strip("[*] ")
            for ln in db_section.group(1).strip().split("\n")
            if ln.strip()
        ]

    return json.dumps({
        "target": target_url,
        "injectable_params": injectable,
        "databases": databases,
    })


# ===========================================================================
# Tool 4b: SQLmap Table Dump (Docker) — NEW / DESTRUCTIVE
# ===========================================================================

@mcp.tool()
def docker_sqlmap_dump(target_url: str, database: str, table: str) -> str:
    """Dump data from a specific database table via confirmed SQL injection.

    Use this AFTER docker_sqlmap_scan has confirmed injectable parameters
    and discovered database names. Requires operator approval.

    Args:
        target_url: The injectable URL (e.g., http://target.com/page?id=1).
        database: Database name discovered by docker_sqlmap_scan.
        table: Table name to dump.
    """
    target_url = _ensure_url_scheme(target_url)
    clean_db = _RE_CLEAN_ALPHANUM.sub("", str(database or "").strip())
    clean_table = _RE_CLEAN_ALPHANUM.sub("", str(table or "").strip())
    if not clean_db or not clean_table:
        return json.dumps({"error": "Both database and table parameters are required and must be valid identifiers."})

    scan_timeout = _get_timeout("sqlmap", 300)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "secsi/sqlmap",
             "-u", target_url,
             "--batch", "--random-agent",
             "-D", clean_db, "-T", clean_table, "--dump",
             "--threads=2"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"SQLmap dump timed out after {scan_timeout}s."})

    # Context Distillation: extract table data lines (CSV-like or formatted)
    lines = result.stdout.strip().split("\n")
    data_lines = [
        ln.strip() for ln in lines
        if ln.strip() and not ln.strip().startswith("[") and "|" in ln
    ]

    # Also grab summary lines
    summary_lines = [ln.strip() for ln in lines if "entries" in ln.lower() or "dumped" in ln.lower()]

    return json.dumps({
        "target": target_url,
        "database": database,
        "table": table,
        "dumped_rows": data_lines[:30],
        "summary": summary_lines[:5],
    })


# ===========================================================================
# Tool 5: Katana Web Crawler (Docker)
# ===========================================================================

@mcp.tool()
def docker_crawl_web(target_url: str) -> str:
    """Crawl a website to discover internal URLs with query parameters.

    Uses ProjectDiscovery Katana with JavaScript crawling, depth-2, random UA.
    Returns up to 10 unique parameterized URLs suitable for injection testing.

    Args:
        target_url: Target URL to crawl (e.g., http://target.com).
    """
    target_url = _ensure_url_scheme(target_url)
    scan_timeout = _get_timeout("crawler", 60)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "projectdiscovery/katana",
             "-u", target_url,
             "-d", "2", "-jc",
             "-f", "qurl",
             "-timeout", "20",
             "-random-agent"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )

        if result.returncode != 0 and not result.stdout.strip():
            err_msg = (result.stderr or "").strip()[:300]
            if err_msg:
                return json.dumps({"target": target_url, "error": f"Crawler failed (exit code {result.returncode}): {err_msg}"})

        urls = result.stdout.strip().split("\n")
        param_urls = list(set(u for u in urls if "?" in u))[:10]
        all_urls = list(set(u for u in urls if u.startswith("http")))[:15]

        return json.dumps({
            "status": "success",
            "parameterized_endpoints": param_urls,
            "all_discovered_urls": all_urls if not param_urls else [],
        })

    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Crawling timed out after {scan_timeout}s."})
    except Exception as e:
        return json.dumps({"error": f"Crawler failed: {str(e)}"})


# ===========================================================================
# Tool 6: Hydra Brute-Force Check (Docker) — Safe mode
# ===========================================================================

@mcp.tool()
def docker_bruteforce(target: str) -> str:
    """Verify that the Hydra brute-force container is operational.

    Runs the help command only for safety. Actual brute-force requires
    operator approval at the orchestrator level.

    Args:
        target: Target IP or hostname (logged for audit, not attacked in this mode).
    """
    scan_timeout = _get_timeout("hydra", 30)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "vanhauser/hydra", "-h"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Hydra container timed out after {scan_timeout}s."})

    if result.returncode in (0, 255):
        return json.dumps({
            "status": "capability_check_only",
            "hydra_available": True,
            "target": target,
            "message": (
                "Hydra brute-force container is operational. "
                "NO attack was performed in this health-check mode. "
                "To perform an actual brute-force attack, use 'bruteforce_ssh' or "
                "'bruteforce_http_form' with specific targets and parameters (requires operator approval)."
            ),
        }, indent=2)
    return json.dumps({"error": f"Hydra exited with code {result.returncode}."})


# ===========================================================================
# Tool 6b: Hydra SSH Brute-Force (Docker) — DESTRUCTIVE
# ===========================================================================

@mcp.tool()
def bruteforce_ssh(target: str, username: str = "root", wordlist: str = "rockyou.txt", port: int = 22, threads: int = 16) -> str:
    """Brute-force SSH login on the target using Hydra Docker container.

    Mounts the local wordlists/ directory into the container and attacks
    the specified user account. Requires operator approval.

    Uses --network host for direct target access, -e nsr for quick
    empty/name/reverse password checks, and configurable thread count.

    Args:
        target: Target IP, hostname, or URL (http:// is auto-stripped).
        username: SSH username to attack (default: root).
        wordlist: Password wordlist filename inside wordlists/ (default: rockyou.txt).
        port: SSH port number (default: 22).
        threads: Number of parallel login threads (default: 16, max: 64).
    """
    target = _normalize_target(target)
    if not target:
        return json.dumps({"error": "Target IP/hostname cannot be empty."})

    wordlist_path = _resolve_wordlist(wordlist)
    if not wordlist_path:
        return json.dumps({"error": f"Wordlist '{wordlist}' not found in {_WORDLISTS_DIR}. Run setup_wordlists.py first."})

    resolved_wordlist = os.path.basename(wordlist_path)
    scan_timeout = _get_timeout("hydra", 600)
    safe_threads = max(1, min(int(threads), 64))

    # Output file for forensics/audit
    safe_target = _RE_CLEAN_ALPHANUM.sub("_", target)
    output_file = os.path.join(_RAW_OUTPUTS_DIR, f"hydra_ssh_{safe_target}.txt")

    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--network", "host",
             "-v", f"{_WORDLISTS_MOUNT}:/wordlists:ro",
             "vanhauser/hydra",
             "-l", username,
             "-P", f"/wordlists/{resolved_wordlist}",
             "-s", str(port),
             "-t", str(safe_threads),
             "-W", "3",
             "-e", "nsr",
             "-f",
             f"ssh://{target}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Hydra SSH brute-force timed out after {scan_timeout}s.", "target": target, "port": port})

    output = result.stdout + "\n" + result.stderr

    # Save raw output to SSD tier for forensics
    try:
        with open(output_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(output)
    except OSError:
        pass  # Non-critical: don't fail the scan if log write fails

    # Check for Hydra-level errors before parsing credentials
    output_lower = output.lower()
    hydra_errors = []
    for err_pattern in ["connection refused", "could not connect", "target.*not found",
                        "can not connect", "no address found", "invalid target",
                        "connection timed out"]:
        if err_pattern.replace(".*", "") in output_lower or (
            ".*" in err_pattern and re.search(err_pattern, output_lower)
        ):
            hydra_errors.append(err_pattern)

    if hydra_errors and "valid password" not in output_lower:
        return json.dumps({
            "target": target, "port": port, "status": "CONNECTION_ERROR",
            "error": f"Hydra could not connect to target: {', '.join(hydra_errors)}",
            "raw_output_saved": output_file,
        })

    # Parse successful credentials
    valid_creds = []
    for ln in output.split("\n"):
        ln_clean = ln.strip()
        ln_lower = ln_clean.lower()
        if "login:" in ln_lower and "password:" in ln_lower and "0 valid" not in ln_lower:
            valid_creds.append(ln_clean)

    # Extract progress summary from Hydra output
    progress_info = ""
    for ln in output.split("\n"):
        ln_stripped = ln.strip()
        if "valid password" in ln_stripped.lower() or "target successfully" in ln_stripped.lower():
            progress_info = ln_stripped
            break

    if valid_creds:
        return json.dumps({
            "target": target, "port": port, "status": "CREDENTIALS_FOUND",
            "results": list(set(valid_creds))[:10],
            "progress": progress_info,
            "raw_output_saved": output_file,
        })
    return json.dumps({
        "target": target, "port": port, "status": "NO_CREDENTIALS_FOUND",
        "message": "No valid credentials found.",
        "progress": progress_info,
        "raw_output_saved": output_file,
    })


# ===========================================================================
# Tool 6c: Hydra HTTP Form Brute-Force (Docker) — DESTRUCTIVE
# ===========================================================================

@mcp.tool()
def bruteforce_http_form(target_url: str, username: str = "admin", wordlist: str = "rockyou.txt",
                         login_path: str = "/login", form_params: str = "username=^USER^&password=^PASS^",
                         failure_string: str = "Invalid") -> str:
    """Brute-force an HTTP POST login form using Hydra Docker container.

    Mounts the local wordlists/ directory and attacks a web login form.
    Requires operator approval.

    Args:
        target_url: Target base URL (e.g., http://192.168.1.10).
        username: Username to brute-force (default: admin).
        wordlist: Password wordlist filename inside wordlists/ (default: rockyou.txt).
        login_path: Path to the login form (default: /login).
        form_params: POST form params with ^USER^ and ^PASS^ placeholders.
        failure_string: String on a failed login page (default: Invalid).
    """
    from urllib.parse import urlparse

    wordlist_path = _resolve_wordlist(wordlist)
    if not wordlist_path:
        return json.dumps({"error": f"Wordlist '{wordlist}' not found in {_WORDLISTS_DIR}. Run setup_wordlists.py first."})

    resolved_wordlist = os.path.basename(wordlist_path)
    scan_timeout = _get_timeout("hydra", 600)

    parsed = urlparse(target_url)
    host = parsed.hostname or target_url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    http_module = "https-post-form" if parsed.scheme == "https" else "http-post-form"
    form_string = f"{login_path}:{form_params}:{failure_string}"

    try:
        result = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{_WORDLISTS_MOUNT}:/wordlists:ro",
             "vanhauser/hydra",
             "-l", username,
             "-P", f"/wordlists/{resolved_wordlist}",
             "-s", str(port),
             "-t", "4", "-f",
             host, http_module, form_string],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Hydra HTTP form brute-force timed out after {scan_timeout}s."})

    output = result.stdout + "\n" + result.stderr

    # Save raw output to SSD tier for forensics
    safe_host = _RE_CLEAN_ALPHANUM.sub("_", host)
    output_file = os.path.join(_RAW_OUTPUTS_DIR, f"hydra_http_{safe_host}.txt")
    try:
        with open(output_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(output)
    except OSError:
        pass

    valid_creds = []
    for ln in output.split("\n"):
        ln_clean = ln.strip()
        ln_lower = ln_clean.lower()
        if "login:" in ln_lower and "password:" in ln_lower and "0 valid" not in ln_lower:
            valid_creds.append(ln_clean)

    if valid_creds:
        return json.dumps({
            "target": target_url,
            "status": "CREDENTIALS_FOUND",
            "results": list(set(valid_creds))[:10],
            "raw_output_saved": output_file,
        })
    return json.dumps({
        "target": target_url,
        "status": "NO_CREDENTIALS_FOUND",
        "message": "No valid credentials found.",
        "raw_output_saved": output_file,
    })


# ===========================================================================
# Tool 7: WPScan WordPress Scanner (Docker)
# ===========================================================================

@mcp.tool()
def docker_wpscan(target_url: str) -> str:
    """Scan a WordPress site for vulnerabilities, plugins, and themes.

    Args:
        target_url: Target WordPress URL (e.g., http://target.com).
    """
    target_url = _ensure_url_scheme(target_url)
    scan_timeout = _get_timeout("wpscan", 300)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "wpscanteam/wpscan",
             "--url", target_url, "--no-banner", "--no-update"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"WPScan timed out after {scan_timeout}s."})

    findings = [
        ln.strip()
        for ln in result.stdout.split("\n")
        if _RE_HTTP_STATUS.search(ln)
    ]

    if not findings:
        return json.dumps({
            "target": target_url,
            "summary": "No WordPress findings detected (site may not be WordPress).",
        })

    return json.dumps({
        "target": target_url,
        "findings": findings[:25],
    })


# ===========================================================================
# Tool 8: Metasploit Exploit Search (Docker)
# ===========================================================================

@mcp.tool()
def docker_msf_search(cve_or_keyword: str) -> str:
    """Search the Metasploit database for exploit modules matching a CVE or keyword.

    Returns the top 5 matching exploit modules to protect VRAM.

    Args:
        cve_or_keyword: Search term (e.g., 'CVE-2021-44228', 'apache 2.4', 'eternalblue').
    """
    clean_query = _RE_SANITIZED_INPUT.sub('', str(cve_or_keyword or "").strip())
    if not clean_query:
        return json.dumps({"error": "cve_or_keyword parameter is required and cannot be empty."})

    scan_timeout = _get_timeout("metasploit", 180)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm",
             "metasploitframework/metasploit-framework",
             "./msfconsole", "-q", "-x", f"search {clean_query}; exit"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Metasploit search timed out after {scan_timeout}s."})

    exploit_lines = [
        ln.strip()
        for ln in result.stdout.split("\n")
        if "exploit/" in ln
    ]

    top_exploits = exploit_lines[:5] if exploit_lines else ["No matching exploits found."]

    return json.dumps({
        "query": cve_or_keyword,
        "top_exploits": top_exploits,
    })


# ===========================================================================
# Tool 9: Web Page Browser (OSINT / Recon)
# ===========================================================================

@mcp.tool()
def browse_webpage(url: str) -> str:
    """Visit a webpage to read its readable text, title, and extract basic links. Use this for Recon and OSINT."""
    url = _ensure_url_scheme(url)
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        try:
            response = requests.get(url, headers=headers, timeout=10, verify=False)
        except Exception as first_err:
            if url.startswith("http://"):
                https_url = "https://" + url[7:]
                response = requests.get(https_url, headers=headers, timeout=10, verify=False)
                url = https_url
            else:
                raise first_err
        soup = BeautifulSoup(response.text, 'html.parser')

        for script in soup(["script", "style"]):
            script.extract()

        text = soup.get_text(separator=' ', strip=True)
        truncated_text = text[:2000] + ("...[TRUNCATED]" if len(text) > 2000 else "")

        links = list(set([a.get('href') for a in soup.find_all('a', href=True) if a.get('href')]))[:10]

        return json.dumps({
            "url": url,
            "status_code": response.status_code,
            "title": soup.title.string if soup.title else "No title",
            "page_text_snippet": truncated_text,
            "extracted_links": links
        })
    except Exception as e:
        return json.dumps({"error": f"Failed to browse {url}: {str(e)}"})


# ===========================================================================
# Tool 10: WhatWeb Technology Fingerprinting (Docker) — NEW
# ===========================================================================

@mcp.tool()
def docker_whatweb(target_url: str) -> str:
    """Fingerprint web technologies (CMS, framework, server, language) on a target.

    Fast and lightweight. Use early in recon to identify the technology stack
    before selecting appropriate exploit tools.

    Args:
        target_url: Target URL (e.g., http://target.com).
    """
    target_url = _ensure_url_scheme(target_url)
    scan_timeout = _get_timeout("whatweb", 60)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "secsi/whatweb",
             "--color=never", "-a", "3", target_url],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"WhatWeb timed out after {scan_timeout}s."})

    output = (result.stdout + "\n" + result.stderr).strip()
    # Extract technology tokens (bracketed items)
    techs = _RE_BRACKET_CONTENT.findall(output)
    # Clean summary lines
    summary_lines = [ln.strip() for ln in output.split("\n") if ln.strip()][:10]

    return json.dumps({
        "target": target_url,
        "technologies_detected": list(set(techs))[:20],
        "raw_summary": summary_lines,
    })


# ===========================================================================
# Tool 11: Nikto Web Scanner (Docker) — NEW
# ===========================================================================

@mcp.tool()
def docker_nikto_scan(target_url: str) -> str:
    """Scan for dangerous files, outdated software, and misconfigurations using Nikto.

    Complements Nuclei by checking for additional web server issues,
    default files, and known dangerous CGI paths.

    Args:
        target_url: Target URL (e.g., http://target.com).
    """
    target_url = _ensure_url_scheme(target_url)
    scan_timeout = _get_timeout("nikto", 240)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "sullo/nikto",
             "-h", target_url,
             "-Tuning", "1234567890abc",
             "-maxtime", "180s",
             "-nointeractive"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Nikto scan timed out after {scan_timeout}s."})

    # Context Distillation: extract lines with + prefix (findings) and OSVDB
    findings = [
        ln.strip()
        for ln in result.stdout.split("\n")
        if ln.strip().startswith("+") or "OSVDB" in ln or "CVE" in ln.upper()
    ]

    return json.dumps({
        "target": target_url,
        "findings": findings[:25] if findings else ["No significant findings detected."],
    })


# ===========================================================================
# Tool 12: Gobuster Directory Brute-Force (Docker) — NEW
# ===========================================================================

@mcp.tool()
def docker_dirb_scan(target_url: str, wordlist: str = "dirb_common.txt") -> str:
    """Brute-force directories and hidden paths on a web server using Gobuster.

    Discovers admin panels, backup files, API endpoints, and hidden paths.
    Mounts the local wordlists/ directory.

    Args:
        target_url: Target URL (e.g., http://target.com).
        wordlist: Wordlist filename inside wordlists/ (default: dirb_common.txt).
    """
    target_url = _ensure_url_scheme(target_url)
    wordlist_path = _resolve_wordlist(wordlist)
    if not wordlist_path:
        return json.dumps({"error": f"Wordlist '{wordlist}' not found in {_WORDLISTS_DIR}. Run setup_wordlists.py first."})

    resolved_wordlist = os.path.basename(wordlist_path)
    scan_timeout = _get_timeout("gobuster", 120)

    try:
        result = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{_WORDLISTS_MOUNT}:/wordlists:ro",
             "ghcr.io/oj/gobuster",
             "dir",
             "-u", target_url,
             "-w", f"/wordlists/{resolved_wordlist}",
             "-t", "10",
             "--no-error",
             "-q"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Gobuster directory scan timed out after {scan_timeout}s."})

    # Context Distillation: extract discovered paths with status codes
    paths = []
    for ln in result.stdout.strip().splitlines():
        ln = ln.strip()
        if ln and ("Status:" in ln or _RE_DIRSEARCH_STATUS.match(ln)):
            paths.append(ln)
        elif ln and ln.startswith("/"):
            paths.append(ln)

    return json.dumps({
        "target": target_url,
        "discovered_paths": paths[:30] if paths else ["No hidden paths discovered."],
    })


# ===========================================================================
# Tool 13: Subfinder Subdomain Enumeration (Docker) — NEW v3.0
# ===========================================================================

@mcp.tool()
def docker_subfinder(domain: str) -> str:
    """Enumerate subdomains of a target domain using ProjectDiscovery Subfinder.

    Discovers subdomains via passive sources (APIs, DNS, certificates).
    Use early in recon to map the full scope of the target organization.

    Args:
        domain: Target root domain (e.g., 'example.com'). Do NOT include http://.
    """
    # Normalize to bare domain/hostname
    domain = _normalize_target(domain)
    scan_timeout = _get_timeout("subfinder", 120)

    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "projectdiscovery/subfinder",
             "-d", domain, "-silent", "-timeout", "30"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Subfinder timed out after {scan_timeout}s."})

    subdomains = [
        ln.strip() for ln in result.stdout.strip().split("\n")
        if ln.strip() and "." in ln
    ]

    # Deduplicate and sort
    subdomains = sorted(set(subdomains))

    return json.dumps({
        "domain": domain,
        "total_subdomains": len(subdomains),
        "subdomains": subdomains[:50],
    })


# ===========================================================================
# Tool 14: FFUF Web Fuzzer (Docker) — NEW v3.0
# ===========================================================================

@mcp.tool()
def docker_ffuf(target_url: str, wordlist: str = "dirb_common.txt",
                mode: str = "dir") -> str:
    """Fuzz a web target for hidden directories, files, or parameters using FFUF.

    Significantly faster than Gobuster. Supports directory fuzzing and
    parameter fuzzing modes.

    Args:
        target_url: Target URL. For dir mode use base URL (e.g., http://target.com/FUZZ).
                     If FUZZ keyword is missing, it will be appended as /FUZZ.
        wordlist: Wordlist filename inside wordlists/ (default: dirb_common.txt).
        mode: Fuzzing mode - 'dir' for directories, 'param' for GET parameter values.
    """
    target_url = _ensure_url_scheme(target_url)
    wordlist_path = _resolve_wordlist(wordlist)
    if not wordlist_path:
        return json.dumps({"error": f"Wordlist '{wordlist}' not found in {_WORDLISTS_DIR}. Run setup_wordlists.py first."})

    resolved_wordlist = os.path.basename(wordlist_path)
    scan_timeout = _get_timeout("ffuf", 180)

    # Ensure FUZZ keyword is in URL
    if "FUZZ" not in target_url:
        if mode == "param":
            # Append as parameter value
            separator = "&" if "?" in target_url else "?"
            target_url = f"{target_url}{separator}fuzz=FUZZ"
        else:
            # Append as directory
            target_url = target_url.rstrip("/") + "/FUZZ"

    try:
        result = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{_WORDLISTS_MOUNT}:/wordlists:ro",
             "ffuf/ffuf",
             "-u", target_url,
             "-w", f"/wordlists/{resolved_wordlist}",
             "-mc", "200,204,301,302,307,401,403",
             "-t", "10",
             "-timeout", "10",
             "-s"],  # Silent mode: only output results
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"FFUF scan timed out after {scan_timeout}s."})

    # Parse results (silent mode outputs one result per line)
    discovered = [
        ln.strip() for ln in result.stdout.strip().split("\n")
        if ln.strip()
    ]

    return json.dumps({
        "target": target_url,
        "mode": mode,
        "wordlist": wordlist,
        "total_found": len(discovered),
        "discovered": discovered[:40],
    })


# ===========================================================================
# Tool 15: testssl.sh SSL/TLS Audit (Docker) — NEW v3.0
# ===========================================================================

@mcp.tool()
def docker_testssl(target_host: str) -> str:
    """Audit SSL/TLS configuration of a target for weak ciphers, expired certs, and vulnerabilities.

    Checks for: Heartbleed, POODLE, BEAST, ROBOT, DROWN, FREAK, Logjam,
    certificate issues, protocol support, and cipher strength.
    Use on any HTTPS target to assess transport layer security.

    Args:
        target_host: Target hostname or IP with optional port (e.g., 'example.com' or 'example.com:8443').
    """
    scan_timeout = _get_timeout("testssl", 300)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm",
             "drwetter/testssl.sh",
             "--quiet", "--color", "0",
             "--fast",
             target_host],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=scan_timeout,
        )
    except FileNotFoundError:
        return json.dumps({"error": "Docker is not installed or not in PATH."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"testssl.sh timed out after {scan_timeout}s."})

    output = result.stdout

    # Context Distillation: extract vulnerability findings and ratings
    vulnerabilities = []
    cert_info = []
    protocol_info = []

    for ln in output.split("\n"):
        ln_stripped = ln.strip()
        if not ln_stripped:
            continue
        # Vulnerability lines (VULNERABLE, not vulnerable, etc.)
        if any(kw in ln_stripped.upper() for kw in
               ["VULNERABLE", "NOT VULNERABLE", "OK", "WARN", "CRITICAL",
                "LOW", "MEDIUM", "HIGH"]):
            # Skip noisy lines
            if len(ln_stripped) < 200:
                vulnerabilities.append(ln_stripped)
        # Certificate lines
        elif any(kw in ln_stripped.lower() for kw in
                 ["certificate", "issuer", "serial", "expir", "subject",
                  "trust", "chain"]):
            cert_info.append(ln_stripped)
        # Protocol lines
        elif any(kw in ln_stripped for kw in
                 ["SSLv2", "SSLv3", "TLS 1", "TLS 1.0", "TLS 1.1",
                  "TLS 1.2", "TLS 1.3"]):
            protocol_info.append(ln_stripped)

    return json.dumps({
        "target": target_host,
        "vulnerabilities": vulnerabilities[:20],
        "certificate": cert_info[:10],
        "protocols": protocol_info[:10],
    })


# ===========================================================================
# Tool 16: Sensitive Files & Backup Scanner
# ===========================================================================

@mcp.tool()
def docker_sensitive_files_scan(target_url: str) -> str:
    """Scan a target web application for exposed sensitive files, credentials, and source backups.

    Checks for: .env, .env.local, .git/HEAD, .git/config, backup.sql, dump.sql,
    wp-config.php.bak, phpinfo.php, id_rsa, .DS_Store, and config.json.
    Applies content signature validation to prevent false positives from soft-404 pages.

    Args:
        target_url: Web application root or base URL (e.g. 'http://example.com' or 'https://target.com/app/').
    """
    import concurrent.futures
    from urllib.parse import urljoin, urlparse

    target_url = _ensure_url_scheme(target_url)
    scan_timeout = _get_timeout("sensitive_files", 60)

    # Baseline 404 test to detect soft-404 behavior
    soft_404_body_len = None
    soft_404_status = None
    try:
        baseline_url = urljoin(target_url, "/non_existent_probe_xyz987456.txt")
        resp_base = requests.get(baseline_url, timeout=10, verify=False, allow_redirects=False)
        soft_404_status = resp_base.status_code
        soft_404_body_len = len(resp_base.text)
    except Exception:
        pass

    sensitive_paths = [
        ("/.env", "Environment Variables File (Credentials)",
         lambda txt, h: any(k in txt for k in ["DB_", "APP_", "SECRET", "KEY=", "TOKEN=", "PASSWORD=", "AUTH_"]) and "<!DOCTYPE" not in txt),
        ("/.env.local", "Local Environment Variables (Credentials)",
         lambda txt, h: any(k in txt for k in ["DB_", "APP_", "SECRET", "KEY=", "TOKEN=", "PASSWORD=", "AUTH_"]) and "<!DOCTYPE" not in txt),
        ("/.git/HEAD", "Git Repository Source Exposure",
         lambda txt, h: "ref: refs/" in txt or (len(txt.strip()) == 40 and bool(_RE_GIT_HASH.match(txt.strip())))),
        ("/.git/config", "Git Repository Config Exposure",
         lambda txt, h: "[core]" in txt or '[remote "' in txt),
        ("/backup.sql", "Database Backup SQL Dump",
         lambda txt, h: any(k in txt for k in ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL", "PostgreSQL"]) and "<!DOCTYPE" not in txt),
        ("/dump.sql", "Database Dump SQL",
         lambda txt, h: any(k in txt for k in ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL", "PostgreSQL"]) and "<!DOCTYPE" not in txt),
        ("/wp-config.php.bak", "WordPress Configuration Backup",
         lambda txt, h: any(k in txt for k in ["DB_NAME", "DB_USER", "DB_PASSWORD", "AUTH_KEY"]) and "<!DOCTYPE" not in txt),
        ("/phpinfo.php", "PHP Info Configuration Disclosure",
         lambda txt, h: "PHP Version" in txt or "Configuration File (php.ini) Path" in txt),
        ("/id_rsa", "Exposed SSH Private Key",
         lambda txt, h: "-----BEGIN" in txt and "PRIVATE KEY-----" in txt),
        ("/.DS_Store", "macOS Directory Artifact Exposure",
         lambda txt, h: "Bud1" in txt or txt.startswith("\x00\x00\x00\x01Bud1")),
        ("/config.json", "Application Configuration File",
         lambda txt, h: any(k in txt.lower() for k in ['"database"', '"password"', '"secret"', '"apikey"', '"auth"']) and "<!DOCTYPE" not in txt),
    ]

    exposed_files = []

    def _check_path(path_spec):
        path, label, validator = path_spec
        check_url = urljoin(target_url, path)
        try:
            r = requests.get(
                check_url,
                timeout=10,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            if r.status_code == 200:
                # Disregard if matches soft-404 baseline exactly
                if soft_404_status == 200 and soft_404_body_len is not None:
                    if abs(len(r.text) - soft_404_body_len) < 50 and "<!DOCTYPE" in r.text:
                        return None

                body_sample = r.text[:2000]
                if validator(body_sample, r.headers):
                    severity = "CRITICAL" if any(p in path for p in [".env", ".git", "id_rsa", ".sql", "wp-config"]) else "HIGH"
                    snippet = body_sample[:150].replace("\n", " ").replace("\r", "")
                    return {
                        "path": path,
                        "url": check_url,
                        "type": label,
                        "severity": severity,
                        "status_code": r.status_code,
                        "content_length": len(r.text),
                        "evidence": snippet,
                    }
        except Exception:
            pass
        return None

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_path = {executor.submit(_check_path, spec): spec for spec in sensitive_paths}
            for future in concurrent.futures.as_completed(future_to_path, timeout=scan_timeout):
                res = future.result()
                if res:
                    exposed_files.append(res)
    except Exception as e:
        if not exposed_files:
            return json.dumps({"target": target_url, "error": f"Sensitive file scan timed out or failed: {e}", "exposed_files": []})

    return json.dumps({
        "target": target_url,
        "scanned_paths_count": len(sensitive_paths),
        "vulnerabilities_found": len(exposed_files),
        "exposed_files": exposed_files,
    })


# ===========================================================================
# Tool 17: CORS Misconfiguration & Security Headers Audit
# ===========================================================================

@mcp.tool()
def docker_cors_scan(target_url: str) -> str:
    """Audit target web application for CORS misconfigurations and missing HTTP security headers.

    Checks:
    - Arbitrary Origin reflection with Access-Control-Allow-Credentials: true (CRITICAL)
    - Null origin reflection with Access-Control-Allow-Credentials (HIGH)
    - Wildcard origin (*) with sensitive endpoints
    - Core defensive headers: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP),
      X-Frame-Options, X-Content-Type-Options, Referrer-Policy.

    Args:
        target_url: Target web URL (e.g. 'https://example.com' or 'http://target.com/api').
    """
    target_url = _ensure_url_scheme(target_url)
    cors_issues = []
    missing_headers = []
    present_headers = {}

    headers_to_check = {
        "Strict-Transport-Security": "Missing HSTS (Strict-Transport-Security) header",
        "Content-Security-Policy": "Missing CSP (Content-Security-Policy) header",
        "X-Frame-Options": "Missing X-Frame-Options (Clickjacking protection)",
        "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME-sniffing protection)",
        "Referrer-Policy": "Missing Referrer-Policy header",
    }

    try:
        # Base request to check security headers
        resp = requests.get(target_url, timeout=15, verify=False, allow_redirects=True)
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, msg in headers_to_check.items():
            h_lower = header.lower()
            if h_lower in resp_headers_lower:
                present_headers[header] = resp_headers_lower[h_lower]
            else:
                missing_headers.append({"header": header, "description": msg, "severity": "MEDIUM" if header in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"] else "LOW"})

        # CORS Origin reflection tests
        test_origins = [
            ("https://evil-attacker.com", "Arbitrary Origin Reflection"),
            ("null", "Null Origin Trust"),
        ]

        for test_origin, label in test_origins:
            req_headers = {
                "Origin": test_origin,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            }
            try:
                cors_resp = requests.get(target_url, headers=req_headers, timeout=10, verify=False, allow_redirects=False)
                cors_h_lower = {k.lower(): v for k, v in cors_resp.headers.items()}
                acao = cors_h_lower.get("access-control-allow-origin", "")
                acac = cors_h_lower.get("access-control-allow-credentials", "")

                if acao == test_origin:
                    if acac.lower() == "true":
                        cors_issues.append({
                            "type": label,
                            "severity": "CRITICAL" if test_origin != "null" else "HIGH",
                            "origin_tested": test_origin,
                            "acao": acao,
                            "acac": acac,
                            "description": f"Reflected origin {test_origin} with Access-Control-Allow-Credentials: true. Allows cross-origin credentialed data theft.",
                        })
                    else:
                        cors_issues.append({
                            "type": label,
                            "severity": "MEDIUM",
                            "origin_tested": test_origin,
                            "acao": acao,
                            "acac": acac,
                            "description": f"Reflected origin {test_origin} without credentials.",
                        })
                elif acao == "*":
                    cors_issues.append({
                        "type": "Wildcard Origin (*)",
                        "severity": "LOW",
                        "origin_tested": test_origin,
                        "acao": acao,
                        "acac": acac,
                        "description": "Wildcard Access-Control-Allow-Origin: * allows any domain to read public API responses.",
                    })
            except Exception:
                pass

    except Exception as e:
        return json.dumps({"target": target_url, "error": f"CORS scan failed: {e}", "cors_misconfigurations": [], "missing_security_headers": []})

    return json.dumps({
        "target": target_url,
        "vulnerabilities_found": len(cors_issues) + len(missing_headers),
        "cors_misconfigurations": cors_issues,
        "missing_security_headers": missing_headers,
        "present_security_headers": present_headers,
    })


# ===========================================================================
# Tool 18: Parameterized Reflected XSS Fuzzing Probe
# ===========================================================================

@mcp.tool()
def docker_xss_scan(target_url: str) -> str:
    """Audit parameterized web URL for Reflected Cross-Site Scripting (XSS) vulnerabilities.

    Tests query parameters with safe canary probes across HTML body, attribute breakout,
    and script contexts to verify if input characters (<, >, \", ') are reflected unescaped.

    Args:
        target_url: Target URL containing query parameters (e.g. 'http://example.com/search?q=test&category=tech').
    """
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    target_url = _ensure_url_scheme(target_url)
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    if not query_params:
        return json.dumps({
            "target": target_url,
            "error": "No query parameters found in target_url to audit for reflected XSS.",
            "parameters_tested": [],
            "vulnerable_parameters": [],
            "vulnerabilities_found": 0,
        })

    vulnerable_params = []
    # Safe canary test tokens
    tag_probe = "xss_probe_canary_tag_9921"
    tag_payload = f"<{tag_probe}>"
    attr_probe = "xss_attr_breakout_9921"
    attr_payload = f'"{attr_probe}\''

    for param_name in query_params.keys():
        findings_for_param = []

        # 1. HTML tag context test
        test_params_tag = dict(query_params)
        test_params_tag[param_name] = [tag_payload]
        new_query_tag = urlencode(test_params_tag, doseq=True)
        test_url_tag = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_tag, parsed.fragment))

        try:
            r_tag = requests.get(test_url_tag, timeout=12, verify=False, allow_redirects=True)
            if tag_payload in r_tag.text:
                findings_for_param.append({
                    "context": "HTML_BODY",
                    "payload_tested": tag_payload,
                    "evidence": f"Unescaped HTML tags {tag_payload} reflected directly in response body.",
                    "severity": "HIGH",
                })
        except Exception:
            pass

        # 2. Attribute breakout test
        test_params_attr = dict(query_params)
        test_params_attr[param_name] = [attr_payload]
        new_query_attr = urlencode(test_params_attr, doseq=True)
        test_url_attr = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_attr, parsed.fragment))

        try:
            r_attr = requests.get(test_url_attr, timeout=12, verify=False, allow_redirects=True)
            if attr_payload in r_attr.text or f'"{attr_probe}' in r_attr.text or f"'{attr_probe}" in r_attr.text:
                findings_for_param.append({
                    "context": "ATTRIBUTE_OR_STRING",
                    "payload_tested": attr_payload,
                    "evidence": f"Unescaped quotes ({attr_payload}) reflected without HTML attribute encoding.",
                    "severity": "HIGH",
                })
        except Exception:
            pass

        if findings_for_param:
            vulnerable_params.append({
                "parameter": param_name,
                "issues": findings_for_param,
            })

    return json.dumps({
        "target": target_url,
        "parameters_tested": list(query_params.keys()),
        "vulnerable_parameters": vulnerable_params,
        "vulnerabilities_found": len(vulnerable_params),
    })


# ===========================================================================
# Tool 19: Multi-Target Active HTTP/HTTPS Alive Probe
# ===========================================================================

@mcp.tool()
def docker_httpx_probe(targets: str) -> str:
    """Active multi-target HTTP/HTTPS probe for discovering alive web hosts, status codes, and server banners.

    Probes subdomains or IP addresses for web services on HTTP and HTTPS, capturing HTTP status codes,
    HTML <title> tags, Server headers, and redirect destinations.

    Args:
        targets: Comma-separated or newline-separated list of hosts, domains, or subdomains to probe.
    """
    import concurrent.futures
    import re

    scan_timeout = _get_timeout("httpx", 120)

    # Split targets by comma or newline
    raw_list = [t.strip() for t in re.split(r"[,;\n\r]+", targets) if t.strip()]
    if not raw_list:
        return json.dumps({
            "error": "No targets provided to probe.",
            "total_probed": 0,
            "alive_count": 0,
            "alive_targets": [],
        })

    # Limit to max 50 targets per batch to keep context tight
    target_hosts = raw_list[:50]
    alive_targets = []

    def _probe_single(target: str):
        schemes = ["https", "http"]
        if target.startswith("http://") or target.startswith("https://"):
            urls_to_try = [target]
        else:
            urls_to_try = [f"{s}://{target}" for s in schemes]

        for url in urls_to_try:
            try:
                r = requests.get(
                    url,
                    timeout=8,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                title = ""
                m = _RE_HTML_TITLE.search(r.text)
                if m:
                    title = m.group(1).strip()[:100]

                server = r.headers.get("Server", "Unknown")
                return {
                    "input_target": target,
                    "url": r.url,
                    "status_code": r.status_code,
                    "title": title,
                    "server": server,
                    "content_length": len(r.content),
                    "alive": True,
                }
            except Exception:
                continue

        return {"input_target": target, "alive": False}

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_t = {executor.submit(_probe_single, t): t for t in target_hosts}
            for future in concurrent.futures.as_completed(future_to_t, timeout=scan_timeout):
                res = future.result()
                if res and res.get("alive"):
                    alive_targets.append(res)
    except Exception as e:
        if not alive_targets:
            return json.dumps({"error": f"HTTP probe timed out or failed: {e}", "alive_count": 0, "alive_targets": []})

    return json.dumps({
        "total_probed": len(target_hosts),
        "alive_count": len(alive_targets),
        "alive_targets": alive_targets,
    })


# ---------------------------------------------------------------------------
# Tool: docker_ssl_cert_audit
# ---------------------------------------------------------------------------
@mcp.tool()
def docker_ssl_cert_audit(target: str) -> str:
    """Kiểm toán chứng chỉ SSL/TLS, ngày hết hạn, mã hóa và trích xuất SANs (Subject Alternative Names).

    Args:
        target: Tên miền hoặc URL mục tiêu (ví dụ: 'example.com' hoặc 'https://example.com:443').
    """
    if not target or not target.strip():
        return json.dumps({"error": "Target must be specified", "valid": False})

    clean_target = target.strip()
    if "://" in clean_target:
        parsed = urlparse(clean_target)
        host = parsed.hostname or clean_target
        port = parsed.port or 443
    else:
        if ":" in clean_target:
            parts = clean_target.split(":", 1)
            host = parts[0].strip()
            port = int(parts[1]) if parts[1].isdigit() else 443
        else:
            host = clean_target.split("/")[0].strip()
            port = 443

    timeout_cfg = _get_timeout("ssl_cert", 30)
    issues = []
    san_domains = []
    cert_info = {}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=min(timeout_cfg, 15)) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher_info = ssock.cipher()

                cert_info["tls_version"] = tls_version
                cert_info["cipher"] = cipher_info[0] if cipher_info else "Unknown"
                key_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 256
                cert_info["key_bits"] = key_bits

                not_after = cert.get("notAfter", "")
                not_before = cert.get("notBefore", "")
                cert_info["valid_from"] = not_before
                cert_info["valid_until"] = not_after
                cert_info["valid_to"] = not_after

                days_left = 365
                if not_after:
                    try:
                        exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        from datetime import timezone
                        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
                        days_left = (exp_date - now_utc).days
                        cert_info["days_until_expiration"] = days_left
                        cert_info["days_until_expiry"] = days_left
                        if days_left < 0:
                            issues.append({
                                "type": "Expired Certificate",
                                "severity": "HIGH",
                                "description": f"Chứng chỉ SSL đã hết hạn cách đây {abs(days_left)} ngày ({not_after})."
                            })
                        elif days_left < 30:
                            issues.append({
                                "type": "Expiring Certificate",
                                "severity": "MEDIUM",
                                "description": f"Chứng chỉ SSL sắp hết hạn trong vòng {days_left} ngày ({not_after})."
                            })
                    except Exception:
                        pass

                subject_dict = dict(x[0] for x in cert.get("subject", []))
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                common_name = subject_dict.get("commonName", host)
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"
                cert_info["common_name"] = common_name
                cert_info["subject_cn"] = common_name
                cert_info["issuer"] = issuer_name
                cert_info["issuer_org"] = issuer_name

                for item in cert.get("subjectAltName", []):
                    if len(item) == 2 and item[0].lower() == "dns":
                        san = item[1].lower().strip()
                        if san and san not in san_domains:
                            san_domains.append(san)

                cert_info["san_domains"] = san_domains
                cert_info["subject_alternative_names"] = san_domains

                if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    issues.append({
                        "type": "Deprecated TLS Protocol",
                        "severity": "HIGH",
                        "description": f"Máy chủ đang sử dụng phiên bản TLS cũ và mất an toàn ({tls_version}). Nên nâng cấp lên TLS 1.2 hoặc TLS 1.3."
                    })

                return json.dumps({
                    "status": "success",
                    "target": host,
                    "hostname": host,
                    "subject_cn": common_name,
                    "issuer_org": issuer_name,
                    "tls_version": tls_version,
                    "key_bits": key_bits,
                    "days_until_expiry": days_left,
                    "subject_alternative_names": san_domains,
                    "port": port,
                    "valid": True,
                    "cert_info": cert_info,
                    "san_count": len(san_domains),
                    "san_domains": san_domains[:30],
                    "issues_count": len(issues),
                    "issues": [iss["description"] for iss in issues],
                    "detailed_issues": issues,
                })

    except ssl.SSLCertVerificationError as e:
        issues.append({
            "type": "SSL Verification Failure",
            "severity": "HIGH",
            "description": f"Xác thực chứng chỉ SSL thất bại: {e}. Có thể là chứng chỉ tự ký (Self-signed) hoặc không khớp tên miền."
        })
        return json.dumps({
            "status": "error",
            "target": host,
            "port": port,
            "valid": False,
            "error": str(e),
            "issues": [iss["description"] for iss in issues],
            "san_domains": [],
        })
    except Exception as e:
        return json.dumps({
            "status": "error",
            "target": host,
            "port": port,
            "valid": False,
            "error": f"Không thể kết nối SSL/TLS tới {host}:{port}: {e}",
            "issues": [str(e)],
            "san_domains": [],
        })


# ---------------------------------------------------------------------------
# Tool: docker_dns_security_audit
# ---------------------------------------------------------------------------
@mcp.tool()
def docker_dns_security_audit(domain: str) -> str:
    """Đánh giá an ninh cấu hình DNS và Email Domain: Kiểm tra SPF, DMARC, DNSSEC, MX records.

    Args:
        domain: Tên miền mục tiêu (ví dụ: 'example.com').
    """
    if not domain or not domain.strip():
        return json.dumps({"error": "Domain must be specified", "issues": []})

    clean_domain = domain.strip().lower()
    if "://" in clean_domain:
        clean_domain = urlparse(clean_domain).hostname or clean_domain
    clean_domain = clean_domain.split("/")[0].split(":")[0].strip()

    timeout_cfg = _get_timeout("dns_security", 30)
    issues = []
    dns_data = {
        "domain": clean_domain,
        "spf_record": None,
        "dmarc_record": None,
        "mx_records": [],
        "dnssec_enabled": False,
    }

    headers = {"Accept": "application/dns-json"}

    def _query_doh(name: str, rtype: str) -> list[dict]:
        endpoints = [
            f"https://dns.google/resolve?name={name}&type={rtype}",
            f"https://cloudflare-dns.com/dns-query?name={name}&type={rtype}",
        ]
        for ep in endpoints:
            try:
                resp = requests.get(ep, headers=headers, timeout=min(timeout_cfg, 8))
                if resp.status_code == 200:
                    data = resp.json()
                    if "AD" in data and data["AD"]:
                        dns_data["dnssec_enabled"] = True
                    return data.get("Answer", [])
            except Exception:
                continue
        return []

    # 1. Query SPF (TXT records on root domain)
    txt_answers = _query_doh(clean_domain, "TXT")
    spf_candidates = []
    for ans in txt_answers:
        val = ans.get("data", "").strip(' "')
        if "v=spf1" in val.lower():
            spf_candidates.append(val)

    if spf_candidates:
        dns_data["spf_record"] = spf_candidates[0]
        if "~all" not in spf_candidates[0] and "-all" not in spf_candidates[0]:
            issues.append({
                "type": "Weak SPF Qualifier",
                "severity": "MEDIUM",
                "description": f"Bản ghi SPF ({spf_candidates[0]}) sử dụng cơ chế kết thúc lỏng lẻo (?all hoặc +all). Nên chuyển sang ~all (SoftFail) hoặc -all (Fail)."
            })
    else:
        issues.append({
            "type": "Missing SPF Record",
            "severity": "HIGH",
            "description": f"Tên miền '{clean_domain}' không có bản ghi SPF (v=spf1). Kẻ tấn công có thể dễ dàng giả mạo email từ miền này (Email Spoofing)."
        })

    # 2. Query DMARC (TXT records on _dmarc.domain)
    dmarc_answers = _query_doh(f"_dmarc.{clean_domain}", "TXT")
    dmarc_candidates = []
    for ans in dmarc_answers:
        val = ans.get("data", "").strip(' "')
        if "v=dmarc1" in val.lower():
            dmarc_candidates.append(val)

    if dmarc_candidates:
        dmarc_rec = dmarc_candidates[0]
        dns_data["dmarc_record"] = dmarc_rec
        p_match = _RE_DMARC_POLICY.search(dmarc_rec)
        policy = p_match.group(1).lower() if p_match else "unknown"
        dns_data["dmarc_policy"] = policy
        if policy == "none":
            issues.append({
                "type": "DMARC Policy Disabled (p=none)",
                "severity": "MEDIUM",
                "description": "Chính sách DMARC đang ở chế độ 'p=none' (chỉ giám sát, không ngăn chặn hoặc cách ly email giả mạo)."
            })
    else:
        issues.append({
            "type": "Missing DMARC Record",
            "severity": "HIGH",
            "description": f"Không tìm thấy bản ghi DMARC (_dmarc.{clean_domain}). Thiếu cơ chế thực thi chính sách xác thực email."
        })

    # 3. Query MX Records
    mx_answers = _query_doh(clean_domain, "MX")
    for ans in mx_answers:
        mx_host = ans.get("data", "").strip(' ".')
        if mx_host and mx_host not in dns_data["mx_records"]:
            dns_data["mx_records"].append(mx_host)

    # 4. Check DNSSEC
    dnskey_answers = _query_doh(clean_domain, "DNSKEY")
    if dnskey_answers or dns_data["dnssec_enabled"]:
        dns_data["dnssec_enabled"] = True
    else:
        issues.append({
            "type": "DNSSEC Not Enabled",
            "severity": "LOW",
            "description": "Tên miền chưa kích hoạt DNSSEC, có nguy cơ bị tấn công DNS Spoofing / Cache Poisoning."
        })

    spf_status = "valid" if dns_data["spf_record"] else "missing"
    dmarc_status = "valid" if dns_data["dmarc_record"] else "missing"
    dmarc_policy = dns_data.get("dmarc_policy", "missing")

    return json.dumps({
        "status": "success",
        "domain": clean_domain,
        "dns_security": dns_data,
        "spf": {
            "status": spf_status,
            "record": dns_data["spf_record"],
        },
        "dmarc": {
            "status": dmarc_status,
            "policy": dmarc_policy,
            "record": dns_data["dmarc_record"],
        },
        "dnssec": {
            "dnssec_enabled": dns_data["dnssec_enabled"],
        },
        "mx_records": dns_data["mx_records"],
        "security_issues": [iss["description"] for iss in issues],
        "issues_count": len(issues),
        "issues": issues,
    })


# ---------------------------------------------------------------------------
# Tool: docker_security_txt_audit
# ---------------------------------------------------------------------------
@mcp.tool()
def docker_security_txt_audit(target_url: str) -> str:
    """Rà soát RFC 9116 security.txt, phân tích robots.txt và sitemap.xml để tìm kiếm các đường dẫn ẩn và nhạy cảm.

    Args:
        target_url: URL hoặc domain mục tiêu (ví dụ: 'https://example.com').
    """
    if not target_url or not target_url.strip():
        return json.dumps({"error": "target_url must be specified", "sensitive_paths": []})

    clean_url = target_url.strip()
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        clean_url = "https://" + clean_url
    base_url = clean_url.rstrip("/")

    timeout_cfg = _get_timeout("security_txt", 30)
    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    results = {
        "status": "success",
        "target": base_url,
        "security_txt": {
            "found": False,
            "url": "",
            "contact": "",
        },
        "robots_txt": {
            "found": False,
            "disallow_rules_count": 0,
            "disallowed_paths": [],
        },
        "sitemap": {
            "found": False,
            "urls_count": 0,
        },
        "security_txt_found": False,
        "security_contacts": [],
        "robots_txt_found": False,
        "disallowed_paths_count": 0,
        "sensitive_hidden_paths": [],
        "interesting_paths_found": [],
        "sitemap_found": False,
        "sample_endpoints": [],
    }

    # 1. Probe security.txt (RFC 9116)
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = requests.get(base_url + path, headers=req_headers, timeout=min(timeout_cfg, 8), verify=False)
            if r.status_code == 200 and ("Contact:" in r.text or "contact:" in r.text.lower()):
                results["security_txt_found"] = True
                results["security_txt_url"] = base_url + path
                contacts = []
                for line in r.text.splitlines():
                    if line.lower().startswith("contact:"):
                        contacts.append(line.split(":", 1)[1].strip())
                results["security_contacts"] = contacts
                results["security_txt"] = {
                    "found": True,
                    "url": base_url + path,
                    "contact": "; ".join(contacts),
                }
                break
        except Exception:
            pass

    # 2. Probe robots.txt
    sensitive_keywords = [
        "admin", "api", "secret", "private", "backup", "config", "panel", "dashboard",
        "internal", "db", "sql", "test", "staging", "dev", "manage", "upload", "user"
    ]
    try:
        r = requests.get(base_url + "/robots.txt", headers=req_headers, timeout=min(timeout_cfg, 8), verify=False)
        if r.status_code == 200 and ("Disallow:" in r.text or "User-agent:" in r.text):
            results["robots_txt_found"] = True
            disallowed = []
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    p = line.split(":", 1)[1].strip()
                    if p and p != "/" and p not in disallowed:
                        disallowed.append(p)
                        if any(kw in p.lower() for kw in sensitive_keywords):
                            if p not in results["sensitive_hidden_paths"]:
                                results["sensitive_hidden_paths"].append(p)
                                results["interesting_paths_found"].append(p)
            results["disallowed_paths_count"] = len(disallowed)
            results["robots_txt"] = {
                "found": True,
                "disallow_rules_count": len(disallowed),
                "disallowed_paths": disallowed,
            }
    except Exception:
        pass

    # 3. Probe sitemap.xml
    try:
        r = requests.get(base_url + "/sitemap.xml", headers=req_headers, timeout=min(timeout_cfg, 8), verify=False)
        if r.status_code == 200 and ("<urlset" in r.text or "<sitemapindex" in r.text):
            results["sitemap_found"] = True
            urls = _RE_SITEMAP_LOC.findall(r.text)
            results["sitemap_urls_count"] = len(urls)
            results["sample_endpoints"] = urls[:10]
            results["sitemap"] = {
                "found": True,
                "urls_count": len(urls),
            }
            for u in urls[:10]:
                if any(kw in u.lower() for kw in sensitive_keywords):
                    if u not in results["interesting_paths_found"]:
                        results["interesting_paths_found"].append(u)
    except Exception:
        pass

    return json.dumps(results)


# ---------------------------------------------------------------------------
# Tool: docker_cookie_security_audit
# ---------------------------------------------------------------------------
@mcp.tool()
def docker_cookie_security_audit(target_url: str) -> str:
    """Kiểm toán các cờ bảo mật của Cookie (Secure, HttpOnly, SameSite) và tiêu đề an ninh HTTP.

    Args:
        target_url: URL mục tiêu (ví dụ: 'https://example.com/login').
    """
    if not target_url or not target_url.strip():
        return json.dumps({"error": "target_url must be specified", "cookie_issues": []})

    clean_url = target_url.strip()
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        clean_url = "https://" + clean_url

    timeout_cfg = _get_timeout("cookie_security", 30)
    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    issues = []
    analyzed_cookies = []

    try:
        r = requests.get(clean_url, headers=req_headers, timeout=min(timeout_cfg, 10), verify=False, allow_redirects=True)
        target_url_str = str(r.url) if hasattr(r, "url") and isinstance(r.url, str) else clean_url
        is_https = target_url_str.startswith("https://")

        set_cookie_headers = []
        try:
            if hasattr(r, 'raw') and hasattr(r.raw, 'headers') and hasattr(r.raw.headers, 'getlist'):
                raw_list = r.raw.headers.getlist('Set-Cookie')
                if isinstance(raw_list, list):
                    set_cookie_headers = [str(x) for x in raw_list]
        except Exception:
            pass

        if not set_cookie_headers and hasattr(r, 'headers'):
            for k, v in r.headers.items():
                if str(k).lower() == 'set-cookie':
                    set_cookie_headers.append(str(v))

        for c in r.cookies:
            c_name = str(getattr(c, "name", "cookie"))
            c_val = str(getattr(c, "value", ""))
            c_domain = str(getattr(c, "domain", ""))
            c_path = str(getattr(c, "path", "/"))
            c_secure = bool(getattr(c, "secure", False))

            c_info = {
                "name": c_name,
                "secure": c_secure,
                "has_non_empty_value": bool(c_val),
                "domain": c_domain,
                "path": c_path,
            }

            raw_hdr = ""
            for h in set_cookie_headers:
                h_str = str(h)
                if h_str.strip().lower().startswith(f"{c_name.lower()}="):
                    raw_hdr = h_str.lower()
                    break

            has_httponly = bool((hasattr(c, 'has_nonstandard_attr') and c.has_nonstandard_attr('httponly')) or "httponly" in raw_hdr)
            has_secure = bool(c_secure or "secure" in raw_hdr)
            samesite = "None"
            if "samesite=strict" in raw_hdr:
                samesite = "Strict"
            elif "samesite=lax" in raw_hdr:
                samesite = "Lax"
            elif "samesite=none" in raw_hdr:
                samesite = "None"
            elif "samesite" not in raw_hdr:
                samesite = "Missing"

            c_info["httponly"] = has_httponly
            c_info["secure"] = has_secure
            c_info["samesite"] = samesite
            analyzed_cookies.append(c_info)

            is_sensitive_cookie = any(k in c.name.lower() for k in ["sess", "auth", "token", "jwt", "id", "login", "csrf"])

            missing_flags = []
            if not has_secure:
                missing_flags.append("Secure")
            if not has_httponly:
                missing_flags.append("HttpOnly")
            if samesite in ("Missing", "None"):
                missing_flags.append("SameSite")

            if missing_flags:
                issues.append({
                    "name": c.name,
                    "cookie": c.name,
                    "missing_flags": missing_flags,
                    "type": "Insecure Cookie Flags",
                    "severity": "HIGH" if (is_sensitive_cookie and ("Secure" in missing_flags or "HttpOnly" in missing_flags)) else "MEDIUM",
                    "risk": "Nguy cơ đánh cắp phiên qua XSS/MITM",
                    "description": f"Cookie '{c.name}' thiếu các cờ bảo mật: {', '.join(missing_flags)}."
                })

        return json.dumps({
            "status": "success",
            "target": target_url_str,
            "total_cookies": len(analyzed_cookies),
            "total_cookies_found": len(analyzed_cookies),
            "cookies": analyzed_cookies,
            "issues_count": len(issues),
            "issues": issues,
        })

    except Exception as e:
        return json.dumps({
            "status": "error",
            "target": clean_url,
            "error": f"Không thể phân tích cookie từ {clean_url}: {e}",
            "total_cookies": 0,
            "total_cookies_found": 0,
            "cookies": [],
            "issues": [],
        })


# ---------------------------------------------------------------------------
# Tool: docker_http_headers_audit
# ---------------------------------------------------------------------------
@mcp.tool()
def docker_http_headers_audit(target_url: str) -> str:
    """Kiểm toán toàn diện các tiêu đề an ninh HTTP (OWASP Secure Headers) và phát hiện rò rỉ banner máy chủ.

    Args:
        target_url: URL mục tiêu cần kiểm toán (ví dụ: 'https://example.com' hoặc 'http://target.local:8080').
    """
    if not target_url or not target_url.strip():
        return json.dumps({"error": "target_url must be specified", "issues": []})

    clean_url = _ensure_url_scheme(target_url.strip(), default_scheme="https")
    timeout_cfg = _get_timeout("http_headers", 30)
    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    try:
        r = requests.get(clean_url, headers=req_headers, timeout=min(timeout_cfg, 10), verify=False, allow_redirects=True)
        headers_lower = {k.lower(): str(v) for k, v in r.headers.items()}
        target_url_str = str(r.url) if hasattr(r, "url") and isinstance(r.url, str) else clean_url
        is_https = target_url_str.startswith("https://")

        issues = []
        present_headers = {}
        missing_headers = []
        info_leaks = []

        # 1. HSTS (Strict-Transport-Security)
        if is_https:
            if "strict-transport-security" in headers_lower:
                hsts_val = headers_lower["strict-transport-security"]
                present_headers["strict-transport-security"] = hsts_val
                if "max-age" not in hsts_val.lower():
                    issues.append({
                        "header": "Strict-Transport-Security",
                        "type": "Misconfigured Header",
                        "severity": "MEDIUM",
                        "risk": "Tiêu đề HSTS thiếu chỉ thị max-age hợp lệ.",
                        "remediation": "Đặt 'max-age=31536000; includeSubDomains; preload'."
                    })
            else:
                missing_headers.append("strict-transport-security")
                issues.append({
                    "header": "Strict-Transport-Security",
                    "type": "Missing Security Header",
                    "severity": "HIGH",
                    "risk": "Thiếu HSTS cho phép kẻ tấn công MITM hạ cấp kết nối HTTPS xuống HTTP không mã hóa (SSL Stripping).",
                    "remediation": "Bổ sung tiêu đề: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
                })

        # 2. CSP (Content-Security-Policy)
        if "content-security-policy" in headers_lower:
            csp_val = headers_lower["content-security-policy"]
            present_headers["content-security-policy"] = csp_val
            csp_lower = csp_val.lower()
            if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
                issues.append({
                    "header": "Content-Security-Policy",
                    "type": "Weak CSP Policy",
                    "severity": "MEDIUM",
                    "risk": "Chính sách CSP cho phép 'unsafe-inline' hoặc 'unsafe-eval', làm giảm khả năng phòng vệ chống lại tấn công XSS.",
                    "remediation": "Loại bỏ 'unsafe-inline'/'unsafe-eval' và áp dụng cơ chế Nonce hoặc Hash cho script."
                })
        else:
            missing_headers.append("content-security-policy")
            issues.append({
                "header": "Content-Security-Policy",
                "type": "Missing Security Header",
                "severity": "HIGH",
                "risk": "Thiếu Content-Security-Policy khiến trình duyệt không thể giới hạn nguồn tài nguyên và mã thực thi, gia tăng mức độ nguy hại của lỗ hổng XSS.",
                "remediation": "Xây dựng và áp dụng chính sách Content-Security-Policy nghiêm ngặt."
            })

        # 3. X-Frame-Options (Clickjacking defense)
        if "x-frame-options" in headers_lower:
            xfo_val = headers_lower["x-frame-options"]
            present_headers["x-frame-options"] = xfo_val
            if xfo_val.upper() not in ("DENY", "SAMEORIGIN") and "ALLOW-FROM" not in xfo_val.upper():
                issues.append({
                    "header": "X-Frame-Options",
                    "type": "Weak X-Frame-Options",
                    "severity": "MEDIUM",
                    "risk": f"Giá trị '{xfo_val}' không đảm bảo chống lồng khung (Clickjacking).",
                    "remediation": "Đặt 'X-Frame-Options: DENY' hoặc 'SAMEORIGIN'."
                })
        else:
            missing_headers.append("x-frame-options")
            issues.append({
                "header": "X-Frame-Options",
                "type": "Missing Security Header",
                "severity": "MEDIUM",
                "risk": "Thiếu X-Frame-Options cho phép trang web bị nhúng vào <iframe> độc hại để thực hiện tấn công đánh lừa cú nhấp chuột (Clickjacking).",
                "remediation": "Cấu hình tiêu đề 'X-Frame-Options: SAMEORIGIN' hoặc 'DENY'."
            })

        # 4. X-Content-Type-Options
        if "x-content-type-options" in headers_lower:
            xcto_val = headers_lower["x-content-type-options"]
            present_headers["x-content-type-options"] = xcto_val
            if "nosniff" not in xcto_val.lower():
                issues.append({
                    "header": "X-Content-Type-Options",
                    "type": "Weak X-Content-Type-Options",
                    "severity": "LOW",
                    "risk": "Giá trị không phải 'nosniff'.",
                    "remediation": "Đặt 'X-Content-Type-Options: nosniff'."
                })
        else:
            missing_headers.append("x-content-type-options")
            issues.append({
                "header": "X-Content-Type-Options",
                "type": "Missing Security Header",
                "severity": "LOW",
                "risk": "Thiếu X-Content-Type-Options cho phép trình duyệt đoán định (MIME sniffing) kiểu dữ liệu, có thể dẫn đến thực thi mã ngoài ý muốn.",
                "remediation": "Bổ sung tiêu đề 'X-Content-Type-Options: nosniff'."
            })

        # 5. Referrer-Policy
        if "referrer-policy" in headers_lower:
            present_headers["referrer-policy"] = headers_lower["referrer-policy"]
        else:
            missing_headers.append("referrer-policy")
            issues.append({
                "header": "Referrer-Policy",
                "type": "Missing Security Header",
                "severity": "LOW",
                "risk": "Thiếu Referrer-Policy có thể làm rò rỉ URL và tham số nhạy cảm sang trang web bên thứ ba qua header Referer.",
                "remediation": "Đặt 'Referrer-Policy: strict-origin-when-cross-origin' hoặc 'no-referrer'."
            })

        # 6. Permissions-Policy
        if "permissions-policy" in headers_lower or "feature-policy" in headers_lower:
            present_headers["permissions-policy"] = headers_lower.get("permissions-policy") or headers_lower.get("feature-policy")
        else:
            missing_headers.append("permissions-policy")

        # 7. Information Leaks
        for leak_hdr in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime"]:
            if leak_hdr in headers_lower:
                val = headers_lower[leak_hdr]
                info_leaks.append({"header": leak_hdr, "value": val})
                issues.append({
                    "header": leak_hdr,
                    "type": "Information Disclosure",
                    "severity": "LOW",
                    "risk": f"Tiêu đề '{leak_hdr}: {val}' để lộ chi tiết phần mềm máy chủ và phiên bản, hỗ trợ kẻ tấn công tra cứu CVE chính xác.",
                    "remediation": f"Vô hiệu hóa hoặc ẩn tiêu đề '{leak_hdr}' trong cấu hình web server."
                })

        # Calculate security score & grade
        max_score = 100
        penalty = (
            len([i for i in issues if i["severity"] == "HIGH"]) * 25
            + len([i for i in issues if i["severity"] == "MEDIUM"]) * 10
            + len([i for i in issues if i["severity"] == "LOW"]) * 5
        )
        score = max(0, max_score - penalty)
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 65:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"

        return json.dumps({
            "status": "success",
            "target": target_url_str,
            "score": score,
            "grade": grade,
            "present_headers_count": len(present_headers),
            "present_headers": present_headers,
            "missing_headers_count": len(missing_headers),
            "missing_headers": missing_headers,
            "information_leaks_count": len(info_leaks),
            "information_leaks": info_leaks,
            "issues_count": len(issues),
            "issues": issues,
        })

    except Exception as e:
        return json.dumps({
            "status": "error",
            "target": clean_url,
            "error": f"Không thể kiểm toán HTTP headers từ {clean_url}: {e}",
            "issues_count": 0,
            "issues": [],
        })


# ---------------------------------------------------------------------------
# Tool: docker_api_docs_audit
# ---------------------------------------------------------------------------
@mcp.tool()
def docker_api_docs_audit(target_url: str) -> str:
    """Dò quét và phát hiện các tài liệu API nhạy cảm (Swagger, OpenAPI, Redoc, GraphQL Introspection) lộ lọt không xác thực.

    Args:
        target_url: URL gốc hoặc đường dẫn ứng dụng web (ví dụ: 'http://example.com' hoặc 'https://api.example.com').
    """
    if not target_url or not target_url.strip():
        return json.dumps({"error": "target_url must be specified", "exposed_docs": []})

    clean_url = _ensure_url_scheme(target_url.strip(), default_scheme="http")
    parsed = urlparse(clean_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    timeout_cfg = _get_timeout("api_docs", 60)
    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    probe_paths = [
        "/swagger.json",
        "/openapi.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        "/api/swagger.json",
        "/swagger/v1/swagger.json",
        "/swagger-ui/",
        "/swagger-ui.html",
        "/api/docs",
        "/docs",
        "/redoc",
    ]

    exposed_docs = []
    issues = []

    # 1. Probe REST / OpenAPI endpoints
    for p in probe_paths:
        try:
            full_probe = base_url + p
            r = requests.get(full_probe, headers=req_headers, timeout=min(timeout_cfg, 6), verify=False, allow_redirects=True)
            if r.status_code == 200:
                content_type = r.headers.get("Content-Type", "").lower()
                text_snippet = r.text[:2000]

                # Case A: JSON OpenAPI / Swagger
                if "application/json" in content_type or (text_snippet.strip().startswith("{") and any(k in text_snippet for k in ["swagger", "openapi", "paths"])):
                    try:
                        spec = r.json()
                        title = spec.get("info", {}).get("title", "API Documentation")
                        version = spec.get("info", {}).get("version", "unknown")
                        paths = list(spec.get("paths", {}).keys())
                        doc_item = {
                            "path": p,
                            "url": full_probe,
                            "type": "OpenAPI / Swagger JSON Specification",
                            "title": title,
                            "api_version": version,
                            "endpoints_count": len(paths),
                            "sample_endpoints": paths[:8],
                            "severity": "HIGH",
                            "risk": f"Lộ lọt đặc tả API '{title}' v{version} gồm {len(paths)} endpoints cho phép kẻ tấn công lập bản đồ bề mặt tấn công chính xác.",
                        }
                        exposed_docs.append(doc_item)
                        issues.append({
                            "type": "Exposed API Specification",
                            "endpoint": full_probe,
                            "severity": "HIGH",
                            "description": doc_item["risk"],
                            "remediation": "Đặt quyền truy cập hoặc vô hiệu hóa public endpoint Swagger/OpenAPI trên môi trường Production."
                        })
                    except Exception:
                        pass

                # Case B: HTML Swagger UI / Redoc
                elif "text/html" in content_type and any(kw in text_snippet.lower() for kw in ["swagger ui", "swagger-ui", "redoc", "api documentation"]):
                    doc_item = {
                        "path": p,
                        "url": full_probe,
                        "type": "Interactive API Documentation UI",
                        "severity": "MEDIUM",
                        "risk": f"Giao diện tương tác API Documentation ({p}) bị công khai cho phép khám phá cấu trúc API.",
                    }
                    exposed_docs.append(doc_item)
                    issues.append({
                        "type": "Exposed API Documentation UI",
                        "endpoint": full_probe,
                        "severity": "MEDIUM",
                        "description": doc_item["risk"],
                        "remediation": "Yêu cầu xác thực quản trị viên hoặc ẩn giao diện tài liệu API trên Internet."
                    })
        except Exception:
            continue

    # 2. Probe GraphQL Introspection
    try:
        graphql_url = base_url + "/graphql"
        gql_payload = {"query": "{ __schema { types { name } } }"}
        r_gql = requests.post(graphql_url, json=gql_payload, headers=req_headers, timeout=min(timeout_cfg, 6), verify=False)
        if r_gql.status_code == 200 and "__schema" in r_gql.text:
            types_count = len(r_gql.json().get("data", {}).get("__schema", {}).get("types", []))
            doc_item = {
                "path": "/graphql",
                "url": graphql_url,
                "type": "GraphQL Schema Introspection",
                "types_count": types_count,
                "severity": "HIGH",
                "risk": f"Điểm cuối GraphQL bật Introspection công khai (phát hiện {types_count} kiểu dữ liệu) cho phép trích xuất toàn bộ schema truy vấn.",
            }
            exposed_docs.append(doc_item)
            issues.append({
                "type": "GraphQL Introspection Enabled",
                "endpoint": graphql_url,
                "severity": "HIGH",
                "description": doc_item["risk"],
                "remediation": "Vô hiệu hóa tính năng Introspection trên GraphQL engine trong môi trường Production."
            })
    except Exception:
        pass

    return json.dumps({
        "status": "success",
        "target": base_url,
        "exposed_docs_count": len(exposed_docs),
        "exposed_docs": exposed_docs,
        "issues_count": len(issues),
        "issues": issues,
    })


# ---------------------------------------------------------------------------
# Tool: docker_subdomain_takeover_audit
# ---------------------------------------------------------------------------
@mcp.tool()
def docker_subdomain_takeover_audit(domain: str, subdomains: list[str] | None = None) -> str:
    """Kiểm toán bản ghi CNAME của các tên miền phụ để phát hiện nguy cơ chiếm đoạt tên miền (Subdomain Takeover).

    Args:
        domain: Tên miền chính (ví dụ: 'example.com').
        subdomains: Danh sách tên miền phụ tùy chọn cần kiểm toán. Nếu không truyền, hệ thống tự động kiểm tra các tiền tố phổ biến.
    """
    if not domain or not domain.strip():
        return json.dumps({"error": "domain must be specified", "vulnerabilities": []})

    clean_domain = _normalize_target(domain)
    timeout_cfg = _get_timeout("subdomain_takeover", 60)

    # Provider CNAME keywords and error fingerprints
    PROVIDER_FINGERPRINTS = [
        {"service": "AWS S3 Bucket", "cname_kw": ["s3.amazonaws.com", "s3-website", "s3."], "error_patterns": ["NoSuchBucket", "The specified bucket does not exist"]},
        {"service": "GitHub Pages", "cname_kw": ["github.io"], "error_patterns": ["There isn't a GitHub Pages site here", "404 - File not found"]},
        {"service": "Heroku", "cname_kw": ["herokudns.com", "herokuapp.com"], "error_patterns": ["No such app", "There's nothing here"]},
        {"service": "Azure Web App", "cname_kw": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"], "error_patterns": ["404 Web Site not found", "Error 404 - Web app not found"]},
        {"service": "CloudFront CDN", "cname_kw": ["cloudfront.net"], "error_patterns": ["Bad Request: ERROR: The request could not be satisfied", "NoSuchDistribution"]},
        {"service": "Shopify", "cname_kw": ["myshopify.com"], "error_patterns": ["Sorry, this shop is currently unavailable"]},
        {"service": "Fastly CDN", "cname_kw": ["fastly.net"], "error_patterns": ["Fastly error: unknown domain"]},
        {"service": "Zendesk", "cname_kw": ["zendesk.com"], "error_patterns": ["Help Center Closed"]},
        {"service": "Surge.sh", "cname_kw": ["surge.sh"], "error_patterns": ["project not found"]},
        {"service": "WordPress.com", "cname_kw": ["wordpress.com"], "error_patterns": ["Do you want to register"]},
        {"service": "Readme.io", "cname_kw": ["readme.io"], "error_patterns": ["Project doesnt exist"]},
    ]

    targets_to_audit = []
    if subdomains and isinstance(subdomains, list):
        for s in subdomains:
            clean_s = _normalize_target(str(s))
            if clean_s and clean_s not in targets_to_audit:
                targets_to_audit.append(clean_s)

    if not targets_to_audit:
        prefixes = ["dev", "staging", "api", "app", "blog", "test", "demo", "mail", "cdn"]
        targets_to_audit = [f"{p}.{clean_domain}" for p in prefixes]
        targets_to_audit.insert(0, clean_domain)

    audited_records = []
    vulnerabilities = []

    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    for sub in targets_to_audit[:15]:
        cname_val = ""
        # 1. Resolve CNAME using DoH
        try:
            doh_url = f"https://cloudflare-dns.com/dns-query?name={sub}&type=CNAME"
            r_dns = requests.get(doh_url, headers={"Accept": "application/dns-json"}, timeout=min(timeout_cfg, 5))
            if r_dns.status_code == 200:
                answers = r_dns.json().get("Answer", [])
                for ans in answers:
                    if ans.get("type") == 5:  # CNAME
                        cname_val = ans.get("data", "").rstrip(".")
                        break
        except Exception:
            pass

        # Fallback local socket resolution if DoH returned empty
        if not cname_val:
            try:
                host_info = socket.gethostbyname_ex(sub)
                if host_info and host_info[0] and host_info[0].lower() != sub.lower():
                    cname_val = host_info[0]
            except Exception:
                pass

        if not cname_val:
            continue

        cname_lower = cname_val.lower()
        matched_provider = None
        for prov in PROVIDER_FINGERPRINTS:
            if any(kw in cname_lower for kw in prov["cname_kw"]):
                matched_provider = prov
                break

        record_info = {
            "subdomain": sub,
            "cname": cname_val,
            "cloud_provider": matched_provider["service"] if matched_provider else "Other / Internal",
            "dangling": False,
        }

        # If CNAME points to known third-party provider, inspect HTTP response for error fingerprints
        if matched_provider:
            try:
                probe_url = f"http://{sub}"
                r_http = requests.get(probe_url, headers=req_headers, timeout=min(timeout_cfg, 5), verify=False, allow_redirects=True)
                body = r_http.text
                for err_pat in matched_provider["error_patterns"]:
                    if err_pat.lower() in body.lower():
                        record_info["dangling"] = True
                        vuln_item = {
                            "subdomain": sub,
                            "cname": cname_val,
                            "service": matched_provider["service"],
                            "fingerprint_matched": err_pat,
                            "severity": "HIGH",
                            "cvss_score": 8.4,
                            "risk": f"Nguy cơ Subdomain Takeover: Tên miền phụ '{sub}' trỏ CNAME tới dịch vụ '{matched_provider['service']}' không tồn tại hoặc bị bỏ hoang. Kẻ tấn công có thể đăng ký tài nguyên này để chiếm quyền kiểm soát website.",
                            "remediation": f"1. Xóa ngay bản ghi CNAME cho '{sub}' trên DNS server.\n2. Hoặc đăng ký lại tài nguyên trên {matched_provider['service']} để giữ quyền sở hữu.",
                        }
                        vulnerabilities.append(vuln_item)
                        break
            except Exception:
                pass

        audited_records.append(record_info)

    return json.dumps({
        "status": "success",
        "domain": clean_domain,
        "total_subdomains_audited": len(audited_records),
        "takeover_vulnerabilities_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "audited_records": audited_records,
    })


# ---------------------------------------------------------------------------
# Tool: docker_waf_detect
# ---------------------------------------------------------------------------
@mcp.tool()
def docker_waf_detect(target_url: str) -> str:
    """Nhận diện Tường lửa Ứng dụng Web (WAF) và CDN (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5, Sucuri).

    Args:
        target_url: URL mục tiêu cần kiểm tra WAF/CDN (ví dụ: 'https://example.com').
    """
    if not target_url or not target_url.strip():
        return json.dumps({"error": "target_url must be specified", "waf_detected": False})

    clean_url = _ensure_url_scheme(target_url.strip(), default_scheme="https")
    timeout_cfg = _get_timeout("waf_detect", 30)
    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    detected_wafs = []
    signals = []

    try:
        # Phase 1: Passive Header & Cookie Inspection
        r = requests.get(clean_url, headers=req_headers, timeout=min(timeout_cfg, 8), verify=False, allow_redirects=True)
        headers_lower = {k.lower(): str(v).lower() for k, v in r.headers.items()}
        cookies_lower = [str(c.name).lower() for c in r.cookies]
        server_hdr = headers_lower.get("server", "")

        # 1. Cloudflare
        if "cf-ray" in headers_lower or "cloudflare" in server_hdr or any("__cfduid" in c for c in cookies_lower):
            detected_wafs.append("Cloudflare")
            signals.append("Header 'cf-ray' hoặc 'server: cloudflare' được ghi nhận")

        # 2. AWS WAF / CloudFront
        if "x-amz-cf-id" in headers_lower or "awselb" in server_hdr or "cloudfront" in server_hdr:
            detected_wafs.append("AWS WAF / CloudFront")
            signals.append("Header 'x-amz-cf-id' hoặc server AWS ghi nhận")

        # 3. Akamai
        if "x-akamai-transformed" in headers_lower or "akamai" in server_hdr or "akamaighost" in server_hdr:
            detected_wafs.append("Akamai Edge")
            signals.append("Header 'x-akamai-transformed' hoặc Akamai Ghost server")

        # 4. Imperva / Incapsula
        if "x-cdn" in headers_lower and "incapsula" in headers_lower["x-cdn"]:
            detected_wafs.append("Imperva Incapsula")
            signals.append("Header 'x-cdn: incapsula'")
        elif any("incap_ses" in c or "visid_incap" in c for c in cookies_lower):
            detected_wafs.append("Imperva Incapsula")
            signals.append("Cookie nhận diện Incapsula WAF")

        # 5. ModSecurity / OWASP CRS
        if "mod_security" in server_hdr or "modsecurity" in headers_lower.get("x-powered-by", ""):
            detected_wafs.append("ModSecurity (OWASP CRS)")
            signals.append("Header Server hoặc X-Powered-By chứa ModSecurity")

        # 6. F5 BIG-IP
        if any("bigipserver" in c or "f5_cspm" in c for c in cookies_lower) or "x-wa-info" in headers_lower:
            detected_wafs.append("F5 BIG-IP ASM")
            signals.append("Cookie hoặc header F5 BIG-IP WAF")

        # 7. Sucuri
        if "x-sucuri-id" in headers_lower or "sucuri" in server_hdr:
            detected_wafs.append("Sucuri CloudProxy")
            signals.append("Header 'x-sucuri-id' hoặc 'server: sucuri'")

        # 8. Fastly
        if "x-fastly-request-id" in headers_lower or "fastly" in server_hdr:
            detected_wafs.append("Fastly CDN / WAF")
            signals.append("Header 'x-fastly-request-id'")

        # Phase 2: Active Benign Probe if not detected passively
        if not detected_wafs:
            try:
                sep = "&" if "?" in clean_url else "?"
                probe_url = f"{clean_url}{sep}waf_test_probe=<script>alert(1)</script>"
                r_probe = requests.get(probe_url, headers=req_headers, timeout=min(timeout_cfg, 6), verify=False)
                if r_probe.status_code in (403, 406, 429, 501):
                    probe_text = r_probe.text.lower()
                    if "cloudflare" in probe_text:
                        detected_wafs.append("Cloudflare")
                        signals.append("Chặn probe với trang cảnh báo Cloudflare (HTTP 403)")
                    elif "incapsula" in probe_text or "imperva" in probe_text:
                        detected_wafs.append("Imperva Incapsula")
                        signals.append("Chặn probe với trang Incapsula Incident ID")
                    elif "sucuri" in probe_text:
                        detected_wafs.append("Sucuri CloudProxy")
                        signals.append("Chặn probe với trang Sucuri Firewall")
                    elif "aws" in probe_text:
                        detected_wafs.append("AWS WAF")
                        signals.append("Chặn probe với mã lỗi AWS WAF (HTTP 403)")
                    else:
                        detected_wafs.append("Generic Web Application Firewall (WAF)")
                        signals.append(f"Máy chủ phản hồi HTTP {r_probe.status_code} khi nhận ký tự kiểm thử XSS")
            except Exception:
                pass

        waf_detected = len(detected_wafs) > 0
        primary_waf = detected_wafs[0] if detected_wafs else "None Detected"

        evasion_tips = []
        if waf_detected:
            evasion_tips = [
                "1. Tìm Origin IP máy chủ gốc (qua DNS history, chứng chỉ SSL SANs, hoặc MX records) để gửi request trực tiếp vòng qua WAF.",
                "2. Giãn cách thời gian giữa các requests (delay 2-5 giây) để tránh bị chặn bởi Rate-Limiting rules.",
                "3. Áp dụng kỹ thuật mã hóa đa tầng (Double URL Encoding, Unicode / UTF-8 Overlong, HPP - HTTP Parameter Pollution).",
                "4. Thay đổi User-Agent thành browser hợp lệ và xoay vòng headers để giảm xác suất bị AI Behavioral Scoring gắn cờ.",
            ]

        return json.dumps({
            "status": "success",
            "target": str(r.url),
            "waf_detected": waf_detected,
            "primary_waf": primary_waf,
            "detected_wafs": detected_wafs,
            "confidence": "HIGH" if waf_detected else "LOW",
            "signals": signals,
            "evasion_recommendations": evasion_tips,
        })

    except Exception as e:
        return json.dumps({
            "status": "error",
            "target": clean_url,
            "error": f"Không thể nhận diện WAF từ {clean_url}: {e}",
            "waf_detected": False,
            "primary_waf": "Error",
            "detected_wafs": [],
            "signals": [],
            "evasion_recommendations": [],
        })


if __name__ == "__main__":
    mcp.run(transport="stdio")



