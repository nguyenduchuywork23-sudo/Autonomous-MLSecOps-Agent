"""Unified MCP Server v4.1 — All Docker Arsenal tools in a single process.

This server provides access to the complete Docker Arsenal security toolkit
inside Docker containers for full OPSEC isolation, alongside companion native servers.

All 31 tools are registered and active:
RECON TOOLS:
  docker_resolve_dns        — DNS resolution helper
  docker_scan_ports_fast    — Nmap fast port scan
  docker_scan_ports_deep    — Nmap deep service/version scan
  docker_crawl_web          — Katana web crawler
  browse_webpage            — HTTP page reader (OSINT)
  docker_whatweb            — Technology fingerprinting
  docker_nikto_scan         — Web server misconfiguration scanner
  docker_nuclei_scan        — CVE/vulnerability scanner
  docker_dirb_scan          — Gobuster directory brute-force
  docker_subfinder          — Subdomain enumeration
  docker_ffuf               — URL/parameter fuzzer
  docker_testssl            — SSL/TLS configuration scan
  docker_sensitive_files_scan — Exposed .env, .git, backups scanner
  docker_cors_scan          — CORS & security headers audit
  docker_httpx_probe        — Multi-target alive HTTP/HTTPS probe
  docker_ssl_cert_audit     — SSL/TLS certificate, expiry, ciphers & SANs extraction
  docker_dns_security_audit — DNS/Email security audit (SPF, DMARC, DNSSEC, MX via DoH)
  docker_security_txt_audit — RFC 9116 security.txt, robots.txt, and sitemap.xml audit
  docker_cookie_security_audit — Cookie security flags (Secure, HttpOnly, SameSite) & session risk
  docker_http_headers_audit — OWASP secure HTTP headers and server leak audit
  docker_api_docs_audit     — Exposed OpenAPI, Swagger, Redoc & GraphQL audit
  docker_subdomain_takeover_audit — Dangling CNAME subdomain takeover audit
  docker_waf_detect         — Web Application Firewall and CDN detection

EXPLOIT TOOLS:
  docker_sqlmap_scan        — SQL injection scanner
  docker_sqlmap_dump        — SQL injection data dump
  docker_bruteforce         — Hydra readiness check
  bruteforce_ssh            — Hydra SSH brute-force
  bruteforce_http_form      — Hydra HTTP form brute-force
  docker_wpscan             — WordPress vulnerability scanner
  docker_msf_search         — Metasploit exploit search
  docker_xss_scan           — Reflected XSS parameter fuzzer
"""

import sys
import pathlib
import json

# Ensure sibling server modules are importable when run as a subprocess
_SERVERS_DIR = str(pathlib.Path(__file__).resolve().parent)
if _SERVERS_DIR not in sys.path:
    sys.path.insert(0, _SERVERS_DIR)

# Import the fully-equipped Docker Arsenal server instance
from docker_arsenal import mcp  # noqa: E402, F401


@mcp.tool()
def docker_arsenal_status() -> str:
    """Return status and inventory of all registered security tools."""
    return json.dumps({
        "status": "online",
        "version": "v4.1",
        "server": "Unified Docker Arsenal",
        "total_tools": 31,
        "recon_tools_count": 23,
        "exploit_tools_count": 8,
    })



if __name__ == "__main__":
    mcp.run(transport="stdio")
