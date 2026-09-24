"""Automated CVE & Threat Intelligence Enrichment Engine.

Provides offline lookup and heuristic threat intelligence enrichment for CVEs:
- CVSS v3.1 Base Score and Vector String
- EPSS (Exploit Prediction Scoring System) probability score (0.0 to 1.0)
- CISA KEV (Known Exploited Vulnerabilities) catalog presence
- Remediation urgency & weaponization status
"""

import re
from typing import Any, Optional

# Curated offline database of high-impact / notorious web & infrastructure CVEs
KNOWN_CVE_INTEL: dict[str, dict[str, Any]] = {
    "CVE-2021-44228": {
        "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "epss_score": 0.975,
        "cisa_kev": True,
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    },
    "CVE-2022-22965": {
        "title": "Spring Framework DataBinder RCE (Spring4Shell)",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "epss_score": 0.942,
        "cisa_kev": True,
        "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding.",
    },
    "CVE-2017-5638": {
        "title": "Apache Struts 2 Jakarta Multipart Parser RCE",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "epss_score": 0.974,
        "cisa_kev": True,
        "description": "Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 allows remote attackers to execute arbitrary commands via a Content-Type header.",
    },
    "CVE-2023-34362": {
        "title": "MOVEit Transfer SQL Injection to RCE",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "epss_score": 0.968,
        "cisa_kev": True,
        "description": "SQL injection vulnerability in Progress Software MOVEit Transfer web application leading to unauthorized access and potential remote code execution.",
    },
    "CVE-2023-4966": {
        "title": "Citrix Bleed NetScaler ADC/Gateway Sensitive Memory Exposure",
        "cvss_score": 9.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "severity": "CRITICAL",
        "epss_score": 0.957,
        "cisa_kev": True,
        "description": "Buffer overflow vulnerability in NetScaler ADC and NetScaler Gateway allowing unauthorized remote information disclosure of session tokens.",
    },
    "CVE-2023-22515": {
        "title": "Atlassian Confluence Data Center Broken Access Control",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "epss_score": 0.965,
        "cisa_kev": True,
        "description": "Broken Access Control vulnerability in Atlassian Confluence Server and Data Center allowing external attackers to create unauthorized administrator accounts.",
    },
    "CVE-2021-26855": {
        "title": "Microsoft Exchange Server SSRF (ProxyLogon)",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "epss_score": 0.971,
        "cisa_kev": True,
        "description": "Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon SSRF).",
    },
    "CVE-2020-5902": {
        "title": "F5 BIG-IP TMUI Remote Code Execution",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "epss_score": 0.963,
        "cisa_kev": True,
        "description": "The Traffic Management User Interface (TMUI) of BIG-IP has an RCE vulnerability in undisclosed pages.",
    },
    "CVE-2014-0160": {
        "title": "OpenSSL TLS Heartbeat Extension Information Disclosure (Heartbleed)",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "HIGH",
        "epss_score": 0.952,
        "cisa_kev": True,
        "description": "TLS heartbeat read overrun allows memory disclosure from process memory in OpenSSL 1.0.1 through 1.0.1f.",
    },
}

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def extract_cve_ids(text: str) -> list[str]:
    """Extract all valid CVE identifiers from a string."""
    if not text:
        return []
    matches = _CVE_PATTERN.findall(text)
    seen = set()
    ordered = []
    for m in matches:
        upper = m.upper()
        if upper not in seen:
            seen.add(upper)
            ordered.append(upper)
    return ordered


def enrich_cve_intel(cve_id: str, current_severity: str = "INFO") -> dict[str, Any]:
    """Enrich a CVE with CVSS score, vector, EPSS score, and CISA KEV status.

    Uses exact curated intelligence if available; otherwise falls back to
    deterministic heuristic estimation based on vulnerability age and severity.
    """
    clean_cve = cve_id.strip().upper() if cve_id else ""
    if not clean_cve or not clean_cve.startswith("CVE-"):
        return {
            "cve_id": clean_cve,
            "cvss_score": None,
            "cvss_vector": "",
            "epss_score": None,
            "cisa_kev": False,
            "is_known_threat": False,
        }

    # 1. Exact match in curated database
    if clean_cve in KNOWN_CVE_INTEL:
        intel = KNOWN_CVE_INTEL[clean_cve]
        return {
            "cve_id": clean_cve,
            "cvss_score": intel["cvss_score"],
            "cvss_vector": intel["cvss_vector"],
            "epss_score": intel["epss_score"],
            "cisa_kev": intel["cisa_kev"],
            "is_known_threat": True,
            "title": intel.get("title", ""),
        }

    # 2. Heuristic estimation based on CVE year and severity
    m = re.match(r"CVE-(\d{4})-(\d+)", clean_cve)
    year = int(m.group(1)) if m else 2023
    
    # Calculate baseline score from severity
    sev_upper = (current_severity or "INFO").upper()
    if "CRIT" in sev_upper:
        base_cvss = 9.8
        base_epss = 0.65
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    elif "HIGH" in sev_upper:
        base_cvss = 7.5
        base_epss = 0.35
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    elif "MED" in sev_upper:
        base_cvss = 5.3
        base_epss = 0.12
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    elif "LOW" in sev_upper:
        base_cvss = 3.3
        base_epss = 0.04
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
    else:
        base_cvss = 5.0
        base_epss = 0.08
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

    # Age adjustment: older critical CVEs without patch tend to have known public exploit code
    age = max(0, 2026 - year)
    if age >= 2 and base_cvss >= 7.0:
        base_epss = min(0.92, round(base_epss + (0.05 * min(age, 5)), 3))

    return {
        "cve_id": clean_cve,
        "cvss_score": base_cvss,
        "cvss_vector": vector,
        "epss_score": round(base_epss, 3),
        "cisa_kev": False,
        "is_known_threat": False,
    }
