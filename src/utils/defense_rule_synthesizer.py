"""Multi-Platform Blue Team Defense Rule Synthesizer.

Automatically generates real-time virtual patching and perimeter defense rules
for discovered vulnerabilities:
- ModSecurity / OWASP CRS WAF Rules (SecRule)
- Suricata / Snort IDS Network Signatures
- Sigma Generic SIEM Detection Rules (YAML)
- Cloudflare WAF Firewall Rule Expressions
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class DefenseRuleSet:
    """Collection of multi-platform defensive virtual patch rules."""

    finding_title: str
    category: str
    modsecurity_rule: str
    suricata_rule: str
    sigma_rule: str
    cloudflare_rule: str

    def to_dict(self) -> dict[str, str]:
        return {
            "finding_title": self.finding_title,
            "category": self.category,
            "modsecurity_rule": self.modsecurity_rule,
            "suricata_rule": self.suricata_rule,
            "sigma_rule": self.sigma_rule,
            "cloudflare_rule": self.cloudflare_rule,
        }

    def format_block(self) -> str:
        """Format defensive virtual patches into an actionable Markdown directive."""
        return (
            f"🛡️ [VIRTUAL PATCH & BLUE TEAM DEFENSE RULES: {self.category.upper()}]\n"
            f"• Lỗ hổng mục tiêu: {self.finding_title}\n"
            f"• ModSecurity WAF:\n```apache\n{self.modsecurity_rule}\n```\n"
            f"• Suricata IDS Signature:\n```suricata\n{self.suricata_rule}\n```\n"
            f"• Cloudflare Firewall Expression:\n```text\n{self.cloudflare_rule}\n```\n"
            f"• Sigma SIEM Rule:\n```yaml\n{self.sigma_rule}\n```"
        )


class DefenseRuleSynthesizer:
    """Automated generator of multi-platform defensive perimeter rules."""

    _rule_counter: int = 1000000

    @classmethod
    def _next_id(cls) -> int:
        cls._rule_counter += 1
        return cls._rule_counter

    def synthesize_rules(
        self,
        finding_title: str,
        description: str = "",
        evidence: str = "",
        cve_id: str = "",
    ) -> DefenseRuleSet:
        """Synthesize ModSecurity, Suricata, Sigma, and Cloudflare rules."""
        text = f"{finding_title} {description} {evidence} {cve_id}".lower()
        rule_id = self._next_id()

        # 1. SQL Injection
        if re.search(r"\b(sql|sqli)\b|\bsql\s+injection\b", text):
            category = "SQL Injection"
            modsec = (
                f'SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS "@rx (?i)(?:union\\s+select|or\\s+[\'"]?\\d+[\'"]?\\s*=\\s*[\'"]?\\d+|sleep\\s*\\(|benchmark\\s*\\()" \\\n'
                f'    "id:{rule_id},phase:2,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,\\\n'
                f'    msg:\'MLSecOps Virtual Patch: SQL Injection Attempt detected on {finding_title}\',\\\n'
                f'    tag:\'application-multi\',tag:\'language-multi\',tag:\'platform-multi\',tag:\'attack-sqli\',severity:\'CRITICAL\'"'
            )
            suricata = (
                f'alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"MLSecOps Virtual Patch: SQL Injection Detected ({cve_id or "Custom"})"; '
                f'flow:established,to_server; http.uri; content:"union"; nocase; pcre:"/(?:union\\s+select|or\\s+1=1)/i"; '
                f'classtype:web-application-attack; sid:{rule_id + 1000000}; rev:1;)'
            )
            sigma = (
                f'title: Potential SQL Injection Exploitation Attempt\n'
                f'id: mlsec-{rule_id}\n'
                f'status: experimental\n'
                f'description: Detects SQL Injection attack payloads in web server request URI or body\n'
                f'logsource:\n'
                f'    category: webserver\n'
                f'detection:\n'
                f'    selection:\n'
                f'        cs-method: ["GET", "POST"]\n'
                f'        cs-uri-query|contains:\n'
                f'            - "union select"\n'
                f'            - "or 1=1"\n'
                f'            - "sleep("\n'
                f'    condition: selection\n'
                f'level: high'
            )
            cf = '(http.request.uri.query contains "union select" or http.request.uri.query contains "or 1=1" or http.request.uri.query contains "sleep(")'

        # 2. Remote Code Execution / Command Injection
        elif re.search(r"\brce\b|remote code|command injection|shell injection", text):
            category = "Command Injection"
            modsec = (
                f'SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i)(?:;|\\|\\||&&|`|\\$\\([^)]+\\))\\s*(?:cat|id|whoami|sh|bash|curl|wget)\\b" \\\n'
                f'    "id:{rule_id},phase:2,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,\\\n'
                f'    msg:\'MLSecOps Virtual Patch: Command Injection Attempt on {finding_title}\',\\\n'
                f'    tag:\'attack-rce\',severity:\'CRITICAL\'"'
            )
            suricata = (
                f'alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"MLSecOps Virtual Patch: Command Injection Execution Attempt"; '
                f'flow:established,to_server; http.request_body; pcre:"/(?:;|\\|\\||&&)\\s*(?:cat|id|whoami|sh|bash)/i"; '
                f'classtype:attempted-admin; sid:{rule_id + 1000000}; rev:1;)'
            )
            sigma = (
                f'title: Command Injection Shell Invocation Attempt\n'
                f'id: mlsec-{rule_id}\n'
                f'status: experimental\n'
                f'description: Detects shell chaining tokens and execution commands in HTTP parameters\n'
                f'logsource:\n'
                f'    category: webserver\n'
                f'detection:\n'
                f'    selection:\n'
                f'        cs-uri-query|re: "(?:;|\\|\\||&&)\\s*(?:cat|id|whoami|sh|bash)"\n'
                f'    condition: selection\n'
                f'level: critical'
            )
            cf = '(http.request.uri.query matches "(?i)(;|\\|\\||&&)\\s*(cat|id|whoami|bash|sh)")'

        # 3. Cross-Site Scripting (XSS)
        elif re.search(r"\bxss\b|cross-site scripting", text):
            category = "Cross-Site Scripting"
            modsec = (
                f'SecRule ARGS|REQUEST_HEADERS:User-Agent "@rx (?i)(?:<\\s*script\\b|javascript:|onerror\\s*=|onload\\s*=)" \\\n'
                f'    "id:{rule_id},phase:2,t:none,t:htmlEntityDecode,t:urlDecodeUni,t:lowercase,deny,status:403,\\\n'
                f'    msg:\'MLSecOps Virtual Patch: XSS Attempt on {finding_title}\',tag:\'attack-xss\',severity:\'HIGH\'"'
            )
            suricata = (
                f'alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"MLSecOps Virtual Patch: XSS Script Injection"; '
                f'flow:established,to_server; http.uri; content:"script"; nocase; pcre:"/<script\\b|onerror=/i"; '
                f'classtype:web-application-attack; sid:{rule_id + 1000000}; rev:1;)'
            )
            sigma = (
                f'title: Cross-Site Scripting Payload in Web Request\n'
                f'id: mlsec-{rule_id}\n'
                f'status: experimental\n'
                f'description: Identifies XSS script tags and event handlers in web server logs\n'
                f'logsource:\n'
                f'    category: webserver\n'
                f'detection:\n'
                f'    selection:\n'
                f'        cs-uri-query|contains:\n'
                f'            - "<script"\n'
                f'            - "onerror="\n'
                f'            - "javascript:"\n'
                f'    condition: selection\n'
                f'level: medium'
            )
            cf = '(http.request.uri.query contains "<script" or http.request.uri.query contains "onerror=" or http.request.uri.query contains "javascript:")'

        # 4. Path Traversal / Arbitrary File Read
        elif re.search(r"path traversal|directory traversal|lfi|file inclusion", text):
            category = "Path Traversal"
            modsec = (
                f'SecRule REQUEST_URI|ARGS "@rx (?i)(?:\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|/etc/passwd|win\\.ini)" \\\n'
                f'    "id:{rule_id},phase:2,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,\\\n'
                f'    msg:\'MLSecOps Virtual Patch: Path Traversal Attempt on {finding_title}\',tag:\'attack-traversal\',severity:\'HIGH\'"'
            )
            suricata = (
                f'alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"MLSecOps Virtual Patch: Directory Traversal Pattern"; '
                f'flow:established,to_server; http.uri; content:".."; pcre:"/(\\.\\.[\\/\\\\]|%2e%2e%2f)/i"; '
                f'classtype:web-application-attack; sid:{rule_id + 1000000}; rev:1;)'
            )
            sigma = (
                f'title: Directory Climbing and Path Traversal Attempt\n'
                f'id: mlsec-{rule_id}\n'
                f'status: experimental\n'
                f'description: Detects path climbing directory dots in request path\n'
                f'logsource:\n'
                f'    category: webserver\n'
                f'detection:\n'
                f'    selection:\n'
                f'        cs-uri-stem|contains:\n'
                f'            - "../"\n'
                f'            - "..\\\\"\n'
                f'            - "/etc/passwd"\n'
                f'    condition: selection\n'
                f'level: high'
            )
            cf = '(http.request.uri.path contains "../" or http.request.uri.path contains "..\\\\" or http.request.uri.path contains "/etc/passwd")'

        # 5. Server-Side Request Forgery (SSRF)
        elif re.search(r"\bssrf\b|request forgery", text):
            category = "SSRF"
            modsec = (
                f'SecRule ARGS "@rx (?i)(?:https?://(?:127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254|10\\.\\d+|172\\.(?:1[6-9]|2\\d|3[01])|192\\.168))" \\\n'
                f'    "id:{rule_id},phase:2,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,\\\n'
                f'    msg:\'MLSecOps Virtual Patch: SSRF to Private / Cloud Metadata IP Denied\',tag:\'attack-ssrf\',severity:\'CRITICAL\'"'
            )
            suricata = (
                f'alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"MLSecOps Virtual Patch: SSRF Cloud Metadata Request"; '
                f'flow:established,to_server; http.request_body; content:"169.254.169.254"; '
                f'classtype:web-application-attack; sid:{rule_id + 1000000}; rev:1;)'
            )
            sigma = (
                f'title: Potential Server-Side Request Forgery (SSRF) to Cloud Metadata\n'
                f'id: mlsec-{rule_id}\n'
                f'status: experimental\n'
                f'description: Detects internal RFC1918 or AWS/GCP metadata IP in request parameters\n'
                f'logsource:\n'
                f'    category: webserver\n'
                f'detection:\n'
                f'    selection:\n'
                f'        cs-uri-query|contains:\n'
                f'            - "169.254.169.254"\n'
                f'            - "127.0.0.1"\n'
                f'            - "localhost"\n'
                f'    condition: selection\n'
                f'level: high'
            )
            cf = '(http.request.uri.query contains "169.254.169.254" or http.request.uri.query contains "127.0.0.1")'

        # Fallback: Generic Web Application Attack
        else:
            category = "Security Misconfiguration"
            modsec = (
                f'SecRule REQUEST_URI "@rx (?i)(?:/\\.env|/\\.git|/config\\.json|/wp-config\\.php)" \\\n'
                f'    "id:{rule_id},phase:1,deny,status:403,msg:\'MLSecOps Virtual Patch: Deny access to sensitive root configuration\',severity:\'HIGH\'"'
            )
            suricata = (
                f'alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"MLSecOps Virtual Patch: Sensitive File Probe"; '
                f'flow:established,to_server; http.uri; content:".env"; classtype:web-application-attack; sid:{rule_id + 1000000}; rev:1;)'
            )
            sigma = (
                f'title: Sensitive Environment File Access Attempt\n'
                f'id: mlsec-{rule_id}\n'
                f'status: experimental\n'
                f'logsource:\n'
                f'    category: webserver\n'
                f'detection:\n'
                f'    selection:\n'
                f'        cs-uri-stem|contains:\n'
                f'            - "/.env"\n'
                f'            - "/.git"\n'
                f'    condition: selection\n'
                f'level: high'
            )
            cf = '(http.request.uri.path contains "/.env" or http.request.uri.path contains "/.git")'

        return DefenseRuleSet(
            finding_title=finding_title,
            category=category,
            modsecurity_rule=modsec,
            suricata_rule=suricata,
            sigma_rule=sigma,
            cloudflare_rule=cf,
        )
