"""ReportState: Shared memory between Red Teamer (7B) and Reporter (3B).

Holds all findings, methodology steps, risk scores, and reporter suggestions
that accumulate during the real-time dual-agent collaboration.

Used by:
- Reporter Agent: updates findings and suggestions after each tool result
- DOCX Generator: reads the final state to produce the report
- Orchestrator: reads suggestions to inject into Red Teamer's context
"""

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Any

# ---------------------------------------------------------------------------
# Pre-compiled Regular Expressions for Attack Surface Discovery
# ---------------------------------------------------------------------------
_RE_PORT_LINE = re.compile(r'(?:port\s+|open\s+port\s+)?(\d{1,5})/(?:tcp|udp)\s+(?:open\s+)?([a-zA-Z0-9_\-\.]+)?', re.IGNORECASE)
_RE_HTTP_URL = re.compile(r'https?://[^\s"\'<>]+')
_RE_WHATWEB_TECH = re.compile(r'([A-Za-z0-9_\-]+)(?:\[[^\]]*\])')
_RE_SUBDOMAIN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')


@dataclass
class Finding:
    """A single security finding discovered during the assessment."""

    title: str
    severity: str = "INFO"  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description: str = ""
    impact: str = ""
    remediation: str = ""
    tool_source: str = ""  # Which tool discovered this
    raw_evidence: str = ""  # Raw evidence snippet
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    cve_id: str = ""
    cvss_score: Optional[float] = None
    owasp_category: str = ""
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    # Valid severity levels (ordered by priority)
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def __post_init__(self):
        """Normalize severity to uppercase, strip, and validate."""
        raw_sev = (self.severity or "INFO").upper().strip()
        sev_map = {
            "CRIT": "CRITICAL",
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MED": "MEDIUM",
            "MEDIUM": "MEDIUM",
            "MODERATE": "MEDIUM",
            "LOW": "LOW",
            "INFO": "INFO",
            "INFORMATIONAL": "INFO",
        }
        self.severity = sev_map.get(raw_sev, "INFO")
        self.title = (self.title or "Untitled Finding").strip()
        self.description = (self.description or "").strip()
        self.impact = (self.impact or "").strip()
        self.remediation = (self.remediation or "").strip()
        self.tool_source = (self.tool_source or "").strip()
        self.raw_evidence = (self.raw_evidence or "").strip()
        self.cve_id = (self.cve_id or "").strip().upper()
        if self.cvss_score is not None:
            try:
                self.cvss_score = float(self.cvss_score)
            except (ValueError, TypeError):
                self.cvss_score = None

        if not self.owasp_category or not self.mitre_techniques:
            self._auto_map_frameworks()

    def _auto_map_frameworks(self) -> None:
        """Automatically classify finding into OWASP Top 10 (2021) and MITRE ATT&CK Matrix."""
        text = f"{self.title} {self.description} {self.tool_source} {self.cve_id}".lower()

        # 1. SQL Injection
        if re.search(r"\b(sql|sqli)\b|injection", text):
            self.owasp_category = self.owasp_category or "A03:2021 - Injection"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Initial Access", "Execution"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1190 - Exploit Public-Facing Application"]
        # 2. Reflected / Stored Cross-Site Scripting (XSS)
        elif re.search(r"\bxss\b|cross-site scripting", text):
            self.owasp_category = self.owasp_category or "A03:2021 - Injection"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Initial Access", "Execution"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1059.007 - JavaScript", "T1189 - Drive-by Compromise"]
        # 3. Remote Code / Command Execution (RCE) — use word boundary so 'force' does not match
        elif re.search(r"\brce\b|remote code|command execution|code execution", text):
            self.owasp_category = self.owasp_category or "A03:2021 - Injection"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Execution", "Lateral Movement"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1059 - Command and Scripting Interpreter", "T1203 - Exploitation for Client Execution"]
        # 4. Server-Side Request Forgery (SSRF)
        elif re.search(r"\bssrf\b|request forgery", text):
            self.owasp_category = self.owasp_category or "A10:2021 - Server-Side Request Forgery (SSRF)"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Initial Access", "Lateral Movement"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1090 - Proxy", "T1190 - Exploit Public-Facing Application"]
        # 5. Outdated Components & Known CVEs
        elif re.search(r"cve-\d{4}-\d+|outdated|vulnerable component|wpscan|joomla|drupal", text):
            self.owasp_category = self.owasp_category or "A06:2021 - Vulnerable and Outdated Components"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Initial Access"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1190 - Exploit Public-Facing Application"]
        # 6. CORS & Session / Cookie Issues
        elif re.search(r"\bcors\b|\bcookie\b|\bhttponly\b|\bsamesite\b|access-control-allow|session flag", text):
            self.owasp_category = self.owasp_category or "A01:2021 - Broken Access Control"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Credential Access", "Defense Evasion"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1539 - Steal Web Session Cookie", "T1557 - Adversary-in-the-Middle"]
        # 7. Sensitive Files, Backups & Secret Leaks
        elif re.search(r"sensitive|\.env\b|\.git\b|backup|dump|leak|config exposure", text):
            self.owasp_category = self.owasp_category or "A05:2021 - Security Misconfiguration"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Discovery", "Credential Access"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1552 - Unsecured Credentials", "T1584 - Compromise Infrastructure"]
        # 8. Authentication & Password Brute Force
        elif re.search(r"\bbrute\b|\bhydra\b|password|credential|auth bypass|login brute", text):
            self.owasp_category = self.owasp_category or "A07:2021 - Identification and Authentication Failures"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Credential Access"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1110 - Brute Force", "T1110.001 - Password Guessing"]
        # 9. Path / Directory Traversal & LFI
        elif re.search(r"traversal|\blfi\b|path traversal|directory traversal", text):
            self.owasp_category = self.owasp_category or "A01:2021 - Broken Access Control"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Discovery", "Credential Access"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1083 - File and Directory Discovery"]
        # 10. SSL / Cryptographic Failures
        elif re.search(r"\bssl\b|\btls\b|\bcipher\b|testssl|cleartext|unencrypted|cert", text):
            self.owasp_category = self.owasp_category or "A02:2021 - Cryptographic Failures"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Credential Access", "Discovery"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1557 - Adversary-in-the-Middle", "T1040 - Network Sniffing"]
        else:
            self.owasp_category = self.owasp_category or "A05:2021 - Security Misconfiguration"
            if not self.mitre_tactics:
                self.mitre_tactics = ["Discovery"]
            if not self.mitre_techniques:
                self.mitre_techniques = ["T1046 - Network Service Discovery"]


@dataclass
class ToolStep:
    """A single tool execution step in the kill chain."""

    step_number: int
    tool_name: str
    arguments: dict
    result_snippet: str  # First N chars of result
    status: str  # SUCCESS / FAILED / TIMEOUT / BLOCKED
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    duration_seconds: float = 0.0
    reporter_comment: str = ""  # Reporter's real-time comment on this step


@dataclass
class ObjectiveMilestone:
    """A strategic milestone decomposing the user's mission objective."""
    id: str
    name: str
    description: str
    status: str = "PENDING"  # PENDING, IN_PROGRESS, COMPLETED
    progress_pct: int = 0
    relevant_tools: list[str] = field(default_factory=list)
    findings_count: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "progress_pct": self.progress_pct,
            "relevant_tools": self.relevant_tools,
            "findings_count": self.findings_count,
        }


@dataclass
class AttackSurfaceGraph:
    """Dynamic representation of the target attack surface discovered during assessment."""

    open_ports: dict[int, dict] = field(default_factory=dict)
    parameterized_endpoints: dict[str, dict] = field(default_factory=dict)
    login_forms: list[dict] = field(default_factory=list)
    detected_technologies: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    tested_vectors: list[str] = field(default_factory=list)
    exposed_sensitive_files: list[dict] = field(default_factory=list)
    alive_subdomains: list[dict] = field(default_factory=list)
    cors_issues: list[dict] = field(default_factory=list)
    ssl_cert_info: dict = field(default_factory=dict)
    dns_security_info: dict = field(default_factory=dict)
    hidden_discovered_paths: list[str] = field(default_factory=list)
    cookie_issues: list[dict] = field(default_factory=list)
    security_headers_info: dict = field(default_factory=dict)
    exposed_api_docs: list[dict] = field(default_factory=list)
    dangling_cnames: list[dict] = field(default_factory=list)
    detected_waf: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._tested_vectors_set: set[str] = set(self.tested_vectors)
        self._detected_technologies_set: set[str] = set(self.detected_technologies)
        self._subdomains_set: set[str] = set(self.subdomains)
        self._hidden_discovered_paths_set: set[str] = set(self.hidden_discovered_paths)

    def add_tested_vector(self, vector_sig: str) -> bool:
        if not hasattr(self, "_tested_vectors_set"):
            self._tested_vectors_set = set(self.tested_vectors)
        if vector_sig not in self._tested_vectors_set:
            self._tested_vectors_set.add(vector_sig)
            self.tested_vectors.append(vector_sig)
            return True
        return False

    def add_detected_technology(self, tech: str) -> bool:
        if not hasattr(self, "_detected_technologies_set"):
            self._detected_technologies_set = set(self.detected_technologies)
        if tech not in self._detected_technologies_set:
            self._detected_technologies_set.add(tech)
            self.detected_technologies.append(tech)
            return True
        return False

    def add_subdomain(self, sub: str) -> bool:
        if not hasattr(self, "_subdomains_set"):
            self._subdomains_set = set(self.subdomains)
        if sub not in self._subdomains_set:
            self._subdomains_set.add(sub)
            self.subdomains.append(sub)
            return True
        return False

    def add_hidden_path(self, path: str) -> bool:
        if not hasattr(self, "_hidden_discovered_paths_set"):
            self._hidden_discovered_paths_set = set(self.hidden_discovered_paths)
        if path not in self._hidden_discovered_paths_set:
            self._hidden_discovered_paths_set.add(path)
            self.hidden_discovered_paths.append(path)
            return True
        return False

    def has_attack_surface(self) -> bool:
        return bool(
            self.open_ports
            or self.parameterized_endpoints
            or self.login_forms
            or self.detected_technologies
            or self.subdomains
            or self.exposed_sensitive_files
            or self.alive_subdomains
            or self.cors_issues
            or self.ssl_cert_info
            or self.dns_security_info
            or self.hidden_discovered_paths
            or self.cookie_issues
            or self.security_headers_info
            or self.exposed_api_docs
            or self.dangling_cnames
            or self.detected_waf
        )

    def to_dict(self) -> dict:
        return {
            "open_ports": self.open_ports,
            "parameterized_endpoints": self.parameterized_endpoints,
            "login_forms": self.login_forms,
            "detected_technologies": self.detected_technologies,
            "subdomains": self.subdomains,
            "tested_vectors": self.tested_vectors,
            "exposed_sensitive_files": self.exposed_sensitive_files,
            "alive_subdomains": self.alive_subdomains,
            "cors_issues": self.cors_issues,
            "ssl_cert_info": self.ssl_cert_info,
            "dns_security_info": self.dns_security_info,
            "hidden_discovered_paths": self.hidden_discovered_paths,
            "cookie_issues": self.cookie_issues,
            "security_headers_info": self.security_headers_info,
            "exposed_api_docs": self.exposed_api_docs,
            "dangling_cnames": self.dangling_cnames,
            "detected_waf": self.detected_waf,
        }


class ReportState:
    """Accumulated report state built in real-time during the assessment.

    This acts as the shared memory between the Red Teamer and Reporter agents.
    The Reporter updates this after every tool execution, and the DOCX generator
    reads the final state to produce the assessment report.
    """

    def __init__(self, target: str, scan_mode: str = "recon", mission_objective: str = "", target_objective: str = ""):
        self.target = target
        self.scan_mode = scan_mode
        self.mission_objective = mission_objective or target_objective
        self.target_objective = self.mission_objective  # Compatibility alias
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None

        # Attack Surface & Tactical Graph
        self.attack_surface: AttackSurfaceGraph = AttackSurfaceGraph()
        self._correlating: bool = False

        # Deep Target Auto-Disambiguation
        self._auto_disambiguate_target()

        # Objective Milestones (Mission Decomposition)
        self.milestones: list[ObjectiveMilestone] = []
        self._init_milestones()

        # Report sections (built incrementally)
        self.executive_summary: str = ""
        self.findings: list[Finding] = []
        self._finding_index: dict[str, int] = {}
        self.methodology: list[ToolStep] = []
        self.risk_score: float = 0.0  # 0-10 scale
        self.recommendations: list[str] = []
        self._recommendations_set: set[str] = set()
        self.reporter_suggestions: list[str] = []  # Real-time suggestions for Red Teamer
        self.conclusion: str = ""

        # RAG Long-term Tactical Memory
        self.rag_applied_patterns: list[dict] = []
        self._rag_applied_ids: set[str] = set()
        self.rag_stored_patterns: list[dict] = []

        # Metadata
        self.total_iterations: int = 0
        self.red_teamer_final_answer: str = ""

    def _auto_disambiguate_target(self) -> None:
        """Deep Target Auto-Disambiguation: parse target URL/host immediately upon init to seed ports, endpoints, and paths."""
        if not self.target or not isinstance(self.target, str):
            return

        from urllib.parse import urlparse
        target_clean = self.target.strip()

        dummy_url = target_clean if "://" in target_clean else f"http://{target_clean}"
        try:
            parsed = urlparse(dummy_url)
        except Exception:
            return

        # 1. Port disambiguation (only if port is explicitly specified in target)
        if parsed.port:
            svc = "https" if (parsed.scheme == "https" or parsed.port in (443, 8443)) else "http"
            self.attack_surface.open_ports[parsed.port] = {"service": svc, "deep_scanned": False}

        # 2. Parameterized endpoint disambiguation
        if parsed.query and "=" in parsed.query:
            full_param_url = target_clean if "://" in target_clean else f"http://{target_clean}"
            self.attack_surface.parameterized_endpoints[full_param_url] = {"tested_sqli": False, "tested_xss": False}

        # 3. Path & login form disambiguation
        if parsed.path and parsed.path != "/":
            path_lower = parsed.path.lower()
            full_url = target_clean if "://" in target_clean else f"http://{target_clean}"
            if any(kw in path_lower for kw in ["login", "signin", "admin", "auth", "dangnhap"]):
                if not any(f.get("url") == full_url for f in self.attack_surface.login_forms):
                    self.attack_surface.login_forms.append({"url": full_url, "tested_bruteforce": False})

            clean_path = parsed.path.strip("/")
            if clean_path and any(kw in path_lower for kw in ["admin", "api", "v1", "v2", "backup", "secret", "config"]):
                path_entry = f"/{clean_path}"
                if path_entry not in self.attack_surface.hidden_discovered_paths:
                    self.attack_surface.hidden_discovered_paths.append(path_entry)

    def _init_milestones(self) -> None:
        """Decompose mission into concrete, trackable objective milestones."""
        obj_lower = (self.mission_objective or self.target_objective or "").lower()

        # M1: Attack Surface Discovery & Recon
        self.milestones.append(ObjectiveMilestone(
            id="m1_recon",
            name="Trinh Sát & Thu Thập Bề Mặt",
            description="Trinh sát bề mặt mạng, cổng dịch vụ, tên miền phụ, công nghệ web, chính sách RFC 9116, nhận diện WAF và kiểm toán takeover.",
            relevant_tools=[
                "docker_resolve_dns", "docker_scan_ports_fast", "docker_scan_ports_deep",
                "docker_subfinder", "docker_httpx_probe", "docker_crawl_web",
                "browse_webpage", "docker_whatweb", "docker_security_txt_audit",
                "docker_subdomain_takeover_audit", "docker_waf_detect"
            ],
        ))

        # M2: Infrastructure & Configuration Audit
        self.milestones.append(ObjectiveMilestone(
            id="m2_infra_audit",
            name="Kiểm Toán Cấu Hình & Hạ Tầng",
            description="Đánh giá chứng chỉ SSL/TLS, cấu hình DNS/SPF/DMARC, chính sách CORS, tiêu đề an ninh HTTP, tài liệu API, tệp nhạy cảm và bảo mật cookie.",
            relevant_tools=[
                "docker_ssl_cert_audit", "docker_dns_security_audit", "docker_cors_scan",
                "docker_sensitive_files_scan", "docker_cookie_security_audit", "docker_testssl",
                "docker_http_headers_audit", "docker_api_docs_audit"
            ],
        ))

        # M3: Deep Vulnerability & Exploitation
        is_full = "full" in self.scan_mode
        has_targeted_vulns = any(kw in obj_lower for kw in [
            "sql", "inject", "xss", "mật khẩu", "password", "brute", "hydra",
            "cve", "vuln", "lỗ hổng", "khai thác", "exploit", "wpscan"
        ])
        if is_full or has_targeted_vulns:
            self.milestones.append(ObjectiveMilestone(
                id="m3_vuln_exploit",
                name="Kiểm Thử Lỗ Hổng & Khai Thác Chuyên Sâu",
                description="Kiểm tra SQL Injection, Cross-Site Scripting (XSS), xác thực mật khẩu yếu và CVE đã biết.",
                relevant_tools=[
                    "docker_sqlmap_scan", "docker_sqlmap_dump", "docker_xss_scan",
                    "bruteforce_http_form", "bruteforce_ssh", "docker_wpscan",
                    "docker_nuclei_scan", "docker_nikto_scan", "docker_msf_search"
                ],
            ))

        # M4: Risk Synthesis & Defensive Hardening
        self.milestones.append(ObjectiveMilestone(
            id="m4_synthesis",
            name="Tổng Hợp Rủi Ro & Khuyến Nghị Phòng Thủ",
            description="Phân loại rủi ro theo CVSS, tổng hợp bằng chứng và xây dựng khuyến nghị phòng thủ doanh nghiệp.",
            relevant_tools=[],
        ))

    def _update_milestones_status(self) -> None:
        """Update milestones status (PENDING -> IN_PROGRESS -> COMPLETED) and progress percentage."""
        tested_tools = (
            set(s.tool_name for s in self.methodology)
            | set(v.split("::")[0] for v in self.attack_surface.tested_vectors)
            | set(self.attack_surface.tested_vectors)
        )
        has_surface = self.attack_surface.has_attack_surface()

        for m in self.milestones:
            if m.id == "m1_recon":
                recon_run = [t for t in m.relevant_tools if t in tested_tools]
                if recon_run:
                    if len(recon_run) >= 2 or (has_surface and len(recon_run) >= 1):
                        m.status = "COMPLETED"
                        m.progress_pct = 100
                    else:
                        m.status = "IN_PROGRESS"
                        m.progress_pct = 50
                else:
                    m.status = "PENDING"
                    m.progress_pct = 0

            elif m.id == "m2_infra_audit":
                infra_run = [t for t in m.relevant_tools if t in tested_tools]
                if infra_run:
                    if len(infra_run) >= 2:
                        m.status = "COMPLETED"
                        m.progress_pct = 100
                    else:
                        m.status = "IN_PROGRESS"
                        m.progress_pct = 50
                else:
                    m.status = "PENDING"
                    m.progress_pct = 0

            elif m.id == "m3_vuln_exploit":
                vuln_run = [t for t in m.relevant_tools if t in tested_tools]
                if vuln_run:
                    if len(vuln_run) >= 2 or len(self.findings) >= 2:
                        m.status = "COMPLETED"
                        m.progress_pct = 100
                    else:
                        m.status = "IN_PROGRESS"
                        m.progress_pct = 50
                else:
                    m.status = "PENDING"
                    m.progress_pct = 0

            elif m.id == "m4_synthesis":
                if self.findings or len(self.methodology) >= 3:
                    m.status = "COMPLETED" if self.end_time else "IN_PROGRESS"
                    m.progress_pct = 100 if self.end_time else 70
                else:
                    m.status = "PENDING"
                    m.progress_pct = 0

            # Count findings discovered under this milestone's tools
            m.findings_count = sum(1 for f in self.findings if f.tool_source in m.relevant_tools)

    def calculate_baseline_risk(self) -> float:
        """Calculate minimum baseline risk score based on confirmed findings."""
        if not self.findings:
            return 0.0
        counts = self.get_severity_counts()
        if counts["CRITICAL"] > 0:
            base = 9.0 + min(1.0, (counts["CRITICAL"] - 1) * 0.5 + counts["HIGH"] * 0.2)
        elif counts["HIGH"] > 0:
            base = 7.0 + min(1.8, (counts["HIGH"] - 1) * 0.4 + counts["MEDIUM"] * 0.2)
        elif counts["MEDIUM"] > 0:
            base = 4.0 + min(2.5, (counts["MEDIUM"] - 1) * 0.3 + counts["LOW"] * 0.1)
        elif counts["LOW"] > 0:
            base = 2.0 + min(1.5, (counts["LOW"] - 1) * 0.2)
        else:
            base = 1.0
        return round(min(base, 10.0), 1)

    def add_finding(self, finding: Finding) -> None:
        """Add a new finding or upgrade existing if higher severity, avoiding duplicates by title."""
        title_key = " ".join(finding.title.lower().split())
        idx = self._finding_index.get(title_key)
        if idx is not None and idx < len(self.findings):
            existing = self.findings[idx]
            # Update if new finding has higher severity
            if Finding.SEVERITY_ORDER.get(finding.severity, 4) < Finding.SEVERITY_ORDER.get(existing.severity, 4):
                self.findings[idx] = finding
            else:
                # Same or lower severity: augment evidence/remediation if existing lacks details
                if not existing.raw_evidence and finding.raw_evidence:
                    existing.raw_evidence = finding.raw_evidence
                if (not existing.remediation or existing.remediation == "N/A") and finding.remediation:
                    existing.remediation = finding.remediation
                if (not existing.impact or existing.impact == "N/A") and finding.impact:
                    existing.impact = finding.impact
                if not getattr(existing, "cve_id", "") and getattr(finding, "cve_id", ""):
                    existing.cve_id = finding.cve_id
                if getattr(existing, "cvss_score", None) is None and getattr(finding, "cvss_score", None) is not None:
                    existing.cvss_score = finding.cvss_score
            self._update_milestones_status()
            return

        self._finding_index[title_key] = len(self.findings)
        self.findings.append(finding)
        # Update baseline risk score if it exceeds current score
        baseline = self.calculate_baseline_risk()
        if baseline > self.risk_score:
            self.risk_score = baseline
        self._update_milestones_status()
        if not self._correlating:
            self.correlate_compound_threats()

    def add_step(self, step: ToolStep) -> None:
        """Record a tool execution step."""
        self.methodology.append(step)
        self._update_milestones_status()

    def add_recommendation(self, rec: str) -> None:
        """Add a remediation recommendation (deduplicated)."""
        if rec and rec not in self._recommendations_set:
            self._recommendations_set.add(rec)
            self.recommendations.append(rec)

    def update_risk_score(self, score: float) -> None:
        """Update risk score (only increase, never decrease during scan)."""
        baseline = self.calculate_baseline_risk()
        effective_score = max(score, baseline)
        if effective_score > self.risk_score:
            self.risk_score = min(effective_score, 10.0)

    def add_suggestion(self, suggestion: str) -> None:
        """Add a real-time suggestion from Reporter for Red Teamer."""
        if suggestion and suggestion.strip():
            self.reporter_suggestions.append(suggestion.strip())

    def record_rag_applied_patterns(self, patterns: list[dict]) -> None:
        """Record past experience / tactical attack patterns retrieved and applied during assessment."""
        if not patterns or not isinstance(patterns, list):
            return
        for p in patterns:
            if not isinstance(p, dict):
                continue
            # Deduplicate by ID or signature
            p_id = p.get("id") or f"{p.get('cwe_id', '')}:{p.get('successful_vector', '')}"
            if p_id not in self._rag_applied_ids:
                self._rag_applied_ids.add(p_id)
                self.rag_applied_patterns.append(p)

    def record_rag_stored_pattern(self, pattern: dict, stored_id: str = "") -> None:
        """Record newly formulated attack pattern learned and saved to Vector DB."""
        if not pattern or not isinstance(pattern, dict):
            return
        entry = dict(pattern)
        if stored_id:
            entry["id"] = stored_id
            entry["stored_id"] = stored_id
        if "timestamp" not in entry:
            entry["timestamp"] = datetime.now().strftime("%H:%M:%S")
        self.rag_stored_patterns.append(entry)

    def finalize(self, red_teamer_answer: str = "", conclusion: str = "") -> None:
        """Mark the report as complete."""
        self.end_time = datetime.now()
        self.red_teamer_final_answer = red_teamer_answer
        if not self._correlating:
            self.correlate_compound_threats()
        baseline = self.calculate_baseline_risk()
        if baseline > self.risk_score:
            self.risk_score = baseline
        if conclusion:
            self.conclusion = conclusion

    def correlate_compound_threats(self) -> list[Finding]:
        """Correlate isolated findings and attack surface signals into compound threat scenarios."""
        if self._correlating:
            return []

        self._correlating = True
        new_compound_findings = []
        try:
            finding_titles = {f.title for f in self.findings}
            has_xss = any(
                "xss" in f.title.lower() or "cross-site scripting" in f.title.lower()
                for f in self.findings
            )
            has_sensitive_leak = (
                bool(self.attack_surface.exposed_sensitive_files)
                or any("nhạy cảm" in f.title.lower() or ".env" in f.title.lower() or "backup" in f.title.lower() for f in self.findings)
            )
            has_dns_issues = (
                bool(self.attack_surface.dns_security_info.get("security_issues"))
                or any("spf" in f.title.lower() or "dmarc" in f.title.lower() for f in self.findings)
            )
            has_cookie_issues = (
                bool(self.attack_surface.cookie_issues)
                or any("cookie" in f.title.lower() or "httponly" in f.title.lower() for f in self.findings)
            )
            has_admin_path = (
                any("admin" in str(p).lower() for p in self.attack_surface.hidden_discovered_paths)
                or any("admin" in str(f.get("url", "")).lower() for f in self.attack_surface.login_forms)
                or any("admin" in f.title.lower() for f in self.findings)
            )
            has_cors_issue = (
                bool(self.attack_surface.cors_issues)
                or any("cors" in f.title.lower() for f in self.findings)
            )

            # 1. Chain: Admin Session Hijacking & Account Takeover (Admin path + Cookie missing flags + XSS)
            title_chain1 = "[CHUỖI TẤN CÔNG] Chiếm quyền điều khiển phiên Quản trị viên qua kết hợp XSS và Cookie lỏng lẻo"
            if (has_xss and has_cookie_issues and has_admin_path) and title_chain1 not in finding_titles:
                f1 = Finding(
                    title=title_chain1,
                    severity="CRITICAL",
                    description=(
                        "Phát hiện chuỗi tấn công phức hợp có mức độ nguy hại đặc biệt nghiêm trọng: "
                        "Kẻ tấn công có thể khai thác lỗ hổng Cross-Site Scripting (XSS) để đọc trộm cookie phiên do thiếu cờ HttpOnly/Secure, "
                        "từ đó chiếm đoạt hoàn toàn tài khoản Quản trị viên (Account Takeover) tại cổng quản trị /admin."
                    ),
                    impact="Chiếm đoạt hoàn toàn quyền kiểm soát hệ thống, thay đổi cấu hình, tạo tài khoản quản trị ngầm và truy cập trái phép toàn bộ dữ liệu.",
                    remediation=(
                        "1. Bổ sung ngay lập tức cờ HttpOnly, Secure và SameSite=Strict cho toàn bộ cookie xác thực quản trị.\n"
                        "2. Áp dụng cơ chế mã hóa/escape dữ liệu đầu ra và cấu hình Content Security Policy (CSP) nghiêm ngặt để chặn thực thi XSS."
                    ),
                    tool_source="Compound Threat Correlation Engine",
                    cvss_score=9.3,
                )
                self.findings.append(f1)
                new_compound_findings.append(f1)
                finding_titles.add(title_chain1)

            # 2. Chain: BEC & Database/Credential Leakage (DNS SPF/DMARC missing + Sensitive .env/backup leak)
            title_chain2 = "[CHUỖI TẤN CÔNG] Giả mạo định danh doanh nghiệp kết hợp lộ lọt thông tin xác thực cơ sở dữ liệu"
            if (has_dns_issues and has_sensitive_leak) and title_chain2 not in finding_titles:
                f2 = Finding(
                    title=title_chain2,
                    severity="HIGH",
                    description=(
                        "Sự kết hợp giữa lỗ hổng cấu hình DNS (thiếu SPF/DMARC) và việc để lộ tệp tin nhạy cảm (.env/backup credentials) "
                        "cho phép kẻ tấn công thực hiện chiến dịch lừa đảo mạo danh doanh nghiệp (Business Email Compromise - BEC) "
                        "có độ tin cậy tuyệt đối nhờ khai thác thông tin nội bộ bị rò rỉ."
                    ),
                    impact="Tổn hại uy tín thương hiệu nghiêm trọng, lừa đảo đối tác/khách hàng chuyển tiền, và nguy cơ bị tấn công xâm nhập sâu vào cơ sở dữ liệu.",
                    remediation=(
                        "1. Thu hồi và đổi toàn bộ mật khẩu cơ sở dữ liệu, API keys bị lộ trong tệp cấu hình.\n"
                        "2. Cấu hình bản ghi DNS SPF 'v=spf1 ... -all' và DMARC 'p=reject' để ngăn chặn giả mạo email tên miền."
                    ),
                    tool_source="Compound Threat Correlation Engine",
                    cvss_score=8.5,
                )
                self.findings.append(f2)
                new_compound_findings.append(f2)
                finding_titles.add(title_chain2)

            # 3. Chain: Cross-Origin Data Exfiltration (CORS Misconfiguration + Missing CSRF/SameSite Cookie)
            title_chain3 = "[CHUỖI TẤN CÔNG] Đánh cắp dữ liệu người dùng qua lỗ hổng phối hợp CORS Misconfiguration và Cookie Session"
            if (has_cors_issue and has_cookie_issues) and title_chain3 not in finding_titles:
                f3 = Finding(
                    title=title_chain3,
                    severity="HIGH",
                    description=(
                        "Chính sách CORS phản xạ Origin tùy ý kết hợp với cookie xác thực không có SameSite cho phép trang web độc hại "
                        "của kẻ tấn công gửi yêu cầu chéo nguồn nhân danh nạn nhân và trích xuất trái phép dữ liệu phản hồi nhạy cảm."
                    ),
                    impact="Lộ lọt thông tin người dùng riêng tư, dữ liệu cá nhân (PII), và vượt qua ranh giới cùng nguồn gốc (SOP).",
                    remediation=(
                        "1. Cấu hình whitelist nghiêm ngặt các domain được phép truy cập CORS thay vì phản xạ header Origin.\n"
                        "2. Đặt SameSite=Lax hoặc Strict cho tất cả session cookie."
                    ),
                    tool_source="Compound Threat Correlation Engine",
                    cvss_score=8.2,
                )
                self.findings.append(f3)
                new_compound_findings.append(f3)
                finding_titles.add(title_chain3)

            # 4. Chain: Database Exposure & Remote Compromise (Open DB ports 3306/5432/27017/6379 + Sensitive file leak)
            open_ports = self.attack_surface.open_ports or {}
            has_db_port = any(
                p in (3306, 5432, 27017, 6379)
                or (isinstance(p, str) and p.isdigit() and int(p) in (3306, 5432, 27017, 6379))
                or (isinstance(info, dict) and any(db in str(info.get("service", "")).lower() for db in ["mysql", "postgres", "mongo", "redis"]))
                for p, info in (open_ports.items() if isinstance(open_ports, dict) else [(p, {}) for p in open_ports])
            )
            title_chain4 = "[CHUỖI TẤN CÔNG] Nguy cơ chiếm đoạt cơ sở dữ liệu và truy xuất dữ liệu từ xa qua cổng dịch vụ công khai"
            if (has_db_port and has_sensitive_leak) and title_chain4 not in finding_titles:
                f4 = Finding(
                    title=title_chain4,
                    severity="CRITICAL",
                    description=(
                        "Phát hiện cổng cơ sở dữ liệu (MySQL/PostgreSQL/MongoDB/Redis) đang mở trực tiếp ra mạng ngoài "
                        "kết hợp với việc lộ tệp tin cấu hình nhạy cảm (.env/backup/credentials). Kẻ tấn công có thể sử dụng "
                        "thông tin xác thực bị rò rỉ để kết nối thẳng từ xa vào cơ sở dữ liệu mà không cần vượt qua ứng dụng web."
                    ),
                    impact="Toàn bộ cơ sở dữ liệu bị đánh cắp, sửa đổi hoặc xóa sạch; nguy cơ bị mã hóa tống tiền (Ransomware).",
                    remediation=(
                        "1. Đóng ngay cổng dịch vụ cơ sở dữ liệu ra Internet công cộng, chỉ cho phép kết nối từ localhost hoặc qua VPN/SSH Tunnel.\n"
                        "2. Thu hồi và đổi toàn bộ thông tin xác thực (database credentials) bị lộ."
                    ),
                    tool_source="Compound Threat Correlation Engine",
                    cvss_score=9.4,
                )
                self.findings.append(f4)
                new_compound_findings.append(f4)
                finding_titles.add(title_chain4)

            # 5. Chain: Subdomain Hijacking & Shadow IT Exploitation (Alive subdomains + DNSSEC disabled or misconfigured DNS)
            has_alive_subdomains = bool(self.attack_surface.alive_subdomains)
            title_chain5 = "[CHUỖI TẤN CÔNG] Nguy cơ chiếm đoạt tên miền phụ (Subdomain Takeover) và khai thác hệ thống Shadow IT"
            if (has_alive_subdomains and has_dns_issues) and title_chain5 not in finding_titles:
                f5 = Finding(
                    title=title_chain5,
                    severity="HIGH",
                    description=(
                        "Hệ thống phát hiện các tên miền phụ đang hoạt động nhưng hạ tầng DNS thiếu cơ chế xác thực toàn vẹn "
                        "(DNSSEC) hoặc tồn tại cấu hình DNS lỏng lẻo. Kẻ tấn công có thể chiếm đoạt CNAME hoặc bản ghi trỏ tới dịch vụ đám mây "
                        "không còn tồn tại (Subdomain Takeover), giả mạo website doanh nghiệp để lừa đảo người dùng."
                    ),
                    impact="Mất kiểm soát uy tín tên miền phụ, lừa đảo chiếm đoạt thông tin thẻ/tài khoản khách hàng (Phishing).",
                    remediation=(
                        "1. Kích hoạt DNSSEC cho toàn bộ tên miền và tên miền phụ.\n"
                        "2. Rà soát và loại bỏ các bản ghi CNAME hoặc A trỏ tới các dịch vụ Cloud (S3, GitHub Pages, Heroku) không còn sử dụng."
                    ),
                    tool_source="Compound Threat Correlation Engine",
                    cvss_score=8.4,
                )
                self.findings.append(f5)
                new_compound_findings.append(f5)
                finding_titles.add(title_chain5)

            # 6. Chain: SSRF & Cloud Metadata Exfiltration (Parameterized URLs with redirect/url/dest + Sensitive Leak or API)
            has_redirect_param = any(
                any(p_name in str(u).lower() for p_name in ["url=", "dest=", "redirect=", "path=", "target=", "uri=", "link=", "next="])
                for u in (self.attack_surface.parameterized_endpoints or {})
            )
            title_chain6 = "[CHUỖI TẤN CÔNG] Nguy cơ tấn công SSRF truy xuất siêu dữ liệu Đám mây (Cloud Metadata) và mạng nội bộ"
            if (has_redirect_param and (has_sensitive_leak or any("api" in str(u).lower() for u in (self.attack_surface.parameterized_endpoints or {})))) and title_chain6 not in finding_titles:
                f6 = Finding(
                    title=title_chain6,
                    severity="HIGH",
                    description=(
                        "Phát hiện các tham số điều hướng URL nhận đầu vào từ người dùng kết hợp với kiến trúc API/dịch vụ nội bộ. "
                        "Kẻ tấn công có thể thao túng tham số để ép máy chủ gửi yêu cầu trái phép tới giao diện Cloud Metadata "
                        "(như http://169.254.169.254) hoặc các dịch vụ nội bộ không công khai ra Internet."
                    ),
                    impact="Lộ lọt thông tin cấu hình IAM role, temporary access keys của hạ tầng Cloud và quét cổng mạng nội bộ.",
                    remediation=(
                        "1. Áp dụng whitelist nghiêm ngặt các domain được phép điều hướng.\n"
                        "2. Chặn hoàn toàn các yêu cầu gửi đến dải IP riêng (RFC 1918) và IP Cloud Metadata (169.254.169.254)."
                    ),
                    tool_source="Compound Threat Correlation Engine",
                    cvss_score=8.6,
                )
                self.findings.append(f6)
                new_compound_findings.append(f6)
                finding_titles.add(title_chain6)

            # 7. Chain: Admin Privilege Escalation via Exposed Internal Interface (Admin path + login forms or weak security headers, without XSS)
            title_chain7 = "[CHUỖI TẤN CÔNG] Nguy cơ leo thang đặc quyền quản trị qua giao diện nội bộ lộ lọt và tấn công giao diện web"
            if (has_admin_path and not has_xss and (bool(self.attack_surface.login_forms) or has_cookie_issues or any("header" in f.title.lower() or "clickjacking" in f.title.lower() for f in self.findings))) and title_chain7 not in finding_titles:
                f7 = Finding(
                    title=title_chain7,
                    severity="HIGH",
                    description=(
                        "Cổng quản trị nội bộ /admin bị công khai trên mạng ngoài kết hợp với form đăng nhập hoặc cookie thiếu cơ chế bảo vệ "
                        "ngăn chặn tấn công brute-force và clickjacking. Kẻ tấn công có thể lừa người dùng quản trị thao tác ngoài ý muốn "
                        "hoặc dò quét mật khẩu quản trị yếu."
                    ),
                    impact="Xâm nhập trái phép giao diện quản trị và chiếm đoạt quyền điều hành hệ thống.",
                    remediation=(
                        "1. Giới hạn truy cập giao diện quản trị theo dải IP nội bộ hoặc bắt buộc VPN.\n"
                        "2. Kích hoạt xác thực 2 bước (2FA/MFA) và thiết lập cơ chế khóa tài khoản sau nhiều lần nhập sai (Rate Limiting)."
                    ),
                    tool_source="Compound Threat Correlation Engine",
                    cvss_score=8.3,
                )
                self.findings.append(f7)
                new_compound_findings.append(f7)
                finding_titles.add(title_chain7)

            # 8. Chain: Web Server / Framework Remote Code Execution (Outdated server + Upload/CGI or critical CVE finding)
            has_rce_precursor = (
                any("2.4.49" in str(t).lower() or "php/7" in str(t).lower() for t in self.attack_surface.detected_technologies)
                or any("cgi" in str(p).lower() or "upload" in str(p).lower() for p in self.attack_surface.hidden_discovered_paths)
            )
            has_cve_finding = any(
                "cve" in f.title.lower() or "rce" in f.title.lower() or "traversal" in f.title.lower()
                for f in self.findings if "[CHUỖI TẤN CÔNG]" not in f.title
            )
            title_chain8 = "[CHUỖI TẤN CÔNG] Nguy cơ thực thi mã từ xa RCE thông qua lỗ hổng máy chủ web và điểm cuối tiếp nhận tệp"
            if (has_rce_precursor and has_cve_finding) and title_chain8 not in finding_titles:
                f8 = Finding(
                    title=title_chain8,
                    severity="CRITICAL",
                    description=(
                        "Máy chủ web đang vận hành phiên bản phần mềm tồn tại lỗ hổng đã công bố (CVE) kết hợp với đường dẫn xử lý mã "
                        "hoặc upload tệp tin. Kẻ tấn công có thể gửi payload khai thác trực tiếp để thực thi lệnh hệ điều hành dưới quyền web server."
                    ),
                    impact="Mất kiểm soát hoàn toàn máy chủ, bị cài đặt webshell/backdoor và sử dụng máy chủ làm bàn đạp tấn công hệ thống khác.",
                    remediation=(
                        "1. Nâng cấp máy chủ web và các module phụ trợ lên phiên bản ổn định mới nhất.\n"
                        "2. Vô hiệu hóa tính năng cgi-bin không sử dụng và kiểm soát nghiêm ngặt quyền thực thi trong thư mục upload."
                    ),
                    tool_source="Compound Threat Correlation Engine",
                    cvss_score=9.8,
                )
                self.findings.append(f8)
                new_compound_findings.append(f8)
                finding_titles.add(title_chain8)

            # Update baseline risk if new findings were added
            if new_compound_findings:
                baseline = self.calculate_baseline_risk()
                if baseline > self.risk_score:
                    self.risk_score = baseline
                self._update_milestones_status()

        finally:
            self._correlating = False
            # Synchronize _finding_index for any newly created compound findings
            for idx, f in enumerate(self.findings):
                k = " ".join(f.title.lower().split())
                if k not in self._finding_index:
                    self._finding_index[k] = idx

        return new_compound_findings

    def is_surface_exhausted(self, tools_called: set[str] | None = None) -> tuple[bool, list[str]]:
        """Verify if all discoverable attack vectors on the target surface have been exhaustively tested."""
        untested: list[str] = []
        tested_tools = (
            set(s.tool_name for s in self.methodology)
            | set(v.split("::")[0] for v in self.attack_surface.tested_vectors)
        )
        if tools_called:
            tested_tools.update(tools_called)

        # 1. Open Ports: Any port not deep scanned
        if isinstance(self.attack_surface.open_ports, dict):
            for port, info in self.attack_surface.open_ports.items():
                if isinstance(info, dict) and not info.get("deep_scanned"):
                    if "docker_scan_ports_deep" not in tested_tools:
                        untested.append(f"Cổng {port}/tcp chưa được quét dịch vụ chuyên sâu (docker_scan_ports_deep)")
                        break

        # 2. Parameterized Endpoints: SQLi testing
        if isinstance(self.attack_surface.parameterized_endpoints, dict):
            untested_sqli = [u for u, inf in self.attack_surface.parameterized_endpoints.items() if not inf.get("tested_sqli")]
            if untested_sqli and "docker_sqlmap_scan" not in tested_tools and self.scan_mode == "full":
                untested.append(f"{len(untested_sqli)} endpoint có tham số chưa kiểm tra SQL Injection (docker_sqlmap_scan)")

            # 3. Parameterized Endpoints: XSS testing
            untested_xss = [u for u, inf in self.attack_surface.parameterized_endpoints.items() if not inf.get("tested_xss")]
            if untested_xss and "docker_xss_scan" not in tested_tools:
                untested.append(f"{len(untested_xss)} endpoint có tham số chưa kiểm tra Reflected XSS (docker_xss_scan)")

        # 4. Login Forms: Brute-force testing in full mode
        if self.attack_surface.login_forms and self.scan_mode == "full":
            untested_forms = [f for f in self.attack_surface.login_forms if not f.get("tested_bruteforce")]
            if untested_forms and not any("bruteforce" in t for t in tested_tools):
                untested.append(f"{len(untested_forms)} form đăng nhập chưa được kiểm tra xác thực yếu (bruteforce_http_form)")

        # 5. Subdomains: Probing alive web servers
        if self.attack_surface.subdomains and not self.attack_surface.alive_subdomains:
            if "docker_httpx_probe" not in tested_tools:
                untested.append("Phát hiện subdomains nhưng chưa dò tìm máy chủ hoạt động (docker_httpx_probe)")

        # 6. Sensitive Files & Credential Leaks
        if "docker_sensitive_files_scan" not in tested_tools:
            untested.append("Chưa rà quét tệp tin cấu hình nhạy cảm và bản sao lưu (docker_sensitive_files_scan)")

        # 7. Cookie & Session Flags
        if "docker_cookie_security_audit" not in tested_tools:
            untested.append("Chưa kiểm toán cờ an toàn Cookie và quản lý phiên (docker_cookie_security_audit)")

        # 8. DNS & Email Security
        if "docker_dns_security_audit" not in tested_tools:
            untested.append("Chưa kiểm toán hạ tầng DNS, SPF, DMARC và DNSSEC (docker_dns_security_audit)")

        # 9. RFC 9116, Robots.txt & Hidden Paths
        if "docker_security_txt_audit" not in tested_tools:
            untested.append("Chưa rà soát chính sách bảo mật RFC 9116 và robots.txt (docker_security_txt_audit)")

        # 10. SSL/TLS Certificate Audit on HTTPS
        if str(self.target).lower().startswith("https") or 443 in self.attack_surface.open_ports or 8443 in self.attack_surface.open_ports:
            if "docker_ssl_cert_audit" not in tested_tools and "docker_testssl" not in tested_tools:
                untested.append("Chưa kiểm toán chứng chỉ SSL/TLS và độ an toàn mật mã (docker_ssl_cert_audit)")

        # 11. HTTP Security Headers Audit on Web Targets
        if str(self.target).lower().startswith("http") and "docker_http_headers_audit" not in tested_tools and "docker_cors_scan" not in tested_tools:
            untested.append("Chưa kiểm toán tiêu đề an ninh HTTP (docker_http_headers_audit)")

        # 12. API Documentation & OpenAPI Audit when API suspected or discovered
        if (any("api" in str(u).lower() for u in self.attack_surface.parameterized_endpoints) or any("api" in str(p).lower() for p in self.attack_surface.hidden_discovered_paths)) and "docker_api_docs_audit" not in tested_tools:
            untested.append("Phát hiện đường dẫn API nhưng chưa kiểm toán tài liệu Swagger/OpenAPI (docker_api_docs_audit)")

        # 13. Subdomain Takeover Audit on subdomains
        if self.attack_surface.subdomains and "docker_subdomain_takeover_audit" not in tested_tools and "docker_httpx_probe" not in tested_tools:
            untested.append("Phát hiện subdomains nhưng chưa kiểm toán nguy cơ Subdomain Takeover (docker_subdomain_takeover_audit)")

        # 14. WAF Detection
        if str(self.target).lower().startswith("http") and self.scan_mode == "full" and "docker_waf_detect" not in tested_tools and "docker_whatweb" not in tested_tools:
            untested.append("Chưa nhận diện giải pháp WAF/CDN bảo vệ mục tiêu (docker_waf_detect)")

        return (len(untested) == 0, untested)

    # ---------------------------------------------------------------
    # Attack Surface & Tactical Roadmap Engine
    # ---------------------------------------------------------------

    def update_attack_surface(self, tool_name: str, arguments: dict, result_str: str) -> None:
        """Dynamically update attack surface graph from tool outputs."""
        if not result_str or not isinstance(result_str, str):
            return

        arg_target = str(arguments.get("target") or arguments.get("target_url") or arguments.get("domain") or arguments.get("target_domain") or self.target)

        # Record this tool execution on target vector
        vector_sig = f"{tool_name}::{arg_target}"
        self.attack_surface.add_tested_vector(vector_sig)

        # 1. Port scanning (docker_scan_ports_fast / docker_scan_ports_deep)
        if "scan_ports" in tool_name:
            is_deep = "deep" in tool_name
            # Try parsing JSON structure first
            try:
                data = json.loads(result_str)
                if isinstance(data, dict):
                    ports_list = data.get("open_ports") or data.get("ports") or []
                    for p in ports_list:
                        if isinstance(p, dict):
                            p_num = int(p.get("port") or p.get("port_number") or 0)
                            p_svc = str(p.get("service") or p.get("name") or "unknown")
                        elif isinstance(p, (int, str)) and str(p).isdigit():
                            p_num = int(p)
                            p_svc = "unknown"
                        else:
                            continue
                        if p_num > 0:
                            if p_num not in self.attack_surface.open_ports:
                                self.attack_surface.open_ports[p_num] = {"service": p_svc, "deep_scanned": is_deep}
                            elif is_deep:
                                self.attack_surface.open_ports[p_num]["deep_scanned"] = True
            except Exception:
                pass

            # Regex fallback for text output
            for match in _RE_PORT_LINE.finditer(result_str):
                p_num = int(match.group(1))
                p_svc = match.group(2) or "unknown"
                if p_num not in self.attack_surface.open_ports:
                    self.attack_surface.open_ports[p_num] = {"service": p_svc, "deep_scanned": is_deep}
                elif is_deep:
                    self.attack_surface.open_ports[p_num]["deep_scanned"] = True

        # 2. Web Crawling & Parameter Discovery (docker_crawl_web)
        if tool_name == "docker_crawl_web":
            try:
                data = json.loads(result_str)
                urls = data.get("endpoints") or data.get("urls") or []
            except Exception:
                urls = _RE_HTTP_URL.findall(result_str)

            for u in urls:
                u_clean = u.strip()
                if "?" in u_clean and "=" in u_clean:
                    if u_clean not in self.attack_surface.parameterized_endpoints:
                        self.attack_surface.parameterized_endpoints[u_clean] = {"tested_sqli": False, "tested_xss": False}
                if any(kw in u_clean.lower() for kw in ["login", "signin", "admin", "auth", "dangnhap"]):
                    if not any(f.get("url") == u_clean for f in self.attack_surface.login_forms):
                        self.attack_surface.login_forms.append({"url": u_clean, "tested_bruteforce": False})

        # 3. Web Browsing (browse_webpage)
        if tool_name == "browse_webpage":
            lower_res = result_str.lower()
            if any(kw in lower_res for kw in ["type=\"password\"", "name=\"password\"", "name=\"pass\"", "login", "đăng nhập"]):
                if not any(f.get("url") == arg_target for f in self.attack_surface.login_forms):
                    self.attack_surface.login_forms.append({"url": arg_target, "tested_bruteforce": False})

            for match in _RE_HTTP_URL.finditer(result_str):
                u = match.group(0)
                if "?" in u and "=" in u and u not in self.attack_surface.parameterized_endpoints:
                    self.attack_surface.parameterized_endpoints[u] = {"tested_sqli": False, "tested_xss": False}

        # 4. Technology Fingerprinting (docker_whatweb)
        if tool_name == "docker_whatweb":
            try:
                data = json.loads(result_str)
                techs = data.get("technologies_detected") or []
                for t in techs:
                    if t:
                        self.attack_surface.add_detected_technology(t)
            except Exception:
                for match in _RE_WHATWEB_TECH.finditer(result_str):
                    t = match.group(1).strip()
                    if t.lower() not in ("http", "https", "status"):
                        self.attack_surface.add_detected_technology(t)

        # 5. SQLMap Execution
        if "sqlmap" in tool_name:
            target_tested = str(arguments.get("target_url") or arguments.get("target") or "")
            if target_tested in self.attack_surface.parameterized_endpoints:
                self.attack_surface.parameterized_endpoints[target_tested]["tested_sqli"] = True
            for ep in self.attack_surface.parameterized_endpoints:
                if ep in target_tested or target_tested in ep:
                    self.attack_surface.parameterized_endpoints[ep]["tested_sqli"] = True

        # 6. HTTP Form Brute-force
        if tool_name == "bruteforce_http_form":
            target_form = str(arguments.get("target_url") or "")
            for f in self.attack_surface.login_forms:
                if f.get("url") in target_form or target_form in f.get("url", ""):
                    f["tested_bruteforce"] = True

        # 7. Subdomains (docker_subfinder / docker_resolve_dns)
        if tool_name in ("docker_subfinder", "docker_resolve_dns"):
            for match in _RE_SUBDOMAIN.finditer(result_str):
                sub = match.group(0).lower()
                if sub != self.target.lower():
                    self.attack_surface.add_subdomain(sub)

        # 8. Sensitive Files Scan (docker_sensitive_files_scan)
        if tool_name == "docker_sensitive_files_scan":
            try:
                data = json.loads(result_str)
                files = data.get("exposed_files") or []
                for f in files:
                    if isinstance(f, dict):
                        f_path = f.get("path") or f.get("url")
                        if not any(ef.get("path") == f_path or ef.get("url") == f_path for ef in self.attack_surface.exposed_sensitive_files):
                            self.attack_surface.exposed_sensitive_files.append(f)
            except Exception:
                pass

        # 9. CORS & Security Headers Audit (docker_cors_scan)
        if tool_name == "docker_cors_scan":
            try:
                data = json.loads(result_str)
                issues = data.get("cors_misconfigurations") or []
                for iss in issues:
                    if isinstance(iss, dict) and iss not in self.attack_surface.cors_issues:
                        self.attack_surface.cors_issues.append(iss)
            except Exception:
                pass

        # 10. Reflected XSS Scan (docker_xss_scan)
        if tool_name == "docker_xss_scan":
            target_tested = str(arguments.get("target_url") or arguments.get("target") or "")
            if target_tested in self.attack_surface.parameterized_endpoints:
                self.attack_surface.parameterized_endpoints[target_tested]["tested_xss"] = True
            for ep in self.attack_surface.parameterized_endpoints:
                if ep in target_tested or target_tested in ep:
                    self.attack_surface.parameterized_endpoints[ep]["tested_xss"] = True

        # 11. Multi-Target Alive Probe (docker_httpx_probe)
        if tool_name == "docker_httpx_probe":
            try:
                data = json.loads(result_str)
                alive_targets = data.get("alive_targets") or []
                for at in alive_targets:
                    if isinstance(at, dict) and at.get("alive"):
                        target_id = at.get("url") or at.get("input_target")
                        if not any(sub.get("url") == target_id or sub.get("input_target") == target_id for sub in self.attack_surface.alive_subdomains):
                            self.attack_surface.alive_subdomains.append(at)
            except Exception:
                pass

        # 12. SSL/TLS Certificate Audit (docker_ssl_cert_audit)
        if tool_name == "docker_ssl_cert_audit":
            try:
                data = json.loads(result_str)
                if isinstance(data, dict):
                    self.attack_surface.ssl_cert_info = data.get("cert_info") or data
                    # SAN domains automatically populate subdomains!
                    sans = data.get("san_domains") or []
                    for s in sans:
                        s_clean = s.replace("*.", "").strip().lower()
                        if s_clean and s_clean != self.target.lower():
                            self.attack_surface.add_subdomain(s_clean)
            except Exception:
                pass

        # 13. DNS & Email Security Audit (docker_dns_security_audit)
        if tool_name == "docker_dns_security_audit":
            try:
                data = json.loads(result_str)
                if isinstance(data, dict):
                    self.attack_surface.dns_security_info = data.get("dns_security") or data
            except Exception:
                pass

        # 14. Security.txt, Robots.txt & Sitemap Audit (docker_security_txt_audit)
        if tool_name == "docker_security_txt_audit":
            try:
                data = json.loads(result_str)
                if isinstance(data, dict):
                    hidden = data.get("sensitive_hidden_paths") or []
                    for hp in hidden:
                        if hp:
                            self.attack_surface.add_hidden_path(hp)
                    # Sample endpoints
                    endpoints = data.get("sample_endpoints") or []
                    for ep in endpoints:
                        if "?" in ep and "=" in ep and ep not in self.attack_surface.parameterized_endpoints:
                            self.attack_surface.parameterized_endpoints[ep] = {"tested_sqli": False, "tested_xss": False}
            except Exception:
                pass

        # 15. Cookie Security Audit (docker_cookie_security_audit)
        if tool_name == "docker_cookie_security_audit":
            try:
                data = json.loads(result_str)
                if isinstance(data, dict):
                    c_issues = data.get("issues") or []
                    for ci in c_issues:
                        if isinstance(ci, dict) and ci not in self.attack_surface.cookie_issues:
                            self.attack_surface.cookie_issues.append(ci)
            except Exception:
                pass

        # 16. HTTP Security Headers Audit (docker_http_headers_audit)
        if tool_name == "docker_http_headers_audit":
            try:
                data = json.loads(result_str)
                if isinstance(data, dict):
                    self.attack_surface.security_headers_info = data
                    missing = data.get("missing_headers") or []
                    leaks = data.get("information_leaks") or []
                    if "strict-transport-security" in missing and str(self.target).lower().startswith("https"):
                        title_hsts = "Thiếu tiêu đề bảo mật HTTP Strict-Transport-Security (HSTS)"
                        if not any(f.title == title_hsts for f in self.findings):
                            self.add_finding(Finding(
                                title=title_hsts,
                                severity="HIGH",
                                description="Máy chủ không cấu hình tiêu đề Strict-Transport-Security (HSTS). Kẻ tấn công có thể thực hiện tấn công SSL Stripping để hạ cấp kết nối.",
                                impact="Mất tính bảo mật của lưu lượng HTTPS, nguy cơ bị nghe lén dữ liệu truyền tải.",
                                remediation="Bổ sung tiêu đề 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                                tool_source="docker_http_headers_audit",
                                cvss_score=7.4,
                            ))
                    if "content-security-policy" in missing:
                        title_csp = "Thiếu chính sách Content-Security-Policy (CSP)"
                        if not any(f.title == title_csp for f in self.findings):
                            self.add_finding(Finding(
                                title=title_csp,
                                severity="HIGH",
                                description="Ứng dụng web thiếu tiêu đề Content-Security-Policy, làm tăng nguy cơ khai thác lỗ hổng Cross-Site Scripting (XSS).",
                                impact="Không có rào chắn bảo vệ phía trình duyệt chống lại tấn công nhúng mã độc.",
                                remediation="Thiết lập chính sách CSP nghiêm ngặt hạn chế domain tải script/styles.",
                                tool_source="docker_http_headers_audit",
                                cvss_score=7.5,
                            ))
                    if leaks:
                        first_leak = leaks[0]
                        title_leak = f"Rò rỉ thông tin phiên bản máy chủ qua HTTP Response Headers ({first_leak.get('header')})"
                        if not any(f.title.startswith("Rò rỉ thông tin phiên bản máy chủ") for f in self.findings):
                            self.add_finding(Finding(
                                title=title_leak,
                                severity="LOW",
                                description=f"Máy chủ để lộ thông tin phần mềm nội bộ: {', '.join([f'{l.get('header')}: {l.get('value')}' for l in leaks])}.",
                                impact="Tạo điều kiện cho kẻ tấn công xác định chính xác phiên bản phần mềm và tìm kiếm các bản vá/CVE khai thác tương ứng.",
                                remediation="Tắt hoặc ẩn tiêu đề Server, X-Powered-By trong cấu hình máy chủ web.",
                                tool_source="docker_http_headers_audit",
                                cvss_score=3.5,
                            ))
            except Exception:
                pass

        # 17. API & Swagger/OpenAPI Documentation Audit (docker_api_docs_audit)
        if tool_name == "docker_api_docs_audit":
            try:
                data = json.loads(result_str)
                if isinstance(data, dict):
                    docs = data.get("exposed_docs") or []
                    for doc in docs:
                        if isinstance(doc, dict):
                            if doc not in self.attack_surface.exposed_api_docs:
                                self.attack_surface.exposed_api_docs.append(doc)
                            for ep in doc.get("sample_endpoints") or []:
                                if ep and ep not in self.attack_surface.hidden_discovered_paths:
                                    self.attack_surface.hidden_discovered_paths.append(ep)
                            title_api = f"Lộ lọt tài liệu API công khai không xác thực ({doc.get('path')})"
                            if not any(f.title == title_api for f in self.findings):
                                self.add_finding(Finding(
                                    title=title_api,
                                    severity=doc.get("severity", "HIGH"),
                                    description=doc.get("risk", f"Phát hiện tài liệu API {doc.get('type')} tại {doc.get('path')}."),
                                    impact="Tiết lộ toàn bộ kiến trúc API nội bộ, các phương thức HTTP và cấu trúc tham số giúp kẻ tấn công lập bản đồ xâm nhập.",
                                    remediation="Vô hiệu hóa hoặc giới hạn quyền truy cập tài liệu Swagger/OpenAPI trong môi trường Production.",
                                    tool_source="docker_api_docs_audit",
                                    cvss_score=7.8 if doc.get("severity") == "HIGH" else 5.3,
                                ))
            except Exception:
                pass

        # 18. Subdomain Takeover Audit (docker_subdomain_takeover_audit)
        if tool_name == "docker_subdomain_takeover_audit":
            try:
                data = json.loads(result_str)
                if isinstance(data, dict):
                    vulns = data.get("vulnerabilities") or []
                    for v in vulns:
                        if isinstance(v, dict):
                            if v not in self.attack_surface.dangling_cnames:
                                self.attack_surface.dangling_cnames.append(v)
                            title_to = f"Nguy cơ chiếm đoạt tên miền phụ (Subdomain Takeover) tại '{v.get('subdomain')}'"
                            if not any(f.title == title_to for f in self.findings):
                                self.add_finding(Finding(
                                    title=title_to,
                                    severity="HIGH",
                                    description=v.get("risk", f"Bản ghi CNAME của '{v.get('subdomain')}' trỏ tới dịch vụ {v.get('service')} bị bỏ hoang."),
                                    impact="Kẻ tấn công có thể đăng ký tài nguyên bị bỏ hoang trên dịch vụ đám mây và chiếm quyền kiểm soát toàn diện tên miền phụ.",
                                    remediation=v.get("remediation", "Xóa bản ghi CNAME hoặc đăng ký lại tài nguyên đám mây để giữ quyền sở hữu."),
                                    tool_source="docker_subdomain_takeover_audit",
                                    cvss_score=8.4,
                                ))
            except Exception:
                pass

        # 19. WAF & Reverse Proxy Detection (docker_waf_detect)
        if tool_name == "docker_waf_detect":
            try:
                data = json.loads(result_str)
                if isinstance(data, dict):
                    self.attack_surface.detected_waf = data
                    if data.get("waf_detected"):
                        waf_name = data.get("primary_waf", "WAF")
                        title_waf = f"Hệ thống được bảo vệ bởi Tường lửa Ứng dụng Web ({waf_name})"
                        if not any(f.title.startswith("Hệ thống được bảo vệ bởi Tường lửa") for f in self.findings):
                            self.add_finding(Finding(
                                title=title_waf,
                                severity="INFO",
                                description=f"Phát hiện giải pháp bảo vệ WAF/CDN: {waf_name}. Tín hiệu nhận diện: {', '.join(data.get('signals', []))}.",
                                impact="WAF có thể chặn các payload kiểm thử tự động và áp dụng cơ chế khóa IP (Rate Limiting).",
                                remediation="Duy trì cấu hình WAF và cập nhật bộ luật (CRS) thường xuyên; áp dụng Origin IP protection.",
                                tool_source="docker_waf_detect",
                                cvss_score=0.0,
                            ))
            except Exception:
                pass

        # Always update milestone progress
        self._update_milestones_status()
        if not self._correlating:
            self.correlate_compound_threats()


    def get_tactical_roadmap(self) -> dict:
        """Analyze current attack surface and mission to generate an actionable tactical roadmap."""
        untested_actions = []
        tested_tool_names = set(s.tool_name for s in self.methodology)

        # Priority 1: SQL Injection testing on discovered parameterized endpoints
        untested_sqli_urls = [
            url for url, info in self.attack_surface.parameterized_endpoints.items()
            if not info.get("tested_sqli", False)
        ]
        if untested_sqli_urls and ("full" in self.scan_mode or "sql" in self.mission_objective.lower() or "inject" in self.mission_objective.lower()):
            untested_actions.append({
                "priority": "HIGH",
                "tool": "docker_sqlmap_scan",
                "target": untested_sqli_urls[0],
                "reason": f"Phát hiện {len(untested_sqli_urls)} endpoint có tham số (?id=...). Cần kiểm tra lỗ hổng SQL Injection ngay.",
            })

        # Priority 1b: Reflected XSS testing on discovered parameterized endpoints
        untested_xss_urls = [
            url for url, info in self.attack_surface.parameterized_endpoints.items()
            if not info.get("tested_xss", False)
        ]
        if untested_xss_urls and ("full" in self.scan_mode or "xss" in self.mission_objective.lower() or "inject" in self.mission_objective.lower()):
            untested_actions.append({
                "priority": "HIGH",
                "tool": "docker_xss_scan",
                "target": untested_xss_urls[0],
                "reason": f"Phát hiện {len(untested_xss_urls)} endpoint có tham số. Cần fuzzing kiểm tra lỗ hổng Cross-Site Scripting (XSS).",
            })

        # Priority 1c: Multi-target alive probe on discovered subdomains
        unprobed_subs = [
            s for s in self.attack_surface.subdomains
            if not any(a.get("input_target") == s or s in str(a.get("url", "")) for a in self.attack_surface.alive_subdomains)
        ]
        if unprobed_subs and "docker_httpx_probe" not in tested_tool_names:
            untested_actions.append({
                "priority": "HIGH",
                "tool": "docker_httpx_probe",
                "target": ",".join(unprobed_subs[:10]),
                "reason": f"Phát hiện {len(unprobed_subs)} subdomain chưa xác định dịch vụ web. Cần probe để lọc máy chủ đang sống.",
            })

        # Priority 2: CMS WordPress deep scan
        has_wordpress = any("wordpress" in str(t).lower() for t in self.attack_surface.detected_technologies)
        if has_wordpress and "docker_wpscan" not in tested_tool_names:
            untested_actions.append({
                "priority": "HIGH",
                "tool": "docker_wpscan",
                "target": self.target,
                "reason": "Phát hiện hệ quản trị WordPress. Cần chạy WPScan để tìm lỗ hổng plugins/themes và CVE.",
            })

        # Priority 3: Form brute-force on discovered login forms
        untested_forms = [f for f in self.attack_surface.login_forms if not f.get("tested_bruteforce", False)]
        if untested_forms and "full" in self.scan_mode:
            untested_actions.append({
                "priority": "MEDIUM",
                "tool": "bruteforce_http_form",
                "target": untested_forms[0].get("url", self.target),
                "reason": f"Phát hiện form đăng nhập ({untested_forms[0].get('url')}). Cần kiểm tra an toàn mật khẩu.",
            })

        # Priority 4: SSH brute-force if port 22 open
        if 22 in self.attack_surface.open_ports and "bruteforce_ssh" not in tested_tool_names and "full" in self.scan_mode:
            untested_actions.append({
                "priority": "MEDIUM",
                "tool": "bruteforce_ssh",
                "target": self.target,
                "reason": "Cổng SSH (22) đang mở. Cần kiểm tra chính sách xác thực và mật khẩu yếu.",
            })

        # Priority 5: Web Reconnaissance & Crawl if not done
        web_ports = [p for p in (80, 443, 8080, 8443) if p in self.attack_surface.open_ports]
        if (web_ports or "http" in self.target) and "docker_crawl_web" not in tested_tool_names:
            untested_actions.append({
                "priority": "HIGH",
                "tool": "docker_crawl_web",
                "target": self.target,
                "reason": "Chưa thu thập các endpoint và tham số web của mục tiêu.",
            })

        # Priority 6: Technology detection if not done
        if (web_ports or "http" in self.target) and "docker_whatweb" not in tested_tool_names:
            untested_actions.append({
                "priority": "HIGH",
                "tool": "docker_whatweb",
                "target": self.target,
                "reason": "Cần nhận diện framework, server web và phiên bản phần mềm.",
            })

        # Priority 6b: Sensitive files and source code exposure audit
        if (web_ports or "http" in self.target) and "docker_sensitive_files_scan" not in tested_tool_names:
            untested_actions.append({
                "priority": "HIGH",
                "tool": "docker_sensitive_files_scan",
                "target": self.target,
                "reason": "Cần quét các tệp cấu hình nhạy cảm (.env, .git, backups, keys) trên máy chủ web.",
            })

        # Priority 6c: CORS & Security headers audit
        if (web_ports or "http" in self.target) and "docker_cors_scan" not in tested_tool_names:
            untested_actions.append({
                "priority": "MEDIUM",
                "tool": "docker_cors_scan",
                "target": self.target,
                "reason": "Cần kiểm toán chính sách CORS và các tiêu đề an ninh HTTP (CSP, HSTS).",
            })

        # Priority 7: Nuclei vulnerability scan if not done
        if (web_ports or "http" in self.target) and "docker_nuclei_scan" not in tested_tool_names:
            untested_actions.append({
                "priority": "HIGH",
                "tool": "docker_nuclei_scan",
                "target": self.target,
                "reason": "Cần quét lỗ hổng bảo mật đã biết và template CVE trên ứng dụng web.",
            })

        # Priority 8: SSL/TLS check if HTTPS
        if (443 in self.attack_surface.open_ports or "https://" in self.target) and "docker_testssl" not in tested_tool_names:
            untested_actions.append({
                "priority": "LOW",
                "tool": "docker_testssl",
                "target": self.target,
                "reason": "Cần đánh giá độ an toàn chứng chỉ SSL/TLS và thuật toán mã hóa.",
            })

        # Priority 8a: Fast SSL/TLS Certificate Audit if HTTPS
        if (443 in self.attack_surface.open_ports or "https://" in self.target) and "docker_ssl_cert_audit" not in tested_tool_names:
            prio = "CRITICAL" if any(kw in self.mission_objective.lower() for kw in ["ssl", "cert", "chứng chỉ"]) else "HIGH"
            untested_actions.append({
                "priority": prio,
                "tool": "docker_ssl_cert_audit",
                "target": self.target,
                "reason": "Kiểm toán chứng chỉ SSL/TLS, ngày hết hạn và trích xuất SANs để phát hiện thêm tên miền phụ.",
            })

        # Priority 8b: DNS & Email Domain Security Audit (SPF, DMARC, DNSSEC)
        if "docker_dns_security_audit" not in tested_tool_names:
            prio = "CRITICAL" if any(kw in self.mission_objective.lower() for kw in ["dns", "spf", "dmarc", "email", "mail"]) else "MEDIUM"
            untested_actions.append({
                "priority": prio,
                "tool": "docker_dns_security_audit",
                "target": self.target,
                "reason": "Kiểm toán cấu hình SPF, DMARC, DNSSEC và MX để phát hiện nguy cơ mạo danh email/DNS.",
            })

        # Priority 8c: Security.txt, Robots.txt & Sitemap Hidden Path Audit
        if (web_ports or "http" in self.target) and "docker_security_txt_audit" not in tested_tool_names:
            prio = "CRITICAL" if any(kw in self.mission_objective.lower() for kw in ["robot", "sitemap", "security.txt"]) else "HIGH"
            untested_actions.append({
                "priority": prio,
                "tool": "docker_security_txt_audit",
                "target": self.target,
                "reason": "Rà soát security.txt, phân tích robots.txt và sitemap.xml để tìm kiếm các đường dẫn ẩn và quản trị nhạy cảm.",
            })

        # Priority 8d: Cookie Security Flags Audit
        if (web_ports or "http" in self.target) and "docker_cookie_security_audit" not in tested_tool_names:
            prio = "CRITICAL" if any(kw in self.mission_objective.lower() for kw in ["cookie", "session", "csrf"]) else "MEDIUM"
            untested_actions.append({
                "priority": prio,
                "tool": "docker_cookie_security_audit",
                "target": self.target,
                "reason": "Kiểm toán các cờ bảo mật của Cookie (Secure, HttpOnly, SameSite) phòng ngừa rủi ro chiếm quyền phiên và CSRF.",
            })

        # Priority 8e: HTTP Security Headers & Banner Leak Audit
        if (web_ports or "http" in self.target) and "docker_http_headers_audit" not in tested_tool_names:
            prio = "CRITICAL" if any(kw in self.mission_objective.lower() for kw in ["header", "hsts", "csp"]) else "HIGH"
            untested_actions.append({
                "priority": prio,
                "tool": "docker_http_headers_audit",
                "target": self.target,
                "reason": "Kiểm toán 100% tiêu đề an ninh HTTP chuẩn OWASP (HSTS, CSP, X-Frame-Options, MIME) và phát hiện rò rỉ banner server.",
            })

        # Priority 8f: Exposed API Docs & Schema Audit
        if (web_ports or "http" in self.target) and "docker_api_docs_audit" not in tested_tool_names:
            prio = "CRITICAL" if any(kw in self.mission_objective.lower() for kw in ["api", "swagger", "openapi", "graphql"]) else "HIGH"
            untested_actions.append({
                "priority": prio,
                "tool": "docker_api_docs_audit",
                "target": self.target,
                "reason": "Dò quét các tài liệu API nhạy cảm, OpenAPI/Swagger schemas và GraphQL Introspection lộ lọt ra ngoài Internet.",
            })

        # Priority 8g: Dangling CNAME & Subdomain Takeover Audit
        if self.attack_surface.subdomains and "docker_subdomain_takeover_audit" not in tested_tool_names:
            prio = "CRITICAL" if any(kw in self.mission_objective.lower() for kw in ["takeover", "cname", "dangling"]) else "HIGH"
            untested_actions.append({
                "priority": prio,
                "tool": "docker_subdomain_takeover_audit",
                "target": self.target,
                "reason": "Kiểm toán các bản ghi CNAME trỏ tới dịch vụ đám mây bên thứ ba bị bỏ hoang để ngăn ngừa nguy cơ Subdomain Takeover.",
            })

        # Priority 8h: WAF & Defense Evasion Detection
        if (web_ports or "http" in self.target) and "docker_waf_detect" not in tested_tool_names:
            prio = "CRITICAL" if any(kw in self.mission_objective.lower() for kw in ["waf", "firewall", "cloudflare", "tường lửa"]) else "HIGH"
            untested_actions.append({
                "priority": prio,
                "tool": "docker_waf_detect",
                "target": self.target,
                "reason": "Nhận diện giải pháp Web Application Firewall (WAF) và CDN để chủ động kích hoạt chiến thuật né tránh phòng thủ.",
            })

        # Elevate priority for tools directly supporting the current active milestone
        active_milestones = [m for m in self.milestones if m.status in ("IN_PROGRESS", "PENDING")]
        if active_milestones:
            current_m = active_milestones[0]
            for action in untested_actions:
                if action["tool"] in current_m.relevant_tools:
                    if action["priority"] != "CRITICAL":
                        action["priority"] = "HIGH"
                    action["reason"] = f"[Mốc: {current_m.name}] " + action["reason"]

        progress = self.calculate_goal_progress()

        return {
            "goal_progress": progress,
            "progress_percentage": progress,
            "untested_actions": untested_actions,
            "top_actions": [
                {"action": a["tool"], "priority": a["priority"], "recommendation": a["reason"]}
                for a in untested_actions
            ],
            "milestones": [m.to_dict() for m in self.milestones],
            "open_ports_count": len(self.attack_surface.open_ports),
            "parameterized_endpoints_count": len(self.attack_surface.parameterized_endpoints),
            "login_forms_count": len(self.attack_surface.login_forms),
            "detected_technologies_count": len(self.attack_surface.detected_technologies),
            "alive_subdomains_count": len(self.attack_surface.alive_subdomains),
            "exposed_sensitive_files_count": len(self.attack_surface.exposed_sensitive_files),
        }

    def calculate_goal_progress(self) -> int:
        """Calculate dynamic goal completion percentage (0 - 100%)."""
        tested_tools = set(s.tool_name for s in self.methodology) | set(self.attack_surface.tested_vectors)
        if not tested_tools and not self.findings:
            return 5

        score = 10  # Started session

        # Phase 1: Port / network recon & subdomain probe & DNS/SSL cert recon & WAF/takeover
        if any("scan_ports" in t or "resolve_dns" in t or "subfinder" in t or "httpx" in t or "ssl_cert" in t or "dns_security" in t or "waf_detect" in t or "takeover" in t for t in tested_tools):
            score += 20

        # Phase 2: Web crawl / technology fingerprinting / sensitive, CORS, robots, cookies, headers & api docs audits
        if any(t in tested_tools for t in ["docker_crawl_web", "docker_whatweb", "browse_webpage", "docker_ffuf", "docker_dirb_scan", "docker_sensitive_files_scan", "docker_cors_scan", "docker_security_txt_audit", "docker_cookie_security_audit", "docker_http_headers_audit", "docker_api_docs_audit"]):
            score += 25

        # Phase 3: Vulnerability scanning (Nuclei, Nikto, WPScan, Testssl, XSS)
        if any(t in tested_tools for t in ["docker_nuclei_scan", "docker_nikto_scan", "docker_wpscan", "docker_testssl", "docker_xss_scan"]):
            score += 25

        # Phase 4: Targeted exploitation or verified negative (SQLMap, Hydra, Metasploit, Brute-force)
        if any(t in tested_tools for t in ["docker_sqlmap_scan", "docker_sqlmap_dump", "bruteforce_ssh", "bruteforce_http_form", "docker_hydra_ssh", "docker_msf_search", "docker_msf_exploit"]):
            score += 20
        elif self.scan_mode == "recon" and len(tested_tools) >= 3:
            score += 20  # Recon mode complete

        # Bonus for confirmed findings
        if any(f.severity in ("CRITICAL", "HIGH") for f in self.findings):
            score += 15
        elif self.findings:
            score += 5

        # Factor in milestone completion
        if self.milestones:
            m_completed = sum(1 for m in self.milestones if m.status == "COMPLETED")
            m_boost = int((m_completed / len(self.milestones)) * 10)
            score = max(score, m_boost)

        return min(score, 100)


    # ---------------------------------------------------------------
    # Summary Methods (used to build prompts for agents)
    # ---------------------------------------------------------------

    def get_current_summary(self) -> str:
        """Generate a concise summary of current state for Reporter prompt.

        This is injected into the Reporter's context so it knows what's
        already been discovered and doesn't duplicate findings.
        """
        lines = []
        if self.mission_objective:
            lines.append(f"Mục tiêu cốt lõi: {self.mission_objective}")
        lines.extend([
            f"Mục tiêu: {self.target}",
            f"Chế độ: {self.scan_mode.upper()}",
            f"Số bước đã thực hiện: {len(self.methodology)}",
            f"Risk Score hiện tại: {self.risk_score}/10",
        ])

        roadmap = self.get_tactical_roadmap()
        lines.append(f"Tiến độ mục tiêu: {roadmap['goal_progress']}%")

        # Attack surface highlights
        surf_parts = []
        if self.attack_surface.open_ports:
            if isinstance(self.attack_surface.open_ports, dict):
                surf_parts.append(f"Cổng mở: {list(self.attack_surface.open_ports.keys())[:8]}")
            else:
                surf_parts.append(f"Cổng mở: {list(self.attack_surface.open_ports)[:8]}")
        if self.attack_surface.parameterized_endpoints:
            surf_parts.append(f"Endpoints có tham số: {len(self.attack_surface.parameterized_endpoints)}")
        if self.attack_surface.login_forms:
            surf_parts.append(f"Form đăng nhập: {len(self.attack_surface.login_forms)}")
        if self.attack_surface.detected_technologies:
            surf_parts.append(f"Công nghệ: {', '.join(self.attack_surface.detected_technologies[:4])}")
        if self.attack_surface.subdomains:
            surf_parts.append(f"Subdomains: {len(self.attack_surface.subdomains)}")
        if self.attack_surface.alive_subdomains:
            surf_parts.append(f"Alive Hosts: {len(self.attack_surface.alive_subdomains)}")
        if self.attack_surface.exposed_sensitive_files:
            surf_parts.append(f"Tệp nhạy cảm lộ: {len(self.attack_surface.exposed_sensitive_files)}")
        if self.attack_surface.cors_issues:
            surf_parts.append(f"CORS issues: {len(self.attack_surface.cors_issues)}")

        if surf_parts:
            lines.append("Bề mặt tấn công: " + " | ".join(surf_parts))

        if self.findings:
            severity_counts = {}
            for f in self.findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            counts_str = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
            lines.append(f"Findings: {len(self.findings)} ({counts_str})")

            # List finding titles
            for i, f in enumerate(self.findings, 1):
                lines.append(f"  [{f.severity}] {f.title}")
        else:
            lines.append("Findings: Chưa có phát hiện nào")

        # Last 3 tools used
        if self.methodology:
            recent = self.methodology[-3:]
            recent_str = ", ".join(f"{s.tool_name}({s.status})" for s in recent)
            lines.append(f"Tools gần nhất: {recent_str}")

        # Tactical roadmap highlights
        if roadmap["untested_actions"]:
            lines.append("Lộ trình chiến thuật ưu tiên kế tiếp:")
            for a in roadmap["untested_actions"][:2]:
                lines.append(f"  → [{a['priority']}] {a['tool']}: {a['reason']}")

        return "\n".join(lines)

    def get_reporter_feedback_block(self, latest_suggestion: str = "",
                                     latest_comment: str = "",
                                     latest_findings: list[Finding] | None = None,
                                     objective_assessment: str = "",
                                     blocking_factor: str = "") -> str:
        """Build the feedback block injected into Red Teamer's context.

        This is what the Red Teamer sees after each Reporter observation.
        """
        progress = self.calculate_goal_progress()
        lines = [f"[📊 SOC ANALYST — Bước {len(self.methodology)} | Tiến độ: {progress}%]"]
        lines.append(f"Risk Score: {self.risk_score}/10")

        if self.milestones:
            m_items = []
            for m in self.milestones:
                icon = "✓" if m.status == "COMPLETED" else ("▶" if m.status == "IN_PROGRESS" else "⏳")
                m_items.append(f"{icon} {m.name} ({m.progress_pct}%)")
            lines.append(f"🎯 Mốc sứ mệnh: {' | '.join(m_items[:3])}")

        if objective_assessment and objective_assessment.strip():
            blocking_str = f" | Cản trở: {blocking_factor}" if blocking_factor and blocking_factor.lower() not in ("không có", "none", "n/a", "no") else ""
            lines.append(f"🎯 Đánh giá mục tiêu: {objective_assessment}{blocking_str}")

        if latest_findings:
            for f in latest_findings:
                lines.append(f"🔍 [{f.severity}] {f.title}")

        if latest_comment:
            lines.append(f"📝 {latest_comment}")

        if latest_suggestion:
            lines.append(f"💡 Gợi ý: {latest_suggestion}")

        # Inject prioritized untried action from tactical roadmap if available
        roadmap = self.get_tactical_roadmap()
        top_actions = [a for a in roadmap.get("top_actions", []) if a.get("priority") in ("CRITICAL", "HIGH")]
        if top_actions:
            lines.append(f"🎯 Lộ trình tối ưu đề xuất: [{top_actions[0]['action']}] {top_actions[0]['recommendation']}")

        if not latest_findings and not latest_suggestion and not top_actions:
            lines.append("✅ Không phát hiện mới từ bước này.")

        return "\n".join(lines)


    # ---------------------------------------------------------------
    # Severity Statistics
    # ---------------------------------------------------------------

    def get_severity_counts(self) -> dict:
        """Count findings by severity level."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def get_overall_risk_label(self) -> str:
        """Determine the overall risk label from findings and score."""
        counts = self.get_severity_counts()
        if counts["CRITICAL"] > 0 or self.risk_score >= 9.0:
            return "CRITICAL"
        if counts["HIGH"] > 0 or self.risk_score >= 7.0:
            return "HIGH"
        if counts["MEDIUM"] > 0 or self.risk_score >= 4.0:
            return "MEDIUM"
        if counts["LOW"] > 0 or self.risk_score >= 2.0:
            return "LOW"
        return "INFO"

    def findings_by_severity(self, severity: str | None = None) -> dict[str, list[Finding]] | list[Finding]:
        """Group all findings by severity level, or return findings for a specific severity."""
        grouped = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for f in self.findings:
            sev = f.severity if f.severity in grouped else "INFO"
            grouped[sev].append(f)
        if severity:
            return grouped.get(severity.strip().upper(), [])
        return grouped

    def get_findings_sorted(self) -> list[Finding]:
        """Return findings sorted by severity (CRITICAL first)."""
        return sorted(self.findings, key=lambda f: Finding.SEVERITY_ORDER.get(f.severity, 4))

    def get_owasp_breakdown(self) -> dict[str, int]:
        """Aggregate finding counts by OWASP Top 10 (2021) category."""
        breakdown: dict[str, int] = {}
        for f in self.findings:
            cat = f.owasp_category or "A05:2021 - Security Misconfiguration"
            breakdown[cat] = breakdown.get(cat, 0) + 1
        return dict(sorted(breakdown.items(), key=lambda x: x[1], reverse=True))

    def get_mitre_breakdown(self) -> dict[str, int]:
        """Aggregate finding counts by MITRE ATT&CK techniques."""
        breakdown: dict[str, int] = {}
        for f in self.findings:
            for tech in f.mitre_techniques:
                breakdown[tech] = breakdown.get(tech, 0) + 1
        return dict(sorted(breakdown.items(), key=lambda x: x[1], reverse=True))

    def generate_attack_graph(self) -> Any:
        """Construct and return the Bayesian Attack Graph for the engagement."""
        from src.utils.attack_graph import BayesianAttackGraph
        return BayesianAttackGraph.build_from_report_state(self)

    # ---------------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------------

    def get_prioritized_roadmap(self) -> list[dict]:
        """Generate a prioritized, multi-phase remediation roadmap (<24h, <7d, <30d)."""
        roadmap: list[dict] = []
        findings = self.get_findings_sorted()

        # Phase 1: Khẩn cấp (< 24 giờ) - CRITICAL findings & active exploits
        crit_findings = [f for f in findings if f.severity == "CRITICAL"]
        if crit_findings:
            for f in crit_findings:
                roadmap.append({
                    "phase": "Khẩn cấp (< 24 giờ)",
                    "priority": "P1 - KHẨN CẤP",
                    "action_item": f.remediation or f"Khắc phục và cô lập lỗ hổng {f.title}",
                    "target_component": f.cve_id or f.tool_source or self.target,
                    "owner": "SecOps / Dev Team",
                    "effort": "Thấp - Cần hành động ngay",
                })
        else:
            roadmap.append({
                "phase": "Khẩn cấp (< 24 giờ)",
                "priority": "P1 - KHẨN CẤP",
                "action_item": "Không có lỗ hổng mức CRITICAL cần cách ly khẩn cấp.",
                "target_component": self.target,
                "owner": "SecOps",
                "effort": "Không áp dụng",
            })

        # Phase 2: Ngắn hạn (< 7 ngày) - HIGH findings, DNS/Email, CORS, Sensitive Files, Cookies
        high_findings = [f for f in findings if f.severity == "HIGH"]
        for f in high_findings:
            roadmap.append({
                "phase": "Ngắn hạn (< 7 ngày)",
                "priority": "P2 - ƯU TIÊN CAO",
                "action_item": f.remediation or f"Vá và kiểm thử lại: {f.title}",
                "target_component": f.cve_id or f.tool_source or self.target,
                "owner": "DevOps / Web Developer",
                "effort": "Trung bình",
            })

        if self.attack_surface.dns_security_info and self.attack_surface.dns_security_info.get("security_issues"):
            roadmap.append({
                "phase": "Ngắn hạn (< 7 ngày)",
                "priority": "P2 - ƯU TIÊN CAO",
                "action_item": "Bổ sung cấu hình bản ghi SPF và DMARC enforce chính sách reject/quarantine.",
                "target_component": "Hạ tầng DNS & Mail Server",
                "owner": "System Administrator",
                "effort": "Thấp (< 2 giờ)",
            })

        if self.attack_surface.cookie_issues:
            roadmap.append({
                "phase": "Ngắn hạn (< 7 ngày)",
                "priority": "P2 - ƯU TIÊN CAO",
                "action_item": "Bật đầy đủ cờ HttpOnly, Secure và SameSite=Strict cho toàn bộ session cookies.",
                "target_component": "Web Application Framework",
                "owner": "Backend Developer",
                "effort": "Thấp (< 4 giờ)",
            })

        # Phase 3: Trung hạn (< 30 ngày) - MEDIUM/LOW, Hardening, RFC 9116, Security Audits
        med_low_findings = [f for f in findings if f.severity in ("MEDIUM", "LOW")]
        for f in med_low_findings[:5]:
            roadmap.append({
                "phase": "Trung hạn (< 30 ngày)",
                "priority": "P3 - TRUNG HẠN",
                "action_item": f.remediation or f"Củng cố và rà soát: {f.title}",
                "target_component": f.tool_source or self.target,
                "owner": "DevOps / QA Team",
                "effort": "Trung bình",
            })

        roadmap.append({
            "phase": "Trung hạn (< 30 ngày)",
            "priority": "P3 - TRUNG HẠN",
            "action_item": "Triển khai tệp /.well-known/security.txt chuẩn RFC 9116 và thiết lập quét CI/CD tự động.",
            "target_component": "Hạ tầng DevSecOps",
            "owner": "Security Engineer",
            "effort": "Trung bình (1-2 ngày)",
        })

        return roadmap

    def to_dict(self) -> dict:
        """Export full state as dictionary for DOCX generator."""
        return {
            "target": self.target,
            "scan_mode": self.scan_mode,
            "mission_objective": self.mission_objective,
            "start_time": self.start_time.strftime("%d/%m/%Y %H:%M:%S"),
            "end_time": self.end_time.strftime("%d/%m/%Y %H:%M:%S") if self.end_time else "N/A",
            "duration": str(self.end_time - self.start_time).split(".")[0] if self.end_time else "N/A",
            "executive_summary": self.executive_summary,
            "findings": [asdict(f) for f in self.findings],
            "compound_threats": [asdict(f) for f in self.findings if "[CHUỖI TẤN CÔNG]" in f.title],
            "methodology": [asdict(s) for s in self.methodology],
            "risk_score": self.risk_score,
            "risk_label": self.get_overall_risk_label(),
            "severity_counts": self.get_severity_counts(),
            "recommendations": self.recommendations,
            "prioritized_roadmap": self.get_prioritized_roadmap(),
            "conclusion": self.conclusion,
            "total_iterations": self.total_iterations,
            "red_teamer_final_answer": self.red_teamer_final_answer,
            "attack_surface": self.attack_surface.to_dict(),
            "goal_progress": self.calculate_goal_progress(),
            "milestones": [m.to_dict() for m in self.milestones],
            "rag_applied_patterns": self.rag_applied_patterns,
            "rag_stored_patterns": self.rag_stored_patterns,
            "owasp_breakdown": self.get_owasp_breakdown(),
            "mitre_breakdown": self.get_mitre_breakdown(),
            "attack_graph_summary": self.generate_attack_graph().to_summary_dict(),
            "attack_graph_mermaid": self.generate_attack_graph().to_mermaid(),
        }

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def export_json(self, file_path: str) -> str:
        """Export report data to JSON file."""
        import os
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        return file_path

    def export_markdown(self, file_path: str) -> str:
        """Export report summary to Markdown file."""
        import os
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.to_markdown())
        return file_path

    def to_markdown(self) -> str:
        """Generate an all-encompassing, highly-detailed Markdown pentest report."""
        counts = self.get_severity_counts()
        total_findings = len(self.findings)
        duration_str = str(self.end_time - self.start_time).split(".")[0] if self.end_time else "Đang thực thi"

        lines: list[str] = [
            f"# BÁO CÁO ĐÁNH GIÁ AN TOÀN THÔNG TIN TOÀN DIỆN — {self.target}",
            "",
            "> **BẢO MẬT & LƯU HÀNH NỘI BỘ (CONFIDENTIAL)**  ",
            f"> Hệ thống thẩm định: **Autonomous MLSecOps Agent (Cognitive Relentless Pursuit Engine)**  ",
            f"> Ngày báo cáo: **{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}**",
            "",
            "---",
            "",
            "## 1. PHẠM VI ĐÁNH GIÁ & THÔNG SỐ TỔNG QUAN (SCOPE & METADATA)",
            "",
            "| Thông số | Giá trị chi tiết |",
            "|---|---|",
            f"| **Mục tiêu đánh giá (Target)** | `{self.target}` |",
            f"| **Mục tiêu yêu cầu (Mission Objective)** | {self.mission_objective or 'Đánh giá toàn diện an toàn thông tin'} |",
            f"| **Chế độ kiểm thử (Scan Mode)** | `{self.scan_mode.upper()}` |",
            f"| **Thời gian bắt đầu** | {self.start_time.strftime('%d/%m/%Y %H:%M:%S')} |",
            f"| **Thời gian hoàn tất** | {self.end_time.strftime('%d/%m/%Y %H:%M:%S') if self.end_time else 'Đang cập nhật'} |",
            f"| **Tổng thời lượng** | {duration_str} |",
            f"| **Chỉ số Rủi ro Tổng thể** | **{self.risk_score:.1f}/10 ({self.get_overall_risk_label()})** |",
            f"| **Tỷ lệ Hoàn thành Mục tiêu** | **{self.calculate_goal_progress()}%** |",
            "",
            "### 1.1. Tiến Độ Các Cột Mốc Chiến Lược (Strategic Mission Milestones)",
            "",
            "| Cột Mốc | Mô tả Mục tiêu | Trạng thái | Tiến độ | Công cụ thực thi | Lỗ hổng phát hiện |",
            "|---|---|---|---|---|---|",
        ]

        for m in self.milestones:
            tools_str = ", ".join(m.relevant_tools[:4]) if m.relevant_tools else "Chưa ghi nhận"
            lines.append(f"| **{m.name}** | {m.description} | `{m.status}` | **{m.progress_pct}%** | `{tools_str}` | {m.findings_count} |")

        lines.extend([
            "",
            "---",
            "",
            "## 2. TÓM TẮT ĐIỀU HÀNH (EXECUTIVE SUMMARY)",
            "",
            self.executive_summary or f"Cuộc đánh giá an toàn thông tin toàn diện đã được tiến hành trên mục tiêu `{self.target}` bởi hệ thống Autonomous MLSecOps Agent.",
            "",
            "### 2.1. Phân Bổ Mức Độ Nghiêm Trọng Của Lỗ Hổng",
            "",
            "| Mức độ | CRITICAL | HIGH | MEDIUM | LOW | INFO | TỔNG CỘNG |",
            "|---|---|---|---|---|---|---|",
            f"| **Số lượng** | **{counts['CRITICAL']}** | **{counts['HIGH']}** | **{counts['MEDIUM']}** | **{counts['LOW']}** | **{counts['INFO']}** | **{total_findings}** |",
            "",
            "---",
            "",
            "## 3. PHÂN TÍCH BỀ MẶT TẤN CÔNG TOÀN DIỆN (ATTACK SURFACE MAPPING)",
            "",
        ])

        # 3.1 Open Ports
        if self.attack_surface.open_ports:
            lines.extend([
                "### 3.1. Các Cổng Dịch Vụ Mở & Dịch Vụ Lắng Nghe (Open Ports & Services)",
                "",
                "| Cổng/Giao thức | Dịch vụ phát hiện | Trạng thái rà soát sâu |",
                "|---|---|---|",
            ])
            if isinstance(self.attack_surface.open_ports, dict):
                for p, info in sorted(self.attack_surface.open_ports.items(), key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0):
                    svc = info.get("service", "unknown") if isinstance(info, dict) else "unknown"
                    deep = "Đã quét chuyên sâu" if isinstance(info, dict) and info.get("deep_scanned") else "Đã rà quét nhanh"
                    lines.append(f"| `{p}/tcp` | `{svc}` | {deep} |")
            else:
                for p in self.attack_surface.open_ports:
                    lines.append(f"| `{p}/tcp` | `unknown` | Đã rà quét |")
            lines.append("")

        # 3.2 Technologies
        if self.attack_surface.detected_technologies:
            lines.extend([
                "### 3.2. Công Nghệ & Nền Tảng Nhận Diện (Technologies & Frameworks)",
                "",
                "- " + "\n- ".join([f"**{t}**" for t in self.attack_surface.detected_technologies]),
                "",
            ])

        # 3.3 Endpoints & Login Forms
        if self.attack_surface.parameterized_endpoints or self.attack_surface.login_forms:
            lines.extend([
                "### 3.3. Điểm Cuối Ứng Dụng Web & Form Xác Thực (Endpoints & Auth)",
                "",
                "| Phân loại | URL / Endpoint | Trạng thái kiểm thử |",
                "|---|---|---|",
            ])
            if isinstance(self.attack_surface.parameterized_endpoints, dict):
                for u, info in list(self.attack_surface.parameterized_endpoints.items())[:20]:
                    sqli = "SQLi: Đã test" if info.get("tested_sqli") else "SQLi: Chưa test"
                    xss = "XSS: Đã test" if info.get("tested_xss") else "XSS: Chưa test"
                    lines.append(f"| Endpoint có tham số | `{u}` | {sqli} / {xss} |")
            for f in self.attack_surface.login_forms[:10]:
                f_url = f.get("url", "") if isinstance(f, dict) else str(f)
                tested = "Đã kiểm tra Brute-force" if isinstance(f, dict) and f.get("tested_bruteforce") else "Chưa kiểm tra"
                lines.append(f"| Form đăng nhập / Auth | `{f_url}` | {tested} |")
            lines.append("")

        # 3.4 Sensitive Files
        if self.attack_surface.exposed_sensitive_files:
            lines.extend([
                "### 3.4. Tập Tin & Đường Dẫn Nhạy Cảm Lộ Lọt (Exposed Sensitive Files)",
                "",
                "| Đường dẫn phát hiện | Phân loại rủi ro | Mức độ | Trạng thái phản hồi |",
                "|---|---|---|---|",
            ])
            for f in self.attack_surface.exposed_sensitive_files[:25]:
                f_path = str(f.get("path") or f.get("url") or "N/A")
                f_risk = str(f.get("risk_type") or "Information Disclosure")
                f_sev = str(f.get("severity") or "MEDIUM").upper()
                f_status = str(f.get("status_code") or "200")
                lines.append(f"| `{f_path}` | {f_risk} | `{f_sev}` | HTTP {f_status} |")
            lines.append("")

        # 3.5 CORS
        if self.attack_surface.cors_issues:
            lines.extend([
                "### 3.5. Lỗ Hổng Cấu Hình CORS & Tiêu Đề Bảo Mật (CORS Misconfigurations)",
                "",
                "| Endpoint / URL | Loại cấu hình sai | Mức độ | Chi tiết phát hiện |",
                "|---|---|---|---|",
            ])
            for iss in self.attack_surface.cors_issues[:15]:
                iss_url = str(iss.get("url") or "Target")
                iss_type = str(iss.get("type") or "CORS Misconfiguration")
                iss_sev = str(iss.get("severity") or "MEDIUM").upper()
                iss_desc = str(iss.get("description") or iss.get("origin") or "Phát hiện cấu hình lỏng lẻo")
                lines.append(f"| `{iss_url}` | {iss_type} | `{iss_sev}` | {iss_desc} |")
            lines.append("")

        # 3.6 Alive Subdomains
        if self.attack_surface.alive_subdomains:
            lines.extend([
                "### 3.6. Tên Miền Phụ Đang Hoạt Động (Alive Subdomains & HTTP Services)",
                "",
                "| URL / Subdomain | HTTP Status | Tiêu đề trang (Title) | Web Server |",
                "|---|---|---|---|",
            ])
            for h in self.attack_surface.alive_subdomains[:25]:
                if isinstance(h, dict):
                    h_url = str(h.get("url") or h.get("input_target") or "N/A")
                    h_status = str(h.get("status_code") or "200")
                    h_title = str(h.get("title") or "—")
                    h_server = str(h.get("webserver") or "—")
                else:
                    h_url = str(h)
                    h_status = "200"
                    h_title = "—"
                    h_server = "—"
                lines.append(f"| `{h_url}` | HTTP {h_status} | {h_title} | `{h_server}` |")
            lines.append("")

        # 3.7 SSL/TLS
        if self.attack_surface.ssl_cert_info:
            ssl = self.attack_surface.ssl_cert_info
            lines.extend([
                "### 3.7. Chứng Chỉ SSL/TLS & Mã Hóa Giao Thức (SSL/TLS Audit)",
                "",
                "| Thuộc tính kiểm tra | Giá trị ghi nhận |",
                "|---|---|",
                f"| **Tên miền chứng chỉ (CN)** | `{ssl.get('subject_cn', 'N/A')}` |",
                f"| **Đơn vị cấp phát (Issuer)** | {ssl.get('issuer_org') or ssl.get('issuer', 'N/A')} |",
                f"| **Hạn sử dụng (Valid To)** | {ssl.get('valid_to', 'N/A')} ({ssl.get('days_until_expiry', 'N/A')} ngày còn lại) |",
                f"| **Phiên bản TLS hỗ trợ** | `{ssl.get('tls_version', 'TLSv1.2 / TLSv1.3')}` |",
                f"| **Độ dài khóa mã hóa** | `{ssl.get('key_bits', 'N/A')} bits` |",
                f"| **Tên miền phụ thay thế (SANs)** | {len(ssl.get('subject_alternative_names', []))} tên miền |",
            ])
            if ssl.get("issues"):
                lines.append(f"| **Cảnh báo bảo mật SSL** | ⚠️ {'; '.join(ssl.get('issues'))} |")
            lines.append("")

        # 3.8 DNS & Email Security
        if self.attack_surface.dns_security_info:
            dns_info = self.attack_surface.dns_security_info
            spf = dns_info.get("spf", {})
            dmarc = dns_info.get("dmarc", {})
            dnssec = dns_info.get("dnssec", {})
            lines.extend([
                "### 3.8. An Toàn Hạ Tầng DNS & Chống Giả Mạo Email (DNS & Email Security)",
                "",
                "| Cơ chế bảo vệ | Trạng thái | Chi tiết bản ghi |",
                "|---|---|---|",
                f"| **SPF (Sender Policy Framework)** | `{spf.get('status', 'N/A')}` | `{spf.get('record') or spf.get('details') or '—'}` |",
                f"| **DMARC (Domain-based Auth)** | `{dmarc.get('status', 'N/A')}` | `{dmarc.get('policy') or dmarc.get('details') or '—'}` |",
                f"| **DNSSEC** | `{'BẬT' if dnssec.get('dnssec_enabled') else 'TẮT'}` | {'Xác thực tính toàn vẹn DNS tốt' if dnssec.get('dnssec_enabled') else 'Nguy cơ DNS Spoofing/Poisoning'} |",
                "",
            ])

        # 3.9 RFC 9116 & Hidden Paths
        if self.attack_surface.hidden_discovered_paths:
            lines.extend([
                "### 3.9. Chính Sách Bảo Mật RFC 9116 & Đường Dẫn Ẩn (Robots.txt & Security.txt)",
                "",
                "| Đường dẫn phát hiện | Nguồn phát hiện | Mức độ nhạy cảm |",
                "|---|---|---|",
            ])
            for p_item in self.attack_surface.hidden_discovered_paths[:25]:
                p_val = p_item if isinstance(p_item, str) else p_item.get("path", str(p_item))
                p_src = "robots.txt" if "/admin" in p_val or "disallow" in str(p_item).lower() else "sitemap / policy"
                p_sens = "Cao (Hidden Admin/API)" if any(k in p_val.lower() for k in ["admin", "api", "backup", "secret", "private"]) else "Bình thường"
                lines.append(f"| `{p_val}` | `{p_src}` | {p_sens} |")
            lines.append("")

        # 3.10 Cookie Security
        if self.attack_surface.cookie_issues:
            lines.extend([
                "### 3.10. An Toàn Cookie & Quản Lý Phiên (Cookie Security Flags)",
                "",
                "| Tên Cookie | Thiếu cờ bảo vệ | Mức độ | Nguy cơ an ninh |",
                "|---|---|---|---|",
            ])
            for c_item in self.attack_surface.cookie_issues[:20]:
                c_name = str(c_item.get("name") or "session_cookie")
                c_flags = ", ".join(c_item.get("missing_flags", [])) or str(c_item.get("issue") or "Missing flags")
                c_sev = str(c_item.get("severity") or "MEDIUM").upper()
                c_risk = str(c_item.get("risk") or "Nguy cơ đánh cắp phiên qua XSS/MITM")
                lines.append(f"| `{c_name}` | `{c_flags}` | `{c_sev}` | {c_risk} |")
            lines.append("")

        # 3.11 HTTP Security Headers & Banner Leaks
        if self.attack_surface.security_headers_info:
            sh = self.attack_surface.security_headers_info
            lines.extend([
                "### 3.11. Tiêu Đề An Ninh HTTP & Rò Rỉ Máy Chủ (HTTP Security Headers Audit)",
                "",
                f"Điểm bảo mật HTTP Headers: **{sh.get('score', 0)}/100** (Hạng: **{sh.get('grade', 'N/A')}**)",
                "",
                "| Loại thông tin | Tiêu đề ghi nhận | Chi tiết cảnh báo |",
                "|---|---|---|",
            ])
            for m_hdr in sh.get("missing_headers", []):
                h_name = m_hdr if isinstance(m_hdr, str) else m_hdr.get("header", str(m_hdr))
                lines.append(f"| `Thiếu Header` | `{h_name}` | Chưa được thiết lập trên máy chủ web |")
            for l_hdr in sh.get("information_leaks", []):
                if isinstance(l_hdr, dict):
                    lines.append(f"| `Rò rỉ Banner` | `{l_hdr.get('header')}` | Giá trị: `{l_hdr.get('value')}` |")
            lines.append("")

        # 3.12 Exposed API Documentation
        if self.attack_surface.exposed_api_docs:
            lines.extend([
                "### 3.12. Tài Liệu API & OpenAPI Schemas Lộ Lọt (Exposed API Documentation)",
                "",
                "| Định dạng / Loại API | Tiêu đề API | Đường dẫn công khai | Số Endpoints | Mức độ |",
                "|---|---|---|---|---|",
            ])
            for doc_item in self.attack_surface.exposed_api_docs:
                d_type = doc_item.get("type", "OpenAPI Spec")
                d_title = doc_item.get("title", "API Docs")
                d_url = doc_item.get("url", doc_item.get("path", "N/A"))
                d_count = doc_item.get("endpoints_count", len(doc_item.get("discovered_paths", [])))
                d_sev = doc_item.get("severity", "HIGH")
                lines.append(f"| `{d_type}` | **{d_title}** | `{d_url}` | {d_count} | `{d_sev}` |")
            lines.append("")

        # 3.13 Subdomain Takeover & Dangling CNAMEs
        if self.attack_surface.dangling_cnames:
            lines.extend([
                "### 3.13. Kiểm Toán Chiếm Đoạt Tên Miền Phụ (Subdomain Takeover & Dangling CNAMEs)",
                "",
                "| Tên miền phụ | Bản ghi CNAME | Dịch vụ Cloud | Mức độ | Rủi ro chiếm đoạt |",
                "|---|---|---|---|---|",
            ])
            for dc in self.attack_surface.dangling_cnames:
                sub_name = dc.get("subdomain", "N/A")
                cname_val = dc.get("cname", "N/A")
                srv = dc.get("service", "Cloud Provider")
                sev = dc.get("severity", "HIGH")
                risk_txt = dc.get("risk", "Bản ghi trỏ tới tài nguyên đám mây bị bỏ hoang")
                lines.append(f"| `{sub_name}` | `{cname_val}` | **{srv}** | `{sev}` | {risk_txt} |")
            lines.append("")

        # 3.14 WAF & CDN Detection
        if self.attack_surface.detected_waf:
            waf_info = self.attack_surface.detected_waf
            primary = waf_info.get("primary_waf", "WAF / CDN")
            status_txt = "Đã phát hiện bảo vệ" if waf_info.get("waf_detected") else "Không phát hiện WAF trực tiếp"
            lines.extend([
                "### 3.14. Nhận Diện Tường Lửa Ứng Dụng Web & CDN (WAF & Defense Evasion)",
                "",
                f"- **Giải pháp bảo vệ chính:** **{primary}** ({status_txt})",
                f"- **Tín hiệu nhận diện:** {', '.join(waf_info.get('signals', ['Header signatures'])) if waf_info.get('signals') else 'Chữ ký phản hồi'}",
                "",
            ])

        # 4. Compound Threat Scenarios & Bayesian Attack Graph
        attack_graph = self.generate_attack_graph()
        crit_path = attack_graph.get_critical_path()
        all_paths = attack_graph.find_all_attack_paths()
        owasp_breakdown = self.get_owasp_breakdown()
        mitre_breakdown = self.get_mitre_breakdown()
        compound_threats = [f for f in self.findings if "[CHUỖI TẤN CÔNG]" in f.title]

        lines.extend([
            "---",
            "",
            "## 4. KỊCH BẢN KHAI THÁC PHỨC HỢP & MÔ HÌNH HÓA ĐỒ THỊ TẤN CÔNG BAYESIAN (BAYESIAN ATTACK GRAPH & THREAT MODELING)",
            "",
            "Hệ thống tự động tổng hợp toàn bộ điểm yếu và bề mặt tấn công thành Đồ thị Tấn công Bayesian động, "
            "tính toán xác suất thâm nhập tích lũy và định vị đường dẫn xâm nhập nguy hiểm nhất đến các tài sản trọng yếu (Crown Jewels).",
            "",
        ])

        if compound_threats:
            lines.extend([
                "### 4.1. Kịch Bản Khai Thác Phức Hợp (Compound Attack Scenarios & Attack Chaining)",
                "",
                "Động cơ Tương quan Lỗ hổng (Vulnerability Correlation Engine) đã tự động liên kết các điểm yếu riêng lẻ thành các chuỗi kịch bản tấn công nguy hại:",
                "",
                "| Kịch bản Chuỗi Tấn Công | Mức độ | Điểm CVSS | Mô tả Đường dẫn Xâm nhập & Tác động |",
                "|---|---|---|---|",
            ])
            for ct in compound_threats:
                t_title = ct.title.replace("[CHUỖI TẤN CÔNG]", "").strip()
                lines.append(f"| **{t_title}** | `{ct.severity}` | **{ct.cvss_score or 'N/A'}** | {ct.description} |")
            lines.append("")

        if crit_path:
            crit_pct = round(crit_path.cumulative_probability * 100, 1)
            chain_str = " ➔ ".join(crit_path.node_ids)
            lines.extend([
                f"> 🚨 **ĐƯỜNG DẪN XÂM NHẬP NGUY HIỂM NHẤT (CRITICAL ATTACK PATH):**  ",
                f"> **Chuỗi tấn công:** `{chain_str}`  ",
                f"> **Mức độ rủi ro:** `{crit_path.risk_label}` | **Xác suất thâm nhập thành công:** **{crit_pct}%**  ",
                f"> **Mục tiêu bị đe dọa trực tiếp:** `{crit_path.target_crown_jewel}`",
                "",
            ])

        # Mermaid Graph Diagram
        lines.extend([
            "### 4.2. Sơ Đồ Đồ Thị Tấn Công (Visual Attack Graph)",
            "",
            attack_graph.to_mermaid(),
            "",
        ])

        # Attack Paths Table
        if all_paths:
            lines.extend([
                "### 4.3. Danh Mục Các Chuỗi Xâm Nhập Khả Thi (Viable Kill-Chain Paths)",
                "",
                "| Mức độ Rủi ro | Xác suất Thành công | Chuỗi Xâm nhập (Kill-Chain Vector) | Tài sản Trọng yếu |",
                "|---|---|---|---|",
            ])
            for p in all_paths[:8]:
                p_pct = round(p.cumulative_probability * 100, 1)
                p_chain = " ➔ ".join(p.node_ids)
                lines.append(f"| `{p.risk_label}` | **{p_pct}%** | `{p_chain}` | `{p.target_crown_jewel}` |")
            lines.append("")

        # OWASP Top 10 Breakdown
        if owasp_breakdown:
            lines.extend([
                "### 4.4. Phân Loại Theo OWASP Top 10 (2021)",
                "",
                "| Danh mục OWASP Top 10 (2021) | Số lượng Phát hiện | Mức độ Ảnh hưởng |",
                "|---|---|---|",
            ])
            for cat, cnt in owasp_breakdown.items():
                lines.append(f"| **{cat}** | `{cnt}` lỗ hổng | Đã ánh xạ kiểm thử tự động |")
            lines.append("")

        # MITRE ATT&CK Matrix Breakdown
        if mitre_breakdown:
            lines.extend([
                "### 4.5. Ánh Xạ Ma Trận Chiến Thuật & Kỹ Thuật MITRE ATT&CK",
                "",
                "| Kỹ thuật MITRE ATT&CK | Số lượng Lỗ hổng Liên đới | Giai đoạn Chiến thuật (Tactic) |",
                "|---|---|---|",
            ])
            for tech, cnt in list(mitre_breakdown.items())[:12]:
                lines.append(f"| `{tech}` | `{cnt}` | Initial Access / Execution / Lateral Movement |")
            lines.append("")

        # 5. Methodology
        lines.extend([
            "---",
            "",
            "## 5. NHẬT KÝ THỰC THI KILL CHAIN (METHODOLOGY TIMELINE)",
            "",
            f"Tổng cộng **{len(self.methodology)} bước** công cụ đã được hệ thống thực thi:",
            "",
            "| Bước (#) | Thời gian | Công cụ | Trạng thái | Thời lượng | Nhận xét SOC Analyst |",
            "|---|---|---|---|---|---|",
        ])
        for step in self.methodology:
            lines.append(f"| `{step.step_number}` | `{step.timestamp}` | `{step.tool_name}` | `{step.status}` | {step.duration_seconds:.1f}s | {step.reporter_comment or '—'} |")
        lines.append("")

        # 6. Detailed Findings
        lines.extend([
            "---",
            "",
            "## 6. DANH MỤC PHÁT HIỆN & HỒ SƠ LỖ HỔNG CHI TIẾT (DETAILED FINDINGS)",
            "",
        ])

        if not self.findings:
            lines.append("Không phát hiện lỗ hổng đáng kể nào trong quá trình kiểm thử.")
        else:
            for idx, f in enumerate(self.get_findings_sorted(), 1):
                mitre_str = ", ".join(f.mitre_techniques) if getattr(f, "mitre_techniques", None) else "N/A"
                lines.extend([
                    f"### 6.{idx}. [{f.severity}] {f.title}",
                    "",
                    "| Thuộc tính | Chi tiết kỹ thuật |",
                    "|---|---|",
                    f"| **Mức độ nghiêm trọng** | **`{f.severity}`** |",
                    f"| **Mã CVE** | `{f.cve_id or 'N/A'}` |",
                    f"| **Điểm CVSS v3.1** | **{f.cvss_score if f.cvss_score is not None else 'N/A'}** |",
                    f"| **Danh mục OWASP (2021)** | `{getattr(f, 'owasp_category', '') or 'N/A'}` |",
                    f"| **Kỹ thuật MITRE ATT&CK** | `{mitre_str}` |",
                    f"| **Công cụ phát hiện** | `{f.tool_source or 'N/A'}` |",
                    f"| **Thời gian phát hiện** | `{f.timestamp}` |",
                    "",
                    f"**Mô tả Kỹ thuật:**  \n{f.description or 'N/A'}",
                    "",
                    f"**Đánh giá Tác động Doanh nghiệp:**  \n{f.impact or 'N/A'}",
                    "",
                    f"**Biện pháp Khắc phục Đề xuất:**  \n{f.remediation or 'N/A'}",
                    "",
                ])
                if f.raw_evidence:
                    lines.extend([
                        "**Bằng chứng Thực nghiệm (Proof of Concept / Raw Evidence):**",
                        "```text",
                        f.raw_evidence[:1500],
                        "```",
                        "",
                    ])

        # 7. Remediation Roadmap
        lines.extend([
            "---",
            "",
            "## 7. LỘ TRÌNH KHẮC PHỤC PHÂN TẦNG THỜI GIAN (PRIORITIZED REMEDIATION ROADMAP)",
            "",
            "| Giai đoạn | Mức độ Ưu tiên | Hạng mục Khắc phục | Thành phần Mục tiêu | Bộ phận Phụ trách | Nỗ lực Ước tính |",
            "|---|---|---|---|---|---|",
        ])
        roadmap = self.get_prioritized_roadmap()
        for r in roadmap:
            lines.append(f"| **{r['phase']}** | `{r['priority']}` | {r['action_item']} | `{r['target_component']}` | {r['owner']} | {r['effort']} |")
        lines.append("")

        # 8. Technical Appendix
        lines.extend([
            "---",
            "",
            "## 8. PHỤ LỤC KỸ THUẬT THỰC THI (TECHNICAL EXECUTION APPENDIX)",
            "",
            "Bảng ghi chi tiết các câu lệnh và kết quả đầu ra của từng bước công cụ:",
            "",
        ])
        for step in self.methodology:
            args_str = json.dumps(step.arguments, ensure_ascii=False, indent=2) if step.arguments else "{}"
            lines.extend([
                f"### 8.{step.step_number}. [{step.status}] `{step.tool_name}` — {step.timestamp} ({step.duration_seconds}s)",
                "",
                f"**Tham số Đầu vào:**",
                "```json",
                args_str,
                "```",
                "",
                f"**Kết quả:**",
                "```json",
                (step.result_snippet or "—"),
                "```",
                "",
            ])
            if step.reporter_comment:
                lines.extend([
                    f"**SOC Analyst:** {step.reporter_comment}",
                    "",
                ])
        lines.append("")

        # 9. Long-term Tactical Memory & Self-learning Playbooks
        lines.extend([
            "---",
            "",
            "## 9. TRÍ NHỚ CHIẾN THUẬT DÀI HẠN & KỊCH BẢN TỰ HỌC (LONG-TERM MEMORY & PLAYBOOK REPLAY)",
            "",
            "Động cơ RAG Long-term Memory tự động kích hoạt truy xuất tri thức từ các chiến dịch trước và lưu trữ kịch bản mới:",
            "",
            "### 9.1. Kịch Bản Quá Khứ Đã Tái Sử Dụng Thành Công (Applied Attack Patterns)",
            "",
        ])
        if self.rag_applied_patterns:
            lines.extend([
                "| Kịch bản / ID | Mã CWE | Bề mặt / Điểm vào | Chuỗi Tấn Công / Vector | Độ Tương Đồng / Tin Cậy |",
                "|---|---|---|---|---|",
            ])
            for p in self.rag_applied_patterns:
                pid = str(p.get("id", "pattern"))[:12]
                cwe = str(p.get("cwe_id", "N/A"))
                entry = str(p.get("entry_point") or p.get("target") or "Target Surface")
                vector = str(p.get("successful_vector") or "Replay Chain")
                sim = p.get("similarity_score") or p.get("rerank_score") or 0.85
                sim_str = f"{sim:.2f}" if isinstance(sim, (int, float)) else str(sim)
                lines.append(f"| `{pid}` | **{cwe}** | `{entry[:40]}` | {vector[:50]} | `{sim_str}` |")
            lines.append("")
        else:
            lines.extend([
                "Không ghi nhận kịch bản cũ nào khớp trực tiếp trong phiên thẩm định này (hệ thống vận hành theo tri thức suy luận mới).",
                "",
            ])

        lines.extend([
            "### 9.2. Kịch Bản Mới Đúc Kết & Lưu Trữ Vào Bộ Nhớ Dài Hạn (Stored Attack Patterns)",
            "",
        ])
        if self.rag_stored_patterns:
            lines.extend([
                "| Thời gian | Mã CWE | Điểm vào | Vector Tấn Công Thành Công | Tóm tắt Lý do / Phát hiện |",
                "|---|---|---|---|---|",
            ])
            for p in self.rag_stored_patterns:
                ts = str(p.get("timestamp", "Vừa lưu"))
                cwe = str(p.get("cwe_id", "N/A"))
                entry = str(p.get("entry_point") or "N/A")
                vector = str(p.get("successful_vector") or "N/A")
                reasoning = str(p.get("agent_reasoning") or p.get("summary") or "Tự học từ thực nghiệm thành công")
                lines.append(f"| `{ts}` | **{cwe}** | `{entry[:35]}` | `{vector[:45]}` | {reasoning[:60]} |")
            lines.append("")
        else:
            lines.extend([
                "Chưa ghi nhận kịch bản mới nào được đưa vào bộ nhớ dài hạn trong phiên này.",
                "",
            ])

        # 10. Conclusion
        lines.extend([
            "---",
            "",
            "## 10. KẾT LUẬN & KIỂM TOÁN (CONCLUSION & AUDIT)",
            "",
            self.conclusion or self.red_teamer_final_answer or (
                f"Cuộc đánh giá mục tiêu `{self.target}` đã hoàn tất. "
                f"Mức độ rủi ro tổng thể: **{self.get_overall_risk_label()} ({self.risk_score:.1f}/10)**. "
                "Đội ngũ an ninh khuyến nghị thực hiện ngay các hành động trong Giai đoạn 1 của Lộ trình Khắc phục."
            ),
            "",
            "> **Nhật ký Kiểm toán:** Chi tiết toàn bộ payload, headers và raw responses được bảo lưu tại `reports/audit_trail.jsonl`.",
            "",
        ])

        return "\n".join(lines)

