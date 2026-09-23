"""Bayesian Attack Graph & Kill-Chain Path Synthesizer.

Models multi-stage penetration paths from initial perimeter exposure to
critical crown jewels (Databases, Host OS, Admin Portals) with Bayesian
breach probability estimation and visual Mermaid graph synthesis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class AttackNode:
    """An asset, service, or privilege boundary in the engagement topology."""
    id: str
    name: str
    category: str  # PERIMETER, ASSET, SERVICE, DATA, ADMIN, HOST
    is_compromised: bool = False
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackEdge:
    """An exploitable vector linking two nodes enabled by one or more findings."""
    source: str
    target: str
    finding_title: str
    severity: str = "MEDIUM"
    probability: float = 0.50
    technique: str = ""
    owasp: str = ""
    evidence_snippet: str = ""


@dataclass
class AttackPath:
    """A multi-hop attack chain from Internet exposure to target asset."""
    node_ids: list[str]
    edges: list[AttackEdge]
    cumulative_probability: float
    target_crown_jewel: str
    risk_label: str = "HIGH"

    def to_summary(self) -> str:
        """Format attack path into a clear human-readable chain."""
        hops = " ➔ ".join(self.node_ids)
        pct = round(self.cumulative_probability * 100, 1)
        return f"[{self.risk_label} - {pct}% Xác suất] {hops}"


class BayesianAttackGraph:
    """Dynamic Bayesian Attack Graph modeling penetration kill-chains."""

    def __init__(self) -> None:
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []
        self._add_default_nodes()

    def _add_default_nodes(self) -> None:
        """Add baseline external perimeter entrypoint."""
        self.add_node(
            AttackNode(
                id="INTERNET",
                name="External Attacker (Internet)",
                category="PERIMETER",
                is_compromised=True,
            )
        )

    def add_node(self, node: AttackNode) -> None:
        """Add or update a node in the attack topology."""
        self.nodes[node.id] = node

    def add_edge(self, edge: AttackEdge) -> None:
        """Add a directed attack vector between two existing nodes."""
        if edge.source in self.nodes and edge.target in self.nodes:
            self.edges.append(edge)

    @classmethod
    def calculate_probability(cls, severity: str, cvss_score: Optional[float] = None) -> float:
        """Compute Bayesian likelihood P(ExploitSuccess | Finding)."""
        if cvss_score is not None and cvss_score > 0:
            # Map CVSS 0.0 - 10.0 into probability [0.10, 0.95]
            base = min(0.95, max(0.10, cvss_score / 10.0))
            return round(base, 2)

        sev = (severity or "MEDIUM").upper().strip()
        sev_map = {
            "CRITICAL": 0.92,
            "HIGH": 0.80,
            "MEDIUM": 0.55,
            "LOW": 0.30,
            "INFO": 0.15,
        }
        return sev_map.get(sev, 0.50)

    @classmethod
    def build_from_report_state(cls, report_state: Any) -> "BayesianAttackGraph":
        """Synthesize a complete Attack Graph from ReportState findings and attack surface."""
        graph = cls()
        if not report_state:
            return graph

        surface = getattr(report_state, "attack_surface", None)
        target_str = str(getattr(report_state, "target", "Target Server"))

        # 1. Instantiate Target Topology Nodes
        web_node_id = "WEB_APPLICATION"
        graph.add_node(AttackNode(id=web_node_id, name=f"Web Application ({target_str})", category="SERVICE"))

        db_node_id = "DATABASE_TIER"
        admin_node_id = "ADMIN_INTERFACE"
        host_node_id = "HOST_SYSTEM"

        has_db_port = False
        has_ssh_port = False

        if surface:
            open_ports = getattr(surface, "open_ports", {})
            for p in open_ports:
                try:
                    p_int = int(p)
                    if p_int in (3306, 5432, 27017, 1433, 1521, 6379):
                        has_db_port = True
                    elif p_int in (22, 2222):
                        has_ssh_port = True
                except (ValueError, TypeError):
                    pass

            # Subdomain nodes
            for sub in list(getattr(surface, "subdomains", []))[:3]:
                sub_id = f"SUB_{sub.replace('.', '_')}"
                graph.add_node(AttackNode(id=sub_id, name=f"Subdomain: {sub}", category="ASSET"))
                # Initial network link
                graph.add_edge(AttackEdge(
                    source="INTERNET",
                    target=sub_id,
                    finding_title="Subdomain Enumeration Discovery",
                    severity="INFO",
                    probability=0.95,
                    technique="T1596",
                ))

        # Core Target Nodes
        graph.add_node(AttackNode(id=db_node_id, name="Database & Persistent Storage", category="DATA"))
        graph.add_node(AttackNode(id=admin_node_id, name="Admin / Management Console", category="ADMIN"))
        graph.add_node(AttackNode(id=host_node_id, name="Underlying Host OS / Container", category="HOST"))

        # Baseline entry edge: Internet to Web Application
        graph.add_edge(AttackEdge(
            source="INTERNET",
            target=web_node_id,
            finding_title="Public Web Application Exposure",
            severity="INFO",
            probability=0.98,
            technique="T1190",
        ))

        # SSH entrypoint if active
        if has_ssh_port:
            ssh_id = "SSH_SERVICE"
            graph.add_node(AttackNode(id=ssh_id, name="SSH Service (Port 22)", category="SERVICE"))
            graph.add_edge(AttackEdge(
                source="INTERNET",
                target=ssh_id,
                finding_title="Public SSH Exposure",
                severity="LOW",
                probability=0.95,
                technique="T1046",
            ))

        # Database direct port if active
        if has_db_port:
            graph.add_edge(AttackEdge(
                source="INTERNET",
                target=db_node_id,
                finding_title="Direct Database Port Exposure",
                severity="MEDIUM",
                probability=0.90,
                technique="T1046",
            ))

        # 2. Correlate Findings into Multi-Hop Exploit Edges
        findings = getattr(report_state, "findings", [])
        for f in findings:
            title_lower = str(f.title).lower()
            desc_lower = str(f.description).lower()
            prob = cls.calculate_probability(f.severity, f.cvss_score)
            technique = f.mitre_techniques[0] if getattr(f, "mitre_techniques", None) else "T1190"
            owasp = getattr(f, "owasp_category", "")

            # SQL Injection -> Web to Database
            if "sql" in title_lower or "sqli" in title_lower or "cve-2021-41773" in title_lower:
                graph.add_edge(AttackEdge(
                    source=web_node_id,
                    target=db_node_id,
                    finding_title=f.title,
                    severity=f.severity,
                    probability=prob,
                    technique=technique,
                    owasp=owasp,
                ))

            # Database Dump / Exfiltration -> Database to Crown Jewel Compromise
            if "dump" in title_lower or "data leak" in title_lower or "exfiltration" in title_lower:
                graph.add_edge(AttackEdge(
                    source=db_node_id,
                    target=host_node_id,
                    finding_title=f.title,
                    severity=f.severity,
                    probability=prob,
                    technique="T1567",
                    owasp=owasp,
                ))

            # XSS / Cookie Hijacking -> Web to Admin Interface
            if "xss" in title_lower or "cookie" in title_lower or "cors" in title_lower or "session" in title_lower:
                graph.add_edge(AttackEdge(
                    source=web_node_id,
                    target=admin_node_id,
                    finding_title=f.title,
                    severity=f.severity,
                    probability=prob,
                    technique=technique,
                    owasp=owasp,
                ))

            # Credential leak / Sensitive file -> Web to Admin or Database
            if "sensitive" in title_lower or ".env" in title_lower or "credentials" in title_lower or "backup" in title_lower:
                graph.add_edge(AttackEdge(
                    source=web_node_id,
                    target=admin_node_id,
                    finding_title=f.title,
                    severity=f.severity,
                    probability=prob,
                    technique="T1552",
                    owasp=owasp,
                ))
                graph.add_edge(AttackEdge(
                    source=web_node_id,
                    target=db_node_id,
                    finding_title=f.title,
                    severity=f.severity,
                    probability=prob,
                    technique="T1552",
                    owasp=owasp,
                ))

            # Brute Force SSH -> SSH Service to Host System
            if "ssh" in title_lower and ("brute" in title_lower or "credential" in title_lower or "login" in title_lower):
                target_src = "SSH_SERVICE" if "SSH_SERVICE" in graph.nodes else web_node_id
                graph.add_edge(AttackEdge(
                    source=target_src,
                    target=host_node_id,
                    finding_title=f.title,
                    severity=f.severity,
                    probability=prob,
                    technique="T1110",
                    owasp=owasp,
                ))

            # Brute Force HTTP Form -> Web to Admin Interface
            if "form" in title_lower and ("brute" in title_lower or "auth" in title_lower):
                graph.add_edge(AttackEdge(
                    source=web_node_id,
                    target=admin_node_id,
                    finding_title=f.title,
                    severity=f.severity,
                    probability=prob,
                    technique="T1110",
                    owasp=owasp,
                ))

            # RCE / Command Execution -> Direct to Host System
            if "rce" in title_lower or "remote code" in title_lower or "command execution" in title_lower:
                graph.add_edge(AttackEdge(
                    source=web_node_id,
                    target=host_node_id,
                    finding_title=f.title,
                    severity=f.severity,
                    probability=prob,
                    technique="T1059",
                    owasp=owasp,
                ))

            # Subdomain Takeover -> Subdomain to Web / Admin
            if "takeover" in title_lower:
                for n_id in list(graph.nodes.keys()):
                    if n_id.startswith("SUB_"):
                        graph.add_edge(AttackEdge(
                            source=n_id,
                            target=admin_node_id,
                            finding_title=f.title,
                            severity=f.severity,
                            probability=prob,
                            technique="T1584",
                            owasp=owasp,
                        ))

        # Admin interface compromise allows pivoting to Host OS
        graph.add_edge(AttackEdge(
            source=admin_node_id,
            target=host_node_id,
            finding_title="Administrative Privilege Escalation & Lateral Movement",
            severity="HIGH",
            probability=0.75,
            technique="T1078",
        ))

        return graph

    def find_all_attack_paths(self, max_depth: int = 5) -> list[AttackPath]:
        """Discover all simple directed penetration paths from INTERNET to terminal targets."""
        terminal_nodes = {"DATABASE_TIER", "ADMIN_INTERFACE", "HOST_SYSTEM"}
        paths: list[AttackPath] = []

        # Build adjacency mapping: source -> list of edges
        adj: dict[str, list[AttackEdge]] = {}
        for edge in self.edges:
            adj.setdefault(edge.source, []).append(edge)

        def dfs(current_node: str, visited: set[str], path_edges: list[AttackEdge]) -> None:
            if current_node in terminal_nodes and path_edges:
                # Calculate Bayesian cumulative path probability
                cum_prob = 1.0
                for e in path_edges:
                    cum_prob *= e.probability

                # Determine risk label
                if cum_prob >= 0.60:
                    risk = "CRITICAL"
                elif cum_prob >= 0.35:
                    risk = "HIGH"
                elif cum_prob >= 0.15:
                    risk = "MEDIUM"
                else:
                    risk = "LOW"

                node_chain = ["INTERNET"] + [e.target for e in path_edges]
                paths.append(
                    AttackPath(
                        node_ids=node_chain,
                        edges=list(path_edges),
                        cumulative_probability=round(cum_prob, 3),
                        target_crown_jewel=current_node,
                        risk_label=risk,
                    )
                )

            if len(path_edges) >= max_depth:
                return

            for nxt_edge in adj.get(current_node, []):
                nxt_node = nxt_edge.target
                if nxt_node not in visited:
                    visited.add(nxt_node)
                    path_edges.append(nxt_edge)
                    dfs(nxt_node, visited, path_edges)
                    path_edges.pop()
                    visited.remove(nxt_node)

        dfs("INTERNET", {"INTERNET"}, [])

        # Sort paths descending by cumulative probability
        paths.sort(key=lambda p: p.cumulative_probability, reverse=True)
        return paths

    def get_critical_path(self) -> AttackPath | None:
        """Retrieve the single highest-probability attack path leading to crown jewels."""
        paths = self.find_all_attack_paths()
        return paths[0] if paths else None

    def to_mermaid(self) -> str:
        """Generate a clean Mermaid flowchart diagram of the attack graph."""
        lines = ["```mermaid", "flowchart TD"]

        # Style definitions
        lines.append("    classDef perimeter fill:#2b2d42,stroke:#8d99ae,stroke-width:2px,color:#edf2f4;")
        lines.append("    classDef service fill:#1d3557,stroke:#457b9d,stroke-width:2px,color:#f1faee;")
        lines.append("    classDef admin fill:#e63946,stroke:#f1faee,stroke-width:2px,color:#ffffff;")
        lines.append("    classDef crown fill:#d90429,stroke:#ffb703,stroke-width:3px,color:#ffffff;")

        # Nodes
        for n_id, node in self.nodes.items():
            clean_name = node.name.replace('"', "'")
            shape = f'["{clean_name}"]'
            if node.category == "HOST":
                shape = f'{{"👑 {clean_name}"}}'
            elif node.category == "DATA":
                shape = f'[("💾 {clean_name}")]'
            elif node.category == "ADMIN":
                shape = f'[["🔑 {clean_name}"]' + "]"

            lines.append(f"    {n_id}{shape}")

            # Assign styling classes
            if node.category == "PERIMETER":
                lines.append(f"    class {n_id} perimeter;")
            elif node.category in ("ADMIN", "DATA"):
                lines.append(f"    class {n_id} admin;")
            elif node.category == "HOST":
                lines.append(f"    class {n_id} crown;")
            else:
                lines.append(f"    class {n_id} service;")

        # Edges (deduplicated by source, target, finding)
        seen_edges = set()
        for edge in self.edges:
            pair = (edge.source, edge.target, edge.finding_title[:20])
            if pair in seen_edges:
                continue
            seen_edges.add(pair)

            pct = int(edge.probability * 100)
            tech_str = f" [{edge.technique}]" if edge.technique else ""
            label = f"{pct}%{tech_str}"
            lines.append(f"    {edge.source} -->|{label}| {edge.target}")

        lines.append("```")
        return "\n".join(lines)

    def to_summary_dict(self) -> dict[str, Any]:
        """Export comprehensive metrics for reporting."""
        paths = self.find_all_attack_paths()
        crit = self.get_critical_path()
        return {
            "total_nodes": len(self.nodes),
            "total_attack_vectors": len(self.edges),
            "total_viable_paths": len(paths),
            "top_paths": [p.to_summary() for p in paths[:5]],
            "critical_path_probability": crit.cumulative_probability if crit else 0.0,
            "critical_path_chain": " ➔ ".join(crit.node_ids) if crit else "None",
        }
