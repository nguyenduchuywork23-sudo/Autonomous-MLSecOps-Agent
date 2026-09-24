"""
Tree-of-Thought (ToT) & Autonomous Backtracking Engine
======================================================
Inspired by Claude 3.7 Extended Thinking and Frontier Reasoning (GPT-5 / o3).

Prevents blind looping and linear dead-ends by maintaining a dynamic tree of attack
vector hypotheses. When an active vector is disproven or blocked by a WAF,
the engine autonomously PRUNES the branch and BACKTRACKS to the next most
promising unexplored vector in the hypothesis space.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class VectorStatus:
    UNEXPLORED = "UNEXPLORED"
    ACTIVE = "ACTIVE"
    CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"
    DEAD_END = "DEAD_END"
    WAF_BLOCKED = "WAF_BLOCKED"


class AttackVectorNode:
    """Represents a node in the attack hypothesis tree."""

    def __init__(
        self,
        node_id: str,
        title: str,
        category: str,
        target_asset: str,
        priority: float = 0.5,
        status: str = VectorStatus.UNEXPLORED,
        parent_id: Optional[str] = None,
        recommended_tools: Optional[List[str]] = None,
    ) -> None:
        self.node_id = node_id
        self.title = title
        self.category = category  # RECON, WEB_EXPLOIT, API_EXPLOIT, AUTH, INFRA
        self.target_asset = target_asset
        self.priority = priority  # 0.0 to 1.0
        self.status = status
        self.parent_id = parent_id
        self.children_ids: List[str] = []
        self.evidence: List[str] = []
        self.dead_end_reason: str = ""
        self.recommended_tools: List[str] = recommended_tools or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "title": self.title,
            "category": self.category,
            "target_asset": self.target_asset,
            "priority": self.priority,
            "status": self.status,
            "parent_id": self.parent_id,
            "children_ids": self.children_ids,
            "evidence": self.evidence,
            "dead_end_reason": self.dead_end_reason,
            "recommended_tools": self.recommended_tools,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackVectorNode:
        node = cls(
            node_id=data["node_id"],
            title=data["title"],
            category=data.get("category", "WEB_EXPLOIT"),
            target_asset=data.get("target_asset", ""),
            priority=data.get("priority", 0.5),
            status=data.get("status", VectorStatus.UNEXPLORED),
            parent_id=data.get("parent_id"),
            recommended_tools=data.get("recommended_tools", []),
        )
        node.children_ids = data.get("children_ids", [])
        node.evidence = data.get("evidence", [])
        node.dead_end_reason = data.get("dead_end_reason", "")
        return node


class BacktrackEvent:
    """Records an autonomous backtracking decision."""

    def __init__(
        self,
        abandoned_node_id: str,
        reason: str,
        next_node_id: str,
        next_node_title: str,
        recommended_tools: List[str],
    ) -> None:
        self.abandoned_node_id = abandoned_node_id
        self.reason = reason
        self.next_node_id = next_node_id
        self.next_node_title = next_node_title
        self.recommended_tools = recommended_tools

    @property
    def guidance_message(self) -> str:
        tools_str = ", ".join(f"`{t}`" for t in self.recommended_tools) if self.recommended_tools else "công cụ phù hợp"
        return (
            f"[🔀 TREE-OF-THOUGHT BACKTRACK]: Nhánh `{self.abandoned_node_id}` đã bế tắc ({self.reason}). "
            f"Tự động QUAY LUI (Backtrack) sang nhánh tiềm năng cao hơn: "
            f"`{self.next_node_id}` ({self.next_node_title}). Gợi ý triển khai: {tools_str}."
        )


class TreeOfThoughtEngine:
    """Manages the attack vector tree and coordinates autonomous backtracking."""

    def __init__(self, target: str = "") -> None:
        self.target = target
        self.nodes: Dict[str, AttackVectorNode] = {}
        self.active_node_id: Optional[str] = None
        self.backtrack_history: List[BacktrackEvent] = []

    def add_node(self, node: AttackVectorNode) -> None:
        """Add a vector node to the tree."""
        self.nodes[node.node_id] = node
        if node.parent_id and node.parent_id in self.nodes:
            if node.node_id not in self.nodes[node.parent_id].children_ids:
                self.nodes[node.parent_id].children_ids.append(node.node_id)

    def seed_from_target_and_tech(
        self,
        target: str,
        tech_stack: Optional[List[str]] = None,
        open_ports: Optional[List[int]] = None,
    ) -> None:
        """Seed high-probability attack vectors based on initial target profile."""
        self.target = target
        techs = [t.lower() for t in (tech_stack or [])]
        ports = open_ports or [80, 443]

        # 1. Base Recon Vector
        self.add_node(AttackVectorNode(
            node_id="VEC-RECON-SURFACE",
            title="Comprehensive Surface Discovery & Tech Fingerprinting",
            category="RECON",
            target_asset=target,
            priority=0.95,
            status=VectorStatus.ACTIVE,
            recommended_tools=["docker_crawl_web", "docker_whatweb", "docker_http_headers_audit"],
        ))
        self.active_node_id = "VEC-RECON-SURFACE"

        # 2. Web Vulnerability Vectors
        self.add_node(AttackVectorNode(
            node_id="VEC-WEB-SQLI",
            title="Database Injection (SQLi) on Input Parameters",
            category="WEB_EXPLOIT",
            target_asset=target,
            priority=0.85,
            status=VectorStatus.UNEXPLORED,
            recommended_tools=["docker_sqlmap_scan"],
        ))
        self.add_node(AttackVectorNode(
            node_id="VEC-WEB-XSS",
            title="Cross-Site Scripting (XSS) on Parameter Reflection",
            category="WEB_EXPLOIT",
            target_asset=target,
            priority=0.75,
            status=VectorStatus.UNEXPLORED,
            recommended_tools=["docker_xss_scan"],
        ))
        self.add_node(AttackVectorNode(
            node_id="VEC-WEB-SENSITIVE",
            title="Exposed Sensitive Files (.git, .env, backups)",
            category="WEB_EXPLOIT",
            target_asset=target,
            priority=0.88,
            status=VectorStatus.UNEXPLORED,
            recommended_tools=["docker_sensitive_files_scan", "docker_dirb_scan"],
        ))

        # 3. Technology-Specific Vectors
        if any("wordpress" in t for t in techs):
            self.add_node(AttackVectorNode(
                node_id="VEC-CMS-WORDPRESS",
                title="WordPress Core, Plugins & User Enumeration",
                category="WEB_EXPLOIT",
                target_asset=target,
                priority=0.92,
                status=VectorStatus.UNEXPLORED,
                recommended_tools=["docker_wpscan", "docker_nuclei_scan"],
            ))
        if any("spring" in t for t in techs):
            self.add_node(AttackVectorNode(
                node_id="VEC-API-SPRING-ACTUATOR",
                title="Spring Boot Actuator & Remote Code Execution",
                category="API_EXPLOIT",
                target_asset=target,
                priority=0.90,
                status=VectorStatus.UNEXPLORED,
                recommended_tools=["docker_ffuf", "docker_nuclei_scan"],
            ))
        if any("php" in t for t in techs):
            self.add_node(AttackVectorNode(
                node_id="VEC-WEB-PHP-ENDPOINTS",
                title="PHP Endpoint Enumeration & Configuration Disclosure",
                category="WEB_EXPLOIT",
                target_asset=target,
                priority=0.82,
                status=VectorStatus.UNEXPLORED,
                recommended_tools=["docker_dirb_scan", "docker_ffuf"],
            ))

        # 4. Port/Auth Vectors
        if 22 in ports:
            self.add_node(AttackVectorNode(
                node_id="VEC-AUTH-SSH",
                title="SSH Authentication Credential Audit",
                category="AUTH",
                target_asset=f"{target}:22",
                priority=0.70,
                status=VectorStatus.UNEXPLORED,
                recommended_tools=["docker_bruteforce_ssh"],
            ))

        # 5. General Infrastructure & CVEs
        self.add_node(AttackVectorNode(
            node_id="VEC-INFRA-CVE",
            title="Known Vulnerability & CVE Template Scanning",
            category="INFRA",
            target_asset=target,
            priority=0.80,
            status=VectorStatus.UNEXPLORED,
            recommended_tools=["docker_nuclei_scan"],
        ))

    def get_active_vector(self) -> Optional[AttackVectorNode]:
        """Get the currently active vector node."""
        if self.active_node_id and self.active_node_id in self.nodes:
            return self.nodes[self.active_node_id]
        return None

    def get_best_unexplored_vector(self) -> Optional[AttackVectorNode]:
        """Find the unexplored vector with highest priority."""
        unexplored = [
            n for n in self.nodes.values()
            if n.status == VectorStatus.UNEXPLORED
        ]
        if not unexplored:
            return None
        unexplored.sort(key=lambda n: n.priority, reverse=True)
        return unexplored[0]

    def mark_vector_confirmed(self, node_id: str, evidence: str = "") -> None:
        """Mark a vector as confirmed vulnerable."""
        if node_id in self.nodes:
            self.nodes[node_id].status = VectorStatus.CONFIRMED_VULNERABLE
            if evidence:
                self.nodes[node_id].evidence.append(evidence)

    def mark_vector_dead_end(self, node_id: str, reason: str = "") -> None:
        """Mark a vector as dead end / exhausted."""
        if node_id in self.nodes:
            self.nodes[node_id].status = VectorStatus.DEAD_END
            self.nodes[node_id].dead_end_reason = reason

    def trigger_backtrack(self, abandoned_node_id: str, reason: str) -> Optional[BacktrackEvent]:
        """Autonomous Backtracking: Prune dead-end branch and pivot to best unexplored vector."""
        self.mark_vector_dead_end(abandoned_node_id, reason)

        next_vector = self.get_best_unexplored_vector()
        if not next_vector:
            logger.info("ToT: All attack vectors in hypothesis tree exhausted.")
            return None

        # Pivot to next vector
        next_vector.status = VectorStatus.ACTIVE
        self.active_node_id = next_vector.node_id

        event = BacktrackEvent(
            abandoned_node_id=abandoned_node_id,
            reason=reason,
            next_node_id=next_vector.node_id,
            next_node_title=next_vector.title,
            recommended_tools=next_vector.recommended_tools,
        )
        self.backtrack_history.append(event)
        return event

    def format_tot_block(self) -> str:
        """Generate structured Tree-of-Thought status for prompt injection."""
        lines = [
            "# 🔀 CÂY SUY LUẬN CHIẾN THUẬT (TREE-OF-THOUGHT HYPOTHESIS TREE):",
        ]

        active = self.get_active_vector()
        if active:
            rec_str = ", ".join(f"`{t}`" for t in active.recommended_tools) if active.recommended_tools else "tự chọn"
            lines.append(f"• **Nhánh Đang Khai Thác (Active Branch)**: `[{active.node_id}]` {active.title}")
            lines.append(f"  - Mục tiêu: `{active.target_asset}` | Ưu tiên: {active.priority * 100:.0f}% | Gợi ý: {rec_str}")

        # Show status breakdown
        confirmed = [n for n in self.nodes.values() if n.status == VectorStatus.CONFIRMED_VULNERABLE]
        dead_ends = [n for n in self.nodes.values() if n.status == VectorStatus.DEAD_END]
        unexplored = [n for n in self.nodes.values() if n.status == VectorStatus.UNEXPLORED]

        if confirmed:
            lines.append(f"• **Đã Xác Nhận Đột Phá ({len(confirmed)})**: " + ", ".join(f"`{n.node_id}`" for n in confirmed))
        if dead_ends:
            lines.append(f"• **Đã Bác Bỏ / Bế Tắc ({len(dead_ends)})**: " + ", ".join(f"`{n.node_id}` ({n.dead_end_reason or 'No hit'})" for n in dead_ends[-2:]))
        if unexplored:
            unexplored.sort(key=lambda n: n.priority, reverse=True)
            lines.append(f"• **Nhánh Dự Phòng Khả Thi Tiếp Theo**: " + ", ".join(f"`{n.node_id}` ({n.priority*100:.0f}%)" for n in unexplored[:3]))

        # Include latest backtrack alert if occurred recently
        if self.backtrack_history:
            last_bt = self.backtrack_history[-1]
            lines.append(f"• **Lần Quay Lui Gần Nhất**: {last_bt.guidance_message}")

        return "\n".join(lines)
