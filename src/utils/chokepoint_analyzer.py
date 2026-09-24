"""Critical Chokepoint & Attack Path Graph Interdiction Engine.

Solves the Network Attack Interdiction Problem on Bayesian Attack Graphs to identify
the minimal set of critical defense interventions (Tử Huyệt Phòng Thủ) that
maximize organizational breach risk reduction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from src.utils.attack_graph import BayesianAttackGraph, AttackPath, AttackEdge

logger = logging.getLogger(__name__)


@dataclass
class ChokepointCandidate:
    """A critical node or edge where an intervention neutralizes the maximum attack paths."""

    element_type: str  # "EDGE" or "NODE"
    element_id: str
    target_crown_jewel: str
    paths_severed_count: int
    breach_reduction_pct: float
    recommended_action: str
    finding_title: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "element_type": self.element_type,
            "element_id": self.element_id,
            "target_crown_jewel": self.target_crown_jewel,
            "paths_severed_count": self.paths_severed_count,
            "breach_reduction_pct": self.breach_reduction_pct,
            "recommended_action": self.recommended_action,
            "finding_title": self.finding_title,
        }


@dataclass
class ChokepointReport:
    """Executive and technical report on optimal defense interdiction."""

    chokepoints: list[ChokepointCandidate]
    total_attack_paths_count: int
    baseline_risk_score: float
    residual_risk_score: float
    risk_reduction_pct: float
    executive_rationale: str

    def format_block(self) -> str:
        """Format an authoritative chokepoint defense directive."""
        lines = [
            "🎯 [CHIẾN LƯỢC CAN THIỆP ĐIỂM NGHẼN TRỌNG YẾU (DEFENSE CHOKEPOINT MATRIX)]",
            f"• Tổng số chuỗi tấn công khả thi tới Crown Jewels: {self.total_attack_paths_count}",
            f"• Mức độ rủi ro ban đầu (Baseline Risk): {self.baseline_risk_score:.1f}/100",
            f"• Mức độ rủi ro sau can thiệp (Residual Risk): {self.residual_risk_score:.1f}/100 "
            f"(Triệt tiêu {self.risk_reduction_pct:.1f}% nguy cơ)",
            "• Danh sách Tử Huyệt Phòng Thủ cần ưu tiên can thiệp ngay lập tức:",
        ]

        for i, cp in enumerate(self.chokepoints[:3], start=1):
            lines.append(
                f"  {i}. [{cp.element_type}] `{cp.element_id}` ➔ Đích: `{cp.target_crown_jewel}`\n"
                f"     - Cắt đứt: {cp.paths_severed_count} chuỗi tấn công (Giảm {cp.breach_reduction_pct:.1f}% nguy cơ)\n"
                f"     - Biện pháp can thiệp: {cp.recommended_action}"
            )

        lines.append(f"• Cơ sở lý luận: {self.executive_rationale}")
        return "\n".join(lines)


class ChokepointAnalyzer:
    """Calculates graph cuts and interdiction metrics on Bayesian Attack Graphs."""

    def analyze(self, attack_graph: BayesianAttackGraph) -> ChokepointReport:
        """Compute optimal chokepoints and risk reduction factors."""
        all_paths: list[AttackPath] = attack_graph.find_all_attack_paths()

        if not all_paths:
            return ChokepointReport(
                chokepoints=[],
                total_attack_paths_count=0,
                baseline_risk_score=0.0,
                residual_risk_score=0.0,
                risk_reduction_pct=0.0,
                executive_rationale="Không phát hiện chuỗi tấn công khả thi tới Crown Jewels.",
            )

        # Baseline risk: Combined probability of at least one path succeeding
        # Risk = 1 - product(1 - P(path_i))
        fail_prob = 1.0
        for p in all_paths:
            fail_prob *= (1.0 - min(0.99, max(0.01, p.cumulative_probability)))
        baseline_breach_prob = 1.0 - fail_prob
        baseline_risk_score = min(100.0, baseline_breach_prob * 100.0)

        # Analyze Edge Cuts: Which single edge severance breaks the most critical paths?
        edge_severed_counts: dict[str, int] = {}
        edge_objects: dict[str, AttackEdge] = {}
        edge_target_jewel: dict[str, str] = {}

        for p in all_paths:
            for e in p.edges:
                key = f"{e.source} ➔ {e.target}"
                edge_severed_counts[key] = edge_severed_counts.get(key, 0) + 1
                edge_objects[key] = e
                edge_target_jewel[key] = p.target_crown_jewel

        chokepoint_candidates: list[ChokepointCandidate] = []

        for edge_key, count in edge_severed_counts.items():
            edge_obj = edge_objects[edge_key]
            # Calculate residual breach probability if this edge is completely severed
            res_fail_prob = 1.0
            for p in all_paths:
                # If path uses this edge, it is severed (cannot succeed)
                if any(f"{pe.source} ➔ {pe.target}" == edge_key for pe in p.edges):
                    continue
                res_fail_prob *= (1.0 - min(0.99, max(0.01, p.cumulative_probability)))

            residual_breach_prob = 1.0 - res_fail_prob
            residual_risk = min(100.0, residual_breach_prob * 100.0)

            reduction = max(0.0, (baseline_risk_score - residual_risk))
            reduction_pct = (reduction / max(0.01, baseline_risk_score)) * 100.0

            action = self._determine_remediation_action(edge_obj)

            chokepoint_candidates.append(
                ChokepointCandidate(
                    element_type="EDGE",
                    element_id=edge_key,
                    target_crown_jewel=edge_target_jewel[edge_key],
                    paths_severed_count=count,
                    breach_reduction_pct=round(reduction_pct, 1),
                    recommended_action=action,
                    finding_title=edge_obj.finding_title,
                )
            )

        # Sort candidates by breach reduction percentage and severed paths
        chokepoint_candidates.sort(key=lambda c: (c.breach_reduction_pct, c.paths_severed_count), reverse=True)

        top_candidates = chokepoint_candidates[:3]
        top_cut_reduction = top_candidates[0].breach_reduction_pct if top_candidates else 0.0
        final_residual_score = max(0.0, baseline_risk_score * (1.0 - top_cut_reduction / 100.0))

        rationale = (
            f"Triển khai vá lỗi hoặc thiết lập luật tường lửa WAF tại điểm nghẽn "
            f"'{top_candidates[0].element_id}' sẽ vô hiệu hóa {top_candidates[0].paths_severed_count}/{len(all_paths)} "
            f"chuỗi tấn công trực diện vào {top_candidates[0].target_crown_jewel}."
            if top_candidates
            else "Cấu trúc đồ thị phòng thủ ổn định."
        )

        return ChokepointReport(
            chokepoints=top_candidates,
            total_attack_paths_count=len(all_paths),
            baseline_risk_score=round(baseline_risk_score, 1),
            residual_risk_score=round(final_residual_score, 1),
            risk_reduction_pct=round(top_cut_reduction, 1),
            executive_rationale=rationale,
        )

    def _determine_remediation_action(self, edge: AttackEdge) -> str:
        """Map edge finding to a high-impact engineering intervention."""
        title_lower = edge.finding_title.lower()
        if "sql" in title_lower or "sqli" in title_lower:
            return "Áp dụng Prepared Statements và bật Rule WAF ModSecurity 942100"
        if "rce" in title_lower or "command" in title_lower:
            return "Vô hiệu hóa shell=True, chuyển sang subprocess argument vector an toàn"
        if "ssh" in title_lower or "brute" in title_lower:
            return "Khóa xác thực mật khẩu SSH, chuyển sang SSH Ed25519 Keys và bật Fail2ban"
        if "xss" in title_lower:
            return "Kích hoạt Content-Security-Policy (CSP) và mã hóa ký tự HTML Entity"
        if "sensitive" in title_lower or ".env" in title_lower:
            return "Chặn truy cập thư mục gốc qua Nginx location block và thu hồi credentials bị rò rỉ"
        return "Triển khai bản vá mã nguồn và hạn chế quyền truy cập tối thiểu (Least Privilege)"
