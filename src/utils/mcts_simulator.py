"""Monte Carlo Tree Search (MCTS) Cyber Lookahead Simulator.

Simulates multi-step cyber reconnaissance, scanning, and exploitation sequences
to evaluate future information gain, detection risks, and vulnerability yield
before taking high-stakes actions in the ReAct loop.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class MCTSNode:
    """Represents an operational decision state in the MCTS tree."""

    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    parent: Optional[MCTSNode] = None
    children: list[MCTSNode] = field(default_factory=list)
    visits: int = 0
    total_reward: float = 0.0
    prior_prob: float = 1.0

    @property
    def value(self) -> float:
        """Average reward for this node."""
        return self.total_reward / max(1, self.visits)

    def uct_score(self, c_param: float = 1.414) -> float:
        """Calculate Upper Confidence Bound for Trees (UCT)."""
        if self.parent is None or self.parent.visits == 0:
            return self.value
        exploitation = self.value
        exploration = (
            c_param
            * self.prior_prob
            * math.sqrt(math.log(self.parent.visits) / (1 + self.visits))
        )
        return exploitation + exploration

    def best_child(self, c_param: float = 1.414) -> Optional[MCTSNode]:
        """Select child with highest UCT score."""
        if not self.children:
            return None
        return max(self.children, key=lambda child: child.uct_score(c_param))


@dataclass
class MCTSSimulationResult:
    """Result of an MCTS Cyber Lookahead Simulation."""

    best_tool: str
    best_arguments: dict[str, Any]
    projected_sequence: list[str]
    expected_gain: float
    stealth_risk: float
    lookahead_depth: int
    rationale: str

    def format_block(self) -> str:
        """Format tactical lookahead guidance for the ReAct orchestrator."""
        seq_str = " ➔ ".join(f"`{t}`" for t in self.projected_sequence)
        risk_pct = int(self.stealth_risk * 100)
        risk_tag = "AN TOÀN" if self.stealth_risk < 0.3 else ("TRUNG BÌNH" if self.stealth_risk < 0.6 else "BÁO ĐỘNG")

        return (
            f"🎲 [BỘ MÔ PHỎNG CHIẾN THUẬT MCTS LOOKAHEAD (ĐỘ SÂU: {self.lookahead_depth})]\n"
            f"• Lệnh tối ưu tức thì: `{self.best_tool}` (Điểm kỳ vọng: {self.expected_gain:.2f})\n"
            f"• Chuỗi bước tối ưu dự phóng: {seq_str}\n"
            f"• Mức độ rủi ro lộ diện (OpSec Risk): {risk_pct}% [{risk_tag}]\n"
            f"• Cơ sở suy luận: {self.rationale}\n"
            f"➔ HÃY ƯU TIÊN SỬ DỤNG HOẶC PHỐI HỢP CÔNG CỤ TRÊN ĐỂ ĐẠT HIỆU QUẢ CAO NHẤT."
        )


class MCTSCyberSimulator:
    """Monte Carlo Tree Search simulator for autonomous cyber operations."""

    # Base tool categories & operational characteristics
    TOOL_PROFILES = {
        # Reconnaissance
        "docker_whatweb": {"category": "recon", "gain": 3.5, "noise": 0.1, "cost": 0.1},
        "docker_httpx": {"category": "recon", "gain": 3.2, "noise": 0.1, "cost": 0.1},
        "docker_crawl_web": {"category": "recon", "gain": 3.8, "noise": 0.2, "cost": 0.2},
        "docker_api_docs": {"category": "recon", "gain": 4.0, "noise": 0.1, "cost": 0.1},
        "docker_resolve_dns": {"category": "recon", "gain": 1.2, "noise": 0.05, "cost": 0.05},
        "docker_subfinder": {"category": "recon", "gain": 2.0, "noise": 0.1, "cost": 0.15},
        "docker_testssl": {"category": "recon", "gain": 1.8, "noise": 0.1, "cost": 0.2},
        # Web Vulnerability Scanning
        "docker_nuclei_scan": {"category": "scan", "gain": 5.5, "noise": 0.35, "cost": 0.4},
        "docker_nikto_scan": {"category": "scan", "gain": 4.0, "noise": 0.5, "cost": 0.5},
        "docker_ffuf_scan": {"category": "fuzz", "gain": 4.5, "noise": 0.6, "cost": 0.4},
        "docker_xss_scan": {"category": "scan", "gain": 3.8, "noise": 0.4, "cost": 0.3},
        "docker_cors_scan": {"category": "scan", "gain": 2.5, "noise": 0.2, "cost": 0.2},
        # Exploitation & Verification
        "docker_sqlmap_scan": {"category": "exploit", "gain": 6.5, "noise": 0.75, "cost": 0.6},
        "docker_sqlmap_dump": {"category": "exploit", "gain": 7.0, "noise": 0.85, "cost": 0.7},
        "docker_wpscan": {"category": "scan", "gain": 4.5, "noise": 0.45, "cost": 0.4},
        "bruteforce_ssh": {"category": "exploit", "gain": 5.0, "noise": 0.8, "cost": 0.6},
        "docker_bruteforce": {"category": "exploit", "gain": 4.5, "noise": 0.8, "cost": 0.6},
        "docker_hydra_attack": {"category": "exploit", "gain": 4.0, "noise": 0.85, "cost": 0.7},
        "docker_msf_search": {"category": "intel", "gain": 3.0, "noise": 0.05, "cost": 0.1},
        "final_answer": {"category": "terminal", "gain": 0.0, "noise": 0.0, "cost": 0.0},
    }

    def __init__(self, exploration_weight: float = 1.414, rng_seed: Optional[int] = 42) -> None:
        self.c_param = exploration_weight
        self.rng = random.Random(rng_seed)

    def simulate(
        self,
        available_tools: list[str],
        current_state: dict[str, Any],
        num_simulations: int = 40,
        max_depth: int = 3,
    ) -> MCTSSimulationResult:
        """Run MCTS simulations to find the highest value path."""
        valid_tools = [t for t in available_tools if t in self.TOOL_PROFILES and t != "final_answer"]
        if not valid_tools:
            valid_tools = available_tools if available_tools else ["docker_httpx"]

        root = MCTSNode(tool_name="root")
        for tool in valid_tools:
            prior = self._compute_prior(tool, current_state)
            child = MCTSNode(
                tool_name=tool,
                arguments=self._default_args_for_tool(tool, current_state),
                parent=root,
                prior_prob=prior,
            )
            root.children.append(child)

        # Execute MCTS Rollouts
        for _ in range(num_simulations):
            # 1. Selection
            node = self._select(root)
            # 2. Expansion
            if node != root and not node.children:
                depth = self._get_depth(node)
                if depth < max_depth:
                    self._expand(node, valid_tools, current_state)
                    if node.children:
                        node = self.rng.choice(node.children)

            # 3. Simulation (Rollout)
            rollout_reward = self._rollout(node, valid_tools, current_state, max_depth)

            # 4. Backpropagation
            self._backpropagate(node, rollout_reward)

        # Select best immediate action based on visit count and value
        best_child = max(root.children, key=lambda c: (c.visits, c.value))

        # Reconstruct projected optimal path
        projected = [best_child.tool_name]
        curr = best_child
        for _ in range(max_depth - 1):
            if not curr.children:
                break
            curr = max(curr.children, key=lambda c: (c.visits, c.value))
            projected.append(curr.tool_name)

        stealth_risk = self._evaluate_sequence_risk(projected, current_state)
        rationale = self._generate_rationale(best_child.tool_name, projected, current_state)

        return MCTSSimulationResult(
            best_tool=best_child.tool_name,
            best_arguments=best_child.arguments,
            projected_sequence=projected,
            expected_gain=best_child.value,
            stealth_risk=stealth_risk,
            lookahead_depth=len(projected),
            rationale=rationale,
        )

    def _select(self, node: MCTSNode) -> MCTSNode:
        """Traverse down the tree using UCT selection."""
        curr = node
        while curr.children:
            unvisited = [c for c in curr.children if c.visits == 0]
            if unvisited:
                return self.rng.choice(unvisited)
            best = curr.best_child(self.c_param)
            if best is None:
                break
            curr = best
        return curr

    def _expand(self, node: MCTSNode, valid_tools: list[str], state: dict[str, Any]) -> None:
        """Expand node by generating child candidate actions."""
        candidates = [t for t in valid_tools if t != node.tool_name]
        if not candidates:
            candidates = valid_tools

        for t in candidates:
            prior = self._compute_prior(t, state)
            child = MCTSNode(
                tool_name=t,
                arguments=self._default_args_for_tool(t, state),
                parent=node,
                prior_prob=prior,
            )
            node.children.append(child)

    def _rollout(
        self,
        node: MCTSNode,
        valid_tools: list[str],
        state: dict[str, Any],
        max_depth: int,
    ) -> float:
        """Stochastic heuristic rollout for lookahead evaluation."""
        total_eval = self._evaluate_step(node.tool_name, state)
        depth = self._get_depth(node)
        sim_tool = node.tool_name

        simulated_state = dict(state)
        for _ in range(depth, max_depth):
            candidates = [t for t in valid_tools if t != sim_tool]
            if not candidates:
                candidates = valid_tools
            sim_tool = self.rng.choice(candidates)
            step_eval = self._evaluate_step(sim_tool, simulated_state)
            total_eval += step_eval * 0.8

        return total_eval

    def _backpropagate(self, node: MCTSNode, reward: float) -> None:
        """Backpropagate simulation rewards up the tree."""
        curr: Optional[MCTSNode] = node
        while curr is not None:
            curr.visits += 1
            curr.total_reward += reward
            curr = curr.parent

    def _evaluate_step(self, tool_name: str, state: dict[str, Any]) -> float:
        """Evaluate expected reward of executing tool given the operational state."""
        open_ports = state.get("open_ports", [])
        waf = state.get("active_waf", None)
        creds = state.get("harvested_creds", [])
        tech = state.get("detected_tech", [])
        executed = state.get("executed_tools", [])

        # Hard prerequisites:
        if tool_name in ("bruteforce_ssh", "docker_bruteforce") and 22 not in open_ports:
            return 0.05
        if tool_name in ("docker_sqlmap_scan", "docker_sqlmap_dump", "docker_xss_scan") and not (80 in open_ports or 443 in open_ports or 8080 in open_ports):
            return 0.05
        if tool_name == "docker_hydra_attack" and not any(p in open_ports for p in (21, 22, 3306, 5432, 1433, 80, 443)):
            return 0.05

        profile = self.TOOL_PROFILES.get(tool_name, {"gain": 2.0, "noise": 0.3, "cost": 0.2})
        base_gain = profile["gain"]
        noise = profile["noise"]
        cost = profile["cost"]

        reward = base_gain - cost

        repeat_count = executed.count(tool_name)
        if repeat_count > 0:
            reward -= (repeat_count * 1.5)

        # Context-aware synergy bonuses
        if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
            if tool_name in ("docker_whatweb", "docker_httpx", "docker_crawl_web", "docker_api_docs"):
                reward += 3.0
            if tool_name in ("docker_nuclei_scan", "docker_ffuf_scan"):
                reward += 3.5

        tech_str = " ".join(tech).lower()
        if "wordpress" in tech_str and tool_name == "docker_wpscan":
            reward += 6.0
        if ("swagger" in tech_str or "openapi" in tech_str or "rest" in tech_str) and tool_name == "docker_api_docs":
            reward += 5.0

        if 22 in open_ports and tool_name in ("bruteforce_ssh", "docker_bruteforce"):
            reward += 2.0
            if creds:
                reward += 8.0  # Harvested credentials create high-confidence attack path!

        # Heavy OpSec penalty for loud tools under active WAF
        if waf and waf != "None":
            if noise >= 0.4:
                reward -= (noise * 8.0)

        return max(0.05, reward)

    def _compute_prior(self, tool_name: str, state: dict[str, Any]) -> float:
        """Compute heuristic prior probability P(a|s) for tree expansion."""
        open_ports = state.get("open_ports", [])
        waf = state.get("active_waf", None)
        creds = state.get("harvested_creds", [])
        profile = self.TOOL_PROFILES.get(tool_name, {"gain": 2.0, "noise": 0.3})

        # Disallow tools without open ports
        if tool_name in ("bruteforce_ssh", "docker_bruteforce") and 22 not in open_ports:
            return 0.01
        if tool_name == "docker_hydra_attack" and not any(p in open_ports for p in (21, 22, 3306, 5432)):
            return 0.01

        prior = profile["gain"]

        # Prioritize SSH if creds exist
        if creds and 22 in open_ports and tool_name in ("bruteforce_ssh", "docker_bruteforce"):
            prior += 15.0

        # WAF handling
        if waf and waf != "None":
            if profile["noise"] >= 0.4:
                prior *= 0.05
            else:
                prior += 5.0

        if (80 in open_ports or 443 in open_ports) and profile["category"] in ("recon", "scan"):
            prior += 4.0

        return max(0.01, prior)

    def _evaluate_sequence_risk(self, sequence: list[str], state: dict[str, Any]) -> float:
        """Calculate cumulative detection risk score for a sequence."""
        waf = state.get("active_waf", None)
        total_noise = 0.0
        for t in sequence:
            profile = self.TOOL_PROFILES.get(t, {"noise": 0.3})
            total_noise += profile["noise"]

        avg_noise = total_noise / max(1, len(sequence))
        if waf and waf != "None":
            avg_noise = min(1.0, avg_noise * 1.5)
        return round(avg_noise, 3)

    def _default_args_for_tool(self, tool_name: str, state: dict[str, Any]) -> dict[str, Any]:
        """Generate sensible default arguments based on current state."""
        target = state.get("target", "localhost")
        if tool_name in ("docker_whatweb", "docker_httpx", "docker_crawl_web", "docker_nuclei_scan", "docker_nikto_scan"):
            return {"target": target}
        if tool_name == "docker_api_docs":
            return {"url": target if target.startswith("http") else f"http://{target}"}
        if tool_name in ("docker_sqlmap_scan", "docker_xss_scan"):
            return {"url": target if target.startswith("http") else f"http://{target}"}
        if tool_name in ("bruteforce_ssh", "docker_bruteforce"):
            return {"target": target, "port": 22}
        return {"target": target}

    def _get_depth(self, node: MCTSNode) -> int:
        """Count depth of node from root."""
        d = 0
        curr: Optional[MCTSNode] = node
        while curr is not None and curr.parent is not None:
            d += 1
            curr = curr.parent
        return d

    def _generate_rationale(self, best_tool: str, sequence: list[str], state: dict[str, Any]) -> str:
        """Explain why the lookahead selected this path."""
        waf = state.get("active_waf", None)
        creds = state.get("harvested_creds", [])
        open_ports = state.get("open_ports", [])

        if creds and best_tool in ("bruteforce_ssh", "docker_bruteforce"):
            return f"Phát hiện {len(creds)} tài khoản/khóa bí mật; MCTS đề xuất khai thác xác thực có mục tiêu."
        if waf and waf != "None" and self.TOOL_PROFILES.get(best_tool, {}).get("noise", 0) <= 0.3:
            return f"WAF ({waf}) đang hoạt động; MCTS chọn công cụ thăm dò tàng hình có chỉ số tiếng ồn thấp để tránh bị khóa IP."
        if 80 in open_ports or 443 in open_ports:
            return f"Bề mặt ứng dụng web đã mở; chuỗi {len(sequence)} bước kết hợp trinh sát và quét sâu tối đa hóa diện tích bao phủ."
        return f"MCTS cân bằng giữa độ tăng thông tin và chi phí thực thi tối ưu qua {len(sequence)} bước dự phóng."
