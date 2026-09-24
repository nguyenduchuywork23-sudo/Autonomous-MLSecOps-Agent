"""
Multi-Persona Deliberative Cognitive Council
============================================
Inspired by Claude Opus Tri-Council Multi-Agent Deliberation.

Simulates an internal council of elite specialists to synthesize complex tactical decisions:
1. Offensive Architect: Formulates multi-hop penetration kill-chains.
2. Cryptographer & Protocol Analyst: Analyzes authentication, tokens, and encryption.
3. OpSec & Anti-Detection Director: Manages evasion, traffic shaping, and tripwires.
4. Executive Arbiter (CSO): Synthesizes competing advice into a decisive operational order.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from src.client.report_state import ReportState

logger = logging.getLogger(__name__)


@dataclass
class CouncilDeliberation:
    """Structured synthesis from the Deliberative Cognitive Council."""
    offensive_view: str
    crypto_view: str
    opsec_view: str
    executive_directive: str
    priority_tool: str
    confidence: float

    def format_block(self) -> str:
        """Format council deliberation into an authoritative prompt block."""
        return (
            "# 🏛️ HỘI ĐỒNG CHIẾN LƯỢC TỐI CAO (COGNITIVE COUNCIL - OPUS TIER):\n"
            f"• ⚔️ **Offensive Architect (Chuyên Gia Tấn Công)**: {self.offensive_view}\n"
            f"• 🔐 **Cryptographer (Chuyên Gia Mật Mã & Auth)**: {self.crypto_view}\n"
            f"• 🛡️ **OpSec Director (Chuyên Gia Ẩn Mình & WAF)**: {self.opsec_view}\n"
            f"• 🎖️ **CHỈ THỊ QUYẾT ĐỊNH CỦA TỔNG TƯ LỆNH (EXECUTIVE DIRECTIVE)**:\n"
            f"  ➔ `{self.executive_directive}` (Độ tin cậy: {self.confidence * 100:.0f}%, Gợi ý ưu tiên: `{self.priority_tool}`)"
        )


class CognitiveCouncil:
    """Coordinates multi-persona deliberation for complex security assessments."""

    @classmethod
    def deliberate(
        cls,
        report_state: ReportState,
        active_vector_title: str = "",
        detected_waf: str = "",
        harvested_creds_count: int = 0,
        harvested_tokens_count: int = 0,
        iteration: int = 1,
    ) -> CouncilDeliberation:
        """
        Synthesize multi-persona perspective based on target state.
        """
        findings = report_state.findings
        techs = list(report_state.attack_surface.detected_technologies)
        open_ports = list(getattr(report_state.attack_surface, "open_ports", []))

        # 1. Offensive Architect View
        if harvested_creds_count > 0:
            off_view = f"Đã thu thập được {harvested_creds_count} thông tin xác thực. Lập tức leo thang qua SSH hoặc Login Portal để chiếm quyền kiểm soát máy chủ."
            prio_tool = "docker_bruteforce_ssh"
        elif any(f.severity in ("CRITICAL", "HIGH") for f in findings):
            off_view = f"Đã phát hiện lỗ hổng nghiêm trọng ({len(findings)} phát hiện). Tập trung khai thác sâu để chứng minh tác động RCE/Data Breach."
            prio_tool = "docker_sqlmap_scan"
        elif len(open_ports) > 0 and len(techs) == 0:
            off_view = "Bề mặt mở nhưng chưa rõ công nghệ. Cần fingerprint sâu bằng whatweb và nuclei."
            prio_tool = "docker_whatweb"
        else:
            off_view = f"Mục tiêu đang mở {len(open_ports)} cổng. Đang khai thác nhánh: '{active_vector_title or 'Tổng quát'}'."
            prio_tool = "docker_crawl_web"

        # 2. Cryptographer View
        if harvested_tokens_count > 0:
            crypto_view = f"Phát hiện {harvested_tokens_count} Token/JWT. Cần kiểm tra thuật toán 'none' hoặc giải mã payload để leo thang đặc quyền API."
        elif 443 in open_ports or 8443 in open_ports:
            crypto_view = "HTTPS kích hoạt. Khuyến nghị kiểm tra cấu hình mã hóa SSL/TLS và chứng chỉ bằng testssl/ssl_cert_audit."
        else:
            crypto_view = "Giao thức truyền rõ (HTTP/Plaintext). Mọi dữ liệu và cookie không có cờ Secure đều dễ bị đánh chặn."

        # 3. OpSec Director View
        if detected_waf:
            opsec_view = f"CẢNH BÁO WAF: Phát hiện '{detected_waf.upper()}'. Bắt buộc giãn cách request, dùng User-Agent Chrome và áp dụng payload tamper."
        else:
            opsec_view = "Chưa phát hiện WAF chủ động. Có thể tăng tốc độ quét và fuzzing ở mức độ kiểm soát."

        # 4. Executive Arbiter Directive
        if harvested_creds_count > 0:
            exec_dir = "HÀNH ĐỘNG KHẨN CẤP: Chuyển hướng toàn lực xác thực thông tin đăng nhập đã thu thập vào các cổng dịch vụ."
            conf = 0.98
        elif detected_waf:
            exec_dir = "TÁC CHIẾN ẨN MÌNH: Ưu tiên khai thác API hoặc dùng payload đột biến (tamper) để xuyên thủng rào cản phòng thủ."
            conf = 0.92
        elif len(findings) > 0:
            exec_dir = "TIẾN CÔNG MỤC TIÊU: Tiếp tục chuỗi Kill-Chain khai thác các điểm yếu đã xác thực trên báo cáo."
            conf = 0.90
        else:
            exec_dir = "TRINH SÁT BỀ MẶT: Hoàn thành rà quét toàn diện các endpoint tham số để tìm lỗ hổng sơ hở đầu tiên."
            conf = 0.85

        return CouncilDeliberation(
            offensive_view=off_view,
            crypto_view=crypto_view,
            opsec_view=opsec_view,
            executive_directive=exec_dir,
            priority_tool=prio_tool,
            confidence=conf,
        )
