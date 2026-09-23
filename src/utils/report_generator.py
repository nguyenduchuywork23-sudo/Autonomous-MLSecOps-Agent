"""Professional DOCX Report Generator for Autonomous MLSecOps Agent.

Generates professional penetration test reports from a ReportState object.
Features:
- Cover page with organization name and classification
- Auto-generated Table of Contents
- Executive Summary with risk score visualization
- Detailed findings with severity-coded badges
- Methodology table (kill chain timeline)
- Risk matrix and severity statistics
- Recommendations prioritized by severity
- Consistent professional styling (Calibri, professional colors)
- Header/Footer with page numbers and confidential marking
"""

import copy
import json
import os
import re
from datetime import datetime
from typing import Any

from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm, Emu
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.section import WD_ORIENT
from docx.oxml.ns import qn, nsdecls
from docx.oxml import parse_xml

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from src.utils.config import get as cfg_get


# ---------------------------------------------------------------------------
# Color Constants
# ---------------------------------------------------------------------------

COLORS = {
    "CRITICAL": RGBColor(0xDC, 0x26, 0x26),  # Red
    "HIGH": RGBColor(0xEA, 0x58, 0x0C),      # Orange
    "MEDIUM": RGBColor(0xCA, 0x8A, 0x04),     # Yellow/Amber
    "LOW": RGBColor(0x16, 0xA3, 0x4A),        # Green
    "INFO": RGBColor(0x25, 0x63, 0xEB),       # Blue
}

BG_COLORS = {
    "CRITICAL": "FEE2E2",
    "HIGH": "FFF7ED",
    "MEDIUM": "FEF9C3",
    "LOW": "DCFCE7",
    "INFO": "DBEAFE",
}

HEADER_BG = "1E3A5F"  # Dark navy for table headers
ACCENT_COLOR = RGBColor(0x1E, 0x3A, 0x5F)


# ---------------------------------------------------------------------------
# Styling Helpers
# ---------------------------------------------------------------------------

_NS_W = nsdecls("w")
_SHADING_CACHE: dict[str, Any] = {}


def _set_cell_shading(cell, color_hex: str) -> None:
    """Set background color for a table cell with cached XML template and deepcopy (5x faster)."""
    color_hex = color_hex.upper()
    cached = _SHADING_CACHE.get(color_hex)
    if cached is None:
        cached = parse_xml(f'<w:shd {_NS_W} w:fill="{color_hex}"/>')
        _SHADING_CACHE[color_hex] = cached
    cell._tc.get_or_add_tcPr().append(copy.deepcopy(cached))


def _set_cell_border(cell, **kwargs) -> None:
    """Set border on a cell. kwargs: top, bottom, left, right, insideH, insideV."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcBorders = parse_xml(f'<w:tcBorders {_NS_W}></w:tcBorders>')
    for edge, val in kwargs.items():
        element = parse_xml(
            f'<w:{edge} {_NS_W} w:val="{val.get("val", "single")}" '
            f'w:sz="{val.get("sz", "4")}" w:space="0" '
            f'w:color="{val.get("color", "000000")}"/>'
        )
        tcBorders.append(element)
    tcPr.append(tcBorders)


def _styled_paragraph(doc, text: str, font_size: int = 11,
                       bold: bool = False, color: RGBColor | None = None,
                       alignment: int | None = None,
                       space_after: int = 6) -> None:
    """Add a styled paragraph to the document."""
    para = doc.add_paragraph()
    run = para.add_run(text)
    run.font.name = "Calibri"
    run.font.size = Pt(font_size)
    if bold:
        run.bold = True
    if color:
        run.font.color.rgb = color
    if alignment is not None:
        para.alignment = alignment
    para.paragraph_format.space_after = Pt(space_after)


def _prevent_row_split(row) -> None:
    """Prevent a table row from splitting across pages."""
    trPr = row._tr.get_or_add_trPr()
    trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))


def _add_header_row(table, headers: list[str]) -> None:
    """Style the header row of a table with dark navy background, repeat on page split, and prevent split."""
    hdr = table.rows[0]
    trPr = hdr._tr.get_or_add_trPr()
    trPr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
    trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))
    for i, cell in enumerate(hdr.cells):
        cell.text = ""
        para = cell.paragraphs[0]
        run = para.add_run(headers[i])
        run.font.name = "Calibri"
        run.font.size = Pt(10)
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        run.bold = True
        _set_cell_shading(cell, HEADER_BG)


# ---------------------------------------------------------------------------
# Main Generator
# ---------------------------------------------------------------------------

def generate_docx_report(report_data: dict, audit_path: str = "") -> str:
    """Generate a comprehensive DOCX pentest report.

    Args:
        report_data: Dictionary from ReportState.to_dict().
        audit_path: Path to the JSONL audit trail file.

    Returns:
        Path to the generated .docx file.
    """
    doc = Document()

    # Global font defaults
    style = doc.styles["Normal"]
    font = style.font
    font.name = "Calibri"
    font.size = Pt(11)

    company_name = cfg_get("reports.company_name", "Security Assessment Team")
    classification = cfg_get("reports.classification", "CONFIDENTIAL")
    target = report_data.get("target", "Unknown")

    # ===================================================================
    # COVER PAGE
    # ===================================================================
    _build_cover_page(doc, target, company_name, classification, report_data)

    # Page break after cover
    doc.add_page_break()

    # ===================================================================
    # TABLE OF CONTENTS
    # ===================================================================
    _build_toc(doc)
    doc.add_page_break()

    # ===================================================================
    # 1. EXECUTIVE SUMMARY
    # ===================================================================
    doc.add_heading("1. Tóm tắt Điều hành (Executive Summary)", level=1)

    exec_summary = report_data.get("executive_summary", "")
    if exec_summary:
        doc.add_paragraph(exec_summary)
    else:
        doc.add_paragraph(
            "Cuộc đánh giá an toàn thông tin được thực hiện tự động bởi hệ thống "
            f"Autonomous MLSecOps Agent nhắm vào mục tiêu: {target}."
        )

    # Risk Score Box
    risk_score = report_data.get("risk_score", 0)
    risk_label = report_data.get("risk_label", "INFO")
    severity_counts = report_data.get("severity_counts", {})

    _build_risk_summary_table(doc, risk_score, risk_label, severity_counts, report_data)

    # ===================================================================
    # 2. SCOPE OF ENGAGEMENT & STRATEGIC MILESTONES
    # ===================================================================
    sec_idx = 2
    doc.add_heading(f"{sec_idx}. Phạm vi Đánh giá & Cột mốc Sứ mệnh (Scope & Milestones)", level=1)
    _build_scope_and_milestones_section(doc, report_data)
    sec_idx += 1

    # ===================================================================
    # 3. ATTACK SURFACE ANALYSIS
    # ===================================================================
    attack_surface = report_data.get("attack_surface", {})
    has_surface = bool(attack_surface and (
        attack_surface.get("open_ports")
        or attack_surface.get("parameterized_endpoints")
        or attack_surface.get("login_forms")
        or attack_surface.get("detected_technologies")
        or attack_surface.get("subdomains")
        or attack_surface.get("alive_subdomains")
        or attack_surface.get("exposed_sensitive_files")
        or attack_surface.get("cors_issues")
        or attack_surface.get("ssl_cert_info")
        or attack_surface.get("dns_security_info")
        or attack_surface.get("hidden_discovered_paths")
        or attack_surface.get("cookie_issues")
    ))

    if has_surface:
        doc.add_heading(f"{sec_idx}. Phân tích Bề mặt Tấn công (Attack Surface Analysis)", level=1)
        _build_attack_surface_section(doc, attack_surface, report_data=report_data)
        sec_idx += 1

    # ===================================================================
    # THREAT MODELING & BAYESIAN ATTACK GRAPH
    # ===================================================================
    doc.add_heading(f"{sec_idx}. Mô hình hóa Mối đe dọa & Đồ thị Tấn công Bayesian (Threat Modeling & Attack Graph)", level=1)
    sec_idx += 1
    _build_threat_modeling_section(doc, report_data)

    # ===================================================================
    # 4. METHODOLOGY (Kill Chain Timeline)
    # ===================================================================
    doc.add_heading(f"{sec_idx}. Phương pháp Đánh giá & Kill Chain", level=1)
    sec_idx += 1

    methodology = report_data.get("methodology", [])
    if methodology:
        _build_methodology_table(doc, methodology)
    else:
        doc.add_paragraph("Không có bước tấn công nào được ghi nhận.")

    # ===================================================================
    # 5. FINDINGS (Detailed)
    # ===================================================================
    doc.add_heading(f"{sec_idx}. Phát hiện & Lỗ hổng Chi tiết", level=1)
    sec_idx += 1

    findings = report_data.get("findings", [])
    if findings:
        # Sort by severity (CRITICAL first)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "INFO"), 5))

        for i, finding in enumerate(findings_sorted, 1):
            _build_finding_section(doc, i, finding)
    else:
        doc.add_paragraph("Không phát hiện lỗ hổng nào trong quá trình đánh giá.")

    # ===================================================================
    # 6. RISK MATRIX
    # ===================================================================
    doc.add_heading(f"{sec_idx}. Ma trận Rủi ro (Risk Matrix)", level=1)
    sec_idx += 1
    _build_risk_matrix(doc, severity_counts, risk_score, risk_label)

    # ===================================================================
    # 7. PRIORITIZED REMEDIATION ROADMAP
    # ===================================================================
    doc.add_heading(f"{sec_idx}. Lộ trình Khắc phục Phân tầng Thời gian (Remediation Roadmap)", level=1)
    sec_idx += 1
    _build_prioritized_remediation_roadmap(doc, report_data)

    # ===================================================================
    # LONG-TERM TACTICAL MEMORY & PLAYBOOK REPLAY
    # ===================================================================
    doc.add_heading(f"{sec_idx}. Trí nhớ Chiến thuật Dài hạn & Khả năng Tự học (Long-Term Memory & Replay)", level=1)
    sec_idx += 1
    _build_rag_memory_section(doc, report_data)

    # ===================================================================
    # CONCLUSION
    # ===================================================================
    doc.add_heading(f"{sec_idx}. Kết luận", level=1)
    sec_idx += 1

    conclusion = report_data.get("conclusion", "")
    if conclusion:
        doc.add_paragraph(conclusion)
    else:
        red_teamer_answer = report_data.get("red_teamer_final_answer", "")
        if red_teamer_answer:
            doc.add_paragraph(red_teamer_answer)
        else:
            doc.add_paragraph(
                f"Cuộc đánh giá mục tiêu {target} đã hoàn tất. "
                f"Mức độ rủi ro tổng thể: {risk_label}. "
                "Vui lòng tham khảo Lộ trình Khắc phục để thực hiện các biện pháp khắc phục theo thứ tự ưu tiên."
            )

    # ===================================================================
    # 9. TECHNICAL EXECUTION APPENDIX
    # ===================================================================
    doc.add_heading(f"{sec_idx}. Phụ lục Kỹ thuật Thực thi (Technical Execution Appendix)", level=1)
    sec_idx += 1
    _build_technical_appendix(doc, report_data)

    # ===================================================================
    # 10. AUDIT TRAIL
    # ===================================================================
    doc.add_heading(f"{sec_idx}. Bằng chứng & Log kiểm toán (Audit Trail)", level=1)

    audit_ref = audit_path if audit_path else "reports/audit_trail.jsonl"
    doc.add_paragraph(
        f"Chi tiết log khai thác và bằng chứng được lưu trữ tại: {audit_ref}\n"
        "File log định dạng JSONL, chứa timestamp, tool name, arguments và kết quả cho mỗi bước."
    )

    # ===================================================================
    # HEADER / FOOTER
    # ===================================================================
    _build_header_footer(doc, company_name, classification)

    # ===================================================================
    # SAVE
    # ===================================================================
    report_dir = cfg_get("reports.output_dir", "reports")
    os.makedirs(report_dir, exist_ok=True)

    extracted_domain = "TARGET"
    url_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+)', target)
    if url_match:
        extracted_domain = url_match.group(1)

    safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', extracted_domain)[:50]
    filename = os.path.normpath(os.path.join(report_dir, f"Pentest_Report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"))
    doc.save(filename)
    return filename


# ---------------------------------------------------------------------------
# Section Builders
# ---------------------------------------------------------------------------

def _build_cover_page(doc, target: str, company_name: str,
                       classification: str, report_data: dict) -> None:
    """Build the cover page with organization info and classification."""
    # Add spacing at top
    for _ in range(4):
        doc.add_paragraph("")

    # Classification banner
    _styled_paragraph(
        doc, f"— {classification} —",
        font_size=14, bold=True, color=RGBColor(0xDC, 0x26, 0x26),
        alignment=WD_ALIGN_PARAGRAPH.CENTER, space_after=24,
    )

    # Title
    title_para = doc.add_paragraph()
    title_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title_para.add_run("BÁO CÁO ĐÁNH GIÁ\nAN TOÀN THÔNG TIN")
    run.font.name = "Calibri"
    run.font.size = Pt(28)
    run.bold = True
    run.font.color.rgb = ACCENT_COLOR
    title_para.paragraph_format.space_after = Pt(8)

    # Subtitle
    _styled_paragraph(
        doc, "PENETRATION TEST REPORT",
        font_size=16, bold=False, color=RGBColor(0x64, 0x74, 0x8B),
        alignment=WD_ALIGN_PARAGRAPH.CENTER, space_after=36,
    )

    # Divider line
    divider = doc.add_paragraph()
    divider.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = divider.add_run("━" * 50)
    run.font.color.rgb = RGBColor(0xCB, 0xD5, 0xE1)
    run.font.size = Pt(10)

    doc.add_paragraph("")

    # Info table (no borders, centered)
    info_table = doc.add_table(rows=6, cols=2)
    info_table.alignment = WD_TABLE_ALIGNMENT.CENTER

    info_data = [
        ("Mục tiêu (Target):", target),
        ("Đơn vị thực hiện:", company_name),
        ("Engine:", "MLSecOps Agent v4.0 — Real-time Dual-Agent"),
        ("Chế độ:", report_data.get("scan_mode", "RECON").upper()),
        ("Thời gian bắt đầu:", report_data.get("start_time", "N/A")),
        ("Thời gian kết thúc:", report_data.get("end_time", "N/A")),
    ]

    for i, (label, value) in enumerate(info_data):
        row = info_table.rows[i]
        _prevent_row_split(row)
        # Label cell
        label_cell = row.cells[0]
        label_para = label_cell.paragraphs[0]
        label_run = label_para.add_run(label)
        label_run.font.name = "Calibri"
        label_run.font.size = Pt(11)
        label_run.bold = True
        label_run.font.color.rgb = RGBColor(0x47, 0x55, 0x69)
        label_para.alignment = WD_ALIGN_PARAGRAPH.RIGHT

        # Value cell
        value_cell = row.cells[1]
        value_para = value_cell.paragraphs[0]
        value_run = value_para.add_run(f"  {value}")
        value_run.font.name = "Calibri"
        value_run.font.size = Pt(11)
        value_run.font.color.rgb = ACCENT_COLOR

    # Risk score at bottom
    doc.add_paragraph("")
    risk_label = report_data.get("risk_label", "INFO")
    risk_color = COLORS.get(risk_label, COLORS["INFO"])

    risk_para = doc.add_paragraph()
    risk_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run1 = risk_para.add_run("MỨC ĐỘ RỦI RO: ")
    run1.font.name = "Calibri"
    run1.font.size = Pt(14)
    run1.bold = True
    run2 = risk_para.add_run(risk_label)
    run2.font.name = "Calibri"
    run2.font.size = Pt(14)
    run2.bold = True
    run2.font.color.rgb = risk_color


def _build_toc(doc) -> None:
    """Insert a Table of Contents field."""
    doc.add_heading("Mục lục", level=1)

    paragraph = doc.add_paragraph()
    run = paragraph.add_run()
    fldChar = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>')
    run._r.append(fldChar)

    run = paragraph.add_run()
    instrText = parse_xml(f'<w:instrText {nsdecls("w")} xml:space="preserve"> TOC \\o "1-3" \\h \\z \\u </w:instrText>')
    run._r.append(instrText)

    run = paragraph.add_run()
    fldChar = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="separate"/>')
    run._r.append(fldChar)

    run = paragraph.add_run("(Nhấn chuột phải → Update Field để cập nhật mục lục)")
    run.font.color.rgb = RGBColor(0x94, 0xA3, 0xB8)
    run.font.size = Pt(10)

    run = paragraph.add_run()
    fldChar = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>')
    run._r.append(fldChar)


def _build_risk_summary_table(doc, risk_score: float, risk_label: str,
                                severity_counts: dict, report_data: dict) -> None:
    """Build a compact risk summary table."""
    table = doc.add_table(rows=2, cols=6)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER

    # Header row
    headers = ["Risk Score", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    _add_header_row(table, headers)

    # Data row
    data_row = table.rows[1]
    _prevent_row_split(data_row)
    risk_color = COLORS.get(risk_label, COLORS["INFO"])

    # Risk score cell
    cell = data_row.cells[0]
    para = cell.paragraphs[0]
    run = para.add_run(f"{risk_score:.1f}/10 ({risk_label})")
    run.font.name = "Calibri"
    run.font.size = Pt(11)
    run.bold = True
    run.font.color.rgb = risk_color
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _set_cell_shading(cell, BG_COLORS.get(risk_label, "FFFFFF"))

    # Severity count cells
    for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], 1):
        cell = data_row.cells[i]
        count = severity_counts.get(sev, 0)
        para = cell.paragraphs[0]
        run = para.add_run(str(count))
        run.font.name = "Calibri"
        run.font.size = Pt(12)
        run.bold = True
        run.font.color.rgb = COLORS[sev]
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        if count > 0:
            _set_cell_shading(cell, BG_COLORS[sev])

    doc.add_paragraph("")  # Spacing


def _build_scope_and_milestones_section(doc, report_data: dict) -> None:
    """Build the Scope of Engagement and Strategic Milestones section."""
    target = report_data.get("target", "Unknown")
    scan_mode = report_data.get("scan_mode", "FULL").upper()
    mission_obj = report_data.get("mission_objective") or "Đánh giá toàn diện an toàn thông tin & Thẩm định lỗ hổng"
    start_time = report_data.get("start_time", "N/A")
    end_time = report_data.get("end_time", "N/A")
    duration = report_data.get("duration", "N/A")
    risk_score = report_data.get("risk_score", 0.0)
    risk_label = report_data.get("risk_label", "INFO")
    goal_progress = report_data.get("goal_progress", 100)

    doc.add_paragraph(
        "Phần này xác định phạm vi ủy quyền kiểm thử, các thông số đánh giá và "
        "tiến độ hoàn thành của các cột mốc chiến lược được đề ra:"
    )

    # Scope Table
    scope_rows = [
        ("Mục tiêu Đánh giá (Target URL/Host)", target),
        ("Mục tiêu Sứ mệnh (Mission Objective)", mission_obj),
        ("Chế độ Thực thi (Execution Mode)", f"{scan_mode} (Cognitive Relentless Pursuit)"),
        ("Thời gian Bắt đầu & Kết thúc", f"{start_time} — {end_time}"),
        ("Tổng Thời lượng Đánh giá", duration),
        ("Chỉ số Rủi ro Tổng thể (Risk Score)", f"{risk_score:.1f}/10 ({risk_label})"),
        ("Tỷ lệ Hoàn thành Mục tiêu Sứ mệnh", f"{goal_progress}%"),
    ]

    scope_table = doc.add_table(rows=len(scope_rows), cols=2)
    scope_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    col_widths = [Cm(6.0), Cm(10.0)]
    for r_idx, (k, v) in enumerate(scope_rows):
        row = scope_table.rows[r_idx]
        _prevent_row_split(row)
        for c_idx, text in enumerate([k, v]):
            cell = row.cells[c_idx]
            cell.width = col_widths[c_idx]
            p = cell.paragraphs[0]
            run = p.add_run(text)
            run.font.name = "Calibri"
            run.font.size = Pt(9.5)
            if c_idx == 0:
                run.bold = True
                _set_cell_shading(cell, "F1F5F9")
            _set_cell_border(cell,
                top={"val": "single", "sz": "4", "color": "E2E8F0"},
                bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
            )
            if r_idx % 2 == 1 and c_idx == 1:
                _set_cell_shading(cell, "F8FAFC")
    doc.add_paragraph("")

    # Strategic Milestones Table
    milestones = report_data.get("milestones", [])
    if milestones:
        doc.add_heading("Tiến Độ Các Cột Mốc Sứ Mệnh Chiến Lược", level=2)
        m_table = doc.add_table(rows=1 + len(milestones), cols=5)
        m_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(m_table, ["Cột Mốc", "Mô tả Mục tiêu", "Trạng thái", "Tiến độ", "Số phát hiện"])
        m_col_widths = [Cm(3.5), Cm(6.5), Cm(2.5), Cm(2.0), Cm(2.0)]

        for r_idx, m in enumerate(milestones, start=1):
            row = m_table.rows[r_idx]
            _prevent_row_split(row)
            m_name = str(m.get("name", f"Cột mốc {r_idx}"))
            m_desc = str(m.get("description", ""))
            m_status = str(m.get("status", "PENDING"))
            m_pct = f"{m.get('progress_pct', 0)}%"
            m_findings = str(m.get("findings_count", 0))

            for c_idx, text in enumerate([m_name, m_desc, m_status, m_pct, m_findings]):
                cell = row.cells[c_idx]
                cell.width = m_col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.bold = True
                elif c_idx == 2:
                    run.bold = True
                    if m_status == "COMPLETED":
                        run.font.color.rgb = COLORS["LOW"]
                    elif m_status == "IN_PROGRESS":
                        run.font.color.rgb = COLORS["HIGH"]
                    else:
                        run.font.color.rgb = COLORS["INFO"]
                elif c_idx == 3:
                    run.bold = True
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                elif c_idx == 4:
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER

                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if r_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")


def _build_prioritized_remediation_roadmap(doc, report_data: dict) -> None:
    """Build a prioritized, multi-phase remediation roadmap table."""
    roadmap = report_data.get("prioritized_roadmap", [])
    if not roadmap:
        findings = report_data.get("findings", [])
        crit = [f for f in findings if f.get("severity") == "CRITICAL"]
        high = [f for f in findings if f.get("severity") == "HIGH"]
        med_low = [f for f in findings if f.get("severity") in ("MEDIUM", "LOW")]

        roadmap = []
        if crit:
            for f in crit:
                roadmap.append({
                    "phase": "Khẩn cấp (< 24 giờ)",
                    "priority": "P1 - KHẨN CẤP",
                    "action_item": f.get("remediation") or f"Khắc phục và cách ly: {f.get('title')}",
                    "target_component": f.get("cve_id") or report_data.get("target", "Target"),
                    "owner": "SecOps / Dev Team",
                    "effort": "Thấp - Khẩn",
                })
        else:
            roadmap.append({
                "phase": "Khẩn cấp (< 24 giờ)",
                "priority": "P1 - KHẨN CẤP",
                "action_item": "Không có lỗ hổng CRITICAL cần cô lập khẩn cấp.",
                "target_component": report_data.get("target", "Target"),
                "owner": "SecOps",
                "effort": "Không áp dụng",
            })
        for f in high:
            roadmap.append({
                "phase": "Ngắn hạn (< 7 ngày)",
                "priority": "P2 - ƯU TIÊN CAO",
                "action_item": f.get("remediation") or f"Vá lỗ hổng: {f.get('title')}",
                "target_component": f.get("cve_id") or report_data.get("target", "Target"),
                "owner": "DevOps / Web Dev",
                "effort": "Trung bình",
            })
        for f in med_low[:4]:
            roadmap.append({
                "phase": "Trung hạn (< 30 ngày)",
                "priority": "P3 - TRUNG HẠN",
                "action_item": f.get("remediation") or f"Củng cố hệ thống: {f.get('title')}",
                "target_component": report_data.get("target", "Target"),
                "owner": "DevOps / QA Team",
                "effort": "Trung bình",
            })

    doc.add_paragraph(
        "Nhằm tối ưu hóa nguồn lực an ninh và giảm thiểu rủi ro nhanh nhất, hệ thống đã tự động "
        "phân tầng kế hoạch khắc phục thành 3 giai đoạn ưu tiên thời gian:"
    )

    table = doc.add_table(rows=1 + len(roadmap), cols=5)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    _add_header_row(table, ["Giai đoạn & Mức độ", "Hạng mục Khắc phục", "Thành phần Mục tiêu", "Bộ phận Phụ trách", "Nỗ lực Ước tính"])
    col_widths = [Cm(3.5), Cm(6.5), Cm(2.5), Cm(2.0), Cm(2.0)]

    for r_idx, r in enumerate(roadmap, start=1):
        row = table.rows[r_idx]
        _prevent_row_split(row)
        r_phase = f"{r.get('phase', '')}\n[{r.get('priority', '')}]"
        r_action = str(r.get("action_item", ""))
        r_target = str(r.get("target_component", ""))
        r_owner = str(r.get("owner", ""))
        r_effort = str(r.get("effort", ""))

        for c_idx, text in enumerate([r_phase, r_action, r_target, r_owner, r_effort]):
            cell = row.cells[c_idx]
            cell.width = col_widths[c_idx]
            p = cell.paragraphs[0]
            run = p.add_run(text)
            run.font.name = "Calibri"
            run.font.size = Pt(8.5)
            if c_idx == 0:
                run.bold = True
                if "KHẨN CẤP" in text or "P1" in text:
                    run.font.color.rgb = COLORS["CRITICAL"]
                elif "P2" in text or "CAO" in text:
                    run.font.color.rgb = COLORS["HIGH"]
                else:
                    run.font.color.rgb = COLORS["MEDIUM"]
            _set_cell_border(cell,
                top={"val": "single", "sz": "4", "color": "E2E8F0"},
                bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
            )
            if r_idx % 2 == 0:
                _set_cell_shading(cell, "F8FAFC")
    doc.add_paragraph("")


def _build_rag_memory_section(doc, report_data: dict) -> None:
    """Build the Long-Term Tactical Memory & Playbook Replay section."""
    rag_applied = report_data.get("rag_applied_patterns", [])
    rag_stored = report_data.get("rag_stored_patterns", [])

    doc.add_paragraph(
        "Hệ thống MLSecOps Agent tích hợp Trí nhớ Dài hạn (RAG Long-Term Memory) với 4 chốt chặn kỹ thuật "
        "(Phễu lọc metadata, Đồ thị HNSW đa tầng, Cross-Encoder Re-ranking và Động cơ Nén bộ nhớ). "
        "Mục này tổng hợp các kịch bản kinh nghiệm quá khứ đã được tái sử dụng thành công và các kịch bản mới "
        "được đúc kết vào cơ sở tri thức cục bộ trong chiến dịch này:"
    )

    # 1. Applied Patterns Table
    doc.add_heading("Kịch Bản Quá Khứ Tái Sử Dụng Thành Công (Applied Attack Patterns)", level=2)
    if rag_applied:
        p_intro = doc.add_paragraph()
        p_intro.add_run(
            f"Hệ thống đã truy xuất và áp dụng thành công {len(rag_applied)} kịch bản tấn công/bypass từ các chiến dịch tương đồng trước đây:"
        )

        table = doc.add_table(rows=1 + len(rag_applied), cols=4)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table, ["Mã CWE / ID", "Bề mặt / Điểm vào", "Chuỗi Tấn công / Công cụ", "Độ Tương đồng / Tin cậy"])
        col_widths = [Cm(3.0), Cm(4.5), Cm(6.5), Cm(2.5)]

        for r_idx, p in enumerate(rag_applied, start=1):
            row = table.rows[r_idx]
            _prevent_row_split(row)
            cwe = str(p.get("cwe_id") or p.get("id", "N/A"))
            entry = str(p.get("entry_point") or p.get("target") or "Bề mặt mục tiêu")[:50]
            vector = str(p.get("successful_vector") or "Chuỗi công cụ Replay")[:70]
            sim = p.get("similarity_score") or p.get("rerank_score") or 0.85
            sim_str = f"{sim:.2f}" if isinstance(sim, (int, float)) else str(sim)

            for c_idx, text in enumerate([cwe, entry, vector, sim_str]):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p_el = cell.paragraphs[0]
                run = p_el.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.bold = True
                elif c_idx == 3:
                    run.bold = True
                    p_el.alignment = WD_ALIGN_PARAGRAPH.CENTER
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if r_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")
    else:
        doc.add_paragraph(
            "Trong phiên kiểm thử này, hệ thống không ghi nhận kịch bản cũ nào khớp trực tiếp từ bộ nhớ dài hạn "
            "(hệ thống vận hành theo tri thức suy luận mới từ mô hình AI)."
        )

    # 2. Stored Patterns Table
    doc.add_heading("Kịch Bản Tấn Công Mới Đúc Kết & Lưu Trữ (Stored Attack Patterns)", level=2)
    if rag_stored:
        p_intro2 = doc.add_paragraph()
        p_intro2.add_run(
            f"Hệ thống đã đúc kết và ghi nhớ {len(rag_stored)} kịch bản tấn công thành công vào Vector DB để tái sử dụng trong các chiến dịch tương lai:"
        )

        table2 = doc.add_table(rows=1 + len(rag_stored), cols=4)
        table2.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table2, ["Thời gian / Mã CWE", "Điểm vào (Entry Point)", "Vector Tấn công Thành công", "Tóm tắt Đúc kết & Phát hiện"])
        col_widths2 = [Cm(3.0), Cm(4.5), Cm(4.5), Cm(4.5)]

        for r_idx, p in enumerate(rag_stored, start=1):
            row = table2.rows[r_idx]
            _prevent_row_split(row)
            ts = p.get("timestamp", "Vừa lưu")
            cwe = str(p.get("cwe_id", "N/A"))
            id_col = f"{cwe}\n({ts})"
            entry = str(p.get("entry_point") or "N/A")[:50]
            vector = str(p.get("successful_vector") or "N/A")[:60]
            reasoning = str(p.get("agent_reasoning") or p.get("summary") or "Tự học từ thực nghiệm thành công")[:120]

            for c_idx, text in enumerate([id_col, entry, vector, reasoning]):
                cell = row.cells[c_idx]
                cell.width = col_widths2[c_idx]
                p_el = cell.paragraphs[0]
                run = p_el.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(8.5)
                if c_idx == 0:
                    run.bold = True
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if r_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")
    else:
        doc.add_paragraph("Chưa ghi nhận kịch bản tấn công mới nào được lưu trữ vào bộ nhớ dài hạn trong phiên này.")


def _build_technical_appendix(doc, report_data: dict) -> None:
    """Build the Technical Execution Appendix table listing detailed tool execution arguments and snippets."""
    methodology = report_data.get("methodology", [])
    if not methodology:
        doc.add_paragraph("Không có log thực thi kỹ thuật nào được ghi nhận.")
        return

    doc.add_paragraph(
        "Phụ lục này ghi nhận chi tiết kỹ thuật các tham số đầu vào và trích xuất kết quả "
        "thực nghiệm của từng bước công cụ trong toàn bộ chuỗi tấn công (Kill Chain):"
    )

    table = doc.add_table(rows=1 + len(methodology), cols=4)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    _add_header_row(table, ["Bước", "Công cụ & Trạng thái", "Tham số Đầu vào (Arguments)", "Đoạn trích Kết quả (Snippet)"])
    col_widths = [Cm(1.5), Cm(3.5), Cm(5.5), Cm(6.0)]

    for r_idx, step in enumerate(methodology, start=1):
        row = table.rows[r_idx]
        _prevent_row_split(row)
        s_num = f"#{step.get('step_number', r_idx)}"
        s_tool = f"{step.get('tool_name', 'N/A')}\n({step.get('status', 'SUCCESS')})"
        args_obj = step.get("arguments", {})
        s_args = json.dumps(args_obj, ensure_ascii=False) if isinstance(args_obj, dict) else str(args_obj)
        s_snip = (step.get("result_snippet") or "—").replace("\n", " ")[:150]

        for c_idx, text in enumerate([s_num, s_tool, s_args[:100], s_snip]):
            cell = row.cells[c_idx]
            cell.width = col_widths[c_idx]
            p = cell.paragraphs[0]
            run = p.add_run(text)
            run.font.name = "Calibri"
            run.font.size = Pt(8.5)
            if c_idx == 0:
                run.bold = True
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            elif c_idx == 1:
                run.bold = True
            elif c_idx in (2, 3):
                run.font.name = "Consolas"
                run.font.size = Pt(8.0)

            _set_cell_border(cell,
                top={"val": "single", "sz": "4", "color": "E2E8F0"},
                bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
            )
            if r_idx % 2 == 0:
                _set_cell_shading(cell, "F8FAFC")
    doc.add_paragraph("")


def _build_methodology_table(doc, methodology: list[dict]) -> None:
    """Build the kill chain timeline table."""
    doc.add_paragraph(
        f"Tổng cộng {len(methodology)} bước tấn công/trinh sát đã được thực hiện:"
    )

    table = doc.add_table(rows=1, cols=5)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    _add_header_row(table, ["#", "Công cụ", "Trạng thái", "Thời gian", "Nhận xét SOC"])

    for step in methodology:
        row = table.add_row()
        _prevent_row_split(row)
        cells = row.cells

        cells[0].text = str(step.get("step_number", ""))
        cells[1].text = step.get("tool_name", "N/A")

        # Status with color
        status = step.get("status", "N/A")
        status_para = cells[2].paragraphs[0]
        status_run = status_para.add_run(status)
        status_run.font.name = "Calibri"
        status_run.font.size = Pt(9)
        status_run.bold = True
        if status == "SUCCESS":
            status_run.font.color.rgb = COLORS["LOW"]
        elif status in ("FAILED", "TIMEOUT"):
            status_run.font.color.rgb = COLORS["CRITICAL"]
        else:
            status_run.font.color.rgb = COLORS["MEDIUM"]

        cells[3].text = step.get("timestamp", "N/A")

        comment = step.get("reporter_comment", "")
        cells[4].text = comment[:100] if comment else "—"

        # Style all cells
        for cell in cells:
            for para in cell.paragraphs:
                for run in para.runs:
                    run.font.name = "Calibri"
                    run.font.size = Pt(9)


def _build_threat_modeling_section(doc, report_data: dict) -> None:
    """Build the Threat Modeling & Bayesian Attack Graph section in DOCX."""
    graph_summary = report_data.get("attack_graph_summary", {})
    mermaid_str = report_data.get("attack_graph_mermaid", "")
    owasp_breakdown = report_data.get("owasp_breakdown", {})
    mitre_breakdown = report_data.get("mitre_breakdown", {})

    intro_p = doc.add_paragraph(
        "Mô hình đồ thị tấn công Bayesian phân tích đa bước cho phép đánh giá định lượng xác suất "
        "kẻ tấn công leo thang đặc quyền từ vòng ngoài Internet đến các tài sản trọng yếu (Database, Host OS, Admin Console). "
        "Dữ liệu được liên kết và đối chiếu trực tiếp với khung chuẩn OWASP Top 10 (2021) và MITRE ATT&CK Matrix."
    )
    intro_p.paragraph_format.space_after = Pt(8)

    # 1. Critical Attack Path Callout Box
    crit_prob = graph_summary.get("critical_path_probability", 0.0)
    crit_chain = graph_summary.get("critical_path_chain", "None")
    if crit_prob > 0 and crit_chain != "None":
        prob_pct = round(crit_prob * 100, 1)
        tbl = doc.add_table(rows=2, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
        tbl.autofit = False

        # Header callout cell
        hdr_cell = tbl.rows[0].cells[0]
        _set_cell_shading(hdr_cell, "DC2626" if prob_pct >= 60 else "EA580C")
        hp = hdr_cell.paragraphs[0]
        hrun = hp.add_run(f"🚨 ĐƯỜNG DẪN XÂM NHẬP NGUY HIỂM NHẤT (CRITICAL ATTACK PATH) — XÁC SUẤT: {prob_pct}%")
        hrun.font.name = "Calibri"
        hrun.font.size = Pt(11)
        hrun.bold = True
        hrun.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

        # Body cell
        body_cell = tbl.rows[1].cells[0]
        _set_cell_shading(body_cell, "FEE2E2" if prob_pct >= 60 else "FFF7ED")
        bp = body_cell.paragraphs[0]
        brun = bp.add_run(f"Chuỗi thâm nhập thực nghiệm:\n{crit_chain}")
        brun.font.name = "Consolas"
        brun.font.size = Pt(10)
        brun.bold = True

        doc.add_paragraph("").paragraph_format.space_after = Pt(4)

    # 2. Top Viable Kill-Chain Paths
    top_paths = graph_summary.get("top_paths", [])
    if top_paths:
        _styled_paragraph(doc, "Các Chuỗi Xâm Nhập Khả Thi (Viable Kill-Chain Paths):", font_size=11, bold=True, space_after=4)
        path_tbl = doc.add_table(rows=1 + len(top_paths[:6]), cols=2)
        path_tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
        _add_header_row(path_tbl, ["STT", "Chuỗi Tấn Công & Xác Suất Thâm Nhập (Bayesian Likelihood)"])

        for idx, p_text in enumerate(top_paths[:6], 1):
            row = path_tbl.rows[idx]
            _prevent_row_split(row)
            c0, c1 = row.cells[0], row.cells[1]
            _set_cell_shading(c0, "F8FAFC" if idx % 2 == 1 else "FFFFFF")
            _set_cell_shading(c1, "F8FAFC" if idx % 2 == 1 else "FFFFFF")

            p0 = c0.paragraphs[0]
            r0 = p0.add_run(str(idx))
            r0.font.name = "Calibri"
            r0.font.size = Pt(10)
            r0.bold = True

            p1 = c1.paragraphs[0]
            r1 = p1.add_run(p_text)
            r1.font.name = "Calibri"
            r1.font.size = Pt(9.5)

        doc.add_paragraph("").paragraph_format.space_after = Pt(6)

    # 3. OWASP Top 10 (2021) Breakdown Table
    if owasp_breakdown:
        _styled_paragraph(doc, "Phân loại Lỗ hổng theo Chuẩn OWASP Top 10 (2021):", font_size=11, bold=True, space_after=4)
        owasp_tbl = doc.add_table(rows=1 + len(owasp_breakdown), cols=3)
        owasp_tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
        _add_header_row(owasp_tbl, ["Danh mục OWASP 2021", "Số lượng Phát hiện", "Mức độ Ảnh hưởng"])

        for idx, (cat, cnt) in enumerate(owasp_breakdown.items(), 1):
            row = owasp_tbl.rows[idx]
            _prevent_row_split(row)
            c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
            _set_cell_shading(c0, "F8FAFC" if idx % 2 == 1 else "FFFFFF")
            _set_cell_shading(c1, "F8FAFC" if idx % 2 == 1 else "FFFFFF")
            _set_cell_shading(c2, "F8FAFC" if idx % 2 == 1 else "FFFFFF")

            r0 = c0.paragraphs[0].add_run(cat)
            r0.font.name = "Calibri"
            r0.font.size = Pt(9.5)
            r0.bold = True

            r1 = c1.paragraphs[0].add_run(f"{cnt} lỗ hổng")
            r1.font.name = "Calibri"
            r1.font.size = Pt(9.5)

            r2 = c2.paragraphs[0].add_run("Đã kiểm chứng tự động")
            r2.font.name = "Calibri"
            r2.font.size = Pt(9)

        doc.add_paragraph("").paragraph_format.space_after = Pt(6)

    # 4. MITRE ATT&CK Matrix Mapping Table
    if mitre_breakdown:
        _styled_paragraph(doc, "Ánh xạ Kỹ thuật Tấn công MITRE ATT&CK Matrix:", font_size=11, bold=True, space_after=4)
        mitre_items = list(mitre_breakdown.items())[:10]
        mitre_tbl = doc.add_table(rows=1 + len(mitre_items), cols=2)
        mitre_tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
        _add_header_row(mitre_tbl, ["Kỹ thuật MITRE ATT&CK", "Số lượng Lỗ hổng Liên đới"])

        for idx, (tech, cnt) in enumerate(mitre_items, 1):
            row = mitre_tbl.rows[idx]
            _prevent_row_split(row)
            c0, c1 = row.cells[0], row.cells[1]
            _set_cell_shading(c0, "F8FAFC" if idx % 2 == 1 else "FFFFFF")
            _set_cell_shading(c1, "F8FAFC" if idx % 2 == 1 else "FFFFFF")

            r0 = c0.paragraphs[0].add_run(tech)
            r0.font.name = "Calibri"
            r0.font.size = Pt(9.5)
            r0.bold = True

            r1 = c1.paragraphs[0].add_run(f"{cnt} phát hiện")
            r1.font.name = "Calibri"
            r1.font.size = Pt(9.5)

        doc.add_paragraph("").paragraph_format.space_after = Pt(6)

    # 5. Mermaid Syntax Export Block for CI/CD & DevOps
    if mermaid_str:
        _styled_paragraph(doc, "Mã Nguồn Đồ Thị Tấn Công (Mermaid Flowchart Specification):", font_size=10, bold=True, space_after=2)
        mm_tbl = doc.add_table(rows=1, cols=1)
        mm_tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
        cell = mm_tbl.rows[0].cells[0]
        _set_cell_shading(cell, "F1F5F9")
        p = cell.paragraphs[0]
        run = p.add_run(mermaid_str)
        run.font.name = "Consolas"
        run.font.size = Pt(8.5)
        run.font.color.rgb = RGBColor(0x33, 0x41, 0x55)
        doc.add_paragraph("").paragraph_format.space_after = Pt(6)


def _build_attack_surface_section(doc, attack_surface: dict, report_data: dict | None = None) -> None:
    """Build the Attack Surface section in the DOCX report."""
    if not attack_surface:
        return

    open_ports = attack_surface.get("open_ports", {})
    param_urls = attack_surface.get("parameterized_endpoints", {})
    login_forms = attack_surface.get("login_forms", [])
    technologies = attack_surface.get("detected_technologies", [])
    subdomains = attack_surface.get("subdomains", [])
    alive_subdomains = attack_surface.get("alive_subdomains", [])
    exposed_files = attack_surface.get("exposed_sensitive_files", [])
    cors_issues = attack_surface.get("cors_issues", [])
    ssl_cert_info = attack_surface.get("ssl_cert_info", {})
    dns_security_info = attack_surface.get("dns_security_info", {})
    hidden_paths = attack_surface.get("hidden_discovered_paths", [])
    cookie_issues = attack_surface.get("cookie_issues", [])

    has_data = (
        open_ports
        or param_urls
        or login_forms
        or technologies
        or subdomains
        or alive_subdomains
        or exposed_files
        or cors_issues
        or ssl_cert_info
        or dns_security_info
        or hidden_paths
        or cookie_issues
    )
    if not has_data:
        return

    intro_p = doc.add_paragraph()
    intro_p.add_run(
        "Bề mặt tấn công của mục tiêu được tổng hợp và tự động ánh xạ theo thời gian thực "
        "thông qua hệ thống Docker Arsenal và động cơ AttackSurfaceGraph:"
    )

    # 1. Open Ports Table
    if open_ports:
        doc.add_heading("Các Cổng Dịch Vụ Mở (Open Ports & Services)", level=2)
        if isinstance(open_ports, dict):
            ports_list = sorted(open_ports.items(), key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0)
        else:
            ports_list = [(p, {"service": "unknown", "deep_scanned": False}) for p in open_ports]

        table = doc.add_table(rows=1 + len(ports_list), cols=3)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table, ["Cổng / Giao thức", "Dịch vụ phát hiện", "Trạng thái kiểm thử sâu"])

        col_widths = [Cm(4.0), Cm(7.0), Cm(5.0)]
        for row_idx, (port, info) in enumerate(ports_list, start=1):
            row = table.rows[row_idx]
            _prevent_row_split(row)
            svc = info.get("service", "unknown") if isinstance(info, dict) else "unknown"
            deep = "Đã quét chuyên sâu" if isinstance(info, dict) and info.get("deep_scanned") else "Đã rà quét nhanh"

            cell_texts = [f"{port}/tcp", svc, deep]
            for c_idx, text in enumerate(cell_texts):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.5)
                if c_idx == 0:
                    run.bold = True
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if row_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")

    # 2. Technologies & Frameworks
    if technologies:
        doc.add_heading("Công nghệ & Nền tảng Nhận diện (Technologies & Frameworks)", level=2)
        tech_p = doc.add_paragraph()
        run_label = tech_p.add_run("Công nghệ phát hiện: ")
        run_label.bold = True
        tech_p.add_run(", ".join(technologies))
        doc.add_paragraph("")

    # 3. Discovered Parameterized URLs & Login Forms
    if param_urls or login_forms:
        doc.add_heading("Điểm Cuối Ứng Dụng Web & Form Xác Thực", level=2)
        endpoints_list = []
        if isinstance(param_urls, dict):
            for u, info in list(param_urls.items())[:15]:
                sqli_status = "SQLi: Đã test" if info.get("tested_sqli") else "SQLi: Chưa test"
                xss_status = "XSS: Đã test" if info.get("tested_xss") else "XSS: Chưa test"
                status_str = f"{sqli_status} | {xss_status}"
                endpoints_list.append(("Endpoint có tham số", u, status_str))
        elif isinstance(param_urls, list):
            for u in param_urls[:15]:
                endpoints_list.append(("Endpoint có tham số", str(u), "Chưa kiểm tra"))

        for f in login_forms[:5]:
            f_url = f.get("url", "") if isinstance(f, dict) else str(f)
            tested = "Đã kiểm tra Brute-force" if isinstance(f, dict) and f.get("tested_bruteforce") else "Chưa kiểm tra"
            endpoints_list.append(("Form đăng nhập / Auth", f_url, tested))

        if endpoints_list:
            table = doc.add_table(rows=1 + len(endpoints_list), cols=3)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            _add_header_row(table, ["Loại bề mặt", "Đường dẫn / Endpoint", "Tình trạng kiểm thử"])

            col_widths = [Cm(4.5), Cm(8.0), Cm(4.0)]
            for row_idx, (ep_type, ep_url, ep_status) in enumerate(endpoints_list, start=1):
                row = table.rows[row_idx]
                _prevent_row_split(row)
                for c_idx, text in enumerate([ep_type, ep_url, ep_status]):
                    cell = row.cells[c_idx]
                    cell.width = col_widths[c_idx]
                    p = cell.paragraphs[0]
                    run = p.add_run(text)
                    run.font.name = "Calibri"
                    run.font.size = Pt(9.0)
                    if c_idx == 0:
                        run.bold = True
                    if c_idx == 1:
                        run.font.name = "Consolas"
                        run.font.size = Pt(8.5)
                    _set_cell_border(cell,
                        top={"val": "single", "sz": "4", "color": "E2E8F0"},
                        bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                    )
                    if row_idx % 2 == 0:
                        _set_cell_shading(cell, "F8FAFC")
            doc.add_paragraph("")

    # 4. Exposed Sensitive Files & Information Disclosure
    if exposed_files:
        doc.add_heading("Tập Tin & Đường Dẫn Nhạy Cảm Lộ Lọt (Sensitive Files Discovered)", level=2)
        table = doc.add_table(rows=1 + len(exposed_files[:20]), cols=4)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table, ["Đường dẫn phát hiện", "Phân loại rủi ro", "Mức độ", "Trạng thái"])

        col_widths = [Cm(6.5), Cm(4.5), Cm(2.5), Cm(3.0)]
        for row_idx, f in enumerate(exposed_files[:20], start=1):
            row = table.rows[row_idx]
            _prevent_row_split(row)
            f_path = str(f.get("path") or f.get("url") or "N/A")
            f_risk = str(f.get("risk_type") or "Information Disclosure")
            f_sev = str(f.get("severity") or "MEDIUM").upper()
            f_status = str(f.get("status_code") or "200")

            cell_texts = [f_path, f_risk, f_sev, f"HTTP {f_status}"]
            for c_idx, text in enumerate(cell_texts):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.font.name = "Consolas"
                    run.font.size = Pt(8.5)
                elif c_idx == 2:
                    run.bold = True
                    sev_color = COLORS.get(f_sev, COLORS["INFO"])
                    run.font.color.rgb = sev_color
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if row_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")

    # 5. CORS Misconfigurations
    if cors_issues:
        doc.add_heading("Cấu Hình CORS & Tiêu Đề Bảo Mật (CORS Misconfigurations)", level=2)
        table = doc.add_table(rows=1 + len(cors_issues[:15]), cols=4)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table, ["Endpoint / URL", "Loại cấu hình sai", "Mức độ", "Chi tiết phát hiện"])

        col_widths = [Cm(5.0), Cm(4.5), Cm(2.5), Cm(4.5)]
        for row_idx, iss in enumerate(cors_issues[:15], start=1):
            row = table.rows[row_idx]
            _prevent_row_split(row)
            iss_url = str(iss.get("url") or "Target")
            iss_type = str(iss.get("type") or "CORS Misconfiguration")
            iss_sev = str(iss.get("severity") or "MEDIUM").upper()
            iss_desc = str(iss.get("description") or iss.get("origin") or "Phát hiện cấu hình lỏng lẻo")

            cell_texts = [iss_url, iss_type, iss_sev, iss_desc[:80]]
            for c_idx, text in enumerate(cell_texts):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.font.name = "Consolas"
                    run.font.size = Pt(8.5)
                elif c_idx == 2:
                    run.bold = True
                    sev_color = COLORS.get(iss_sev, COLORS["INFO"])
                    run.font.color.rgb = sev_color
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if row_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")

    # 6. Alive Subdomains & Web Services
    if alive_subdomains:
        doc.add_heading("Tên Miền Phụ Đang Hoạt Động (Alive Subdomains & HTTP Services)", level=2)
        table = doc.add_table(rows=1 + len(alive_subdomains[:20]), cols=4)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table, ["URL / Subdomain", "Mã phản hồi", "Tiêu đề trang (Title)", "Web Server"])

        col_widths = [Cm(5.5), Cm(2.5), Cm(5.0), Cm(3.5)]
        for row_idx, host in enumerate(alive_subdomains[:20], start=1):
            row = table.rows[row_idx]
            _prevent_row_split(row)
            if isinstance(host, dict):
                h_url = str(host.get("url") or host.get("input_target") or "N/A")
                h_status = str(host.get("status_code") or "200")
                h_title = str(host.get("title") or "—")[:40]
                h_server = str(host.get("webserver") or "—")[:30]
            else:
                h_url = str(host)
                h_status = "200"
                h_title = "—"
                h_server = "—"

            cell_texts = [h_url, f"HTTP {h_status}", h_title, h_server]
            for c_idx, text in enumerate(cell_texts):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.font.name = "Consolas"
                    run.font.size = Pt(8.5)
                elif c_idx == 1:
                    run.bold = True
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if row_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")

    # 7. Subdomains (Fallback or Raw List)
    if subdomains and not alive_subdomains:
        doc.add_heading("Danh Sách Tên Miền Phụ (Subdomains Discovered)", level=2)
        sub_p = doc.add_paragraph()
        run_label = sub_p.add_run("Tên miền phụ phát hiện: ")
        run_label.bold = True
        sub_p.add_run(", ".join(subdomains[:30]))
        doc.add_paragraph("")

    # 8. SSL/TLS Certificate & Encryption
    if ssl_cert_info:
        doc.add_heading("Kiểm tra Chứng chỉ SSL/TLS & Mã hóa (SSL/TLS Certificate Audit)", level=2)
        ssl_rows = [
            ("Tên miền chính (Common Name)", str(ssl_cert_info.get("subject_cn") or "N/A")),
            ("Tổ chức phát hành (Issuer)", str(ssl_cert_info.get("issuer_org") or ssl_cert_info.get("issuer") or "N/A")),
            ("Ngày hết hạn (Expiry Date)", str(ssl_cert_info.get("valid_to") or "N/A")),
            ("Thời hạn còn lại (Days Remaining)", f"{ssl_cert_info.get('days_until_expiry', 'N/A')} ngày"),
            ("Phiên bản TLS hỗ trợ", str(ssl_cert_info.get("tls_version") or "TLSv1.2 / TLSv1.3")),
            ("Độ dài khóa mã hóa (Key Length)", f"{ssl_cert_info.get('key_bits', 'N/A')} bits"),
            ("Số lượng SANs phụ (Alternative Names)", f"{len(ssl_cert_info.get('subject_alternative_names', []))} tên miền"),
        ]
        issues = ssl_cert_info.get("issues", [])
        if issues:
            ssl_rows.append(("Cảnh báo & Lỗ hổng phát hiện", "; ".join(issues)))

        table = doc.add_table(rows=len(ssl_rows), cols=2)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        col_widths = [Cm(6.0), Cm(10.0)]
        for r_idx, (k, v) in enumerate(ssl_rows):
            row = table.rows[r_idx]
            _prevent_row_split(row)
            for c_idx, text in enumerate([k, v]):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.bold = True
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if r_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")

    # 9. DNS & Email Security (SPF, DMARC, DNSSEC)
    if dns_security_info:
        doc.add_heading("An toàn Hạ tầng DNS & Chống Giả mạo Email (DNS & Email Security)", level=2)
        spf_data = dns_security_info.get("spf", {})
        dmarc_data = dns_security_info.get("dmarc", {})
        dnssec_data = dns_security_info.get("dnssec", {})
        sec_issues = dns_security_info.get("security_issues", [])

        dns_rows = [
            ("Bản ghi SPF (Sender Policy Framework)", str(spf_data.get("status", "N/A")), str(spf_data.get("record") or spf_data.get("details") or "—")[:80]),
            ("Bản ghi DMARC (Domain-based Auth)", str(dmarc_data.get("status", "N/A")), str(dmarc_data.get("policy") or dmarc_data.get("details") or "—")[:80]),
            ("Bảo mật DNSSEC", "BẬT" if dnssec_data.get("dnssec_enabled") else "TẮT", "Hỗ trợ xác thực tính toàn vẹn DNS" if dnssec_data.get("dnssec_enabled") else "Thiếu bảo vệ DNS spoofing/cache poisoning"),
        ]
        table = doc.add_table(rows=1 + len(dns_rows), cols=3)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table, ["Cơ chế Bảo vệ", "Trạng thái", "Chi tiết cấu hình"])
        col_widths = [Cm(5.0), Cm(3.0), Cm(8.0)]
        for r_idx, row_vals in enumerate(dns_rows, start=1):
            row = table.rows[r_idx]
            _prevent_row_split(row)
            for c_idx, text in enumerate(row_vals):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.bold = True
                elif c_idx == 1:
                    run.bold = True
                    if text in ("valid", "enforced", "BẬT"):
                        run.font.color.rgb = COLORS["LOW"]
                    elif text in ("missing", "TẮT"):
                        run.font.color.rgb = COLORS["HIGH"]
                    else:
                        run.font.color.rgb = COLORS["MEDIUM"]
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if r_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        if sec_issues:
            warn_p = doc.add_paragraph()
            warn_p.add_run("⚠️ Cảnh báo cấu hình DNS: ").bold = True
            warn_p.add_run("; ".join(sec_issues))
        doc.add_paragraph("")

    # 10. RFC 9116, Robots.txt & Hidden Discovered Paths
    if hidden_paths:
        doc.add_heading("Chính sách Bảo mật RFC 9116 & Đường dẫn Ẩn (Robots.txt & Security.txt)", level=2)
        table = doc.add_table(rows=1 + len(hidden_paths[:20]), cols=3)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table, ["Đường dẫn phát hiện (Path)", "Nguồn phát hiện", "Độ nhạy cảm"])
        col_widths = [Cm(8.0), Cm(4.5), Cm(3.5)]
        for r_idx, p_item in enumerate(hidden_paths[:20], start=1):
            row = table.rows[r_idx]
            _prevent_row_split(row)
            p_val = p_item if isinstance(p_item, str) else p_item.get("path", str(p_item))
            p_src = "robots.txt" if "/admin" in p_val or "disallow" in str(p_item).lower() else "sitemap / policy"
            if isinstance(p_item, dict):
                p_src = p_item.get("source", p_src)
            p_sens = "Cao (Hidden Admin/API)" if any(k in p_val.lower() for k in ["admin", "api", "backup", "secret", "private"]) else "Bình thường"

            for c_idx, text in enumerate([p_val, p_src, p_sens]):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.font.name = "Consolas"
                    run.font.size = Pt(8.5)
                elif c_idx == 2 and "Cao" in text:
                    run.bold = True
                    run.font.color.rgb = COLORS["HIGH"]
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if r_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")

    # 11. Cookie & Session Security
    if cookie_issues:
        doc.add_heading("An Toàn Cookie & Quản Lý Phiên (Cookie Security Flags)", level=2)
        table = doc.add_table(rows=1 + len(cookie_issues[:15]), cols=4)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table, ["Tên Cookie", "Thiếu cờ bảo vệ (Missing Flags)", "Mức độ", "Rủi ro an ninh"])
        col_widths = [Cm(4.0), Cm(4.5), Cm(2.5), Cm(5.0)]
        for r_idx, c_item in enumerate(cookie_issues[:15], start=1):
            row = table.rows[r_idx]
            _prevent_row_split(row)
            c_name = str(c_item.get("name") or "session_cookie")
            c_flags = ", ".join(c_item.get("missing_flags", [])) or str(c_item.get("issue") or "Missing flags")
            c_sev = str(c_item.get("severity") or "MEDIUM").upper()
            c_risk = str(c_item.get("risk") or "Nguy cơ đánh cắp phiên qua XSS/MITM")

            for c_idx, text in enumerate([c_name, c_flags, c_sev, c_risk]):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.font.name = "Consolas"
                    run.font.size = Pt(8.5)
                elif c_idx == 2:
                    run.bold = True
                    run.font.color.rgb = COLORS.get(c_sev, COLORS["MEDIUM"])
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if r_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")

    # 12. Compound Attack Scenarios (Chuỗi Kịch Bản Tấn Công Phức Hợp)
    compound_findings = []
    if report_data:
        compound_findings = report_data.get("compound_threats") or [
            f for f in report_data.get("findings", [])
            if "[CHUỖI TẤN CÔNG]" in str(f.get("title", ""))
        ]
    if compound_findings:
        doc.add_heading("Kịch Bản Khai Thác Phức Hợp (Compound Attack Scenarios & Attack Chaining)", level=2)
        intro_p = doc.add_paragraph()
        intro_p.add_run(
            "Động cơ Tương quan Lỗ hổng (Vulnerability Correlation Engine) đã tự động liên kết các điểm yếu riêng lẻ "
            "thành các chuỗi kịch bản tấn công hoàn chỉnh (Kill Chain Scenarios) có mức độ nguy hại cao đối với doanh nghiệp:"
        )

        table = doc.add_table(rows=1 + len(compound_findings), cols=4)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _add_header_row(table, ["Kịch bản chuỗi tấn công", "Mức độ", "Điểm CVSS", "Mô tả đường dẫn xâm nhập & Tác động"])
        col_widths = [Cm(5.0), Cm(2.5), Cm(2.5), Cm(6.0)]

        for r_idx, c_finding in enumerate(compound_findings, start=1):
            row = table.rows[r_idx]
            _prevent_row_split(row)
            t_title = str(c_finding.get("title", "")).replace("[CHUỖI TẤN CÔNG]", "").strip()
            t_sev = str(c_finding.get("severity", "HIGH")).upper()
            t_cvss = str(c_finding.get("cvss_score") or "N/A")
            t_desc = str(c_finding.get("description", "") or c_finding.get("impact", ""))[:200]

            for c_idx, text in enumerate([t_title, t_sev, t_cvss, t_desc]):
                cell = row.cells[c_idx]
                cell.width = col_widths[c_idx]
                p = cell.paragraphs[0]
                run = p.add_run(text)
                run.font.name = "Calibri"
                run.font.size = Pt(9.0)
                if c_idx == 0:
                    run.bold = True
                elif c_idx == 1:
                    run.bold = True
                    run.font.color.rgb = COLORS.get(t_sev, COLORS["HIGH"])
                elif c_idx == 2 and text != "N/A":
                    run.bold = True
                _set_cell_border(cell,
                    top={"val": "single", "sz": "4", "color": "E2E8F0"},
                    bottom={"val": "single", "sz": "4", "color": "E2E8F0"},
                )
                if r_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
        doc.add_paragraph("")


def _build_finding_section(doc, index: int, finding: dict) -> None:
    """Build a detailed section for a single finding."""
    severity = str(finding.get("severity") or "INFO").upper().strip()
    title = str(finding.get("title") or "Untitled Finding").strip()

    # Finding heading with severity badge
    doc.add_heading(f"Phát hiện #{index}: [{severity}] {title}", level=2)

    detail_rows = [
        ("Mức độ:", severity),
        ("Mô tả:", str(finding.get("description") or "N/A")),
        ("Tác động:", str(finding.get("impact") or "N/A")),
        ("Khuyến nghị:", str(finding.get("remediation") or "N/A")),
        ("Công cụ phát hiện:", str(finding.get("tool_source") or "N/A")),
    ]

    cve_id = str(finding.get("cve_id") or "").strip()
    if cve_id:
        detail_rows.append(("Mã CVE:", cve_id))

    cvss_score = finding.get("cvss_score")
    if cvss_score is not None and str(cvss_score).strip():
        detail_rows.append(("Điểm CVSS:", str(cvss_score)))

    owasp = str(finding.get("owasp_category") or "").strip()
    if owasp:
        detail_rows.append(("OWASP Top 10:", owasp))

    mitre_tech = finding.get("mitre_techniques") or []
    if mitre_tech:
        detail_rows.append(("MITRE ATT&CK:", ", ".join(mitre_tech)))

    details_table = doc.add_table(rows=len(detail_rows), cols=2)
    details_table.alignment = WD_TABLE_ALIGNMENT.LEFT

    for i, (label, value) in enumerate(detail_rows):
        row = details_table.rows[i]
        _prevent_row_split(row)

        # Label
        label_cell = row.cells[0]
        label_para = label_cell.paragraphs[0]
        label_run = label_para.add_run(label)
        label_run.font.name = "Calibri"
        label_run.font.size = Pt(10)
        label_run.bold = True
        _set_cell_shading(label_cell, "F1F5F9")

        # Value
        value_cell = row.cells[1]
        value_para = value_cell.paragraphs[0]

        if i == 0:  # Severity row — color coded
            value_run = value_para.add_run(value)
            value_run.font.name = "Calibri"
            value_run.font.size = Pt(10)
            value_run.bold = True
            value_run.font.color.rgb = COLORS.get(severity, COLORS["INFO"])
            _set_cell_shading(value_cell, BG_COLORS.get(severity, "FFFFFF"))
        elif label == "Mã CVE:":
            value_run = value_para.add_run(value)
            value_run.font.name = "Consolas"
            value_run.font.size = Pt(10)
            value_run.bold = True
            value_run.font.color.rgb = RGBColor(0xDC, 0x26, 0x26)
        elif label == "Điểm CVSS:":
            value_run = value_para.add_run(value)
            value_run.font.name = "Calibri"
            value_run.font.size = Pt(10)
            value_run.bold = True
        else:
            value_run = value_para.add_run(value)
            value_run.font.name = "Calibri"
            value_run.font.size = Pt(10)

    # Evidence snippet
    evidence = str(finding.get("raw_evidence") or "").strip()
    if evidence:
        doc.add_paragraph("")
        evidence_para = doc.add_paragraph()
        run = evidence_para.add_run(f"Bằng chứng: {evidence[:500]}")
        run.font.name = "Consolas"
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

    doc.add_paragraph("")  # Spacing


def _build_risk_matrix(doc, severity_counts: dict, risk_score: float,
                        risk_label: str) -> None:
    """Build the risk matrix summary."""
    doc.add_paragraph("Tổng hợp phân loại rủi ro theo mức độ nghiêm trọng:")

    # Matrix table
    table = doc.add_table(rows=2, cols=6)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    _add_header_row(table, ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TỔNG"])

    data_row = table.rows[1]
    _prevent_row_split(data_row)
    total = 0
    for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]):
        count = severity_counts.get(sev, 0)
        total += count
        cell = data_row.cells[i]
        para = cell.paragraphs[0]
        run = para.add_run(str(count))
        run.font.name = "Calibri"
        run.font.size = Pt(12)
        run.bold = True
        run.font.color.rgb = COLORS[sev]
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        if count > 0:
            _set_cell_shading(cell, BG_COLORS[sev])

    # Total cell
    total_cell = data_row.cells[5]
    total_para = total_cell.paragraphs[0]
    total_run = total_para.add_run(str(total))
    total_run.font.name = "Calibri"
    total_run.font.size = Pt(12)
    total_run.bold = True
    total_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph("")

    # Risk assessment paragraph
    risk_color = COLORS.get(risk_label, COLORS["INFO"])
    risk_para = doc.add_paragraph()
    run1 = risk_para.add_run("Đánh giá rủi ro tổng thể: ")
    run1.font.name = "Calibri"
    run1.font.size = Pt(12)
    run1.bold = True
    run2 = risk_para.add_run(f"{risk_label} ({risk_score:.1f}/10)")
    run2.font.name = "Calibri"
    run2.font.size = Pt(12)
    run2.bold = True
    run2.font.color.rgb = risk_color

    # Risk description
    risk_descriptions = {
        "CRITICAL": "Phát hiện lỗ hổng cực kỳ nghiêm trọng. Hệ thống có thể bị xâm nhập hoàn toàn. Cần xử lý KHẨN CẤP.",
        "HIGH": "Phát hiện lỗ hổng nghiêm trọng. Kẻ tấn công có thể khai thác để gây thiệt hại lớn. Cần xử lý trong thời gian sớm nhất.",
        "MEDIUM": "Một số vấn đề bảo mật cần được khắc phục. Rủi ro ở mức trung bình.",
        "LOW": "Vấn đề bảo mật nhỏ hoặc mang tính thông tin. Rủi ro thấp.",
        "INFO": "Không phát hiện lỗ hổng đáng kể. Hệ thống trong tình trạng an toàn tốt.",
    }
    doc.add_paragraph(risk_descriptions.get(risk_label, ""))


def _build_header_footer(doc, company_name: str, classification: str) -> None:
    """Add header and footer to all sections."""
    for section in doc.sections:
        section.different_first_page_header_footer = True
        # Header
        header = section.header
        header.is_linked_to_previous = False
        header_para = header.paragraphs[0] if header.paragraphs else header.add_paragraph()
        header_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

        run = header_para.add_run(f"{company_name} — {classification}")
        run.font.name = "Calibri"
        run.font.size = Pt(8)
        run.font.color.rgb = RGBColor(0x94, 0xA3, 0xB8)

        # Footer with page number
        footer = section.footer
        footer.is_linked_to_previous = False
        footer_para = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
        footer_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

        run = footer_para.add_run("MLSecOps Agent v4.0 — Trang ")
        run.font.name = "Calibri"
        run.font.size = Pt(8)
        run.font.color.rgb = RGBColor(0x94, 0xA3, 0xB8)

        # Page number field
        fldChar1 = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>')
        footer_para.add_run()._r.append(fldChar1)

        instrText = parse_xml(f'<w:instrText {nsdecls("w")} xml:space="preserve"> PAGE </w:instrText>')
        footer_para.add_run()._r.append(instrText)

        fldChar2 = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>')
        footer_para.add_run()._r.append(fldChar2)
