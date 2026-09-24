"""Interactive Standalone HTML Cyber Executive Dashboard Generator.

Generates a sleek, 100% offline, self-contained interactive cybersecurity dashboard:
- Dark Cyberpunk & Glassmorphism Design System (tailored HSL colors, responsive grid)
- SVG Risk Gauges & Severity Breakdown Visuals
- Real-time Client-Side Interactive Filtering (Filter by Severity, OWASP Category, Search keywords)
- Copy-to-Clipboard Actionable Remediation Code Blocks
- Attack Surface & Discovered Services Visual Badges
- Zero external CDN dependencies (works in isolated, air-gapped security environments)
- Print-optimized CSS for direct Save-as-PDF from browser
"""

import html
import json
import os
from typing import Any


def generate_html_report(report_data: dict[str, Any], output_path: str | None = None) -> str:
    """Generate a standalone interactive HTML cybersecurity assessment report."""
    target = html.escape(str(report_data.get("target", "N/A")))
    scan_mode = html.escape(str(report_data.get("scan_mode", "recon")).upper())
    risk_score = float(report_data.get("risk_score", 0.0))
    risk_label = html.escape(str(report_data.get("risk_label", "LOW")))
    exec_summary = html.escape(str(report_data.get("executive_summary", "Không có tóm tắt điều hành.")))
    conclusion = html.escape(str(report_data.get("conclusion", report_data.get("red_teamer_final_answer", ""))))
    start_time = html.escape(str(report_data.get("start_time", "N/A")))
    end_time = html.escape(str(report_data.get("end_time", "N/A")))
    duration = html.escape(str(report_data.get("duration", "N/A")))
    total_iterations = report_data.get("total_iterations", 0)

    # Severity counts
    counts = report_data.get("severity_counts", {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})
    crit_count = counts.get("CRITICAL", 0)
    high_count = counts.get("HIGH", 0)
    med_count = counts.get("MEDIUM", 0)
    low_count = counts.get("LOW", 0)
    info_count = counts.get("INFO", 0)
    total_findings = crit_count + high_count + med_count + low_count + info_count

    # Risk badge theme
    if "CRIT" in risk_label:
        risk_theme = "rose"
        risk_color = "#f43f5e"
    elif "HIGH" in risk_label:
        risk_theme = "amber"
        risk_color = "#f59e0b"
    elif "MED" in risk_label:
        risk_theme = "cyan"
        risk_color = "#06b6d4"
    else:
        risk_theme = "emerald"
        risk_color = "#10b981"

    # Surface info
    attack_surface = report_data.get("attack_surface", {})
    open_ports = attack_surface.get("open_ports", {})
    detected_tech = attack_surface.get("detected_technologies", [])
    detected_waf = attack_surface.get("detected_waf", {})
    primary_waf = detected_waf.get("primary_waf", "None") if detected_waf else "None"
    endpoints_count = len(attack_surface.get("parameterized_endpoints", {}))
    subdomains_count = len(attack_surface.get("subdomains", []))

    # Findings
    findings = report_data.get("findings", [])
    roadmap = report_data.get("prioritized_roadmap", [])
    methodology = report_data.get("methodology", [])

    # Format findings cards HTML
    findings_cards_html = []
    for idx, f in enumerate(findings, 1):
        f_title = html.escape(str(f.get("title", "Untitled Finding")))
        f_sev = html.escape(str(f.get("severity", "INFO")).upper())
        f_desc = html.escape(str(f.get("description", ""))).replace("\n", "<br>")
        f_impact = html.escape(str(f.get("impact", ""))).replace("\n", "<br>")
        f_remed = html.escape(str(f.get("remediation", ""))).replace("\n", "<br>")
        f_tool = html.escape(str(f.get("tool_source", "N/A")))
        f_cve = html.escape(str(f.get("cve_id", "N/A")))
        f_cvss = f.get("cvss_score")
        f_cvss_str = f"{f_cvss:.1f}" if f_cvss is not None else "N/A"
        f_vector = html.escape(str(f.get("cvss_vector", "N/A")))
        f_epss = f.get("epss_score")
        f_epss_str = f"{f_epss * 100:.1f}%" if f_epss is not None else "N/A"
        f_cisa = "CÓ (Đang bị khai thác)" if f.get("cisa_kev") else "Không"
        f_owasp = html.escape(str(f.get("owasp_category", "A05:2021 - Security Misconfiguration")))
        f_evidence = html.escape(str(f.get("raw_evidence", "")))
        f_rem_code = html.escape(str(f.get("remediation_code", "")))

        sev_class = f_sev.lower()

        card = f"""
        <div class="finding-card {sev_class}" data-severity="{f_sev}" data-owasp="{f_owasp}">
            <div class="finding-header" onclick="toggleAccordion('f-{idx}')">
                <div class="finding-title-group">
                    <span class="badge badge-{sev_class}">{f_sev}</span>
                    <h3 class="finding-title">#{idx}. {f_title}</h3>
                </div>
                <div class="finding-meta-tags">
                    {f'<span class="pill pill-cve">{f_cve}</span>' if f_cve != 'N/A' else ''}
                    <span class="pill pill-tool">{f_tool}</span>
                    <span class="chevron" id="chev-f-{idx}">▼</span>
                </div>
            </div>
            <div class="finding-body" id="f-{idx}">
                <div class="meta-grid">
                    <div class="meta-item"><span class="meta-lbl">Điểm CVSS v3.1:</span> <span class="meta-val font-bold">{f_cvss_str}</span></div>
                    <div class="meta-item"><span class="meta-lbl">Vector CVSS:</span> <span class="meta-val font-mono">{f_vector}</span></div>
                    <div class="meta-item"><span class="meta-lbl">Xác suất EPSS:</span> <span class="meta-val font-bold text-amber">{f_epss_str}</span></div>
                    <div class="meta-item"><span class="meta-lbl">CISA KEV Catalog:</span> <span class="meta-val {'text-rose font-bold' if f.get('cisa_kev') else ''}">{f_cisa}</span></div>
                    <div class="meta-item full"><span class="meta-lbl">Danh mục OWASP:</span> <span class="meta-val">{f_owasp}</span></div>
                </div>

                <div class="section-block">
                    <h4 class="block-title">Mô Tả Kỹ Thuật:</h4>
                    <p class="block-content">{f_desc or 'Không có mô tả chi tiết.'}</p>
                </div>

                <div class="section-block">
                    <h4 class="block-title">Đánh Giá Tác Động Doanh Nghiệp:</h4>
                    <p class="block-content">{f_impact or 'Có nguy cơ gây rủi ro an ninh.'}</p>
                </div>

                <div class="section-block">
                    <h4 class="block-title">Biện Pháp Khắc Phục Khuyến Nghị:</h4>
                    <p class="block-content">{f_remed or 'Áp dụng bản vá bảo mật mới nhất.'}</p>
                </div>

                {f'''
                <div class="section-block code-block-wrap">
                    <div class="code-header">
                        <span class="code-title">💻 Mã Nguồn / Cấu Hình Khắc Phục Thực Chiến (Actionable Fix):</span>
                        <button class="btn-copy" onclick="copySnippet('code-{idx}')">Sao Chép Code</button>
                    </div>
                    <pre><code id="code-{idx}">{f_rem_code}</code></pre>
                </div>
                ''' if f_rem_code else ''}

                {f'''
                <div class="section-block">
                    <details class="evidence-details">
                        <summary>🔍 Bằng chứng Thực nghiệm (Raw Proof-of-Concept Evidence)</summary>
                        <pre class="evidence-pre"><code>{f_evidence[:2000]}</code></pre>
                    </details>
                </div>
                ''' if f_evidence else ''}
            </div>
        </div>
        """
        findings_cards_html.append(card)

    findings_html_str = "\n".join(findings_cards_html) if findings_cards_html else "<p class='no-findings'>Không phát hiện lỗ hổng bảo mật nào trong phiên kiểm thử này.</p>"

    # Roadmap rows HTML
    roadmap_rows = []
    for r in roadmap:
        phase = html.escape(str(r.get("phase", "")))
        prio = html.escape(str(r.get("priority", "HIGH")))
        item = html.escape(str(r.get("action_item", "")))
        comp = html.escape(str(r.get("target_component", "")))
        owner = html.escape(str(r.get("owner", "")))
        effort = html.escape(str(r.get("effort", "")))
        p_class = "rose" if prio == "CRITICAL" else ("amber" if prio == "HIGH" else "cyan")
        roadmap_rows.append(f"""
        <tr>
            <td><strong class="text-{p_class}">{phase}</strong></td>
            <td><span class="badge badge-{p_class.lower()}">{prio}</span></td>
            <td>{item}</td>
            <td><code>{comp}</code></td>
            <td>{owner}</td>
            <td>{effort}</td>
        </tr>
        """)
    roadmap_html_str = "\n".join(roadmap_rows) if roadmap_rows else "<tr><td colspan='6' class='text-center'>Không có hạng mục lộ trình.</td></tr>"

    # Ports badges HTML
    ports_badges = []
    for p, pinfo in open_ports.items():
        svc = pinfo.get("service", "unknown") if isinstance(pinfo, dict) else "open"
        ports_badges.append(f"<span class='tag-port'><span class='p-num'>{p}</span>/<span class='p-svc'>{svc}</span></span>")
    ports_html_str = "".join(ports_badges) if ports_badges else "<span class='text-muted'>Chưa phát hiện cổng mở</span>"

    # Technologies badges HTML
    tech_badges = [f"<span class='tag-tech'>{html.escape(t)}</span>" for t in detected_tech]
    tech_html_str = "".join(tech_badges) if tech_badges else "<span class='text-muted'>Chưa nhận diện</span>"

    html_template = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Báo Cáo An Ninh Mạng — {target}</title>
    <style>
        :root {{
            --bg-base: #0a0f1d;
            --bg-surface: #111827;
            --bg-elevated: #1f2937;
            --border: #374151;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --color-rose: #f43f5e;
            --color-amber: #f59e0b;
            --color-cyan: #06b6d4;
            --color-emerald: #10b981;
            --color-blue: #3b82f6;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: var(--font-sans);
            line-height: 1.6;
            padding: 24px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        /* Header Hero */
        .hero {{
            background: linear-gradient(135deg, rgba(31, 41, 55, 0.7), rgba(17, 24, 39, 0.9));
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(8px);
        }}
        .hero-top {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 20px; }}
        .hero-title h1 {{ font-size: 26px; font-weight: 800; letter-spacing: -0.5px; color: #fff; }}
        .hero-title p {{ color: var(--text-muted); font-size: 14px; margin-top: 4px; }}
        .badge-risk-hero {{
            padding: 8px 18px;
            border-radius: 9999px;
            font-weight: 800;
            font-size: 15px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: rgba(244, 63, 94, 0.2);
            color: var(--color-rose);
            border: 1px solid var(--color-rose);
        }}
        
        /* Metric Cards Grid */
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .metric-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}
        .metric-card .label {{ color: var(--text-muted); font-size: 13px; text-transform: uppercase; font-weight: 600; }}
        .metric-card .val {{ font-size: 32px; font-weight: 800; margin-top: 6px; }}
        
        /* Severity Bar */
        .sev-bar-wrap {{ margin-top: 14px; display: flex; height: 10px; border-radius: 9999px; overflow: hidden; background: var(--bg-elevated); }}
        .sev-seg-crit {{ background: var(--color-rose); }}
        .sev-seg-high {{ background: var(--color-amber); }}
        .sev-seg-med {{ background: var(--color-cyan); }}
        .sev-seg-low {{ background: var(--color-emerald); }}

        /* Attack Surface Panel */
        .surface-panel {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 22px;
            margin-bottom: 24px;
        }}
        .panel-heading {{ font-size: 18px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }}
        .surface-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
        .surface-box {{ background: var(--bg-elevated); padding: 14px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.05); }}
        .surface-box h4 {{ font-size: 13px; color: var(--text-muted); margin-bottom: 10px; }}
        .tag-port, .tag-tech {{ display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; border-radius: 6px; font-size: 12px; margin: 3px; font-family: var(--font-mono); }}
        .tag-port {{ background: rgba(59, 130, 246, 0.2); border: 1px solid rgba(59, 130, 246, 0.4); color: #93c5fd; }}
        .tag-tech {{ background: rgba(16, 185, 129, 0.2); border: 1px solid rgba(16, 185, 129, 0.4); color: #a7f3d0; }}

        /* Controls & Filter Bar */
        .filter-bar {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 18px; }}
        .btn-filter {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .btn-filter:hover, .btn-filter.active {{ background: #2563eb; border-color: #3b82f6; color: #fff; }}
        .search-box {{
            flex-grow: 1;
            min-width: 220px;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: #fff;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 14px;
        }}

        /* Findings Accordion */
        .finding-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 14px;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        .finding-card:hover {{ border-color: #4b5563; }}
        .finding-card.critical {{ border-left: 5px solid var(--color-rose); }}
        .finding-card.high {{ border-left: 5px solid var(--color-amber); }}
        .finding-card.medium {{ border-left: 5px solid var(--color-cyan); }}
        .finding-card.low {{ border-left: 5px solid var(--color-emerald); }}
        
        .finding-header {{
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .finding-title-group {{ display: flex; align-items: center; gap: 12px; }}
        .finding-title {{ font-size: 16px; font-weight: 700; color: #f3f4f6; }}
        .badge {{ padding: 3px 10px; border-radius: 6px; font-size: 11px; font-weight: 800; text-transform: uppercase; }}
        .badge-critical, .badge-rose {{ background: rgba(244, 63, 94, 0.2); color: var(--color-rose); border: 1px solid rgba(244,63,94,0.4); }}
        .badge-high, .badge-amber {{ background: rgba(245, 158, 11, 0.2); color: var(--color-amber); border: 1px solid rgba(245,158,11,0.4); }}
        .badge-medium, .badge-cyan {{ background: rgba(6, 182, 212, 0.2); color: var(--color-cyan); border: 1px solid rgba(6,182,212,0.4); }}
        .badge-low, .badge-emerald {{ background: rgba(16, 185, 129, 0.2); color: var(--color-emerald); border: 1px solid rgba(16,185,129,0.4); }}
        
        .finding-meta-tags {{ display: flex; align-items: center; gap: 8px; }}
        .pill {{ padding: 2px 8px; border-radius: 4px; font-size: 12px; font-family: var(--font-mono); background: var(--bg-elevated); color: var(--text-muted); }}
        .pill-cve {{ background: rgba(244,63,94,0.15); color: #fda4af; }}
        .chevron {{ font-size: 12px; color: var(--text-muted); transition: transform 0.2s; }}

        .finding-body {{ padding: 0 20px 20px 20px; display: none; border-top: 1px solid rgba(255,255,255,0.05); margin-top: 10px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; padding: 14px 0; border-bottom: 1px solid var(--border); }}
        .meta-item {{ font-size: 13px; }}
        .meta-item.full {{ grid-column: 1 / -1; }}
        .meta-lbl {{ color: var(--text-muted); margin-right: 4px; }}
        
        .section-block {{ margin-top: 16px; }}
        .block-title {{ font-size: 13px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; margin-bottom: 6px; }}
        .block-content {{ font-size: 14px; color: #e5e7eb; }}

        /* Code Snippet Box */
        .code-block-wrap {{
            background: #030712;
            border: 1px solid #1f2937;
            border-radius: 8px;
            overflow: hidden;
            margin-top: 14px;
        }}
        .code-header {{
            background: #111827;
            padding: 8px 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1f2937;
        }}
        .code-title {{ font-size: 12px; font-weight: 600; color: #a5f3fc; }}
        .btn-copy {{
            background: #374151;
            border: none;
            color: #fff;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .btn-copy:hover {{ background: #4b5563; }}
        pre {{ padding: 14px; overflow-x: auto; font-family: var(--font-mono); font-size: 13px; color: #38bdf8; line-height: 1.5; }}
        .evidence-details summary {{ font-size: 13px; color: var(--color-cyan); cursor: pointer; padding: 6px 0; font-weight: 600; }}
        .evidence-pre {{ max-height: 250px; overflow-y: auto; background: #030712; border-radius: 6px; }}

        /* Table */
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
        th, td {{ padding: 12px; border-bottom: 1px solid var(--border); text-align: left; }}
        th {{ background: var(--bg-elevated); color: var(--text-muted); font-weight: 700; text-transform: uppercase; font-size: 12px; }}

        /* Utility classes */
        .text-rose {{ color: var(--color-rose); }}
        .text-amber {{ color: var(--color-amber); }}
        .text-cyan {{ color: var(--color-cyan); }}
        .text-emerald {{ color: var(--color-emerald); }}
        .font-bold {{ font-weight: 700; }}
        .font-mono {{ font-family: var(--font-mono); }}

        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .btn-filter, .search-box, .btn-copy, .filter-bar {{ display: none; }}
            .finding-body {{ display: block !important; }}
            .hero, .metric-card, .surface-panel, .finding-card {{ border: 1px solid #ccc; box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Hero Header -->
        <header class="hero">
            <div class="hero-top">
                <div class="hero-title">
                    <h1>🛡️ Báo Cáo Đánh Giá An Ninh Mạng Toàn Diện</h1>
                    <p>Mục tiêu: <strong>{target}</strong> | Chế độ: <strong>{scan_mode}</strong> | Thời lượng: <strong>{duration}</strong></p>
                </div>
                <div class="badge-risk-hero">Mức độ rủi ro: {risk_label} ({risk_score:.1f}/10)</div>
            </div>
            <p class="hero-summary"><strong>Tóm tắt điều hành:</strong> {exec_summary}</p>
        </header>

        <!-- Metrics Overview -->
        <section class="metrics-grid">
            <div class="metric-card">
                <span class="label">Tổng Lỗ Hổng Phát Hiện</span>
                <span class="val text-rose">{total_findings}</span>
                <div class="sev-bar-wrap">
                    <div class="sev-seg-crit" style="width: {(crit_count/max(1, total_findings))*100}%"></div>
                    <div class="sev-seg-high" style="width: {(high_count/max(1, total_findings))*100}%"></div>
                    <div class="sev-seg-med" style="width: {(med_count/max(1, total_findings))*100}%"></div>
                    <div class="sev-seg-low" style="width: {(low_count/max(1, total_findings))*100}%"></div>
                </div>
            </div>
            <div class="metric-card">
                <span class="label">Phát Hiện Nghiêm Trọng / Cao</span>
                <span class="val text-rose">{crit_count} <span style="font-size: 18px; color: var(--color-amber);">/ {high_count}</span></span>
            </div>
            <div class="metric-card">
                <span class="label">Cổng Dịch Vụ Mở</span>
                <span class="val text-cyan">{len(open_ports)}</span>
            </div>
            <div class="metric-card">
                <span class="label">Endpoints Tham Số / Subdomains</span>
                <span class="val text-emerald">{endpoints_count} <span style="font-size: 18px; color: var(--text-muted);">/ {subdomains_count}</span></span>
            </div>
        </section>

        <!-- Attack Surface Panel -->
        <section class="surface-panel">
            <h3 class="panel-heading">🌐 Bề Mặt Tấn Công & Công Nghệ Nhận Diện</h3>
            <div class="surface-grid">
                <div class="surface-box">
                    <h4>Cổng Mở & Dịch Vụ Mạng:</h4>
                    {ports_html_str}
                </div>
                <div class="surface-box">
                    <h4>Công Nghệ Máy Chủ Phát Hiện:</h4>
                    {tech_html_str}
                </div>
                <div class="surface-box">
                    <h4>Hệ Thống Tường Lửa Ứng Dụng Web (WAF):</h4>
                    <span class="font-bold text-amber">{primary_waf}</span>
                </div>
            </div>
        </section>

        <!-- Detailed Findings Section -->
        <section class="findings-section">
            <h3 class="panel-heading">🔍 Danh Mục Hồ Sơ Lỗ Hổng Chi Tiết ({total_findings})</h3>
            
            <!-- Filters -->
            <div class="filter-bar">
                <button class="btn-filter active" onclick="filterFindings('ALL')">Tất cả ({total_findings})</button>
                <button class="btn-filter" onclick="filterFindings('CRITICAL')">🔴 Critical ({crit_count})</button>
                <button class="btn-filter" onclick="filterFindings('HIGH')">🟠 High ({high_count})</button>
                <button class="btn-filter" onclick="filterFindings('MEDIUM')">🟡 Medium ({med_count})</button>
                <button class="btn-filter" onclick="filterFindings('LOW')">🔵 Low ({low_count})</button>
                <input type="text" id="findingSearch" class="search-box" placeholder="🔍 Tìm kiếm lỗ hổng theo từ khóa, CVE, mã lỗi..." onkeyup="searchFindings()">
            </div>

            <div id="findingsContainer">
                {findings_html_str}
            </div>
        </section>

        <!-- Prioritized Roadmap -->
        <section class="surface-panel" style="margin-top: 24px;">
            <h3 class="panel-heading">📋 Lộ Trình Khắc Phục Phân Tầng Thời Gian (Remediation Roadmap)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Giai Đoạn</th>
                        <th>Mức Ưu Tiên</th>
                        <th>Hạng Mục Khắc Phục</th>
                        <th>Thành Phần Mục Tiêu</th>
                        <th>Bộ Phận Phụ Trách</th>
                        <th>Nỗ Lực</th>
                    </tr>
                </thead>
                <tbody>
                    {roadmap_html_str}
                </tbody>
            </table>
        </section>
    </div>

    <script>
        function toggleAccordion(id) {{
            const el = document.getElementById(id);
            const chev = document.getElementById('chev-' + id);
            if (el.style.display === 'block') {{
                el.style.display = 'none';
                if (chev) chev.innerText = '▼';
            }} else {{
                el.style.display = 'block';
                if (chev) chev.innerText = '▲';
            }}
        }}

        function filterFindings(sev) {{
            const btns = document.querySelectorAll('.btn-filter');
            btns.forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (sev === 'ALL' || card.getAttribute('data-severity') === sev) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        function searchFindings() {{
            const query = document.getElementById('findingSearch').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                const text = card.innerText.toLowerCase();
                card.style.display = text.includes(query) ? 'block' : 'none';
            }});
        }}

        function copySnippet(id) {{
            const codeEl = document.getElementById(id);
            if (!codeEl) return;
            navigator.clipboard.writeText(codeEl.innerText).then(() => {{
                event.target.innerText = 'Đã Sao Chép!';
                setTimeout(() => {{ event.target.innerText = 'Sao Chép Code'; }}, 2000);
            }});
        }}
    </script>
</body>
</html>
"""

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)

    return html_template
