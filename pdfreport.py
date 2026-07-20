"""
pdfreport.py — Multi-format report generation for CySyMo (Brique 5).

Exports:
  - PDF  via ReportLab (Platypus)
  - DOCX via python-docx
  - HTML via plain string templating (self-contained, inline CSS)

Public API:
  build_pdf(model_dict, formula, risk_value, level, normalised) -> bytes
  build_docx(model_dict, formula, risk_value, level, normalised) -> bytes
  build_html(model_dict, formula, risk_value, level, normalised) -> str
"""

from __future__ import annotations
import io
import datetime

# ─────────────────────────────────────────────────────────────
#  Shared helpers
# ─────────────────────────────────────────────────────────────

LEVEL_COLORS = {"Low": "#1F9D74", "Moderate": "#D6982B", "High": "#D8433A"}
OCTAVE = ["actor", "motive", "access", "outcome"]

def _ts():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

def _level_color(level: str) -> str:
    return LEVEL_COLORS.get(level, "#6B6F7B")


# ─────────────────────────────────────────────────────────────
#  PDF  (ReportLab Platypus)
# ─────────────────────────────────────────────────────────────

def build_pdf(model_dict: dict, formula: str, risk_value: float,
              level: str, normalised: float) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    # custom styles
    title_style = ParagraphStyle("CTitle", parent=styles["Title"],
                                 fontSize=22, spaceAfter=6)
    h1 = ParagraphStyle("CH1", parent=styles["Heading1"],
                        fontSize=14, spaceAfter=4, spaceBefore=14,
                        textColor=colors.HexColor("#15161C"))
    h2 = ParagraphStyle("CH2", parent=styles["Heading2"],
                        fontSize=11, spaceAfter=4, spaceBefore=8,
                        textColor=colors.HexColor("#4F46E5"))
    body = ParagraphStyle("CBody", parent=styles["Normal"],
                          fontSize=9.5, leading=14, spaceAfter=4)
    mono = ParagraphStyle("CMono", parent=styles["Normal"],
                          fontSize=9, fontName="Courier", spaceAfter=2)

    lc = colors.HexColor(_level_color(level))

    def tbl_style(header_color=colors.HexColor("#4F46E5")):
        return TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), header_color),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0), 8),
            ("FONTSIZE",    (0, 1), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F5F5F8")]),
            ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#EAEAF0")),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ])

    story = []

    # ── Title page ──
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("CySyMo", title_style))
    story.append(Paragraph("Cyber System Risk Assessment Report", styles["Heading2"]))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(f"Generated: {_ts()}", body))
    story.append(Spacer(1, 0.8*cm))

    # Risk summary box (simulate with a 1-row table)
    formula_label = {"mean": "Mean risk (CySyMo default)",
                     "total": "Total risk (un-normalised)",
                     "max": "Worst-case risk"}.get(formula, formula)
    pct = f"{normalised*100:.1f}%"
    r_str = f"{risk_value:.4f}" if formula != "total" else f"{risk_value:.2f}"

    summary_data = [
        ["Risk Score (R)", "Level", "% of Maximum", "Formula"],
        [r_str, level, pct, formula_label],
    ]
    summary_tbl = Table(summary_data, colWidths=[3.5*cm, 2.5*cm, 3*cm, 7.5*cm])
    summary_tbl.setStyle(tbl_style(lc))
    story.append(summary_tbl)
    story.append(Spacer(1, 0.6*cm))

    # ── Executive Summary ──
    story.append(Paragraph("Executive Summary", h1))
    vuln_count = len(model_dict.get("vulnerabilities", []))
    threat_count = len(model_dict.get("threats", []))
    asset_count = len(model_dict.get("assets", []))
    story.append(Paragraph(
        f"This report summarises the cyber risk assessment produced by CySyMo using the "
        f"formula <b>R = e · A<sub rise='-3' size='7'>I</sub> · p</b>. "
        f"The model covers <b>{vuln_count}</b> vulnerabilit{'y' if vuln_count==1 else 'ies'}, "
        f"<b>{threat_count}</b> threat{'s' if threat_count!=1 else ''}, and "
        f"<b>{asset_count}</b> critical asset{'s' if asset_count!=1 else ''}. "
        f"The overall risk score is <b>{r_str}</b>, rated <b>{level}</b> "
        f"({pct} of the theoretical maximum).",
        body))
    story.append(Spacer(1, 0.4*cm))

    # ── Assets ──
    assets = model_dict.get("assets", [])
    if assets:
        story.append(Paragraph("Critical Assets", h1))
        rows = [["ID", "Description"]]
        for a in assets:
            rows.append([a.get("id",""), a.get("description","")])
        t = Table(rows, colWidths=[2.5*cm, 14*cm])
        t.setStyle(tbl_style())
        story.append(t)
        story.append(Spacer(1, 0.4*cm))

    # ── Vulnerabilities ──
    vulns = model_dict.get("vulnerabilities", [])
    if vulns:
        story.append(Paragraph("Vulnerabilities", h1))
        rows = [["ID", "Description", "NIST Control", "Effectiveness", "Asset"]]
        for v in vulns:
            eff = f"{float(v.get('effectiveness',0))*100:.0f}%"
            rows.append([
                v.get("id",""),
                Paragraph(v.get("description",""), body),
                f"{v.get('nist_control','')} {v.get('nist_title','')}".strip(),
                eff,
                v.get("asset_id",""),
            ])
        t = Table(rows, colWidths=[1.8*cm, 6.5*cm, 4.5*cm, 2*cm, 1.7*cm])
        t.setStyle(tbl_style())
        story.append(t)
        story.append(Spacer(1, 0.4*cm))

    # ── Threats ──
    threats = model_dict.get("threats", [])
    if threats:
        story.append(Paragraph("Threats", h1))
        rows = [["ID", "Description", "Actor", "Motive", "Access", "Outcome", "Prob."]]
        for t_ in threats:
            rows.append([
                t_.get("id",""),
                Paragraph(t_.get("description",""), body),
                t_.get("actor",""),
                t_.get("motive",""),
                t_.get("access",""),
                t_.get("outcome",""),
                f"{float(t_.get('probability',1)):.2f}",
            ])
        t = Table(rows, colWidths=[1.5*cm, 5.5*cm, 2*cm, 2*cm, 2*cm, 2*cm, 1.5*cm])
        t.setStyle(tbl_style())
        story.append(t)
        story.append(Spacer(1, 0.4*cm))

    # ── Impact matrix ──
    impacts_list = model_dict.get("impacts", [])
    if impacts_list and vulns and threats:
        story.append(Paragraph("Impact Matrix (A<sub rise='-3' size='9'>I</sub>)", h1))
        story.append(Paragraph(
            "Cell (i, j) = impact of threat j exploiting vulnerability i. "
            "Values in [0, 1]: 0 = no impact, 1 = catastrophic.", body))
        story.append(Spacer(1, 0.2*cm))
        imp_map = {(r["vuln_id"], r["threat_id"]): r["value"] for r in impacts_list}
        t_ids = [t_.get("id","") for t_ in threats]
        header = [""] + t_ids
        matrix_rows = [header]
        for v in vulns:
            row = [v.get("id","")]
            for t_ in threats:
                val = imp_map.get((v.get("id",""), t_.get("id","")), 0)
                row.append(f"{float(val):.2f}")
            matrix_rows.append(row)
        col_w = max(1.0*cm, 16.5*cm / (len(t_ids)+1))
        mt = Table(matrix_rows, colWidths=[col_w]*(len(t_ids)+1))
        mt.setStyle(tbl_style())
        story.append(mt)
        story.append(Spacer(1, 0.4*cm))

    # ── Recommendations ──
    story.append(Paragraph("Recommendations", h1))
    if level == "High":
        rec = ("The assessed risk level is <b>High</b>. Immediate remediation is recommended. "
               "Prioritise controls for vulnerabilities with the highest exposure (e close to 1.0) "
               "paired with high-probability threats.")
    elif level == "Moderate":
        rec = ("The assessed risk level is <b>Moderate</b>. Review controls for vulnerabilities "
               "with moderate exposure and consider strengthening NIST controls where effectiveness "
               "is below 0.5.")
    else:
        rec = ("The assessed risk level is <b>Low</b>. Continue monitoring the threat landscape "
               "and schedule periodic reassessments to maintain this risk posture.")
    story.append(Paragraph(rec, body))
    story.append(Spacer(1, 0.6*cm))

    # ── Footer note ──
    story.append(Paragraph(
        f"<i>CySyMo — Cyber System Risk Model · Report generated {_ts()}</i>",
        ParagraphStyle("footer", parent=body, fontSize=8,
                       textColor=colors.HexColor("#9AA0AD"))))

    doc.build(story)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────
#  DOCX  (python-docx)
# ─────────────────────────────────────────────────────────────

def build_docx(model_dict: dict, formula: str, risk_value: float,
               level: str, normalised: float) -> bytes:
    from docx import Document
    from docx.shared import Pt, RGBColor, Cm
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement

    doc = Document()

    # page margins
    for section in doc.sections:
        section.top_margin    = Cm(2.5)
        section.bottom_margin = Cm(2.5)
        section.left_margin   = Cm(2.5)
        section.right_margin  = Cm(2.5)

    accent = RGBColor(0x4F, 0x46, 0xE5)
    lc_hex = _level_color(level)
    lc_rgb = RGBColor(
        int(lc_hex[1:3],16), int(lc_hex[3:5],16), int(lc_hex[5:7],16))

    def set_cell_bg(cell, hex_color):
        tc   = cell._tc
        tcPr = tc.get_or_add_tcPr()
        shd  = OxmlElement("w:shd")
        shd.set(qn("w:val"),   "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"),  hex_color.lstrip("#"))
        tcPr.append(shd)

    def add_table(headers, rows, col_widths_cm=None):
        t = doc.add_table(rows=1, cols=len(headers))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.LEFT
        hdr_cells = t.rows[0].cells
        for i, h in enumerate(headers):
            hdr_cells[i].text = h
            hdr_cells[i].paragraphs[0].runs[0].bold = True
            hdr_cells[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF,0xFF,0xFF)
            hdr_cells[i].paragraphs[0].runs[0].font.size = Pt(8)
            set_cell_bg(hdr_cells[i], "4F46E5")
        for row_data in rows:
            r = t.add_row().cells
            for i, val in enumerate(row_data):
                r[i].text = str(val)
                for para in r[i].paragraphs:
                    for run in para.runs:
                        run.font.size = Pt(8)
        if col_widths_cm:
            for i, row in enumerate(t.rows):
                for j, cell in enumerate(row.cells):
                    if j < len(col_widths_cm):
                        cell.width = Cm(col_widths_cm[j])
        return t

    # ── Title ──
    title = doc.add_heading("CySyMo", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT
    sub = doc.add_paragraph("Cyber System Risk Assessment Report")
    sub.runs[0].font.size = Pt(13)
    sub.runs[0].font.color.rgb = RGBColor(0x6B,0x6F,0x7B)
    doc.add_paragraph(f"Generated: {_ts()}").runs[0].font.size = Pt(9)
    doc.add_paragraph()

    # ── Risk summary ──
    formula_label = {"mean":"Mean risk","total":"Total risk","max":"Worst-case"}.get(formula,formula)
    r_str = f"{risk_value:.4f}" if formula != "total" else f"{risk_value:.2f}"
    pct   = f"{normalised*100:.1f}%"
    add_table(
        ["Risk Score (R)", "Level", "% of Maximum", "Formula"],
        [[r_str, level, pct, formula_label]],
        [3, 2.5, 3, 7],
    )
    doc.add_paragraph()

    # ── Executive Summary ──
    doc.add_heading("Executive Summary", 1)
    vuln_count   = len(model_dict.get("vulnerabilities",[]))
    threat_count = len(model_dict.get("threats",[]))
    asset_count  = len(model_dict.get("assets",[]))
    p = doc.add_paragraph(
        f"This report summarises the cyber risk assessment produced by CySyMo "
        f"(R = e · AI · p). The model covers {vuln_count} "
        f"vulnerabilit{'y' if vuln_count==1 else 'ies'}, "
        f"{threat_count} threat{'s' if threat_count!=1 else ''}, and "
        f"{asset_count} critical asset{'s' if asset_count!=1 else ''}. "
        f"The overall risk score is {r_str}, rated {level} ({pct} of maximum).")
    p.runs[0].font.size = Pt(10)

    # ── Assets ──
    assets = model_dict.get("assets", [])
    if assets:
        doc.add_heading("Critical Assets", 1)
        add_table(["ID","Description"],
                  [[a.get("id",""), a.get("description","")] for a in assets],
                  [2.5, 13])

    # ── Vulnerabilities ──
    vulns = model_dict.get("vulnerabilities", [])
    if vulns:
        doc.add_heading("Vulnerabilities", 1)
        add_table(
            ["ID","Description","NIST Control","Effectiveness","Asset"],
            [[v.get("id",""), v.get("description",""),
              f"{v.get('nist_control','')} {v.get('nist_title','')}".strip(),
              f"{float(v.get('effectiveness',0))*100:.0f}%",
              v.get("asset_id","")] for v in vulns],
            [1.8, 6.5, 4.5, 2, 1.7],
        )

    # ── Threats ──
    threats = model_dict.get("threats", [])
    if threats:
        doc.add_heading("Threats", 1)
        add_table(
            ["ID","Description","Actor","Motive","Access","Outcome","Prob."],
            [[t.get("id",""), t.get("description",""),
              t.get("actor",""), t.get("motive",""),
              t.get("access",""), t.get("outcome",""),
              f"{float(t.get('probability',1)):.2f}"] for t in threats],
            [1.5, 5.5, 2, 2, 2, 2, 1.5],
        )

    # ── Impact matrix ──
    impacts_list = model_dict.get("impacts", [])
    if impacts_list and vulns and threats:
        doc.add_heading("Impact Matrix (AI)", 1)
        doc.add_paragraph("Cell (i,j) = impact of threat j on vulnerability i. Range [0,1]."
                          ).runs[0].font.size = Pt(9)
        imp_map = {(r["vuln_id"],r["threat_id"]): r["value"] for r in impacts_list}
        t_ids   = [t.get("id","") for t in threats]
        headers = [""] + t_ids
        rows    = []
        for v in vulns:
            row = [v.get("id","")]
            for t in threats:
                val = imp_map.get((v.get("id",""), t.get("id","")), 0)
                row.append(f"{float(val):.2f}")
            rows.append(row)
        add_table(headers, rows)

    # ── Recommendations ──
    doc.add_heading("Recommendations", 1)
    if level == "High":
        rec = ("Risk level is HIGH. Immediate remediation recommended. "
               "Prioritise controls for vulnerabilities with high exposure (e ≈ 1) "
               "paired with high-probability threats.")
    elif level == "Moderate":
        rec = ("Risk level is MODERATE. Review and strengthen controls where "
               "effectiveness is below 0.5. Schedule a follow-up assessment.")
    else:
        rec = ("Risk level is LOW. Continue monitoring the threat landscape "
               "and reassess periodically.")
    doc.add_paragraph(rec).runs[0].font.size = Pt(10)

    doc.add_paragraph()
    footer = doc.add_paragraph(f"CySyMo · Report generated {_ts()}")
    footer.runs[0].font.size  = Pt(8)
    footer.runs[0].font.color.rgb = RGBColor(0x9A,0xA0,0xAD)
    footer.runs[0].font.italic = True

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────
#  HTML  (self-contained, inline CSS)
# ─────────────────────────────────────────────────────────────

def build_html(model_dict: dict, formula: str, risk_value: float,
               level: str, normalised: float) -> str:
    lc = _level_color(level)
    r_str = f"{risk_value:.4f}" if formula != "total" else f"{risk_value:.2f}"
    pct   = f"{normalised*100:.1f}"
    formula_label = {"mean":"Mean risk (CySyMo default)",
                     "total":"Total risk (un-normalised)",
                     "max":"Worst-case risk"}.get(formula, formula)

    def esc(s):
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    def table(headers, rows, notes=""):
        cols = len(headers)
        th = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body_rows = ""
        for i, row in enumerate(rows):
            cls = "even" if i % 2 else ""
            tds = "".join(f"<td>{esc(c)}</td>" for c in row)
            body_rows += f"<tr class='{cls}'>{tds}</tr>"
        note_html = f"<p class='note'>{esc(notes)}</p>" if notes else ""
        return f"""
        {note_html}
        <table>
          <thead><tr>{th}</tr></thead>
          <tbody>{body_rows}</tbody>
        </table>"""

    assets  = model_dict.get("assets", [])
    vulns   = model_dict.get("vulnerabilities", [])
    threats = model_dict.get("threats", [])
    impacts = model_dict.get("impacts", [])

    assets_html = ""
    if assets:
        rows = [[a.get("id",""), a.get("description","")] for a in assets]
        assets_html = "<h2>Critical Assets</h2>" + table(["ID","Description"], rows)

    vulns_html = ""
    if vulns:
        rows = [[v.get("id",""), v.get("description",""),
                 f"{v.get('nist_control','')} {v.get('nist_title','')}".strip(),
                 f"{float(v.get('effectiveness',0))*100:.0f}%",
                 v.get("asset_id","")] for v in vulns]
        vulns_html = "<h2>Vulnerabilities</h2>" + table(
            ["ID","Description","NIST Control","Effectiveness","Asset"], rows)

    threats_html = ""
    if threats:
        rows = [[t.get("id",""), t.get("description",""),
                 t.get("actor",""), t.get("motive",""),
                 t.get("access",""), t.get("outcome",""),
                 f"{float(t.get('probability',1)):.2f}"] for t in threats]
        threats_html = "<h2>Threats</h2>" + table(
            ["ID","Description","Actor","Motive","Access","Outcome","Prob."], rows)

    matrix_html = ""
    if impacts and vulns and threats:
        imp_map = {(r["vuln_id"],r["threat_id"]): r["value"] for r in impacts}
        t_ids   = [t.get("id","") for t in threats]
        headers = [""] + t_ids
        rows    = []
        for v in vulns:
            row = [v.get("id","")]
            for t in threats:
                val = imp_map.get((v.get("id",""), t.get("id","")), 0)
                row.append(f"{float(val):.2f}")
            rows.append(row)
        matrix_html = "<h2>Impact Matrix (A<sub>I</sub>)</h2>" + table(
            headers, rows,
            notes="Cell (i,j) = impact of threat j on vulnerability i. Range [0,1].")

    if level == "High":
        rec = ("Risk level is <strong>HIGH</strong>. Immediate remediation recommended. "
               "Prioritise controls for high-exposure vulnerabilities paired with "
               "high-probability threats.")
    elif level == "Moderate":
        rec = ("Risk level is <strong>MODERATE</strong>. Strengthen controls where "
               "effectiveness is below 50%. Schedule a follow-up assessment.")
    else:
        rec = ("Risk level is <strong>LOW</strong>. Continue monitoring and reassess "
               "periodically to maintain this risk posture.")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>CySyMo Risk Report</title>
<style>
  :root{{--accent:#4F46E5;--ink:#15161C;--muted:#6B6F7B;--line:#EAEAF0;
        --surface:#F5F5F8;--low:#1F9D74;--mod:#D6982B;--high:#D8433A}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;color:var(--ink);
        font-size:14px;line-height:1.6;padding:40px;max-width:960px;margin:0 auto}}
  h1{{font-size:28px;font-weight:700;letter-spacing:-.02em;margin-bottom:4px}}
  h2{{font-size:17px;font-weight:600;color:var(--accent);
      margin:32px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}}
  .subtitle{{font-size:15px;color:var(--muted);margin-bottom:4px}}
  .ts{{font-size:12px;color:#9AA0AD;margin-bottom:24px}}
  .summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}}
  .card{{background:var(--surface);border-radius:10px;padding:16px}}
  .card .k{{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#9AA0AD}}
  .card .v{{font-size:22px;font-weight:700;margin-top:6px}}
  .card .v.Low{{color:var(--low)}}.card .v.Moderate{{color:var(--mod)}}.card .v.High{{color:var(--high)}}
  table{{width:100%;border-collapse:collapse;margin-bottom:8px;font-size:13px}}
  thead tr{{background:var(--accent);color:#fff}}
  th{{text-align:left;padding:8px 10px;font-size:11px;font-weight:600;letter-spacing:.05em}}
  td{{padding:7px 10px;border-bottom:1px solid var(--line)}}
  tr.even td{{background:var(--surface)}}
  .note{{font-size:12px;color:var(--muted);margin-bottom:8px}}
  .rec{{background:#EEEDFC;border-left:4px solid var(--accent);
        padding:14px 16px;border-radius:6px;margin-top:8px;font-size:13px}}
  footer{{margin-top:40px;font-size:11px;color:#9AA0AD;border-top:1px solid var(--line);
          padding-top:12px}}
  @media print{{body{{padding:20px}}.summary{{grid-template-columns:repeat(2,1fr)}}}}
</style>
</head>
<body>
  <h1>CySyMo</h1>
  <p class="subtitle">Cyber System Risk Assessment Report</p>
  <p class="ts">Generated: {_ts()}</p>

  <div class="summary">
    <div class="card"><div class="k">Risk Score · R</div>
      <div class="v" style="color:{lc}">{esc(r_str)}</div></div>
    <div class="card"><div class="k">Risk Level</div>
      <div class="v {esc(level)}">{esc(level)}</div></div>
    <div class="card"><div class="k">% of Maximum</div>
      <div class="v">{pct}%</div></div>
    <div class="card"><div class="k">Formula</div>
      <div class="v" style="font-size:13px">{esc(formula_label)}</div></div>
  </div>

  <h2>Executive Summary</h2>
  <p>This report summarises the cyber risk assessment produced by CySyMo
  using the formula <strong>R = e · A<sub>I</sub> · p</strong>.
  The model covers <strong>{len(vulns)}</strong> vulnerability(-ies),
  <strong>{len(threats)}</strong> threat(s), and
  <strong>{len(assets)}</strong> critical asset(s).
  The overall risk score is <strong>{esc(r_str)}</strong>,
  rated <strong>{esc(level)}</strong> ({pct}% of maximum).</p>

  {assets_html}
  {vulns_html}
  {threats_html}
  {matrix_html}

  <h2>Recommendations</h2>
  <div class="rec">{rec}</div>

  <footer>CySyMo — Cyber System Risk Model &nbsp;·&nbsp; Report generated {_ts()}</footer>
</body>
</html>"""
