"""
sim_report.py — Generate a PDF report from a CySyMo adversarial simulation.
Called by backend.py: GET /api/simulation/{sim_id}/report
"""

import io
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── Colours ──────────────────────────────────────────
C_INK      = colors.HexColor("#1A2332")
C_ACCENT   = colors.HexColor("#4F46E5")
C_ATK      = colors.HexColor("#D8433A")
C_DEF      = colors.HexColor("#1F9D74")
C_MUTED    = colors.HexColor("#6B7280")
C_SURFACE  = colors.HexColor("#F8F9FA")
C_LINE     = colors.HexColor("#E5E7EB")
C_HIGH     = colors.HexColor("#D8433A")
C_MOD      = colors.HexColor("#E9A23B")
C_LOW      = colors.HexColor("#1F9D74")


def risk_color(r: float):
    if r >= 0.66: return C_HIGH
    if r >= 0.33: return C_MOD
    return C_LOW


def risk_label(r: float) -> str:
    if r >= 0.66: return "HIGH"
    if r >= 0.33: return "MODERATE"
    return "LOW"


def generate_simulation_report(state: dict) -> bytes:
    """
    Generate a PDF report from a simulation state dict.
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title="CySyMo Simulation Report",
        author="CySyMo",
    )

    W = A4[0] - 4*cm   # usable width

    # ── Styles ──
    base = getSampleStyleSheet()

    def style(name, **kw):
        s = ParagraphStyle(name, parent=base["Normal"], **kw)
        return s

    S_TITLE   = style("Title2",   fontSize=22, fontName="Helvetica-Bold",   textColor=C_INK,    spaceAfter=4,  leading=28)
    S_SUB     = style("Sub",      fontSize=11, fontName="Helvetica",         textColor=C_MUTED,  spaceAfter=16)
    S_H1      = style("H1",       fontSize=13, fontName="Helvetica-Bold",   textColor=C_ACCENT, spaceBefore=16, spaceAfter=6, borderPadding=(0,0,4,0))
    S_H2      = style("H2",       fontSize=11, fontName="Helvetica-Bold",   textColor=C_INK,    spaceBefore=10, spaceAfter=4)
    S_BODY    = style("Body",     fontSize=10, fontName="Helvetica",         textColor=C_INK,    spaceAfter=6,  leading=15)
    S_MONO    = style("Mono",     fontSize=9,  fontName="Courier",           textColor=C_INK,    spaceAfter=4,  leading=13)
    S_ATK     = style("Atk",      fontSize=10, fontName="Helvetica-Bold",   textColor=C_ATK,    spaceAfter=2)
    S_DEF     = style("Def",      fontSize=10, fontName="Helvetica-Bold",   textColor=C_DEF,    spaceAfter=2)
    S_MUTED   = style("Muted",    fontSize=9,  fontName="Helvetica-Oblique", textColor=C_MUTED,  spaceAfter=4,  leading=13)
    S_CENTER  = style("Center",   fontSize=10, alignment=TA_CENTER,          textColor=C_INK)

    def hr():
        return HRFlowable(width="100%", thickness=1, color=C_LINE, spaceAfter=10, spaceBefore=4)

    def kv_table(rows, col_widths=None):
        """2-col key/value table."""
        if col_widths is None:
            col_widths = [4*cm, W - 4*cm]
        data = [[Paragraph(f"<b>{k}</b>", S_BODY), Paragraph(str(v), S_MONO)] for k, v in rows]
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, -1), C_SURFACE),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, C_SURFACE]),
            ("GRID",        (0, 0), (-1, -1), 0.5, C_LINE),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0,0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        return t

    # ── Extract data ──
    sim_id   = state.get("sim_id", "unknown")
    now      = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    log      = state.get("log", [])
    atk      = state.get("attacker", {})
    defn     = state.get("defender", {})
    vulns    = state.get("vulns", [])
    assets   = state.get("assets", [])
    init_r   = state.get("initial_risk", 0)
    curr_r   = state.get("current_risk", 0)
    winner   = state.get("winner")
    turns    = state.get("turn", 0)
    max_t    = state.get("max_turns", 0)
    game_over= state.get("game_over", False)

    delta    = init_r - curr_r
    delta_pct= f"{delta/init_r*100:.1f}%" if init_r > 0 else "0%"

    story = []

    # ══════════════════════════════════════════════════════
    # COVER
    # ══════════════════════════════════════════════════════
    story.append(Spacer(1, 1.5*cm))
    story.append(Paragraph("CySyMo", style("Brand", fontSize=28, fontName="Helvetica-Bold", textColor=C_ACCENT)))
    story.append(Paragraph("Adversarial Simulation Report", S_TITLE))
    story.append(Paragraph(f"Simulation ID: {sim_id} &nbsp;·&nbsp; Generated: {now}", S_SUB))
    story.append(hr())

    # Winner banner
    if game_over and winner:
        w_color = C_ATK if winner == "attacker" else C_DEF
        w_text  = "🔴 ATTACKER WINS — Data Exfiltrated" if winner == "attacker" else "🔵 DEFENDER WINS — Attack Neutralised"
        banner  = Table([[Paragraph(w_text, style("Banner", fontSize=13, fontName="Helvetica-Bold",
                          textColor=colors.white, alignment=TA_CENTER))]],
                        colWidths=[W])
        banner.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), w_color),
            ("TOPPADDING",    (0,0), (-1,-1), 12),
            ("BOTTOMPADDING", (0,0), (-1,-1), 12),
            ("ROUNDEDCORNERS",(0,0), (-1,-1), [6,6,6,6]),
        ]))
        story.append(banner)
        story.append(Spacer(1, 0.4*cm))

    # ══════════════════════════════════════════════════════
    # SECTION 1 — SUMMARY
    # ══════════════════════════════════════════════════════
    story.append(Paragraph("1. Executive Summary", S_H1))
    story.append(hr())

    # Risk summary cards (2×2 table)
    r_color = risk_color(curr_r)
    summary_data = [
        [
            Paragraph("<b>Initial Risk R</b>", S_BODY),
            Paragraph(f"<b>{init_r:.4f}</b>", style("RV", fontSize=13, fontName="Helvetica-Bold", textColor=risk_color(init_r), alignment=TA_CENTER)),
            Paragraph("<b>Final Risk R</b>", S_BODY),
            Paragraph(f"<b>{curr_r:.4f}</b>", style("RV2", fontSize=13, fontName="Helvetica-Bold", textColor=r_color, alignment=TA_CENTER)),
        ],
        [
            Paragraph("<b>Risk Reduction</b>", S_BODY),
            Paragraph(f"<b>{delta_pct}</b>", style("DV", fontSize=13, fontName="Helvetica-Bold", textColor=C_DEF, alignment=TA_CENTER)),
            Paragraph("<b>Level</b>", S_BODY),
            Paragraph(f"<b>{risk_label(curr_r)}</b>", style("LV", fontSize=13, fontName="Helvetica-Bold", textColor=r_color, alignment=TA_CENTER)),
        ],
    ]
    summary_t = Table(summary_data, colWidths=[3.5*cm, 3.5*cm, 3.5*cm, 3.5*cm])
    summary_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_SURFACE),
        ("GRID",          (0,0), (-1,-1), 0.5, C_LINE),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ]))
    story.append(summary_t)
    story.append(Spacer(1, 0.4*cm))

    story.append(kv_table([
        ("Turns played",       f"{turns} / {max_t}"),
        ("Attacker stage",     atk.get("stage", "—")),
        ("Attacker budget left", f"{atk.get('budget','—')} pts"),
        ("Attacker foothold",  ", ".join(atk.get("foothold", [])) or "none"),
        ("Defender budget left", f"{defn.get('budget','—')} pts"),
        ("IDS level",          f"{int(defn.get('ids_level',0.3)*100)}%"),
        ("MFA enabled",        "Yes" if defn.get("mfa") else "No"),
        ("Network segmented",  "Yes" if defn.get("segmented") else "No"),
    ]))
    story.append(Spacer(1, 0.3*cm))

    # Formula
    story.append(Paragraph("Risk Formula", S_H2))
    story.append(Paragraph(
        "R = (Sigma e<sub>i</sub> &middot; A<sub>Iij</sub> &middot; p<sub>j</sub>) / (m &middot; n) &nbsp;&nbsp; "
        "where e<sub>i</sub> = 1 &minus; NIST effectiveness",
        S_BODY
    ))

    # ══════════════════════════════════════════════════════
    # SECTION 2 — VULNERABILITY STATUS
    # ══════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(Paragraph("2. Vulnerability Status", S_H1))
    story.append(hr())

    if vulns:
        v_data = [[
            Paragraph("<b>ID</b>",          S_BODY),
            Paragraph("<b>Description</b>", S_BODY),
            Paragraph("<b>NIST</b>",        S_BODY),
            Paragraph("<b>e<sub>i</sub></b>", S_BODY),
            Paragraph("<b>Status</b>",      S_BODY),
        ]]
        for v in vulns:
            eff = float(v.get("effectiveness", 0))
            ei  = round(1 - eff, 3)
            ei_color = C_HIGH if ei > 0.7 else C_MOD if ei > 0.4 else C_LOW
            patched = v.get("patched", False)
            v_data.append([
                Paragraph(str(v.get("id","")),          S_MONO),
                Paragraph(str(v.get("description",""))[:80], S_BODY),
                Paragraph(str(v.get("nist_control","—")), S_MONO),
                Paragraph(f'<font color="#{ei_color.hexval()[2:]}">{ei:.2f}</font>', S_MONO),
                Paragraph(
                    '<font color="#1F9D74"><b>Patched</b></font>' if patched
                    else '<font color="#D8433A">Open</font>', S_BODY
                ),
            ])
        vt = Table(v_data, colWidths=[1.2*cm, 6.5*cm, 2*cm, 1.5*cm, 2*cm])
        vt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), C_ACCENT),
            ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, C_SURFACE]),
            ("GRID",          (0,0), (-1,-1), 0.5, C_LINE),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ]))
        story.append(vt)
    else:
        story.append(Paragraph("No vulnerability data available.", S_MUTED))

    # ══════════════════════════════════════════════════════
    # SECTION 3 — TURN-BY-TURN LOG
    # ══════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(Paragraph("3. Turn-by-Turn Log", S_H1))
    story.append(hr())

    if not log:
        story.append(Paragraph("No turns were played.", S_MUTED))
    else:
        for entry in log:
            t_num = entry.get("turn", "?")
            risk  = entry.get("risk_after", entry.get("risk", 0))
            a     = entry.get("attacker", {})
            d     = entry.get("defender", {})

            # Turn header
            story.append(Paragraph(
                f"Turn {t_num} &nbsp;·&nbsp; R after = {risk:.4f}",
                style("TurnH", fontSize=11, fontName="Helvetica-Bold", textColor=C_INK,
                      spaceBefore=12, spaceAfter=4, backColor=C_SURFACE,
                      borderPadding=(5,8,5,8))
            ))

            # Attacker
            story.append(Paragraph("🔴 Attacker", S_ATK))
            a_action = a.get("action","—")
            a_target = a.get("target","")
            a_ok     = "✓ SUCCESS" if a.get("success") else "✗ FAILED"
            a_det    = " · ⚠ Detected" if a.get("detected") else ""
            story.append(Paragraph(
                f"<b>Action:</b> {a_action} → {a_target or '—'} &nbsp; {a_ok}{a_det} &nbsp; (−{a.get('cost',0)} pts)",
                S_BODY
            ))
            if a.get("analysis"):
                story.append(Paragraph(f"<i>Reasoning: {a.get('analysis','')}</i>", S_MUTED))
            story.append(Paragraph(f"Outcome: {a.get('outcome','—')}", S_BODY))

            story.append(Spacer(1, 0.2*cm))

            # Defender
            story.append(Paragraph("🔵 Defender", S_DEF))
            d_action = d.get("action","—")
            d_target = d.get("target","")
            story.append(Paragraph(
                f"<b>Action:</b> {d_action} → {d_target or '—'} &nbsp; (−{d.get('cost',0)} pts)",
                S_BODY
            ))
            if d.get("analysis"):
                story.append(Paragraph(f"<i>Reasoning: {d.get('analysis','')}</i>", S_MUTED))
            story.append(Paragraph(f"Outcome: {d.get('outcome','—')}", S_BODY))

            story.append(hr())

    # ══════════════════════════════════════════════════════
    # SECTION 4 — ANALYSIS
    # ══════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(Paragraph("4. Analysis", S_H1))
    story.append(hr())

    patched_vulns = [v for v in vulns if v.get("patched")]
    open_vulns    = [v for v in vulns if not v.get("patched")]

    story.append(Paragraph("Key observations", S_H2))

    obs = []
    obs.append(f"The simulation ran for {turns} turn(s) out of {max_t} maximum.")
    if winner == "attacker":
        obs.append("The attacker reached the Exfiltration stage — the system was breached.")
    elif winner == "defender":
        obs.append("The defender successfully prevented data exfiltration.")
    if patched_vulns:
        obs.append(f"{len(patched_vulns)} vulnerability(-ies) were patched: {', '.join(v['id'] for v in patched_vulns)}.")
    if open_vulns:
        obs.append(f"{len(open_vulns)} vulnerability(-ies) remain open: {', '.join(v['id'] for v in open_vulns)}.")
    if delta > 0.001:
        obs.append(f"Risk R decreased by {delta_pct} ({init_r:.4f} → {curr_r:.4f}).")
    elif abs(delta) < 0.001:
        obs.append("Risk R remained unchanged — no vulnerabilities were patched this simulation.")
    if atk.get("foothold"):
        obs.append(f"Attacker established foothold on: {', '.join(atk['foothold'])}.")
    if defn.get("mfa"):
        obs.append("MFA was enabled — privilege escalation and credential attacks were mitigated.")
    if defn.get("segmented"):
        obs.append("Network segmentation was deployed — lateral movement was blocked.")

    for o in obs:
        story.append(Paragraph(f"• {o}", S_BODY))

    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("Formula interpretation", S_H2))
    story.append(Paragraph(
        "R = (Sigma e_i · A_Iij · p_j) / (m · n). "
        "R decreases when vulnerabilities are patched (e_i approaches 0) or when "
        "NIST control effectiveness increases (via enable_mfa). "
        "Actions such as reconnaissance, persistence, and lateral movement change the "
        "attacker position but do not affect the formula values directly.",
        S_BODY
    ))

    # ── Footer note ──
    story.append(Spacer(1, 1*cm))
    story.append(hr())
    story.append(Paragraph(
        f"CySyMo · Kingston University London · Module CI7526 · {now}",
        style("Footer", fontSize=8, textColor=C_MUTED, alignment=TA_CENTER)
    ))

    doc.build(story)
    return buf.getvalue()
