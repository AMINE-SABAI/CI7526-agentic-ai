"""
app.py - Streamlit human-in-the-loop interface for the CySyMo agent.
AI proposes -> human validates/corrects -> engine calculates.
Run with: streamlit run app.py
"""

import copy
import streamlit as st

from cysymo import CyberSystemModel
from agent import build_agent

st.set_page_config(page_title="Agentic CySyMo", page_icon="🛡️", layout="wide")

OCTAVE_FIELDS = ["actor", "motive", "access", "outcome"]


# ---------- helpers ----------

def run_agent_live(description: str) -> CyberSystemModel:
    """Lance l'agent (sans simulate) en affichant chaque etape en direct."""
    agent = build_agent(include_simulate=False)

    initial_state = {
        "description": description,
        "data": {},
        "model": None,
        "risk_before": 0.0,
        "risk_after": 0.0,
        "verification_passed": False,
        "attempts": 0,
    }

    labels = {
        "extract": "Extraction (AI proposes vulnerabilities / threats / assets)",
        "verify": "Self-verification of the AI's output",
        "build": "Building the CySyMo model",
        "impact": "Estimating the impact matrix",
        "controls": "Selecting NIST controls",
    }

    final_state = None
    with st.status("The agent is working...", expanded=True) as status:
        for step in agent.stream(initial_state):
            for node_name, node_state in step.items():
                label = labels.get(node_name, node_name)
                if node_name == "verify":
                    ok = node_state.get("verification_passed")
                    st.write(f"✓ {label} — {'passed' if ok else 'failed, looping back'}")
                else:
                    st.write(f"✓ {label}")
                final_state = node_state
        status.update(label="Analysis complete", state="complete")

    return final_state["model"]


def model_to_session(model: CyberSystemModel) -> None:
    """Copie le modele dans des structures editables (session_state)."""
    st.session_state.vulns = [
        {"id": v[0], "description": v[1],
         "nist_control": v[2].get("nist_control", "") if isinstance(v[2], dict) else "",
         "nist_title": v[2].get("nist_title", "") if isinstance(v[2], dict) else ""}
        for v in model.vulnerabilities
    ]
    st.session_state.threats = [
        {"id": t[0], "description": t[1],
         **{f: (t[2].get(f, "") if isinstance(t[2], dict) else "") for f in OCTAVE_FIELDS}}
        for t in model.threats
    ]
    st.session_state.impacts = {
        (v[0], t[0]): model.get_impact(v[0], t[0])
        for v in model.vulnerabilities for t in model.threats
    }
    st.session_state.has_result = True


def rebuild_model_from_session() -> CyberSystemModel:
    """Reconstruit un CyberSystemModel PROPRE a partir des valeurs validees par l'humain."""
    model = CyberSystemModel()
    for v in st.session_state.vulns:
        metrics = {"nist_control": v["nist_control"], "nist_title": v["nist_title"]}
        model.add_vuln([v["id"], v["description"], metrics])
    for t in st.session_state.threats:
        profile = {f: t[f] for f in OCTAVE_FIELDS}
        model.add_threat([t["id"], t["description"], profile])
    for (vid, tid), val in st.session_state.impacts.items():
        model.set_impact(vid, tid, val)
    return model


# ---------- UI ----------

st.title("🛡️ Agentic AI for Cyber Risk Modelling")
st.caption("The AI proposes · the human validates · the CySyMo engine calculates")

if "has_result" not in st.session_state:
    st.session_state.has_result = False

# --- 1. Input ---
st.subheader("1. Describe the system")
default_desc = (
    "An online shop. Customers log in with email and password. "
    "Their personal data and credit cards are stored in a database. "
    "A payment API processes the transactions."
)
description = st.text_area("System description", value=default_desc, height=120)

if st.button("Analyse with the agent", type="primary"):
    model = run_agent_live(description)
    model_to_session(model)
    st.rerun()

# --- 2. Review & edit (human-in-the-loop) ---
if st.session_state.has_result:
    st.divider()
    st.subheader("2. Review and correct (human-in-the-loop)")
    st.caption("The agent proposed the following. Correct it freely before computing the risk.")

    st.markdown("**Vulnerabilities & NIST controls**")
    st.session_state.vulns = st.data_editor(
        st.session_state.vulns, num_rows="dynamic", use_container_width=True,
        key="ed_vulns",
    )

    st.markdown("**Threats & OCTAVE profiles**")
    st.session_state.threats = st.data_editor(
        st.session_state.threats, num_rows="dynamic", use_container_width=True,
        key="ed_threats",
    )

    st.markdown("**Impact matrix** (0 = none, 1 = catastrophic)")
    vuln_ids = [v["id"] for v in st.session_state.vulns]
    threat_ids = [t["id"] for t in st.session_state.threats]
    rows = []
    for vid in vuln_ids:
        row = {"vuln": vid}
        for tid in threat_ids:
            row[tid] = st.session_state.impacts.get((vid, tid), 0.0)
        rows.append(row)
    edited = st.data_editor(rows, use_container_width=True, key="ed_impacts",
                            disabled=["vuln"])
    for r in edited:
        vid = r["vuln"]
        for tid in threat_ids:
            if tid in r:
                st.session_state.impacts[(vid, tid)] = float(r[tid])

    # --- 3. Simulation parameters ---
    st.divider()
    st.subheader("3. Compute the risk")
    col1, col2 = st.columns(2)
    with col1:
        attack_p = st.slider("Attack probability (all threats)", 0.0, 1.0, 1.0, 0.05)
    with col2:
        control_strength = st.slider("Strength of applied NIST controls", 0.0, 1.0, 0.7, 0.05)

    if st.button("Validate and compute", type="primary"):
        model = rebuild_model_from_session()
        model.attack([attack_p] * len(model.threats))

        before_model = copy.deepcopy(model)
        risk_before = before_model.compute_risk()

        after_model = copy.deepcopy(model)
        after_model.protect([control_strength] * len(after_model.vulnerabilities))
        risk_after = after_model.compute_risk()

        reduction = 0.0
        if risk_before:
            reduction = (risk_before - risk_after) / risk_before * 100

        st.divider()
        st.subheader("Result")
        m1, m2, m3 = st.columns(3)
        m1.metric("Risk before", f"{risk_before:.4f}")
        m2.metric("Risk after controls", f"{risk_after:.4f}")
        m3.metric("Reduction", f"{reduction:.1f} %")