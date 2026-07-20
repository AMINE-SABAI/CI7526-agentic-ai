"""
backend.py — FastAPI backend for CySyMo (full upgrade).

All briques integrated:
  Brique 2  : CVE/CVSS lookup + keyword search
  Brique 5  : PDF / DOCX / HTML reports
  Brique 6  : User profile
  Brique 8  : SQLite persistence + history CSV export + backup/restore
  Brique 9  : Docker-ready

New endpoints:
  GET  /api/scenarios          list all scenarios
  POST /api/scenarios          create/save a scenario
  POST /api/scenarios/generate AI-generate a scenario
  DELETE /api/scenarios/{id}   delete a scenario
  GET  /api/history/csv        export history as CSV
  GET  /api/cve/search/{kw}    keyword search in CVE descriptions
"""

import os
import datetime

from fastapi import FastAPI, Body
from fastapi.responses import FileResponse, Response, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

from cysymo import CyberSystemModel
import risk_formulas
import database as DB
import profile as prof
from cve import lookup_cve
import scenarios as SC

OCTAVE_FIELDS = ["actor", "motive", "access", "outcome"]
HERE       = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")

app = FastAPI(title="CySyMo")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════

def _clamp01(x):
    try: return max(0.0, min(1.0, float(x)))
    except: return 0.0

def model_to_dict(model):
    vulns = []
    for v in model.vulnerabilities:
        meta = v[2] if isinstance(v[2], dict) else {}
        vulns.append({"id": v[0], "description": v[1],
                      "nist_control": meta.get("nist_control",""),
                      "nist_title": meta.get("nist_title",""),
                      "effectiveness": float(meta.get("effectiveness",0.0)),
                      "asset_id": meta.get("asset_id","")})
    threats = []
    for j, t in enumerate(model.threats):
        profile = t[2] if isinstance(t[2], dict) else {}
        entry = {"id": t[0], "description": t[1]}
        for f in OCTAVE_FIELDS: entry[f] = profile.get(f,"")
        entry["probability"] = float(model.p[j]) if j < len(model.p) else 1.0
        entry["asset_id"] = profile.get("asset_id","")
        threats.append(entry)
    assets  = [{"id": a[0], "description": a[1]} for a in model.assets]
    impacts = [{"vuln_id": v[0], "threat_id": t[0],
                "value": float(model.get_impact(v[0], t[0]))}
               for v in model.vulnerabilities for t in model.threats]
    return {"vulnerabilities": vulns, "threats": threats, "assets": assets, "impacts": impacts}

def dict_to_model(data):
    model = CyberSystemModel()
    for v in data.get("vulnerabilities", []):
        if not str(v.get("id","")).strip(): continue
        meta = {"nist_control": v.get("nist_control",""), "nist_title": v.get("nist_title",""),
                "effectiveness": _clamp01(v.get("effectiveness",0.0)), "asset_id": v.get("asset_id","")}
        model.add_vuln([v["id"], v.get("description",""), meta])
    for t in data.get("threats", []):
        if not str(t.get("id","")).strip(): continue
        profile = {f: t.get(f,"") for f in OCTAVE_FIELDS}
        profile["asset_id"] = t.get("asset_id","")
        model.add_threat([t["id"], t.get("description",""), profile])
    for a in data.get("assets", []):
        if not str(a.get("id","")).strip(): continue
        model.add_asset([a["id"], a.get("description","")])
    probs = [_clamp01(t.get("probability",1.0)) for t in data.get("threats",[]) if str(t.get("id","")).strip()]
    if probs: model.attack(probs)
    vids = {v[0] for v in model.vulnerabilities}
    tids = {t[0] for t in model.threats}
    for imp in data.get("impacts", []):
        if imp.get("vuln_id") in vids and imp.get("threat_id") in tids:
            model.set_impact(imp["vuln_id"], imp["threat_id"], _clamp01(imp.get("value",0.0)))
    return model

def _controls_vector(data):
    return [_clamp01(v.get("effectiveness",0.0))
            for v in data.get("vulnerabilities",[]) if str(v.get("id","")).strip()]

def _build_report_context(payload):
    data = payload.get("model", {}); formula = payload.get("formula","mean")
    model = dict_to_model(data); controls = _controls_vector(data)
    if controls: model.protect(controls)
    value = risk_formulas.compute_risk(model, formula)
    norm  = risk_formulas.normalised(model, formula, value)
    lvl   = risk_formulas.level(norm)
    return {"model_dict": data, "formula": formula, "risk_value": value,
            "level": lvl, "normalised": norm}


# ══════════════════════════════════════════════════════
#  PROFILE  (Brique 6)
# ══════════════════════════════════════════════════════

@app.get("/api/profile")
def api_profile_get(): return prof.get_profile()

@app.post("/api/profile")
def api_profile_set(payload: dict = Body(...)):
    return prof.set_profile(payload.get("profile","enterprise"))


# ══════════════════════════════════════════════════════
#  CVE  (Brique 2)
# ══════════════════════════════════════════════════════

@app.get("/api/cve/{cve_id}")
async def api_cve_lookup(cve_id: str):
    return await lookup_cve(cve_id)

@app.get("/api/cve/search/{keyword}")
async def api_cve_search(keyword: str):
    """Search NVD for CVEs matching a keyword."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": keyword, "resultsPerPage": 10},
                headers={"User-Agent": "CySyMo/1.0"}
            )
        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")
            metrics = cve.get("metrics", {})
            score = None
            for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    score = entries[0].get("cvssData",{}).get("baseScore")
                    break
            results.append({"cve_id": cve.get("id",""), "description": desc[:200],
                            "cvss_score": score})
        return {"results": results, "keyword": keyword}
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════
#  AI GENERATION
# ══════════════════════════════════════════════════════

@app.post("/api/generate")
def api_generate(payload: dict = Body(...)):
    from agent import build_agent
    description = payload.get("description","").strip()
    if not description: return {"error": "Please provide a system description."}
    try:
        agent = build_agent(include_simulate=False)
        state = {"description": description, "data": {}, "model": None,
                 "risk_before": 0.0, "risk_after": 0.0,
                 "verification_passed": False, "attempts": 0}
        final = agent.invoke(state)
        return {"model": model_to_dict(final["model"])}
    except Exception as e:
        return {"error": f"AI generation failed: {e}"}

VALID_SECTIONS = {"vulnerabilities","threats","assets","impacts","controls"}

@app.post("/api/generate_section")
def api_generate_section(payload: dict = Body(...)):
    from extractor import (extract_elements, build_model,
                           estimate_impact, estimate_probability, suggest_controls)
    description = payload.get("description","").strip()
    section     = payload.get("section","")
    current     = payload.get("model",{})
    if not description: return {"error": "Please provide a system description."}
    if section not in VALID_SECTIONS: return {"error": f"Unknown section '{section}'."}
    try:
        if section == "assets":
            data = extract_elements(description)
            return {"assets": data.get("assets",[])}
        elif section == "threats":
            data = extract_elements(description); model = build_model(data)
            model = estimate_probability(model)
            return {"threats": model_to_dict(model)["threats"]}
        elif section == "vulnerabilities":
            data = extract_elements(description); model = build_model(data)
            return {"vulnerabilities": model_to_dict(model)["vulnerabilities"]}
        elif section == "controls":
            if not current.get("vulnerabilities"): return {"error": "Add vulnerabilities first."}
            model = dict_to_model(current); model = suggest_controls(model)
            return {"vulnerabilities": model_to_dict(model)["vulnerabilities"]}
        elif section == "impacts":
            if not current.get("vulnerabilities") or not current.get("threats"):
                return {"error": "Add both vulnerabilities and threats first."}
            model = dict_to_model(current); model = estimate_impact(model)
            return {"impacts": model_to_dict(model)["impacts"]}
    except Exception as e:
        return {"error": f"AI generation failed: {e}"}


# ══════════════════════════════════════════════════════
#  COMPUTE / SIMULATE
# ══════════════════════════════════════════════════════

@app.post("/api/compute")
def api_compute(payload: dict = Body(...)):
    data = payload.get("model",{}); formula = payload.get("formula","mean")
    save = payload.get("save_history", True)
    try:
        model = dict_to_model(data); controls = _controls_vector(data)
        if controls: model.protect(controls)
        value = risk_formulas.compute_risk(model, formula)
        norm  = risk_formulas.normalised(model, formula, value)
        lvl   = risk_formulas.level(norm)
        m = len(model.vulnerabilities); n = len(model.threats)
        if save and m > 0 and n > 0:
            DB.append_history(formula, value, lvl, m, n)
        return {"risk": value, "normalised": norm, "level": lvl, "m": m, "n": n}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/simulate")
def api_simulate(payload: dict = Body(...)):
    data = payload.get("model",{}); formula = payload.get("formula","mean")
    try:
        model = dict_to_model(data)
        risk_before = risk_formulas.compute_risk(model, formula)
        controls = _controls_vector(data)
        if controls: model.protect(controls)
        risk_after = risk_formulas.compute_risk(model, formula)
        reduction = (risk_before - risk_after) / risk_before * 100.0 if risk_before else 0.0
        return {"risk_before": risk_before, "risk_after": risk_after,
                "reduction": reduction, "formula": formula}
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/formulas")
def api_formulas(): return risk_formulas.FORMULAS


# ══════════════════════════════════════════════════════
#  SCENARIOS
# ══════════════════════════════════════════════════════

def _compute_scenario_risk(scenario: dict, model_data: dict) -> dict:
    """
    Compute R = e * A_I[vuln][threat] * p for one (vuln, threat) pair
    using the ACTUAL values from the current model.

    Principle: AI proposes the pair → engine calculates the risk.
    """
    vuln_id   = scenario.get("vuln_id", "")
    threat_id = scenario.get("threat_id", "")

    # e = 1 - effectiveness  (exposure of the vulnerability)
    e = 1.0
    for v in model_data.get("vulnerabilities", []):
        if v.get("id") == vuln_id:
            e = 1.0 - _clamp01(v.get("effectiveness", 0.0))
            break

    # p = attack probability of the threat
    p = 1.0
    for t in model_data.get("threats", []):
        if t.get("id") == threat_id:
            p = _clamp01(t.get("probability", 1.0))
            break

    # A_I[vuln][threat] = impact value from the matrix
    impact = 0.0
    for imp in model_data.get("impacts", []):
        if imp.get("vuln_id") == vuln_id and imp.get("threat_id") == threat_id:
            impact = _clamp01(imp.get("value", 0.0))
            break

    # R = e * A_I * p  — engine formula, single cell
    risk = round(e * impact * p, 4)

    scenario["exposure"]    = round(e,      4)
    scenario["probability"] = round(p,      4)
    scenario["impact"]      = round(impact, 4)
    scenario["risk"]        = risk

    return scenario


@app.get("/api/scenarios")
def api_scenarios_list():
    return {"scenarios": SC.get_scenarios()}


@app.post("/api/scenarios")
def api_scenarios_save(payload: dict = Body(...)):
    """Save a scenario — recomputes risk from engine before saving."""
    scenario   = payload.get("scenario", {})
    model_data = payload.get("model", {})
    if not scenario.get("id"):
        scenario["id"] = SC.next_scenario_id()
    # always recompute from engine values if model provided
    if model_data.get("vulnerabilities"):
        scenario = _compute_scenario_risk(scenario, model_data)
    saved = SC.save_scenario(scenario)
    return {"scenario": saved}


@app.post("/api/scenarios/generate")
def api_scenarios_generate(payload: dict = Body(...)):
    """
    AI proposes: name, narrative, asset/vuln/threat selection, recommendations.
    Engine computes: e, p, impact, R — from actual model values.
    """
    from extractor import generate_scenario
    description = payload.get("description", "").strip()
    model_data  = payload.get("model", {})
    if not description:
        return {"error": "Provide a system description."}
    if not model_data.get("vulnerabilities"):
        return {"error": "Generate a model first."}
    try:
        model    = dict_to_model(model_data)
        existing = SC.get_scenarios()

        # AI proposes the scenario structure (no risk values trusted from AI)
        scenario = generate_scenario(description, model, existing)
        scenario["id"] = SC.next_scenario_id()

        # Engine calculates the actual risk
        scenario = _compute_scenario_risk(scenario, model_data)

        saved = SC.save_scenario(scenario)
        return {"scenario": saved}
    except Exception as e:
        return {"error": f"Scenario generation failed: {e}"}


@app.post("/api/scenarios/compute")
def api_scenarios_compute(payload: dict = Body(...)):
    """
    Recompute risk for a scenario using current model values.
    Called when user changes vuln_id, threat_id, or model parameters.
    """
    scenario   = payload.get("scenario", {})
    model_data = payload.get("model", {})
    if not scenario:
        return {"error": "Provide a scenario."}
    try:
        updated = _compute_scenario_risk(scenario, model_data)
        saved   = SC.save_scenario(updated)
        return {"scenario": saved}
    except Exception as e:
        return {"error": str(e)}


@app.delete("/api/scenarios/{scenario_id}")
def api_scenarios_delete(scenario_id: str):
    deleted = SC.delete_scenario(scenario_id)
    return {"ok": deleted}


# ══════════════════════════════════════════════════════
#  PERSISTENCE  (Brique 8)
# ══════════════════════════════════════════════════════

@app.post("/api/model/save")
def api_model_save(payload: dict = Body(...)):
    try: DB.save_model(payload.get("model",{})); return {"ok": True}
    except Exception as e: return {"error": str(e)}

@app.get("/api/model/load")
def api_model_load():
    try: return {"model": DB.load_model()}
    except Exception as e: return {"error": str(e)}

@app.get("/api/history")
def api_history_get(): 
    try: return {"history": DB.get_history()}
    except Exception as e: return {"error": str(e)}

@app.delete("/api/history")
def api_history_delete():
    try: DB.clear_history(); return {"ok": True}
    except Exception as e: return {"error": str(e)}

@app.get("/api/history/csv")
def api_history_csv():
    try:
        csv_data = DB.export_history_csv()
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return Response(content=csv_data, media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="cysymo_history_{ts}.csv"'})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/backup")
def api_backup():
    try:
        blob = DB.export_json()
        ts   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return Response(content=blob, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="cysymo_backup_{ts}.json"'})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/restore")
async def api_restore(payload: dict = Body(...)):
    try:
        blob = payload.get("data","")
        if not blob: return {"error": "No backup data provided."}
        DB.import_json(blob)
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════
#  REPORTS  (Brique 5)
# ══════════════════════════════════════════════════════

@app.post("/api/report/pdf")
def api_report_pdf(payload: dict = Body(...)):
    try:
        from pdfreport import build_pdf
        ctx = _build_report_context(payload); data = build_pdf(**ctx)
        ts  = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return Response(content=data, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="cysymo_report_{ts}.pdf"'})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/report/docx")
def api_report_docx(payload: dict = Body(...)):
    try:
        from pdfreport import build_docx
        ctx = _build_report_context(payload); data = build_docx(**ctx)
        ts  = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return Response(content=data,
                        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": f'attachment; filename="cysymo_report_{ts}.docx"'})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/report/html")
def api_report_html(payload: dict = Body(...)):
    try:
        from pdfreport import build_html
        ctx = _build_report_context(payload); html = build_html(**ctx)
        ts  = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return Response(content=html, media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="cysymo_report_{ts}.html"'})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ══════════════════════════════════════════════════════
#  SIMULATION  (adversarial game)
# ══════════════════════════════════════════════════════

import simulation as SIM

@app.post("/api/simulation/start")
def api_sim_start(payload: dict = Body(...)):
    """Start a new adversarial simulation from the current CySyMo model."""
    model  = payload.get("model", {})
    config = payload.get("config", {})
    if not model.get("vulnerabilities"):
        return {"error": "Generate a model first (need at least one vulnerability)."}
    try:
        sim_id = SIM.start_simulation(model, config)
        return {"sim_id": sim_id, "state": SIM.get_state(sim_id)}
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/simulation/{sim_id}")
def api_sim_state(sim_id: str):
    """Get current state of an ongoing simulation."""
    return SIM.get_state(sim_id)

@app.get("/api/simulation/{sim_id}/stream")
async def api_sim_stream(sim_id: str):
    """
    SSE stream: plays the full game automatically, emitting one event
    per pipeline step so the frontend can display each agent's reasoning.
    """
    return StreamingResponse(
        SIM.stream_full_game(sim_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

@app.post("/api/simulation/{sim_id}/turn")
def api_sim_turn(sim_id: str):
    """Play one turn synchronously (fallback)."""
    try:
        return SIM.next_turn(sim_id)
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/simulations")
def api_simulations_list():
    """List all saved simulations."""
    return {"simulations": DB.list_simulations()}

@app.get("/api/simulations/{sim_id}/restore")
def api_simulation_restore(sim_id: str):
    """Restore a simulation from SQLite into memory and return its state."""
    ok = SIM.restore_simulation(sim_id)
    if not ok:
        return {"error": "Simulation not found."}
    return {"sim_id": sim_id, "state": SIM.get_state(sim_id)}

@app.delete("/api/simulations/{sim_id}")
def api_simulation_delete(sim_id: str):
    ok = DB.delete_simulation(sim_id)
    return {"ok": ok}

import sim_report as SIM_REPORT

@app.get("/api/simulation/{sim_id}/report")
def api_sim_report(sim_id: str):
    """Generate and return a PDF report for a completed simulation."""
    ok = SIM.restore_simulation(sim_id)
    if not ok:
        return JSONResponse({"error": "Simulation not found."}, status_code=404)
    state = SIM.get_state(sim_id)
    if "error" in state:
        return JSONResponse(state, status_code=404)
    try:
        pdf_bytes = SIM_REPORT.generate_simulation_report(state)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="cysymo_sim_{sim_id}.pdf"'},
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ══════════════════════════════════════════════════════
#  SERIOUS GAME  (human-in-the-loop)
# ══════════════════════════════════════════════════════

import game_engine as GE

# ── Professor endpoints ──

@app.post("/api/game/create")
def api_game_create(payload: dict = Body(...)):
    model = payload.get("model", {})
    rules = payload.get("rules", {})
    label = payload.get("label", "")
    if not model.get("vulnerabilities"):
        return {"error": "Generate a CySyMo model first."}
    try:
        game_id = GE.create_game(model, rules, label)
        return {"game_id": game_id}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/game/{game_id}/start")
def api_game_start(game_id: str):
    return GE.start_game(game_id)

@app.get("/api/game/{game_id}/master")
def api_game_master(game_id: str):
    return GE.get_master_view(game_id)

@app.get("/api/games")
def api_games_list():
    return {"games": GE.list_games()}

@app.delete("/api/game/{game_id}")
def api_game_delete(game_id: str):
    return {"ok": DB.delete_game(game_id)}

# ── Student endpoints ──

@app.get("/api/game/{game_id}/attacker")
def api_game_attacker_view(game_id: str):
    return GE.get_attacker_view(game_id)

@app.get("/api/game/{game_id}/defender")
def api_game_defender_view(game_id: str):
    return GE.get_defender_view(game_id)

@app.post("/api/game/{game_id}/attacker/submit")
def api_game_attacker_submit(game_id: str, payload: dict = Body(...)):
    return GE.submit_attacker_action(
        game_id,
        payload.get("action", ""),
        payload.get("target", ""),
        payload.get("justification", ""),
    )

@app.post("/api/game/{game_id}/defender/submit")
def api_game_defender_submit(game_id: str, payload: dict = Body(...)):
    return GE.submit_defender_action(
        game_id,
        payload.get("action", ""),
        payload.get("target", ""),
        payload.get("justification", ""),
    )

# ── URL routing for game pages (serve index.html) ──

@app.get("/game/{game_id}/master")
def game_master_page(game_id: str):
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.get("/game/{game_id}/attacker")
def game_attacker_page(game_id: str):
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.get("/game/{game_id}/defender")
def game_defender_page(game_id: str):
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/sim/{sim_id}")
def sim_page(sim_id: str):
    """Serve the main app for a specific simulation URL."""
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# ══════════════════════════════════════════════════════
#  SETTINGS
# ══════════════════════════════════════════════════════

import re as _re

# In-memory settings (overrideable per session)
_settings = {
    "model":      os.environ.get("CYSYMO_MODEL", "claude-sonnet-4-6"),
    "thresholds": {"low": 0.33, "moderate": 0.66, "high": 0.90},
}

@app.post("/api/settings/api-key")
def api_save_api_key(payload: dict = Body(...)):
    """Save API key to .env file."""
    key = payload.get("api_key", "").strip()
    if not key.startswith("sk-ant-"):
        return {"ok": False, "error": "Invalid API key format."}
    try:
        env_path = Path(".env")
        content  = env_path.read_text() if env_path.exists() else ""
        if "ANTHROPIC_API_KEY" in content:
            content = _re.sub(r"ANTHROPIC_API_KEY=.*", f"ANTHROPIC_API_KEY={key}", content)
        else:
            content += f"\nANTHROPIC_API_KEY={key}\n"
        env_path.write_text(content)
        os.environ["ANTHROPIC_API_KEY"] = key
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.post("/api/settings/model")
def api_save_model(payload: dict = Body(...)):
    """Set the Claude model — takes effect immediately for all subsequent AI calls."""
    model = payload.get("model", "claude-sonnet-4-6")
    _settings["model"] = model
    os.environ["CYSYMO_MODEL"] = model  # picked up by extractor.py + simulation.py
    return {"ok": True, "model": model}

@app.post("/api/settings/api-key")
def api_save_api_key(payload: dict = Body(...)):
    """Save API key to .env file and apply immediately."""
    key = payload.get("api_key", "").strip()
    if not key.startswith("sk-ant-"):
        return {"ok": False, "error": "Invalid API key — must start with sk-ant-"}
    try:
        env_path = Path(".env")
        content  = env_path.read_text() if env_path.exists() else ""
        if "ANTHROPIC_API_KEY" in content:
            content = _re.sub(r"ANTHROPIC_API_KEY=.*", f"ANTHROPIC_API_KEY={key}", content)
        else:
            content += f"\nANTHROPIC_API_KEY={key}\n"
        env_path.write_text(content)
        os.environ["ANTHROPIC_API_KEY"] = key  # applies immediately, no restart needed
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.get("/api/settings")
def api_get_settings():
    """Return current settings (safe — no API key returned)."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    return {
        "model":       os.environ.get("CYSYMO_MODEL", "claude-sonnet-4-6"),
        "thresholds":  _settings["thresholds"],
        "api_key_set": bool(key) and key.startswith("sk-ant-"),
        "api_key_hint": f"…{key[-6:]}" if len(key) > 10 else "not set",
    }
def api_save_thresholds(payload: dict = Body(...)):
    """Save risk level thresholds."""
    low  = float(payload.get("low",      0.33))
    mod  = float(payload.get("moderate", 0.66))
    high = float(payload.get("high",     0.90))
    if not (0 < low < mod < high < 1):
        return {"ok": False, "error": "Thresholds must be in order: 0 < low < moderate < high < 1"}
    _settings["thresholds"] = {"low": low, "moderate": mod, "high": high}
    return {"ok": True, "thresholds": _settings["thresholds"]}

@app.get("/api/settings")
def api_get_settings():
    """Return current settings (safe — no API key)."""
    return {
        "model":      _settings["model"],
        "thresholds": _settings["thresholds"],
    }

@app.get("/api/projects")
def api_projects_list():
    return {"projects": DB.list_projects()}

@app.post("/api/projects")
def api_project_create(payload: dict = Body(...)):
    name = payload.get("name", "Untitled")
    return DB.create_project(name)

@app.get("/api/projects/{project_id}")
def api_project_load(project_id: str):
    p = DB.load_project(project_id)
    if not p:
        return {"error": "Project not found."}
    return p

@app.put("/api/projects/{project_id}")
def api_project_save(project_id: str, payload: dict = Body(...)):
    """Save full project state (called on every model change)."""
    state = payload.get("state", {})
    name  = payload.get("name", "Untitled")
    risk  = float(payload.get("risk", 0.0))
    level = payload.get("level", "")
    DB.save_project(project_id, name, state, risk, level)
    return {"ok": True}

@app.patch("/api/projects/{project_id}/rename")
def api_project_rename(project_id: str, payload: dict = Body(...)):
    ok = DB.rename_project(project_id, payload.get("name", "Untitled"))
    return {"ok": ok}

@app.delete("/api/projects/{project_id}")
def api_project_delete(project_id: str):
    ok = DB.delete_project(project_id)
    return {"ok": ok}

@app.get("/project/{project_id}")
def project_page(project_id: str):
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# ══════════════════════════════════════════════════════
#  STATIC
# ══════════════════════════════════════════════════════

@app.get("/")
def index(): return FileResponse(os.path.join(STATIC_DIR, "index.html"))
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
