"""
extractor.py — AI extraction pipeline for CySyMo.

Upgrades vs original:
  - Asset linking: vulnerabilities and threats get asset_id assigned by AI
  - Scenario support: extract_scenario() for named independent scenarios
  - Better prompts: more structured, consistent output
"""

import json
import os
from dotenv import load_dotenv
from anthropic import Anthropic
from cysymo import CyberSystemModel

load_dotenv()


# ══════════════════════════════════════════════════════
#  PROMPTS
# ══════════════════════════════════════════════════════

EXTRACTION_PROMPT = """You are a cybersecurity risk analyst.

Read the following plain-language description of a system and extract:
- ASSETS      (the valuable things worth protecting)
- VULNERABILITIES (weaknesses an attacker could exploit, each linked to one asset)
- THREATS     (who or what could attack, and how, each linked to one asset)

For each THREAT, give an OCTAVE threat profile:
  actor   : who attacks (e.g. external attacker, malicious insider)
  motive  : deliberate or accidental
  access  : how (e.g. network, physical, via application)
  outcome : disclosure | modification | destruction | interruption

Rules:
- Base everything strictly on the description. Do not invent components.
- Assign asset_id to EVERY vulnerability and threat (must match an asset id).
- Give each item a short unique id (V1, V2... ; T1, T2... ; A1, A2...).
- Keep each description to one clear sentence.
- Respond with JSON ONLY. No explanations, no markdown.

JSON structure:
{
  "assets": [{"id": "A1", "description": "..."}],
  "vulnerabilities": [{"id": "V1", "description": "...", "asset_id": "A1"}],
  "threats": [
    {
      "id": "T1",
      "description": "...",
      "asset_id": "A1",
      "octave_profile": {
        "actor": "...",
        "motive": "...",
        "access": "...",
        "outcome": "..."
      }
    }
  ]
}

System description:
\"\"\"{description}\"\"\"
"""


IMPACT_PROMPT = """You are a cybersecurity risk analyst.

Estimate the IMPACT of each threat exploiting each vulnerability, as a float [0.0, 1.0]:
  0.0 = no impact
  1.0 = catastrophic

Rules:
- Give a value for EVERY (vulnerability, threat) pair.
- Prefer higher values when the threat directly targets the vulnerability's asset.
- Respond with JSON ONLY.

JSON structure:
{
  "impacts": [
    {"vuln_id": "V1", "threat_id": "T1", "impact": 0.7}
  ]
}

Vulnerabilities:
{vulnerabilities}

Threats:
{threats}
"""


PROBABILITY_PROMPT = """You are a cybersecurity risk analyst.

Estimate the PROBABILITY that each threat is actually attempted [0.0, 1.0]:
  1.0 = almost certain
  0.5 = plausible
  0.1 = rare

Rules:
- Give a probability for EVERY threat.
- Respond with JSON ONLY.

JSON structure:
{
  "probabilities": [
    {"threat_id": "T1", "probability": 0.8}
  ]
}

Threats:
{threats}
"""


NIST_PROMPT = """You are a cybersecurity risk analyst.

For each vulnerability, choose the SINGLE most relevant NIST SP 800-53 control
from the catalogue and estimate its effectiveness [0.0, 1.0]:
  0.0 = no mitigation
  1.0 = full mitigation

Rules:
- Choose only from the catalogue. Do not invent control ids.
- Respond with JSON ONLY.

JSON structure:
{
  "mappings": [
    {"vuln_id": "V1", "control_id": "AC-7", "control_title": "Unsuccessful Logon Attempts", "effectiveness": 0.6}
  ]
}

Vulnerabilities:
{vulnerabilities}

NIST control catalogue (id: title):
{catalogue}
"""


SCENARIO_PROMPT = """You are a cybersecurity risk analyst.

Create a named security assessment SCENARIO for the system described below.

A scenario focuses on ONE specific attack path:
  - A specific threat actor targeting a specific asset through a specific vulnerability.
  - Include a realistic attack narrative.
  - Provide risk parameters: exposure (e), probability (p), and estimated impact.

Rules:
- Respond with JSON ONLY. No explanations, no markdown.

JSON structure:
{
  "scenario": {
    "id": "S1",
    "name": "...",
    "description": "...",
    "asset_id": "A1",
    "vuln_id": "V1",
    "threat_id": "T1",
    "narrative": "Step-by-step attack description...",
    "exposure": 0.8,
    "probability": 0.6,
    "impact": 0.9,
    "risk": 0.432,
    "recommendations": ["...", "..."]
  }
}

System description:
\"\"\"{description}\"\"\"

Available assets:
{assets}

Available vulnerabilities:
{vulnerabilities}

Available threats:
{threats}
"""


# ══════════════════════════════════════════════════════
#  CLAUDE CALL
# ══════════════════════════════════════════════════════

def _call_claude(prompt: str, max_tokens: int = 2000) -> dict:
    """Send a prompt to Claude and return parsed JSON."""
    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = message.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    return json.loads(raw)


def _clamp01(x) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return 0.0


# ══════════════════════════════════════════════════════
#  EXTRACTION
# ══════════════════════════════════════════════════════

def extract_elements(description: str) -> dict:
    """
    Extract assets, vulnerabilities and threats from a system description.
    Returns a dict with asset_id assigned to every vuln and threat.
    """
    prompt = EXTRACTION_PROMPT.replace("{description}", description.strip())
    data = _call_claude(prompt, max_tokens=2000)

    # Ensure asset_id is present on every item
    asset_ids = [a["id"] for a in data.get("assets", [])]
    default_asset = asset_ids[0] if asset_ids else ""

    for v in data.get("vulnerabilities", []):
        if not v.get("asset_id") or v["asset_id"] not in asset_ids:
            v["asset_id"] = default_asset

    for t in data.get("threats", []):
        if not t.get("asset_id") or t["asset_id"] not in asset_ids:
            t["asset_id"] = default_asset

    return data


def build_model(data: dict) -> CyberSystemModel:
    """Build a CyberSystemModel from extracted data."""
    model = CyberSystemModel()

    for a in data.get("assets", []):
        model.add_asset([a["id"], a["description"]])

    for v in data.get("vulnerabilities", []):
        meta = {"asset_id": v.get("asset_id", "")}
        model.add_vuln([v["id"], v["description"], meta])

    for t in data.get("threats", []):
        profile = t.get("octave_profile", {})
        profile["asset_id"] = t.get("asset_id", "")
        model.add_threat([t["id"], t["description"], profile])

    return model


# ══════════════════════════════════════════════════════
#  IMPACT + PROBABILITY
# ══════════════════════════════════════════════════════

def estimate_impact(model: CyberSystemModel) -> CyberSystemModel:
    """Ask Claude to estimate impact for every (vuln, threat) pair."""
    vulns_text  = "\n".join(f"{v[0]}: {v[1]}" for v in model.vulnerabilities)
    threats_text = "\n".join(f"{t[0]}: {t[1]}" for t in model.threats)

    prompt = IMPACT_PROMPT.replace("{vulnerabilities}", vulns_text)
    prompt = prompt.replace("{threats}", threats_text)

    data = _call_claude(prompt, max_tokens=2000)
    for entry in data.get("impacts", []):
        model.set_impact(entry["vuln_id"], entry["threat_id"],
                         _clamp01(entry["impact"]))
    return model


def estimate_probability(model: CyberSystemModel) -> CyberSystemModel:
    """Ask Claude for realistic attack probabilities per threat."""
    lines = []
    for t in model.threats:
        profile = t[2] if isinstance(t[2], dict) else {}
        profile_txt = ", ".join(
            f"{k}={profile.get(k, '')}"
            for k in ["actor", "motive", "access", "outcome"]
        )
        lines.append(f"{t[0]}: {t[1]} ({profile_txt})")
    threats_text = "\n".join(lines)

    prompt = PROBABILITY_PROMPT.replace("{threats}", threats_text)
    data   = _call_claude(prompt, max_tokens=1000)

    prob_map = {e["threat_id"]: _clamp01(e["probability"])
                for e in data.get("probabilities", [])}
    p = [prob_map.get(t[0], 1.0) for t in model.threats]
    if p:
        model.attack(p)
    return model


# ══════════════════════════════════════════════════════
#  NIST CONTROLS
# ══════════════════════════════════════════════════════

def suggest_controls(model: CyberSystemModel) -> CyberSystemModel:
    """Suggest the best NIST SP 800-53 control for each vulnerability."""
    with open("nist_controls.json", encoding="utf-8") as f:
        controls = json.load(f)

    catalogue_text = "\n".join(f"{c['id']}: {c['title']}" for c in controls)
    vulns_text     = "\n".join(f"{v[0]}: {v[1]}" for v in model.vulnerabilities)

    prompt = NIST_PROMPT.replace("{vulnerabilities}", vulns_text)
    prompt = prompt.replace("{catalogue}", catalogue_text)

    data = _call_claude(prompt, max_tokens=2000)

    for m in data.get("mappings", []):
        for v in model.vulnerabilities:
            if v[0] == m["vuln_id"]:
                meta = v[2] if isinstance(v[2], dict) else {}
                meta["nist_control"]  = m["control_id"]
                meta["nist_title"]    = m["control_title"]
                meta["effectiveness"] = _clamp01(m.get("effectiveness", 0.0))
                v[2] = meta

    return model


# ══════════════════════════════════════════════════════
#  SCENARIOS
# ══════════════════════════════════════════════════════

def generate_scenario(description: str, model: CyberSystemModel,
                      existing_scenarios: list | None = None) -> dict:
    """
    Ask Claude to generate one attack scenario using the current model.
    Returns a scenario dict ready to store.
    """
    assets_text = "\n".join(f"{a[0]}: {a[1]}" for a in model.assets)
    vulns_text  = "\n".join(f"{v[0]}: {v[1]}" for v in model.vulnerabilities)
    threats_text = "\n".join(f"{t[0]}: {t[1]}" for t in model.threats)

    # Offset the ID to avoid collisions
    n = len(existing_scenarios) + 1 if existing_scenarios else 1

    prompt = SCENARIO_PROMPT.replace("{description}", description.strip())
    prompt = prompt.replace("{assets}",        assets_text)
    prompt = prompt.replace("{vulnerabilities}", vulns_text)
    prompt = prompt.replace("{threats}",       threats_text)

    data     = _call_claude(prompt, max_tokens=1500)
    scenario = data.get("scenario", data)

    # Ensure id is unique
    scenario["id"] = f"S{n}"

    # Clamp numeric fields
    for field in ("exposure", "probability", "impact", "risk"):
        if field in scenario:
            scenario[field] = _clamp01(scenario[field])

    return scenario


# ══════════════════════════════════════════════════════
#  SIMULATION
# ══════════════════════════════════════════════════════

def simulate_protection(model: CyberSystemModel):
    """
    Recompute risk before and after applying controls.
    Returns (risk_before, risk_after).
    """
    risk_before = model.compute_risk()

    controls = []
    for v in model.vulnerabilities:
        meta = v[2] if isinstance(v[2], dict) else {}
        controls.append(_clamp01(meta.get("effectiveness", 0.0)))

    e_backup = list(model.e)
    if controls:
        model.protect(controls)
    risk_after  = model.compute_risk()
    model.e     = e_backup

    return risk_before, risk_after
