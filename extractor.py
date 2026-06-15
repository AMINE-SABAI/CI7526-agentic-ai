import json
import os
from dotenv import load_dotenv
from anthropic import Anthropic
from cysymo import CyberSystemModel

load_dotenv()


EXTRACTION_PROMPT = """You are a cybersecurity risk analyst.

Read the following plain-language description of a system and extract:
- its VULNERABILITIES (weaknesses an attacker could exploit),
- its THREATS (who or what could attack, and how),
- its ASSETS (the valuable things worth protecting).

For each THREAT, also give an OCTAVE threat profile with four attributes:
- actor:   who attacks (e.g. external attacker, malicious insider, accidental user)
- motive:  deliberate or accidental
- access:  how the attack happens (e.g. network, physical, via an application)
- outcome: the result (disclosure, modification, destruction, or interruption)

Rules:
- Base everything strictly on the description. Do not invent components.
- Give each item a short unique id (V1, V2... ; T1, T2... ; A1, A2...).
- Keep each description to one clear sentence.
- Respond with JSON ONLY. No explanations, no markdown.

Use exactly this JSON structure:
{
  "vulnerabilities": [{"id": "V1", "description": "..."}],
  "threats": [
    {
      "id": "T1",
      "description": "...",
      "octave_profile": {
        "actor": "...",
        "motive": "...",
        "access": "...",
        "outcome": "..."
      }
    }
  ],
  "assets": [{"id": "A1", "description": "..."}]
}

System description:
\"\"\"
{description}
\"\"\"
"""


IMPACT_PROMPT = """You are a cybersecurity risk analyst.

Given a list of vulnerabilities and a list of threats, estimate the IMPACT of each
threat exploiting each vulnerability, as a number between 0.0 and 1.0:
- 0.0 = no impact (this threat cannot meaningfully exploit this vulnerability)
- 1.0 = catastrophic impact

Rules:
- Give an impact value for EVERY (vulnerability, threat) pair.
- Base your estimate on how plausibly and severely the threat could exploit the vulnerability.
- Respond with JSON ONLY. No explanations, no markdown.

Use exactly this JSON structure (one entry per pair):
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


NIST_PROMPT = """You are a cybersecurity risk analyst.

For each vulnerability below, choose the SINGLE most relevant NIST SP 800-53
control from the provided catalogue to mitigate it.

Rules:
- Choose only from the catalogue provided. Do not invent control ids.
- Pick the one control that best addresses each vulnerability.
- Respond with JSON ONLY. No explanations, no markdown.

Use exactly this JSON structure:
{
  "mappings": [
    {"vuln_id": "V1", "control_id": "AC-7", "control_title": "Unsuccessful Logon Attempts"}
  ]
}

Vulnerabilities:
{vulnerabilities}

NIST control catalogue (id: title):
{catalogue}
"""


def extract_elements(description):
    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    prompt = EXTRACTION_PROMPT.replace("{description}", description.strip())

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    return json.loads(raw)


def build_model(data):
    model = CyberSystemModel()

    for v in data.get("vulnerabilities", []):
        model.add_vuln([v["id"], v["description"], []])

    for t in data.get("threats", []):
        profile = t.get("octave_profile", {})
        model.add_threat([t["id"], t["description"], profile])

    for a in data.get("assets", []):
        model.add_asset([a["id"], a["description"]])

    return model


def estimate_impact(model):
    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    vulns_text = "\n".join(f"{v[0]}: {v[1]}" for v in model.vulnerabilities)
    threats_text = "\n".join(f"{t[0]}: {t[1]}" for t in model.threats)

    prompt = IMPACT_PROMPT.replace("{vulnerabilities}", vulns_text)
    prompt = prompt.replace("{threats}", threats_text)

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    data = json.loads(raw)

    for entry in data.get("impacts", []):
        model.set_impact(entry["vuln_id"], entry["threat_id"], entry["impact"])

    return model


def suggest_controls(model):
    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    with open("nist_controls.json", encoding="utf-8") as f:
        controls = json.load(f)

    catalogue_text = "\n".join(f"{c['id']}: {c['title']}" for c in controls)
    vulns_text = "\n".join(f"{v[0]}: {v[1]}" for v in model.vulnerabilities)

    prompt = NIST_PROMPT.replace("{vulnerabilities}", vulns_text)
    prompt = prompt.replace("{catalogue}", catalogue_text)

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    data = json.loads(raw)

    for m in data.get("mappings", []):
        for v in model.vulnerabilities:
            if v[0] == m["vuln_id"]:
                v[2] = {"nist_control": m["control_id"], "nist_title": m["control_title"]}

    return model


def simulate_protection(model, control_strength=0.7):
    risk_before = model.compute_risk()

    controls = [control_strength for _ in model.vulnerabilities]
    model.protect(controls)

    risk_after = model.compute_risk()

    return risk_before, risk_after


if __name__ == "__main__":
    description = (
        "An online shop. Customers log in with email and password. "
        "Their personal data and credit cards are stored in a database. "
        "A payment API processes the transactions."
    )

    data = extract_elements(description)
    model = build_model(data)
    model = estimate_impact(model)
    model = suggest_controls(model)

    print("Vulnerabilities:")
    for v in model.vulnerabilities:
        print(" ", v[0], ":", v[1])
        print("      NIST control:", v[2])

    print("\nThreats:")
    for t in model.threats:
        print(" ", t[0], ":", t[1])
        print("      OCTAVE profile:", t[2])

    print("\nImpact matrix:")
    for row in model.AI:
        print(" ", row)

    risk_before, risk_after = simulate_protection(model)

    print("\n=== RISK SIMULATION ===")
    print("  Risk BEFORE applying controls:", round(risk_before, 4))
    print("  Risk AFTER applying NIST controls:", round(risk_after, 4))
    reduction = round((risk_before - risk_after) / risk_before * 100, 1) if risk_before else 0
    print("  Risk reduction:", reduction, "%")