"""
simulation.py — Adversarial game engine for CySyMo.
Supports SSE streaming so the frontend sees each pipeline step in real time.
"""

import os
import json
import random
import uuid
import asyncio
from anthropic import Anthropic
import database as DB

# ─────────────────────────────────────────────
#  KILL CHAIN
# ─────────────────────────────────────────────

KILL_CHAIN = [
    "reconnaissance",
    "initial_access",
    "persistence",
    "lateral_movement",
    "privilege_escalation",
    "exfiltration",
]

STAGE_LABELS = {
    "reconnaissance":       "1 · Reconnaissance",
    "initial_access":       "2 · Initial Access",
    "persistence":          "3 · Persistence",
    "lateral_movement":     "4 · Lateral Movement",
    "privilege_escalation": "5 · Privilege Escalation",
    "exfiltration":         "6 · Exfiltration",
}

_games: dict[str, dict] = {}


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def _clamp01(x) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return 0.0


def _exposure(vuln: dict) -> float:
    return round(1.0 - _clamp01(vuln.get("effectiveness", 0.0)), 4)


def _current_risk(game: dict) -> float:
    vulns   = [v for v in game["vulns"]   if not v.get("patched")]
    threats = [t for t in game["threats"] if not t.get("neutralised")]
    impacts = game["impacts"]
    if not vulns or not threats:
        return 0.0
    total = sum(
        _exposure(v) * _clamp01(impacts.get(f"{v['id']}|{t['id']}", 0.0)) * _clamp01(t.get("probability", 1.0))
        for v in vulns for t in threats
    )
    return round(total / (len(vulns) * len(threats)), 4)


def _call_llm(system: str, user: str) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    model   = os.environ.get("CYSYMO_MODEL", "claude-sonnet-4-6")
    client  = Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model,
        max_tokens=600,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return msg.content[0].text.strip()


def _parse_json(text: str) -> dict:
    clean = text
    if "```" in clean:
        clean = clean.split("```")[1]
        if clean.startswith("json"):
            clean = clean[4:]
    try:
        return json.loads(clean.strip())
    except Exception:
        start, end = clean.find("{"), clean.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(clean[start:end])
            except Exception:
                pass
    return {"action": "wait", "rationale": "Parse error."}


def _sse(event: str, data: dict) -> str:
    """Format a Server-Sent Event string."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ─────────────────────────────────────────────
#  ATTACKER PROMPTS — progressive info reveal
# ─────────────────────────────────────────────

def _attacker_system(game: dict) -> str:
    stage     = game["attacker_stage"]
    budget    = game["attacker_budget"]
    foothold  = ", ".join(game["attacker_foothold"]) or "none"
    discovered = game.get("attacker_vulns_discovered", False)

    # Assets — always visible
    asset_list = "\n".join(
        f"  - {a['id']}: {a['description']}" for a in game["assets"]
    ) or "  (none)"

    # ── STAGE 1 — RECONNAISSANCE ──
    # Claude only knows assets exist. No vulns. Must scan to discover.
    if stage == "reconnaissance":
        return f"""You are a cyber attacker. Objective: exfiltrate data from the target system.

CURRENT STAGE: 1 · Reconnaissance
You are OUTSIDE the system. You can see the network exists but you do not know its vulnerabilities yet.
You must perform reconnaissance to discover what can be exploited.

WHAT YOU KNOW:
  Target assets (externally visible):
{asset_list}

WHAT YOU DON'T KNOW YET:
  - Vulnerabilities (you need to scan to find them)
  - Which assets are exploitable
  - What defenses are in place

BUDGET: {budget} pts remaining

YOUR AVAILABLE ACTIONS:
  scan_network         → active scan — discovers ALL vulnerabilities
  passive_recon        → passive observation — discovers PARTIAL vulnerabilities
  fingerprint_services → probe a specific asset for its services

Respond with JSON ONLY:
{{
  "action": "<scan_network | passive_recon | fingerprint_services>",
  "target": "<asset_id if fingerprinting, else empty>",
  "analysis": "<2-3 sentences: what you observe about the target and why you choose this recon method>",
  "rationale": "<one short sentence>"
}}"""

    # ── STAGE 2 — INITIAL ACCESS ──
    # Claude now knows the vulnerabilities (after recon). Must exploit one to enter.
    elif stage == "initial_access":
        open_vulns = [v for v in game["vulns"] if not v.get("patched")]
        vuln_list  = "\n".join(
            f"  - {v['id']}: {v['description']} | asset={v.get('asset_id','?')} | exposure e={_exposure(v):.2f} | NIST={v.get('nist_control','?')}"
            for v in open_vulns
        ) or "  (none found)"

        return f"""You are a cyber attacker. Objective: exfiltrate data from the target system.

CURRENT STAGE: 2 · Initial Access
Reconnaissance complete. You now know the vulnerabilities. Your goal: exploit one to enter the system.

WHAT YOU KNOW:
  Target assets:
{asset_list}

  Discovered vulnerabilities (from your scan):
{vuln_list}

BUDGET: {budget} pts remaining

YOUR AVAILABLE ACTIONS:
  exploit_vuln <vuln_id>  → exploit a specific vulnerability
                            success probability ∝ exposure e_i (higher e = easier to exploit)
  phishing                → social engineering attack on users
  brute_force             → credential brute force

STRATEGY: Pick the vulnerability with the highest exposure e_i — that means its NIST control is weak.

Respond with JSON ONLY:
{{
  "action": "<exploit_vuln | phishing | brute_force>",
  "target": "<vuln_id to exploit, or empty>",
  "analysis": "<2-3 sentences: which vuln you pick, why (reference e_i value), what asset you'll reach>",
  "rationale": "<one short sentence>"
}}"""

    # ── STAGE 3 — PERSISTENCE ──
    # Claude has a foothold. Must install backdoor to maintain access.
    elif stage == "persistence":
        return f"""You are a cyber attacker. Objective: exfiltrate data from the target system.

CURRENT STAGE: 3 · Persistence
You have a foothold on: {foothold}
The defender may detect and evict you. You must establish persistence to survive eviction.

WHAT YOU KNOW:
  Your foothold: {foothold}
  Assets you can reach: {foothold}

BUDGET: {budget} pts remaining

YOUR AVAILABLE ACTIONS:
  install_backdoor  → plant a hidden backdoor process
  create_account    → create a hidden admin account
  scheduled_task    → create a hidden scheduled task

Respond with JSON ONLY:
{{
  "action": "<install_backdoor | create_account | scheduled_task>",
  "target": "<asset_id where you're installing, or empty>",
  "analysis": "<2-3 sentences: why you need persistence now, which method you choose and why>",
  "rationale": "<one short sentence>"
}}"""

    # ── STAGE 4 — LATERAL MOVEMENT ──
    # Claude has foothold on one asset. Must spread to others to reach the database.
    elif stage == "lateral_movement":
        open_vulns = [v for v in game["vulns"] if not v.get("patched")]
        reachable  = "\n".join(
            f"  - {a['id']}: {a['description']}"
            for a in game["assets"] if a["id"] not in game["attacker_foothold"]
        ) or "  (none — all assets compromised)"

        return f"""You are a cyber attacker. Objective: exfiltrate data from the target system.

CURRENT STAGE: 4 · Lateral Movement
You control: {foothold}
You need to spread to other assets to reach the data you want to steal.

WHAT YOU KNOW:
  Assets you control: {foothold}
  Assets not yet compromised:
{reachable}

BUDGET: {budget} pts remaining

YOUR AVAILABLE ACTIONS:
  lateral_movement  → move from your foothold to an adjacent asset
  pass_the_hash     → reuse stolen credentials to access another asset
  pivot             → tunnel through compromised asset to reach isolated assets

Respond with JSON ONLY:
{{
  "action": "<lateral_movement | pass_the_hash | pivot>",
  "target": "<asset_id you want to move to>",
  "analysis": "<2-3 sentences: which asset you target, how you move there, why it brings you closer to data>",
  "rationale": "<one short sentence>"
}}"""

    # ── STAGE 5 — PRIVILEGE ESCALATION ──
    # Claude is on multiple assets but needs root/admin to exfiltrate.
    elif stage == "privilege_escalation":
        return f"""You are a cyber attacker. Objective: exfiltrate data from the target system.

CURRENT STAGE: 5 · Privilege Escalation
You control: {foothold}
You have user-level access. You need admin/root to access protected data and exfiltrate it.

BUDGET: {budget} pts remaining

YOUR AVAILABLE ACTIONS:
  privilege_escalation  → exploit local vulnerability to become root/admin
  kernel_exploit        → use kernel vulnerability for guaranteed root
  sudo_abuse            → abuse misconfigured sudo rules

Respond with JSON ONLY:
{{
  "action": "<privilege_escalation | kernel_exploit | sudo_abuse>",
  "target": "<asset_id where you escalate>",
  "analysis": "<2-3 sentences: which asset, which method, why you have enough access to attempt this>",
  "rationale": "<one short sentence>"
}}"""

    # ── STAGE 6 — EXFILTRATION ──
    # Claude has root on at least one asset. Final step: steal the data.
    elif stage == "exfiltration":
        return f"""You are a cyber attacker. Objective: exfiltrate data from the target system.

CURRENT STAGE: 6 · Exfiltration — FINAL STAGE
You have root/admin access on: {foothold}
This is your final objective. Extract the data and win.

BUDGET: {budget} pts remaining

YOUR AVAILABLE ACTIONS:
  exfiltrate_data   → copy data to external server
  compress_encrypt  → compress and encrypt data before exfil
  covert_channel    → use DNS/ICMP to smuggle data out

Respond with JSON ONLY:
{{
  "action": "<exfiltrate_data | compress_encrypt | covert_channel>",
  "target": "<asset_id with the data>",
  "analysis": "<2-3 sentences: which asset holds the most valuable data, which method you use to avoid detection>",
  "rationale": "<one short sentence>"
}}"""

    else:
        return "You are a cyber attacker. Wait for your turn."


# ─────────────────────────────────────────────
#  DEFENDER PROMPT
# ─────────────────────────────────────────────

def _defender_system(game: dict) -> str:
    open_vulns  = [v for v in game["vulns"] if not v.get("patched")]
    alerts      = game["defender_alerts"][-5:]
    alert_list  = "\n".join(f"  ⚠ {a}" for a in alerts) or "  (no alerts)"
    ids_level   = game.get("defender_ids_level", 0.3)
    mfa         = game.get("defender_mfa", False)
    segmented   = game.get("defender_segmented", False)

    # Vulnerabilities with full detail — defender always knows their own system
    vuln_list = "\n".join(
        f"  - {v['id']}: {v['description']}\n"
        f"    asset={v.get('asset_id','?')} | NIST={v.get('nist_control','?')} | "
        f"effectiveness={v.get('effectiveness',0):.2f} | exposure e={_exposure(v):.2f}"
        for v in open_vulns
    ) or "  (all vulnerabilities patched — excellent!)"

    # What the defender knows about the attacker
    atk_stage   = game["attacker_stage"]
    atk_foothold = ", ".join(game["attacker_foothold"]) or "unknown"
    atk_info    = ""
    if alerts:
        atk_info = f"\n  Last known attacker position: {atk_foothold} (from IDS alerts)"
    else:
        atk_info = "\n  Attacker position: unknown (no IDS alerts yet)"

    return f"""You are a Blue Team defender (CISO). Objective: prevent the attacker from exfiltrating data.

YOUR SYSTEM STATUS:
  Budget remaining : {game['defender_budget']} pts
  IDS detection    : {ids_level:.0%} (chance of detecting attacker actions)
  MFA enabled      : {"yes" if mfa else "no"}
  Network segmented: {"yes" if segmented else "no"}

WHAT YOU KNOW — YOUR VULNERABILITIES:
  (You know your own system completely. Each vuln has an exposure e = 1 - NIST_effectiveness.
   High e means the control is weak and the attacker will target it first.)
{vuln_list}

WHAT YOUR IDS TELLS YOU:
{alert_list}{atk_info}

AVAILABLE DEFENSIVE ACTIONS:
  patch_vuln <vuln_id>   → permanently close a vulnerability
                           effect: removes vuln from formula → e_i = 0 → R decreases
  deploy_ids             → upgrade intrusion detection
                           effect: detection % increases by 20% → more alerts next turn
  enable_mfa             → force MFA on all assets
                           effect: effectiveness of all vulns +15% → e_i decreases → R decreases
  network_segmentation   → isolate assets from each other
                           effect: blocks attacker lateral movement
  incident_response      → evict attacker from detected position
                           effect: removes attacker from foothold (only works if IDS detected them)
  honeypot               → deploy decoy asset
                           effect: attacker may waste a turn on the decoy
  wait                   → monitor only

STRATEGY HINT: The vulnerability with the highest exposure e_i is the attacker's most likely target.
Patch it before the attacker reaches Initial Access stage.

Respond with JSON ONLY:
{{
  "action": "<action_key>",
  "target": "<vuln_id if patching, else empty>",
  "analysis": "<2-3 sentences: what alerts you see, which vuln is most at risk, why you choose this action>",
  "rationale": "<one short sentence>"
}}"""


# ─────────────────────────────────────────────
#  ATTACKER ENGINE
# ─────────────────────────────────────────────

def _run_attacker(game: dict) -> dict:
    stage = game["attacker_stage"]

    last_def = game["log"][-1]["defender"]["action"] if game["log"] else "nothing yet"
    user_msg = (
        f"Turn {game['turn']}. "
        f"Defender last action: {last_def}. "
        f"What is your action this turn?"
    )

    raw      = _call_llm(_attacker_system(game), user_msg)
    decision = _parse_json(raw)

    action   = decision.get("action", "wait")
    target   = decision.get("target", "")
    analysis = decision.get("analysis", "")
    rational = decision.get("rationale", "")

    default_costs = {
        "scan_network": 5, "passive_recon": 5, "fingerprint_services": 5,
        "reconnaissance": 5, "scan": 5,
        "exploit_vuln": 15, "phishing": 12, "brute_force": 10,
        "install_backdoor": 15, "create_account": 10, "scheduled_task": 10,
        "persistence": 15,
        "lateral_movement": 15, "pass_the_hash": 15, "pivot": 15,
        "privilege_escalation": 20, "kernel_exploit": 25, "sudo_abuse": 15,
        "exfiltrate_data": 25, "compress_encrypt": 10, "covert_channel": 20,
        "exfiltrate": 25, "exfiltration": 25,
        "wait": 0,
    }
    custom = game.get("custom_costs", {})
    costs  = {**default_costs, **custom}
    cost   = costs.get(action, 10)

    success_prob = 0.65
    for v in game["vulns"]:
        if v["id"] == target and not v.get("patched"):
            success_prob = min(0.95, 0.5 + _exposure(v) * 0.5)
            break

    control_strength = sum(
        _clamp01(v.get("effectiveness", 0.0)) for v in game["vulns"] if not v.get("patched")
    ) / max(len(game["vulns"]), 1)
    detection_prob = 0.20 + control_strength * 0.4
    if game.get("defender_ids_level", 0.3) > 0.5:
        detection_prob = min(0.9, detection_prob + 0.2)
    if action == "passive_recon":
        detection_prob = max(0.05, detection_prob - 0.15)
    if action == "scan_network":
        detection_prob = min(0.9, detection_prob + 0.1)

    success  = random.random() < success_prob
    detected = random.random() < detection_prob
    outcome_msg = ""

    # Stage 1 — Reconnaissance
    if action in ("scan_network", "reconnaissance", "scan"):
        n = len([v for v in game["vulns"] if not v.get("patched")])
        outcome_msg = f"Active scan complete — discovered {n} open vulnerabilities across {len(game['assets'])} assets."
        game["attacker_vulns_discovered"] = True
        if stage == "reconnaissance": game["attacker_stage"] = "initial_access"
        success = True
    elif action == "passive_recon":
        n = len([v for v in game["vulns"] if not v.get("patched")])
        outcome_msg = f"Passive recon complete — detected {max(1,int(n*0.6))}/{n} vulnerabilities (partial). Stealthy."
        game["attacker_vulns_discovered"] = True
        if stage == "reconnaissance": game["attacker_stage"] = "initial_access"
        success = True
    elif action == "fingerprint_services":
        outcome_msg = f"Fingerprinted {target or 'target'} — identified software versions and open ports."
        game["attacker_vulns_discovered"] = True
        if stage == "reconnaissance": game["attacker_stage"] = "initial_access"
        success = True

    # Stage 2 — Initial Access
    elif action in ("exploit_vuln", "initial_access"):
        if success:
            for v in game["vulns"]:
                if v["id"] == target and not v.get("patched"):
                    asset_id = v.get("asset_id", target)
                    if asset_id not in game["attacker_foothold"]:
                        game["attacker_foothold"].append(asset_id)
                    outcome_msg = f"Exploited {target} (e={_exposure(v):.2f}) → foothold on {asset_id}."
                    if stage == "initial_access": game["attacker_stage"] = "persistence"
                    break
            else:
                outcome_msg = f"Exploit of {target} failed — not found or already patched."
                success = False
        else:
            outcome_msg = f"Exploit of {target} failed — NIST controls blocked the attempt."
    elif action == "phishing":
        if success:
            for a in game["assets"]:
                if a["id"] not in game["attacker_foothold"]:
                    game["attacker_foothold"].append(a["id"])
                    outcome_msg = f"Phishing succeeded — credentials obtained, foothold on {a['id']}."
                    if stage == "initial_access": game["attacker_stage"] = "persistence"
                    break
        else:
            outcome_msg = "Phishing blocked — MFA or user awareness stopped the attack."
    elif action == "brute_force":
        if success:
            for a in game["assets"]:
                if a["id"] not in game["attacker_foothold"]:
                    game["attacker_foothold"].append(a["id"])
                    outcome_msg = f"Brute force succeeded — weak credentials on {a['id']}."
                    if stage == "initial_access": game["attacker_stage"] = "persistence"
                    break
        else:
            outcome_msg = "Brute force failed — account lockout or strong passwords."

    # Stage 3 — Persistence
    elif action in ("install_backdoor", "persistence", "create_account", "scheduled_task"):
        if success:
            game["attacker_persistent"] = True
            msgs = {"install_backdoor":"Backdoor installed — survives reboots.",
                    "create_account":"Hidden admin account created.",
                    "scheduled_task":"Scheduled task planted — re-executes on reboot."}
            outcome_msg = msgs.get(action, "Persistence established.")
            if stage == "persistence": game["attacker_stage"] = "lateral_movement"
        else:
            outcome_msg = "Persistence failed — EDR/AV detected and removed the mechanism."

    # Stage 4 — Lateral Movement
    elif action in ("lateral_movement", "pass_the_hash", "pivot"):
        if game.get("defender_segmented"):
            success = False
            outcome_msg = "Lateral movement blocked — network segmentation is active."
        elif success:
            for a in game["assets"]:
                if a["id"] not in game["attacker_foothold"]:
                    game["attacker_foothold"].append(a["id"])
                    msgs = {"lateral_movement":f"Moved laterally to {a['id']}.",
                            "pass_the_hash":f"Pass-the-hash to {a['id']} — reused stolen credentials.",
                            "pivot":f"Pivoted through foothold to {a['id']}."}
                    outcome_msg = msgs.get(action, f"Reached {a['id']}.")
                    if stage == "lateral_movement": game["attacker_stage"] = "privilege_escalation"
                    break
            else:
                outcome_msg = "No new assets reachable."
        else:
            outcome_msg = "Lateral movement failed — host firewall blocked the connection."

    # Stage 5 — Privilege Escalation
    elif action in ("privilege_escalation", "kernel_exploit", "sudo_abuse"):
        if game.get("defender_mfa") and action != "kernel_exploit":
            success = False
            outcome_msg = "Privilege escalation blocked — MFA enforcement active."
        elif success:
            game["attacker_root"] = True
            msgs = {"privilege_escalation":"Local priv-esc succeeded — root obtained.",
                    "kernel_exploit":"Kernel exploit succeeded — ring-0 access.",
                    "sudo_abuse":"Sudo misconfiguration exploited — root via sudo."}
            outcome_msg = msgs.get(action, "Root access obtained.")
            if stage == "privilege_escalation": game["attacker_stage"] = "exfiltration"
        else:
            outcome_msg = "Privilege escalation failed — system is hardened."

    # Stage 6 — Exfiltration
    elif action in ("exfiltrate_data", "exfiltrate", "exfiltration", "compress_encrypt", "covert_channel"):
        if success:
            game["attacker_score"] += 50
            game["game_over"] = True
            game["winner"]    = "attacker"
            msgs = {"exfiltrate_data":"DATA EXFILTRATED — files copied to C2 server. Attacker wins.",
                    "compress_encrypt":"Compressed & encrypted data exfiltrated. Attacker wins.",
                    "covert_channel":"Covert DNS channel used — silent exfiltration. Attacker wins."}
            outcome_msg = msgs.get(action, "DATA EXFILTRATED. Attacker wins.")
        else:
            outcome_msg = "Exfiltration blocked — DLP or firewall detected the outbound transfer."
    else:
        outcome_msg = f"Action '{action}' executed." if success else f"Action '{action}' failed."

    game["attacker_budget"] -= cost
    if game["attacker_budget"] < 0:
        game["attacker_budget"] = 0
        if not game["game_over"]:
            game["game_over"] = True
            game["winner"]    = "defender"

    if detected:
        game["defender_alerts"].append(
            f"Turn {game['turn']}: Suspicious — {action} on {target or 'system'}: {outcome_msg[:60]}"
        )

    return {
        "action":    action,
        "target":    target,
        "analysis":  analysis,
        "rationale": rational,
        "success":   success,
        "detected":  detected,
        "cost":      cost,
        "outcome":   outcome_msg,
        "stage":     STAGE_LABELS[game["attacker_stage"]],
    }


# ─────────────────────────────────────────────
#  DEFENDER ENGINE
# ─────────────────────────────────────────────

def _run_defender(game: dict, atk: dict) -> dict:
    if atk["detected"]:
        game["defender_alerts"].append(
            f"Turn {game['turn']}: {atk['action']} on {atk['target']} — {atk['outcome']}"
        )

    user_msg = (
        f"Turn {game['turn']}. "
        f"Attacker detected this turn: {atk['detected']}. "
        f"{'ALERT: ' + atk['outcome'] if atk['detected'] else 'No new alert.'} "
        f"Choose your defensive action."
    )

    raw      = _call_llm(_defender_system(game), user_msg)
    decision = _parse_json(raw)

    action   = decision.get("action", "wait")
    target   = decision.get("target", "")
    analysis = decision.get("analysis", "")
    rational = decision.get("rationale", "")

    default_costs = {
        "patch_vuln": 20, "deploy_ids": 25, "enable_mfa": 10,
        "network_segmentation": 30, "incident_response": 20,
        "honeypot": 15, "wait": 0,
    }
    custom = game.get("custom_costs", {})
    costs  = {**default_costs, **custom}
    cost   = costs.get(action, 10)
    outcome_msg = ""

    if action == "patch_vuln":
        patched = False
        for v in game["vulns"]:
            if v["id"] == target and not v.get("patched"):
                v["patched"] = True
                outcome_msg = f"{target} patched and closed permanently."
                patched = True
                break
        if not patched:
            open_v = [v for v in game["vulns"] if not v.get("patched")]
            if open_v:
                best = max(open_v, key=_exposure)
                best["patched"] = True
                outcome_msg = f"Auto-patched most exposed vulnerability {best['id']}."
            else:
                outcome_msg = "No vulnerabilities left to patch."
                cost = 0

    elif action == "deploy_ids":
        game["defender_ids_level"] = min(1.0, game.get("defender_ids_level", 0.3) + 0.2)
        outcome_msg = f"IDS upgraded → detection now at {game['defender_ids_level']:.0%}."

    elif action == "enable_mfa":
        game["defender_mfa"] = True
        for v in game["vulns"]:
            v["effectiveness"] = min(1.0, _clamp01(v.get("effectiveness", 0)) + 0.15)
        outcome_msg = "MFA enabled on all assets — effectiveness raised."

    elif action == "network_segmentation":
        game["defender_segmented"] = True
        if game["attacker_foothold"]:
            removed = game["attacker_foothold"].pop()
            outcome_msg = f"Network segmented — attacker evicted from {removed}."
        else:
            outcome_msg = "Network segmented — lateral movement now blocked."

    elif action == "incident_response":
        if atk["detected"] and game["attacker_foothold"]:
            removed = game["attacker_foothold"].pop(0)
            game["attacker_persistent"] = False
            outcome_msg = f"IR team deployed — attacker evicted from {removed}."
        else:
            outcome_msg = "IR team deployed but attacker not located yet."

    elif action == "honeypot":
        game["defender_honeypot"] = True
        outcome_msg = "Honeypot deployed — attacker may waste next turn on decoy."
    else:
        outcome_msg = "Defender monitoring — no action taken."
        cost = 0

    game["defender_budget"] -= cost
    if game["defender_budget"] < 0:
        game["defender_budget"] = 0
        if not game["game_over"]:
            game["game_over"] = True
            game["winner"]    = "attacker"

    if all(v.get("patched") for v in game["vulns"]) and not game["game_over"]:
        game["game_over"] = True
        game["winner"]    = "defender"
        outcome_msg      += " ALL VULNERABILITIES PATCHED — Defender wins!"

    return {
        "action":    action,
        "target":    target,
        "analysis":  analysis,
        "rationale": rational,
        "cost":      cost,
        "outcome":   outcome_msg,
    }


# ─────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────

def _game_to_storable(game: dict) -> dict:
    """Convert in-memory game to a JSON-serialisable snapshot."""
    return {
        "sim_id":              game["sim_id"],
        "turn":                game["turn"],
        "max_turns":           game["max_turns"],
        "vulns":               game["vulns"],
        "threats":             game["threats"],
        "assets":              game["assets"],
        "impacts":             game["impacts"],
        "attacker_budget":     game["attacker_budget"],
        "attacker_stage":      game["attacker_stage"],
        "attacker_foothold":   game["attacker_foothold"],
        "attacker_score":      game["attacker_score"],
        "attacker_persistent": game["attacker_persistent"],
        "attacker_root":       game["attacker_root"],
        "defender_budget":     game["defender_budget"],
        "defender_alerts":     game["defender_alerts"],
        "defender_ids_level":  game["defender_ids_level"],
        "defender_mfa":        game["defender_mfa"],
        "defender_segmented":  game["defender_segmented"],
        "defender_honeypot":   game["defender_honeypot"],
        "game_over":           game["game_over"],
        "winner":              game["winner"],
        "initial_risk":        game["initial_risk"],
        "log":                 game["log"],
    }


def restore_simulation(sim_id: str) -> bool:
    """
    Load a simulation from SQLite back into _games memory.
    Returns True if found, False if not.
    """
    if sim_id in _games:
        return True  # already in memory
    row = DB.load_simulation(sim_id)
    if not row:
        return False
    state = row["state"]
    _games[sim_id] = state
    return True


def start_simulation(model: dict, config: dict) -> str:
    sim_id = str(uuid.uuid4())[:8]

    impacts = {
        f"{imp['vuln_id']}|{imp['threat_id']}": _clamp01(imp.get("value", 0.0))
        for imp in model.get("impacts", [])
    }
    vulns   = [dict(v, patched=False) for v in model.get("vulnerabilities", [])]
    threats = [dict(t) for t in model.get("threats", [])]
    assets  = [dict(a) for a in model.get("assets", [])]

    initial_risk = _current_risk({"vulns": vulns, "threats": threats, "impacts": impacts})

    game = {
        "sim_id":              sim_id,
        "turn":                0,
        "max_turns":           config.get("max_turns", 10),
        "vulns":               vulns,
        "threats":             threats,
        "assets":              assets,
        "impacts":             impacts,
        "attacker_budget":     config.get("attacker_budget", 100),
        "attacker_stage":      "reconnaissance",
        "attacker_foothold":   [],
        "attacker_score":      0,
        "attacker_persistent": False,
        "attacker_root":       False,
        "attacker_vulns_discovered": False,
        "custom_costs":        config.get("costs", {}),  # user-defined costs
        "defender_budget":     config.get("defender_budget", 120),
        "defender_alerts":     [],
        "defender_ids_level":  0.3,
        "defender_mfa":        False,
        "defender_segmented":  False,
        "defender_honeypot":   False,
        "game_over":           False,
        "winner":              None,
        "initial_risk":        initial_risk,
        "log":                 [],
    }
    _games[sim_id] = game

    # Persist initial state to SQLite
    label = config.get("label", f"Simulation {sim_id}")
    DB.save_simulation(sim_id, label, config, _game_to_storable(game))

    return sim_id


def get_state(sim_id: str) -> dict:
    game = _games.get(sim_id)
    if not game:
        return {"error": "Simulation not found."}

    open_vulns = [v for v in game["vulns"] if not v.get("patched")]
    return {
        "sim_id":       sim_id,
        "turn":         game["turn"],
        "max_turns":    game["max_turns"],
        "game_over":    game["game_over"],
        "winner":       game["winner"],
        "initial_risk": game["initial_risk"],
        "current_risk": _current_risk(game),
        "attacker": {
            "stage":      STAGE_LABELS[game["attacker_stage"]],
            "budget":     game["attacker_budget"],
            "score":      game["attacker_score"],
            "foothold":   game["attacker_foothold"],
            "persistent": game["attacker_persistent"],
            "root":       game["attacker_root"],
        },
        "defender": {
            "budget":    game["defender_budget"],
            "alerts":    len(game["defender_alerts"]),
            "ids_level": game["defender_ids_level"],
            "mfa":       game["defender_mfa"],
            "segmented": game["defender_segmented"],
        },
        "open_vulns":  len(open_vulns),
        "total_vulns": len(game["vulns"]),
        "vulns":       [{"id": v["id"], "patched": v.get("patched", False),
                         "description": v.get("description", "")} for v in game["vulns"]],
        "log":         game["log"],
    }


async def stream_full_game(sim_id: str):
    """
    Generator that streams the ENTIRE game turn by turn via SSE.
    Each turn emits multiple events so the frontend sees each pipeline step.
    """
    game = _games.get(sim_id)
    if not game:
        yield _sse("error", {"message": "Simulation not found."})
        return

    delay = 1.2  # seconds between pipeline steps

    while not game["game_over"] and game["turn"] < game["max_turns"]:
        game["turn"] += 1

        # ── TURN START ──
        yield _sse("turn_start", {
            "turn":     game["turn"],
            "max":      game["max_turns"],
            "risk":     _current_risk(game),
        })
        await asyncio.sleep(delay)

        # ── ATTACKER: thinking ──
        yield _sse("atk_thinking", {
            "stage":  STAGE_LABELS[game["attacker_stage"]],
            "budget": game["attacker_budget"],
            "msg":    f"Analysing {len([v for v in game['vulns'] if not v.get('patched')])} open vulnerabilities…",
        })
        await asyncio.sleep(delay)

        # ── ATTACKER: send prompt to frontend BEFORE LLM call ──
        atk_system = _attacker_system(game)
        atk_user   = (
            f"Turn {game['turn']}. "
            f"Defender last action: {game['log'][-1]['defender']['action'] if game['log'] else 'nothing yet'}. "
            f"What is your action this turn?"
        )
        yield _sse("atk_prompt", {
            "turn":   game["turn"],
            "system": atk_system,
            "user":   atk_user,
            "stage":  STAGE_LABELS[game["attacker_stage"]],
        })
        await asyncio.sleep(delay * 0.5)

        # ── ATTACKER: LLM call ──
        atk = _run_attacker(game)

        yield _sse("atk_analysis", {
            "analysis": atk["analysis"],
            "stage":    atk["stage"],
        })
        await asyncio.sleep(delay)

        yield _sse("atk_decision", {
            "action":    atk["action"],
            "target":    atk["target"],
            "rationale": atk["rationale"],
            "cost":      atk["cost"],
        })
        await asyncio.sleep(delay)

        yield _sse("atk_outcome", {
            "success":  atk["success"],
            "detected": atk["detected"],
            "outcome":  atk["outcome"],
            "budget":   game["attacker_budget"],
            "foothold": game["attacker_foothold"],
        })
        await asyncio.sleep(delay)

        if game["game_over"]:
            yield _sse("game_over", {"winner": game["winner"], "state": get_state(sim_id)})
            return

        # ── DEFENDER: thinking ──
        yield _sse("def_thinking", {
            "alerts":    len(game["defender_alerts"]),
            "detected":  atk["detected"],
            "ids_level": game["defender_ids_level"],
            "msg":       f"{'⚠ Alert received — analysing threat…' if atk['detected'] else 'No alert — evaluating vulnerabilities to patch…'}",
        })
        await asyncio.sleep(delay)

        # ── DEFENDER: send prompt to frontend BEFORE LLM call ──
        def_system = _defender_system(game)
        def_user   = (
            f"Turn {game['turn']}. "
            f"Attacker detected this turn: {atk['detected']}. "
            f"{'ALERT: ' + atk['outcome'] if atk['detected'] else 'No new alert.'} "
            f"Choose your defensive action."
        )
        yield _sse("def_prompt", {
            "turn":   game["turn"],
            "system": def_system,
            "user":   def_user,
            "alerts": game["defender_alerts"][-3:],
        })
        await asyncio.sleep(delay * 0.5)

        # ── DEFENDER: LLM call ──
        dfn = _run_defender(game, atk)

        yield _sse("def_analysis", {
            "analysis": dfn["analysis"],
        })
        await asyncio.sleep(delay)

        yield _sse("def_decision", {
            "action":    dfn["action"],
            "target":    dfn["target"],
            "rationale": dfn["rationale"],
            "cost":      dfn["cost"],
        })
        await asyncio.sleep(delay)

        yield _sse("def_outcome", {
            "outcome": dfn["outcome"],
            "budget":  game["defender_budget"],
            "mfa":     game["defender_mfa"],
            "segmented": game["defender_segmented"],
        })
        await asyncio.sleep(delay)

        # ── TURN SUMMARY ──
        turn_log = {
            "turn":     game["turn"],
            "attacker": atk,
            "defender": dfn,
            "risk":     _current_risk(game),
        }
        game["log"].append(turn_log)

        # Persist to SQLite after every turn
        DB.save_simulation(sim_id, f"Simulation {sim_id}", {}, _game_to_storable(game))

        yield _sse("turn_end", {
            "turn":  game["turn"],
            "risk":  _current_risk(game),
            "state": get_state(sim_id),
        })
        await asyncio.sleep(delay * 1.5)

        if game["game_over"]:
            yield _sse("game_over", {"winner": game["winner"], "state": get_state(sim_id)})
            return

    # Max turns reached
    if not game["game_over"]:
        game["game_over"] = True
        game["winner"]    = "defender"

    yield _sse("game_over", {"winner": game["winner"], "state": get_state(sim_id)})


def next_turn(sim_id: str) -> dict:
    """Synchronous single-turn (kept for compatibility)."""
    game = _games.get(sim_id)
    if not game:
        return {"error": "Simulation not found."}
    if game["game_over"]:
        return {"error": "Game over.", "state": get_state(sim_id)}
    if game["turn"] >= game["max_turns"]:
        game["game_over"] = True
        game["winner"]    = "defender"
        return {"error": "Max turns reached.", "state": get_state(sim_id)}

    game["turn"] += 1
    atk = _run_attacker(game)
    dfn = _run_defender(game, atk) if not game["game_over"] else {"action":"—","target":"—","analysis":"—","rationale":"—","cost":0,"outcome":"—"}

    turn_log = {"turn": game["turn"], "attacker": atk, "defender": dfn, "risk": _current_risk(game)}
    game["log"].append(turn_log)

    return {"turn_result": turn_log, "state": get_state(sim_id)}
