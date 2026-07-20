"""
game_engine.py — Human-in-the-loop serious game for CySyMo.

3 roles:
  - Professor (Game Master): creates the game, sets rules, watches everything
  - Attacker student: picks actions manually, must justify
  - Defender student: picks controls manually, must justify

Flow:
  1. Prof creates game from CySyMo model + sets rules
  2. Prof shares /game/{id}/attacker and /game/{id}/defender URLs to students
  3. Students take turns submitting actions with justifications
  4. Prof sees everything in real time at /game/{id}/master
  5. Game engine resolves each turn and updates state
  6. Prof reviews justifications and declares winner
"""

import json
import uuid
import random
import datetime
import database as DB

# ─────────────────────────────────────────────
#  CONSTANTS
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

# All possible attacker actions per kill chain stage
ATTACKER_ACTIONS = {
    "reconnaissance":       ["scan_network", "passive_recon", "fingerprint_services"],
    "initial_access":       ["exploit_vuln", "phishing", "brute_force"],
    "persistence":          ["install_backdoor", "create_account", "scheduled_task"],
    "lateral_movement":     ["lateral_movement", "pass_the_hash", "pivot"],
    "privilege_escalation": ["privilege_escalation", "kernel_exploit", "sudo_abuse"],
    "exfiltration":         ["exfiltrate_data", "compress_encrypt", "covert_channel"],
}

# All possible defender actions
DEFENDER_ACTIONS = [
    {"key": "patch_vuln",            "label": "Patch Vulnerability",     "cost": 20},
    {"key": "deploy_ids",            "label": "Deploy / Upgrade IDS",    "cost": 25},
    {"key": "enable_mfa",            "label": "Enable MFA",              "cost": 10},
    {"key": "network_segmentation",  "label": "Network Segmentation",    "cost": 30},
    {"key": "incident_response",     "label": "Incident Response",       "cost": 20},
    {"key": "honeypot",              "label": "Deploy Honeypot",         "cost": 15},
    {"key": "backup_restore",        "label": "Backup & Restore",        "cost": 15},
    {"key": "wait",                  "label": "Monitor / Wait",          "cost":  0},
]

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
    threats = game["threats"]
    impacts = game["impacts"]
    if not vulns or not threats:
        return 0.0
    total = sum(
        _exposure(v) * _clamp01(impacts.get(f"{v['id']}|{t['id']}", 0.0)) * _clamp01(t.get("probability", 1.0))
        for v in vulns for t in threats
    )
    return round(total / (len(vulns) * len(threats)), 4)


def _now() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _save(game: dict):
    """Persist game to SQLite."""
    DB.save_game(game["game_id"], game)


def _check_victory(game: dict) -> tuple[bool, str | None]:
    """Check if any victory condition is met. Returns (game_over, winner)."""
    rules = game["rules"]

    # Attacker: exfiltration success
    if game["attacker_exfiltrated"]:
        return True, "attacker"

    # Attacker: defender out of budget
    if game["defender_budget"] <= 0:
        return True, "attacker"

    # Defender: all critical vulns patched
    if rules.get("defender_wins_all_patched", True):
        critical = [v for v in game["vulns"] if not v.get("patched")]
        if not critical:
            return True, "defender"

    # Defender: max turns reached without exfiltration
    if game["turn"] >= game["max_turns"]:
        return True, "defender"

    # Attacker: out of budget
    if game["attacker_budget"] <= 0:
        return True, "defender"

    return False, None


# ─────────────────────────────────────────────
#  ACTION RESOLUTION
# ─────────────────────────────────────────────

def _resolve_attacker_action(game: dict, action: str, target: str) -> dict:
    """Apply attacker action and return outcome dict."""
    stage = game["attacker_stage"]
    rules = game["rules"]

    # Enforce kill chain order if required
    if rules.get("strict_kill_chain", True):
        expected = KILL_CHAIN[game["attacker_stage_index"]]
        allowed  = ATTACKER_ACTIONS.get(expected, [])
        # Be lenient: if action keyword matches stage name, allow it
        if action not in allowed and expected not in action:
            return {
                "success": False,
                "detected": False,
                "outcome": f"Invalid action for stage {STAGE_LABELS[stage]}. Must play a {stage} action.",
                "cost": 0,
            }

    # Cost
    costs = {
        "scan_network": 5, "passive_recon": 5, "fingerprint_services": 5,
        "exploit_vuln": 15, "phishing": 12, "brute_force": 10,
        "install_backdoor": 15, "create_account": 10, "scheduled_task": 10,
        "lateral_movement": 15, "pass_the_hash": 15, "pivot": 15,
        "privilege_escalation": 20, "kernel_exploit": 25, "sudo_abuse": 15,
        "exfiltrate_data": 25, "compress_encrypt": 10, "covert_channel": 20,
    }
    cost = costs.get(action, 10)

    # Success probability — based on vuln exposure or base rate
    success_prob = 0.60
    for v in game["vulns"]:
        if v["id"] == target and not v.get("patched"):
            success_prob = min(0.95, 0.45 + _exposure(v) * 0.55)
            break

    # Detection probability — based on IDS level and controls
    ids_level = game.get("defender_ids_level", 0.3)
    detect_prob = 0.20 + ids_level * 0.5
    if game.get("defender_honeypot") and stage in ("reconnaissance", "initial_access"):
        detect_prob = min(1.0, detect_prob + 0.25)

    success  = random.random() < success_prob
    detected = random.random() < detect_prob

    outcome = ""

    if stage == "reconnaissance":
        # Reconnaissance always "succeeds" — reveals info
        success = True
        visible = rules.get("attacker_vuln_visibility", "after_recon")
        if visible == "after_recon":
            game["attacker_vulns_revealed"] = True
        outcome = f"Reconnaissance complete. Discovered {len(game['vulns'])} vulnerabilities on {len(game['assets'])} assets."
        game["attacker_stage_index"] = min(game["attacker_stage_index"] + 1, len(KILL_CHAIN) - 1)
        game["attacker_stage"] = KILL_CHAIN[game["attacker_stage_index"]]

    elif stage == "initial_access" and success:
        for v in game["vulns"]:
            if v["id"] == target and not v.get("patched"):
                asset_id = v.get("asset_id", target)
                if asset_id not in game["attacker_foothold"]:
                    game["attacker_foothold"].append(asset_id)
                outcome = f"Successfully exploited {target} — gained foothold on {asset_id}."
                game["attacker_stage_index"] = min(game["attacker_stage_index"] + 1, len(KILL_CHAIN) - 1)
                game["attacker_stage"] = KILL_CHAIN[game["attacker_stage_index"]]
                break
        else:
            success = False
            outcome = f"Exploit of {target} failed — vulnerability may be patched or target not found."

    elif stage == "initial_access" and not success:
        outcome = f"Initial access attempt failed — controls blocked the exploit."

    elif stage == "persistence" and success:
        game["attacker_persistent"] = True
        outcome = "Backdoor installed — access will persist across reboots."
        game["attacker_stage_index"] = min(game["attacker_stage_index"] + 1, len(KILL_CHAIN) - 1)
        game["attacker_stage"] = KILL_CHAIN[game["attacker_stage_index"]]

    elif stage == "persistence" and not success:
        outcome = "Persistence attempt failed — EDR/AV detected and blocked the backdoor."

    elif stage == "lateral_movement" and success:
        if game.get("defender_segmented"):
            success = False
            outcome = "Lateral movement blocked — network segmentation is active."
        else:
            for a in game["assets"]:
                if a["id"] not in game["attacker_foothold"]:
                    game["attacker_foothold"].append(a["id"])
                    outcome = f"Moved laterally to {a['id']}."
                    game["attacker_stage_index"] = min(game["attacker_stage_index"] + 1, len(KILL_CHAIN) - 1)
                    game["attacker_stage"] = KILL_CHAIN[game["attacker_stage_index"]]
                    break
            else:
                outcome = "No new assets reachable."

    elif stage == "lateral_movement" and not success:
        outcome = "Lateral movement failed — host-based firewall blocked the attempt."

    elif stage == "privilege_escalation" and success:
        if game.get("defender_mfa"):
            success = False
            outcome = "Privilege escalation blocked — MFA is enforced."
        else:
            game["attacker_root"] = True
            outcome = "Privilege escalation successful — root/admin access obtained."
            game["attacker_stage_index"] = min(game["attacker_stage_index"] + 1, len(KILL_CHAIN) - 1)
            game["attacker_stage"] = KILL_CHAIN[game["attacker_stage_index"]]

    elif stage == "privilege_escalation" and not success:
        outcome = "Privilege escalation failed."

    elif stage == "exfiltration" and success:
        game["attacker_exfiltrated"] = True
        outcome = "DATA EXFILTRATED — Attacker objective complete."

    elif stage == "exfiltration" and not success:
        outcome = "Exfiltration attempt blocked — DLP/firewall detected the transfer."

    else:
        outcome = f"Action '{action}' executed." if success else f"Action '{action}' failed."

    game["attacker_budget"] -= cost

    if detected:
        game["defender_alerts"].append(
            f"Turn {game['turn']} — Suspicious: {action} on {target or '?'} · {outcome}"
        )

    return {"success": success, "detected": detected, "outcome": outcome, "cost": cost}


def _resolve_defender_action(game: dict, action: str, target: str) -> dict:
    """Apply defender action and return outcome dict."""
    costs = {a["key"]: a["cost"] for a in DEFENDER_ACTIONS}
    cost  = costs.get(action, 0)
    outcome = ""

    if action == "patch_vuln":
        patched = False
        for v in game["vulns"]:
            if v["id"] == target and not v.get("patched"):
                v["patched"] = True
                outcome = f"{target} patched and closed permanently."
                patched = True
                break
        if not patched:
            open_v = [v for v in game["vulns"] if not v.get("patched")]
            if open_v:
                best = max(open_v, key=_exposure)
                best["patched"] = True
                outcome = f"Auto-patched most exposed vulnerability {best['id']}."
            else:
                outcome = "No vulnerabilities left to patch."
                cost = 0

    elif action == "deploy_ids":
        game["defender_ids_level"] = min(1.0, game.get("defender_ids_level", 0.3) + 0.25)
        outcome = f"IDS upgraded — detection now at {game['defender_ids_level']:.0%}."

    elif action == "enable_mfa":
        game["defender_mfa"] = True
        for v in game["vulns"]:
            v["effectiveness"] = min(1.0, _clamp01(v.get("effectiveness", 0)) + 0.15)
        outcome = "MFA enabled on all assets."

    elif action == "network_segmentation":
        game["defender_segmented"] = True
        if game["attacker_foothold"]:
            removed = game["attacker_foothold"].pop()
            outcome = f"Network segmented — attacker evicted from {removed}."
        else:
            outcome = "Network segmented — lateral movement now blocked."

    elif action == "incident_response":
        if game["attacker_foothold"]:
            removed = game["attacker_foothold"].pop(0)
            game["attacker_persistent"] = False
            outcome = f"IR team deployed — attacker removed from {removed}."
        else:
            outcome = "IR team deployed but attacker not located yet."

    elif action == "honeypot":
        game["defender_honeypot"] = True
        outcome = "Honeypot deployed — attacker detection chance increased."

    elif action == "backup_restore":
        # Restore reduces attacker progress
        if game["attacker_foothold"]:
            game["attacker_foothold"].clear()
            game["attacker_persistent"] = False
            outcome = "Backup restored — attacker foothold wiped from all systems."
        else:
            outcome = "Backup verified — systems clean."

    else:
        outcome = "Monitoring — no action taken."
        cost = 0

    game["defender_budget"] -= cost
    return {"outcome": outcome, "cost": cost}


# ─────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────

def create_game(model: dict, rules: dict, label: str = "") -> str:
    """
    Create a new game session from a CySyMo model.
    rules = {
      max_turns, attacker_budget, defender_budget,
      strict_kill_chain, attacker_vuln_visibility,  (all / after_recon / none)
      defender_sees_attacker,                        (always / on_detection / never)
      defender_wins_all_patched, justification_required, min_justification_words,
      active_stages                                  (list of stage keys)
    }
    """
    game_id = str(uuid.uuid4())[:8]

    impacts = {
        f"{imp['vuln_id']}|{imp['threat_id']}": _clamp01(imp.get("value", 0.0))
        for imp in model.get("impacts", [])
    }
    vulns   = [dict(v, patched=False) for v in model.get("vulnerabilities", [])]
    threats = [dict(t) for t in model.get("threats", [])]
    assets  = [dict(a) for a in model.get("assets", [])]

    game = {
        "game_id":               game_id,
        "label":                 label or f"Game {game_id}",
        "created_at":            _now(),
        "status":                "waiting",   # waiting → playing → finished
        "turn":                  0,
        "max_turns":             rules.get("max_turns", 8),
        "rules":                 rules,
        "vulns":                 vulns,
        "threats":               threats,
        "assets":                assets,
        "impacts":               impacts,
        # Attacker state
        "attacker_budget":       rules.get("attacker_budget", 100),
        "attacker_stage":        "reconnaissance",
        "attacker_stage_index":  0,
        "attacker_foothold":     [],
        "attacker_persistent":   False,
        "attacker_root":         False,
        "attacker_exfiltrated":  False,
        "attacker_vulns_revealed": rules.get("attacker_vuln_visibility", "all") == "all",
        # Defender state
        "defender_budget":       rules.get("defender_budget", 120),
        "defender_alerts":       [],
        "defender_ids_level":    0.3,
        "defender_mfa":          False,
        "defender_segmented":    False,
        "defender_honeypot":     False,
        # Turn management
        "current_turn_atk":      None,   # pending attacker submission
        "current_turn_def":      None,   # pending defender submission
        "waiting_for":           "both", # always both in simultaneous mode
        "game_over":             False,
        "winner":                None,
        "initial_risk":          _current_risk({"vulns": vulns, "threats": threats, "impacts": impacts}),
        "log":                   [],
    }

    _games[game_id] = game
    _save(game)
    return game_id


def get_game(game_id: str) -> dict | None:
    """Get game from memory or restore from DB."""
    if game_id not in _games:
        row = DB.load_game(game_id)
        if row:
            _games[game_id] = row
    return _games.get(game_id)


def get_master_view(game_id: str) -> dict:
    """Full view for the professor — sees everything."""
    game = get_game(game_id)
    if not game:
        return {"error": "Game not found."}
    return {
        "game_id":        game["game_id"],
        "label":          game["label"],
        "status":         game["status"],
        "turn":           game["turn"],
        "max_turns":      game["max_turns"],
        "waiting_for":    game["waiting_for"],
        "game_over":      game["game_over"],
        "winner":         game["winner"],
        "initial_risk":   game["initial_risk"],
        "current_risk":   _current_risk(game),
        "rules":          game["rules"],
        "attacker": {
            "stage":      STAGE_LABELS[game["attacker_stage"]],
            "budget":     game["attacker_budget"],
            "foothold":   game["attacker_foothold"],
            "persistent": game["attacker_persistent"],
            "root":       game["attacker_root"],
            "exfiltrated":game["attacker_exfiltrated"],
        },
        "defender": {
            "budget":     game["defender_budget"],
            "alerts":     game["defender_alerts"],
            "ids_level":  game["defender_ids_level"],
            "mfa":        game["defender_mfa"],
            "segmented":  game["defender_segmented"],
        },
        "vulns":          game["vulns"],
        "assets":         game["assets"],
        "threats":        game["threats"],
        "log":            game["log"],
        "pending_atk":    game["current_turn_atk"],
        "pending_def":    game["current_turn_def"],
    }


def get_attacker_view(game_id: str) -> dict:
    """Restricted view for attacker student."""
    game = get_game(game_id)
    if not game:
        return {"error": "Game not found."}

    rules = game["rules"]

    # Visibility of vulnerabilities
    visibility = rules.get("attacker_vuln_visibility", "all")
    if visibility == "all" or game["attacker_vulns_revealed"]:
        visible_vulns = [
            {"id": v["id"], "description": v["description"],
             "asset_id": v.get("asset_id", ""), "patched": v.get("patched", False)}
            for v in game["vulns"]
        ]
    elif visibility == "none":
        visible_vulns = []
    else:
        visible_vulns = []  # revealed after recon

    # Available actions for current stage
    stage      = game["attacker_stage"]
    avail_acts = ATTACKER_ACTIONS.get(stage, [])

    return {
        "game_id":      game["game_id"],
        "label":        game["label"],
        "status":       game["status"],
        "turn":         game["turn"],
        "max_turns":    game["max_turns"],
        "game_over":    game["game_over"],
        "winner":       game["winner"],
        "waiting_for":  game["waiting_for"],
        "my_turn":      not game["game_over"] and game["current_turn_atk"] is None,
        "already_submitted": game["current_turn_atk"] is not None,
        "stage":        STAGE_LABELS[stage],
        "stage_key":    stage,
        "budget":       game["attacker_budget"],
        "foothold":     game["attacker_foothold"],
        "persistent":   game["attacker_persistent"],
        "root":         game["attacker_root"],
        "vulns":        visible_vulns,
        "assets":       game["assets"],
        "available_actions": avail_acts,
        "justification_required": rules.get("justification_required", True),
        "min_words":    rules.get("min_justification_words", 30),
        "log": [          # attacker sees only their own actions + outcomes
            {
                "turn":    e["turn"],
                "action":  e["attacker"]["action"],
                "target":  e["attacker"]["target"],
                "success": e["attacker"]["success"],
                "outcome": e["attacker"]["outcome"],
                "justification": e["attacker"]["justification"],
            }
            for e in game["log"]
        ],
    }


def get_defender_view(game_id: str) -> dict:
    """Restricted view for defender student."""
    game = get_game(game_id)
    if not game:
        return {"error": "Game not found."}

    rules = game["rules"]
    sees_attacker = rules.get("defender_sees_attacker", "on_detection")

    # What the defender sees about the attacker
    atk_info = None
    if sees_attacker == "always":
        atk_info = {
            "stage":    STAGE_LABELS[game["attacker_stage"]],
            "foothold": game["attacker_foothold"],
            "root":     game["attacker_root"],
        }
    elif sees_attacker == "on_detection":
        atk_info = None  # only alerts reveal position

    return {
        "game_id":      game["game_id"],
        "label":        game["label"],
        "status":       game["status"],
        "turn":         game["turn"],
        "max_turns":    game["max_turns"],
        "game_over":    game["game_over"],
        "winner":       game["winner"],
        "waiting_for":  game["waiting_for"],
        "my_turn":      not game["game_over"] and game["current_turn_def"] is None,
        "already_submitted": game["current_turn_def"] is not None,
        "budget":       game["defender_budget"],
        "alerts":       game["defender_alerts"][-5:],
        "ids_level":    game["defender_ids_level"],
        "mfa":          game["defender_mfa"],
        "segmented":    game["defender_segmented"],
        "vulns": [
            {"id": v["id"], "description": v["description"],
             "nist_control": v.get("nist_control", ""),
             "effectiveness": v.get("effectiveness", 0),
             "asset_id": v.get("asset_id", ""),
             "patched": v.get("patched", False)}
            for v in game["vulns"]
        ],
        "assets":            game["assets"],
        "available_actions": DEFENDER_ACTIONS,
        "attacker_info":     atk_info,
        "justification_required": rules.get("justification_required", True),
        "min_words":         rules.get("min_justification_words", 30),
        "log": [
            {
                "turn":    e["turn"],
                "action":  e["defender"]["action"],
                "target":  e["defender"]["target"],
                "outcome": e["defender"]["outcome"],
                "justification": e["defender"]["justification"],
                "atk_detected": e["attacker"]["detected"],
            }
            for e in game["log"]
        ],
    }


def submit_attacker_action(game_id: str, action: str, target: str, justification: str) -> dict:
    """Student submits their attacker move. Resolves turn if defender already submitted."""
    game = get_game(game_id)
    if not game:
        return {"error": "Game not found."}
    if game["game_over"]:
        return {"error": "Game is over."}
    if game["current_turn_atk"] is not None:
        return {"error": "You already submitted this turn."}

    # Justification check
    rules = game["rules"]
    if rules.get("justification_required", True):
        word_count = len(justification.split())
        min_words  = rules.get("min_justification_words", 30)
        if word_count < min_words:
            return {"error": f"Justification too short — need at least {min_words} words (you wrote {word_count})."}

    game["current_turn_atk"] = {
        "action": action, "target": target, "justification": justification
    }

    # Simultaneous mode — resolve only when BOTH have submitted
    if game["current_turn_def"] is not None:
        return _resolve_turn(game)

    # Still waiting for defender — but attacker can already see "submitted"
    _save(game)
    return {"status": "submitted", "waiting_for": "both"}


def submit_defender_action(game_id: str, action: str, target: str, justification: str) -> dict:
    """Student submits their defender move. Resolves turn if attacker already submitted."""
    game = get_game(game_id)
    if not game:
        return {"error": "Game not found."}
    if game["game_over"]:
        return {"error": "Game is over."}
    if game["current_turn_def"] is not None:
        return {"error": "You already submitted this turn."}

    rules = game["rules"]
    if rules.get("justification_required", True):
        word_count = len(justification.split())
        min_words  = rules.get("min_justification_words", 30)
        if word_count < min_words:
            return {"error": f"Justification too short — need at least {min_words} words (you wrote {word_count})."}

    game["current_turn_def"] = {
        "action": action, "target": target, "justification": justification
    }

    # Simultaneous mode — resolve only when BOTH have submitted
    if game["current_turn_atk"] is not None:
        return _resolve_turn(game)

    # Still waiting for attacker — but defender can already see "submitted"
    _save(game)
    return {"status": "submitted", "waiting_for": "both"}


def _resolve_turn(game: dict) -> dict:
    """Both players have submitted — resolve the turn."""
    game["turn"] += 1
    game["status"] = "playing"

    atk_sub = game["current_turn_atk"]
    def_sub = game["current_turn_def"]

    # Apply defender first (more realistic — defense is pre-positioned)
    def_result = _resolve_defender_action(game, def_sub["action"], def_sub.get("target", ""))

    # Then apply attacker
    atk_result = _resolve_attacker_action(game, atk_sub["action"], atk_sub.get("target", ""))

    # Build log entry
    entry = {
        "turn": game["turn"],
        "attacker": {
            "action":        atk_sub["action"],
            "target":        atk_sub.get("target", ""),
            "justification": atk_sub["justification"],
            "success":       atk_result["success"],
            "detected":      atk_result["detected"],
            "outcome":       atk_result["outcome"],
            "cost":          atk_result["cost"],
        },
        "defender": {
            "action":        def_sub["action"],
            "target":        def_sub.get("target", ""),
            "justification": def_sub["justification"],
            "outcome":       def_result["outcome"],
            "cost":          def_result["cost"],
        },
        "risk_after": _current_risk(game),
    }
    game["log"].append(entry)

    # Reset pending submissions
    game["current_turn_atk"] = None
    game["current_turn_def"] = None

    # Check victory
    game_over, winner = _check_victory(game)
    if game_over:
        game["game_over"] = True
        game["winner"]    = winner
        game["status"]    = "finished"
        game["waiting_for"] = "none"
    else:
        game["waiting_for"] = "both"

    _save(game)

    return {
        "status":    "resolved",
        "turn":      game["turn"],
        "entry":     entry,
        "game_over": game["game_over"],
        "winner":    game["winner"],
    }


def list_games() -> list[dict]:
    return DB.list_games()


def start_game(game_id: str) -> dict:
    """Professor starts the game — students can now play."""
    game = get_game(game_id)
    if not game:
        return {"error": "Game not found."}
    game["status"]       = "playing"
    game["waiting_for"]  = "both"
    _save(game)
    return {"status": "playing", "game_id": game_id}
