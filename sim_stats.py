"""
sim_stats.py — Debrief statistics for CySyMo adversarial simulations.

Pure functions over the state dict returned by SIM.get_state(sim_id).
No I/O, no dependency on simulation.py — safe to import anywhere.

Usage:
    import sim_stats
    stats = sim_stats.compute_stats(SIM.get_state(sim_id))
    md    = sim_stats.stats_markdown(stats)
"""

from collections import Counter


def _num(x, default=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def compute_stats(state: dict) -> dict:
    """Aggregate a finished (or ongoing) simulation state into flat metrics."""
    if not state or state.get("error"):
        return {"error": (state or {}).get("error", "No state.")}

    log = state.get("log") or []
    atk_moves = [e.get("attacker") for e in log if e.get("attacker")]
    def_moves = [e.get("defender") for e in log if e.get("defender")]

    successes = sum(1 for a in atk_moves if a.get("success"))
    detected = sum(1 for a in atk_moves if a.get("detected"))

    r_init = _num(state.get("initial_risk"))
    r_end = _num(state.get("current_risk"))
    risks = [r_init] + [_num(e.get("risk"), r_init) for e in log if e.get("risk") is not None]

    attacker = state.get("attacker") or {}
    defender = state.get("defender") or {}
    foothold = attacker.get("foothold") or []
    assets = state.get("assets") or []

    def spend(moves):
        return sum(_num(m.get("cost")) for m in moves)

    # Risk swing attributable to each turn — useful to spot the pivotal move.
    turning_point = None
    if len(risks) > 1:
        deltas = [(i + 1, risks[i + 1] - risks[i]) for i in range(len(risks) - 1)]
        turn_no, delta = max(deltas, key=lambda d: abs(d[1]))
        if abs(delta) > 1e-6:
            entry = next((e for e in log if e.get("turn") == turn_no), None)
            turning_point = {
                "turn": turn_no,
                "delta": round(delta, 6),
                "action": (entry or {}).get("attacker", {}).get("action"),
                "target": (entry or {}).get("attacker", {}).get("target"),
            }

    controls = []
    if defender.get("mfa"):
        controls.append("MFA")
    if defender.get("segmented"):
        controls.append("Segmentation")
    if _num(defender.get("ids_level")) > 0:
        controls.append(f"IDS {round(_num(defender.get('ids_level')) * 100)}%")

    total_vulns = state.get("total_vulns") or 0
    open_vulns = state.get("open_vulns") or 0

    return {
        "sim_id": state.get("sim_id"),
        "outcome": {
            "game_over": bool(state.get("game_over")),
            "winner": state.get("winner"),
            "turns_played": state.get("turn"),
            "max_turns": state.get("max_turns"),
            "final_stage": attacker.get("stage"),
        },
        "risk": {
            "initial": round(r_init, 6),
            "final": round(r_end, 6),
            "peak": round(max(risks), 6) if risks else 0.0,
            "delta_pct": round((r_end - r_init) / r_init * 100, 2) if r_init else 0.0,
            "series": [round(r, 6) for r in risks],
            "turning_point": turning_point,
        },
        "attacker": {
            "moves": len(atk_moves),
            "successes": successes,
            "success_rate": round(successes / len(atk_moves), 4) if atk_moves else 0.0,
            "detected": detected,
            "detection_rate": round(detected / len(atk_moves), 4) if atk_moves else 0.0,
            "budget_spent": round(spend(atk_moves), 2),
            "cost_per_success": round(spend(atk_moves) / successes, 2) if successes else None,
            "root": bool(attacker.get("root")),
            "persistent": bool(attacker.get("persistent")),
            "action_counts": dict(Counter(a.get("action") for a in atk_moves if a.get("action"))),
        },
        "defender": {
            "moves": len(def_moves),
            "alerts": defender.get("alerts", 0),
            "budget_spent": round(spend(def_moves), 2),
            "controls": controls,
            "action_counts": dict(Counter(d.get("action") for d in def_moves if d.get("action"))),
        },
        "exposure": {
            "assets_compromised": len(foothold),
            "assets_total": len(assets),
            "compromised_ids": list(foothold),
            "vulns_open": open_vulns,
            "vulns_total": total_vulns,
            "vulns_remediated": max(total_vulns - open_vulns, 0),
        },
    }


def stats_markdown(s: dict) -> str:
    """Render stats as Markdown — drop straight into a report section."""
    if s.get("error"):
        return f"_Debrief unavailable: {s['error']}_"

    o, r, a, d, e = s["outcome"], s["risk"], s["attacker"], s["defender"], s["exposure"]

    if not o["game_over"]:
        verdict = f"Simulation in progress — turn {o['turns_played']} of {o['max_turns']}."
    elif o["winner"] == "attacker":
        verdict = (f"Attacker won in {o['turns_played']} turns, reaching stage "
                   f"{o['final_stage']} with {e['assets_compromised']} asset(s) compromised.")
    else:
        verdict = (f"Defender held for {o['turns_played']} turns; attacker stopped at "
                   f"stage {o['final_stage']}.")

    lines = [
        "## Simulation debrief", "", verdict, "",
        f"- **Risk**: {r['initial']:.4f} → {r['final']:.4f} "
        f"(peak {r['peak']:.4f}, {r['delta_pct']:+.1f}%)",
        f"- **Attacker**: {a['successes']}/{a['moves']} moves succeeded "
        f"({a['success_rate']:.0%}), {a['detected']} detected ({a['detection_rate']:.0%}), "
        f"{a['budget_spent']:g} pts spent",
        f"- **Defender**: {d['moves']} responses, {d['alerts']} alerts, "
        f"{d['budget_spent']:g} pts spent, controls: {', '.join(d['controls']) or 'none'}",
        f"- **Exposure**: {e['assets_compromised']}/{e['assets_total']} assets compromised, "
        f"{e['vulns_open']}/{e['vulns_total']} vulnerabilities still open",
    ]

    tp = r.get("turning_point")
    if tp:
        direction = "increase" if tp["delta"] > 0 else "reduction"
        lines.append(f"- **Turning point**: turn {tp['turn']} — `{tp['action']}` on "
                     f"{tp['target'] or '—'} ({tp['delta']:+.4f} risk {direction})")

    for label, counts in (("Attacker actions", a["action_counts"]),
                          ("Defender actions", d["action_counts"])):
        if counts:
            lines += ["", f"| {label} | Times |", "|---|---|"]
            lines += [f"| `{k}` | {v} |"
                      for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]

    return "\n".join(lines)
