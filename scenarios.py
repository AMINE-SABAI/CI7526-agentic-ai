"""
scenarios.py — Independent scenario management for CySyMo.

A scenario = one specific attack path:
  asset + vulnerability + threat + narrative + risk parameters

Stored in the scenarios table in SQLite (via database.py connection).

Public API:
  get_scenarios()              -> list[dict]
  save_scenario(scenario)      -> dict
  delete_scenario(scenario_id) -> bool
  clear_scenarios()            -> None
"""

import sqlite3
import json
from pathlib import Path
from database import _conn, init_db


# Ensure the scenarios table exists
def _ensure_table():
    with _conn() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS scenarios (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL DEFAULT '',
            description  TEXT NOT NULL DEFAULT '',
            asset_id     TEXT NOT NULL DEFAULT '',
            vuln_id      TEXT NOT NULL DEFAULT '',
            threat_id    TEXT NOT NULL DEFAULT '',
            narrative    TEXT NOT NULL DEFAULT '',
            exposure     REAL NOT NULL DEFAULT 0.0,
            probability  REAL NOT NULL DEFAULT 0.0,
            impact       REAL NOT NULL DEFAULT 0.0,
            risk         REAL NOT NULL DEFAULT 0.0,
            recommendations TEXT NOT NULL DEFAULT '[]'
        )
        """)

_ensure_table()


def get_scenarios() -> list[dict]:
    """Return all scenarios ordered by id."""
    with _conn() as con:
        rows = con.execute("SELECT * FROM scenarios ORDER BY id").fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["recommendations"] = json.loads(d["recommendations"])
        except Exception:
            d["recommendations"] = []
        result.append(d)
    return result


def save_scenario(scenario: dict) -> dict:
    """
    Insert or replace a scenario.
    scenario must have at least: id, name
    """
    recs = scenario.get("recommendations", [])
    if isinstance(recs, list):
        recs = json.dumps(recs)

    with _conn() as con:
        con.execute("""
        INSERT OR REPLACE INTO scenarios
          (id, name, description, asset_id, vuln_id, threat_id,
           narrative, exposure, probability, impact, risk, recommendations)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scenario.get("id", "S1"),
            scenario.get("name", "Unnamed scenario"),
            scenario.get("description", ""),
            scenario.get("asset_id", ""),
            scenario.get("vuln_id", ""),
            scenario.get("threat_id", ""),
            scenario.get("narrative", ""),
            float(scenario.get("exposure", 0.0)),
            float(scenario.get("probability", 0.0)),
            float(scenario.get("impact", 0.0)),
            float(scenario.get("risk", 0.0)),
            recs,
        ))
    return get_scenario(scenario.get("id", "S1"))


def get_scenario(scenario_id: str) -> dict | None:
    """Return a single scenario by id."""
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM scenarios WHERE id = ?", (scenario_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["recommendations"] = json.loads(d["recommendations"])
    except Exception:
        d["recommendations"] = []
    return d


def delete_scenario(scenario_id: str) -> bool:
    """Delete a scenario by id. Returns True if deleted."""
    with _conn() as con:
        cur = con.execute(
            "DELETE FROM scenarios WHERE id = ?", (scenario_id,)
        )
    return cur.rowcount > 0


def clear_scenarios() -> None:
    """Delete all scenarios."""
    with _conn() as con:
        con.execute("DELETE FROM scenarios")


def next_scenario_id() -> str:
    """Return the next available scenario id (S1, S2, ...)."""
    existing = {s["id"] for s in get_scenarios()}
    n = 1
    while f"S{n}" in existing:
        n += 1
    return f"S{n}"
