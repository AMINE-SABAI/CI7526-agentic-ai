"""
database.py — SQLite persistence layer for CySyMo.

Tables:
  assets, vulnerabilities, threats, impacts, risk_history, scenarios

Upgrades:
  - export_history_csv() -> str
  - CYSYMO_DB_PATH env var support for Docker
  - scenarios table included
"""

import json
import csv
import io
import sqlite3
import datetime
import os
from pathlib import Path

DB_PATH = Path(os.environ.get("CYSYMO_DB_PATH", "cysymo_data.db"))


def _conn():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db():
    with _conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS assets (
            id          TEXT PRIMARY KEY,
            description TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id            TEXT PRIMARY KEY,
            description   TEXT NOT NULL DEFAULT '',
            nist_control  TEXT NOT NULL DEFAULT '',
            nist_title    TEXT NOT NULL DEFAULT '',
            effectiveness REAL NOT NULL DEFAULT 0.0,
            asset_id      TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS threats (
            id          TEXT PRIMARY KEY,
            description TEXT NOT NULL DEFAULT '',
            probability REAL NOT NULL DEFAULT 1.0,
            asset_id    TEXT NOT NULL DEFAULT '',
            actor       TEXT NOT NULL DEFAULT '',
            motive      TEXT NOT NULL DEFAULT '',
            access      TEXT NOT NULL DEFAULT '',
            outcome     TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS impacts (
            vuln_id   TEXT NOT NULL,
            threat_id TEXT NOT NULL,
            value     REAL NOT NULL DEFAULT 0.0,
            PRIMARY KEY (vuln_id, threat_id)
        );
        CREATE TABLE IF NOT EXISTS risk_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            formula   TEXT    NOT NULL DEFAULT 'mean',
            risk      REAL    NOT NULL DEFAULT 0.0,
            level     TEXT    NOT NULL DEFAULT '',
            m         INTEGER NOT NULL DEFAULT 0,
            n         INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS scenarios (
            id              TEXT PRIMARY KEY,
            name            TEXT NOT NULL DEFAULT '',
            description     TEXT NOT NULL DEFAULT '',
            asset_id        TEXT NOT NULL DEFAULT '',
            vuln_id         TEXT NOT NULL DEFAULT '',
            threat_id       TEXT NOT NULL DEFAULT '',
            narrative       TEXT NOT NULL DEFAULT '',
            exposure        REAL NOT NULL DEFAULT 0.0,
            probability     REAL NOT NULL DEFAULT 0.0,
            impact          REAL NOT NULL DEFAULT 0.0,
            risk            REAL NOT NULL DEFAULT 0.0,
            recommendations TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS simulations (
            sim_id      TEXT PRIMARY KEY,
            created_at  TEXT NOT NULL,
            label       TEXT NOT NULL DEFAULT '',
            config      TEXT NOT NULL DEFAULT '{}',
            state       TEXT NOT NULL DEFAULT '{}',
            game_over   INTEGER NOT NULL DEFAULT 0,
            winner      TEXT NOT NULL DEFAULT ''
        );
        """)


def save_model(model_dict: dict) -> None:
    with _conn() as con:
        con.execute("DELETE FROM impacts")
        con.execute("DELETE FROM vulnerabilities")
        con.execute("DELETE FROM threats")
        con.execute("DELETE FROM assets")
        for a in model_dict.get("assets", []):
            if not str(a.get("id", "")).strip(): continue
            con.execute("INSERT INTO assets (id, description) VALUES (?, ?)",
                        (a["id"], a.get("description", "")))
        for v in model_dict.get("vulnerabilities", []):
            if not str(v.get("id", "")).strip(): continue
            con.execute("""INSERT INTO vulnerabilities
               (id, description, nist_control, nist_title, effectiveness, asset_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
                (v["id"], v.get("description",""), v.get("nist_control",""),
                 v.get("nist_title",""), float(v.get("effectiveness",0.0)),
                 v.get("asset_id","")))
        for t in model_dict.get("threats", []):
            if not str(t.get("id", "")).strip(): continue
            con.execute("""INSERT INTO threats
               (id, description, probability, asset_id, actor, motive, access, outcome)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (t["id"], t.get("description",""), float(t.get("probability",1.0)),
                 t.get("asset_id",""), t.get("actor",""), t.get("motive",""),
                 t.get("access",""), t.get("outcome","")))
        for imp in model_dict.get("impacts", []):
            vid, tid = imp.get("vuln_id"), imp.get("threat_id")
            if vid and tid:
                con.execute("INSERT OR REPLACE INTO impacts (vuln_id, threat_id, value) VALUES (?, ?, ?)",
                            (vid, tid, float(imp.get("value", 0.0))))


def load_model() -> dict:
    with _conn() as con:
        assets = [{"id": r["id"], "description": r["description"]}
                  for r in con.execute("SELECT * FROM assets ORDER BY id")]
        vulnerabilities = [
            {"id": r["id"], "description": r["description"],
             "nist_control": r["nist_control"], "nist_title": r["nist_title"],
             "effectiveness": r["effectiveness"], "asset_id": r["asset_id"]}
            for r in con.execute("SELECT * FROM vulnerabilities ORDER BY id")]
        threats = [
            {"id": r["id"], "description": r["description"],
             "probability": r["probability"], "asset_id": r["asset_id"],
             "actor": r["actor"], "motive": r["motive"],
             "access": r["access"], "outcome": r["outcome"]}
            for r in con.execute("SELECT * FROM threats ORDER BY id")]
        impacts = [{"vuln_id": r["vuln_id"], "threat_id": r["threat_id"], "value": r["value"]}
                   for r in con.execute("SELECT * FROM impacts")]
    return {"assets": assets, "vulnerabilities": vulnerabilities,
            "threats": threats, "impacts": impacts}


def append_history(formula: str, risk: float, level: str, m: int, n: int) -> None:
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with _conn() as con:
        con.execute("INSERT INTO risk_history (timestamp, formula, risk, level, m, n) VALUES (?, ?, ?, ?, ?, ?)",
                    (ts, formula, risk, level, m, n))


def get_history() -> list[dict]:
    with _conn() as con:
        rows = con.execute("SELECT * FROM risk_history ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def clear_history() -> None:
    with _conn() as con:
        con.execute("DELETE FROM risk_history")


def export_history_csv() -> str:
    rows = get_history()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id","timestamp","formula","risk","level","m","n"])
    writer.writeheader()
    for row in reversed(rows):
        writer.writerow(row)
    return output.getvalue()


def export_json() -> str:
    model = load_model()
    with _conn() as con:
        history   = [dict(r) for r in con.execute("SELECT * FROM risk_history ORDER BY id")]
        scenarios_raw = con.execute("SELECT * FROM scenarios ORDER BY id").fetchall()
    scenarios = []
    for r in scenarios_raw:
        d = dict(r)
        try: d["recommendations"] = json.loads(d["recommendations"])
        except: d["recommendations"] = []
        scenarios.append(d)
    return json.dumps({"model": model, "history": history, "scenarios": scenarios}, indent=2)


def import_json(blob: str) -> None:
    data = json.loads(blob)
    save_model(data.get("model", {}))
    with _conn() as con:
        con.execute("DELETE FROM risk_history")
        for row in data.get("history", []):
            con.execute("INSERT INTO risk_history (timestamp, formula, risk, level, m, n) VALUES (?, ?, ?, ?, ?, ?)",
                (row.get("timestamp",""), row.get("formula","mean"),
                 float(row.get("risk",0.0)), row.get("level",""),
                 int(row.get("m",0)), int(row.get("n",0))))
        con.execute("DELETE FROM scenarios")
        for s in data.get("scenarios", []):
            recs = s.get("recommendations", [])
            if isinstance(recs, list): recs = json.dumps(recs)
            con.execute("""INSERT OR REPLACE INTO scenarios
              (id, name, description, asset_id, vuln_id, threat_id,
               narrative, exposure, probability, impact, risk, recommendations)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (s.get("id",""), s.get("name",""), s.get("description",""),
                 s.get("asset_id",""), s.get("vuln_id",""), s.get("threat_id",""),
                 s.get("narrative",""), float(s.get("exposure",0)),
                 float(s.get("probability",0)), float(s.get("impact",0)),
                 float(s.get("risk",0)), recs))


init_db()

# ══════════════════════════════════════════════════════
#  SIMULATION PERSISTENCE
# ══════════════════════════════════════════════════════

def save_simulation(sim_id: str, label: str, config: dict, state: dict) -> None:
    """Upsert a simulation snapshot — called after every turn."""
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with _conn() as con:
        con.execute("""
            INSERT INTO simulations (sim_id, created_at, label, config, state, game_over, winner)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sim_id) DO UPDATE SET
                state     = excluded.state,
                game_over = excluded.game_over,
                winner    = excluded.winner
        """, (
            sim_id,
            ts,
            label,
            json.dumps(config),
            json.dumps(state),
            1 if state.get("game_over") else 0,
            state.get("winner") or "",
        ))


def list_simulations() -> list[dict]:
    """Return all simulations, most recent first."""
    with _conn() as con:
        rows = con.execute(
            "SELECT sim_id, created_at, label, game_over, winner FROM simulations ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def load_simulation(sim_id: str) -> dict | None:
    """Return the full state snapshot for a simulation, or None."""
    with _conn() as con:
        row = con.execute(
            "SELECT config, state FROM simulations WHERE sim_id = ?", (sim_id,)
        ).fetchone()
    if not row:
        return None
    return {
        "config": json.loads(row["config"]),
        "state":  json.loads(row["state"]),
    }


def delete_simulation(sim_id: str) -> bool:
    with _conn() as con:
        cur = con.execute("DELETE FROM simulations WHERE sim_id = ?", (sim_id,))
    return cur.rowcount > 0

# ══════════════════════════════════════════════════════
#  GAME PERSISTENCE  (serious game)
# ══════════════════════════════════════════════════════

def _ensure_games_table():
    with _conn() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS games (
                game_id    TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                label      TEXT NOT NULL DEFAULT '',
                status     TEXT NOT NULL DEFAULT 'waiting',
                game_over  INTEGER NOT NULL DEFAULT 0,
                winner     TEXT NOT NULL DEFAULT '',
                state      TEXT NOT NULL DEFAULT '{}'
            )
        """)

_ensure_games_table()


def save_game(game_id: str, state: dict) -> None:
    with _conn() as con:
        con.execute("""
            INSERT INTO games (game_id, created_at, label, status, game_over, winner, state)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(game_id) DO UPDATE SET
                status    = excluded.status,
                game_over = excluded.game_over,
                winner    = excluded.winner,
                state     = excluded.state
        """, (
            game_id,
            state.get("created_at", ""),
            state.get("label", ""),
            state.get("status", "waiting"),
            1 if state.get("game_over") else 0,
            state.get("winner") or "",
            json.dumps(state),
        ))


def load_game(game_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT state FROM games WHERE game_id = ?", (game_id,)).fetchone()
    return json.loads(row["state"]) if row else None


def list_games() -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT game_id, created_at, label, status, game_over, winner FROM games ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_game(game_id: str) -> bool:
    with _conn() as con:
        cur = con.execute("DELETE FROM games WHERE game_id = ?", (game_id,))
    return cur.rowcount > 0

# ══════════════════════════════════════════════════════
#  PROJECTS
# ══════════════════════════════════════════════════════

def _ensure_projects_table():
    with _conn() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS projects (
                project_id  TEXT PRIMARY KEY,
                name        TEXT NOT NULL DEFAULT 'Untitled',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                risk        REAL NOT NULL DEFAULT 0.0,
                level       TEXT NOT NULL DEFAULT '',
                state       TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS simulation_project (
                sim_id     TEXT NOT NULL,
                project_id TEXT NOT NULL,
                PRIMARY KEY (sim_id, project_id)
            );
        """)

_ensure_projects_table()


def create_project(name: str) -> dict:
    """Create a new empty project and return it."""
    import uuid
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    project_id = str(uuid.uuid4())[:8]
    empty_state = json.dumps({
        "assets": [], "vulnerabilities": [], "threats": [],
        "impacts": [], "scenarios": [], "history": []
    })
    with _conn() as con:
        con.execute("""
            INSERT INTO projects (project_id, name, created_at, updated_at, risk, level, state)
            VALUES (?, ?, ?, ?, 0.0, '', ?)
        """, (project_id, name.strip() or "Untitled", ts, ts, empty_state))
    return {
        "project_id": project_id,
        "name": name.strip() or "Untitled",
        "created_at": ts,
        "updated_at": ts,
        "risk": 0.0,
        "level": "",
    }


def list_projects() -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT project_id, name, created_at, updated_at, risk, level FROM projects ORDER BY updated_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def load_project(project_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM projects WHERE project_id = ?", (project_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["state"] = json.loads(d["state"])
    except Exception:
        d["state"] = {}
    return d


def save_project(project_id: str, name: str, state: dict,
                 risk: float = 0.0, level: str = "") -> None:
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with _conn() as con:
        # Check if project exists
        exists = con.execute(
            "SELECT 1 FROM projects WHERE project_id = ?", (project_id,)
        ).fetchone()
        if exists:
            con.execute("""
                UPDATE projects
                SET name=?, updated_at=?, risk=?, level=?, state=?
                WHERE project_id=?
            """, (name or "Untitled", ts, risk, level, json.dumps(state), project_id))
        else:
            # Create it if it doesn't exist yet
            con.execute("""
                INSERT INTO projects (project_id, name, created_at, updated_at, risk, level, state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (project_id, name or "Untitled", ts, ts, risk, level, json.dumps(state)))


def rename_project(project_id: str, name: str) -> bool:
    ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with _conn() as con:
        cur = con.execute(
            "UPDATE projects SET name=?, updated_at=? WHERE project_id=?",
            (name.strip() or "Untitled", ts, project_id)
        )
    return cur.rowcount > 0


def delete_project(project_id: str) -> bool:
    with _conn() as con:
        cur = con.execute("DELETE FROM projects WHERE project_id=?", (project_id,))
        con.execute("DELETE FROM simulation_project WHERE project_id=?", (project_id,))
    return cur.rowcount > 0


def link_simulation_to_project(sim_id: str, project_id: str) -> None:
    """Associate a simulation with a project."""
    with _conn() as con:
        con.execute("""
            INSERT OR IGNORE INTO simulation_project (sim_id, project_id) VALUES (?, ?)
        """, (sim_id, project_id))


def list_project_simulations(project_id: str) -> list[dict]:
    """Return all simulations linked to a project."""
    with _conn() as con:
        rows = con.execute("""
            SELECT s.sim_id, s.created_at, s.label, s.game_over, s.winner
            FROM simulations s
            JOIN simulation_project sp ON s.sim_id = sp.sim_id
            WHERE sp.project_id = ?
            ORDER BY s.created_at DESC
        """, (project_id,)).fetchall()
    return [dict(r) for r in rows]
