"""
agent.py - Orchestration LangGraph avec auto-verification.
Reutilise les fonctions de extractor.py et les organise en graphe d'agent.
"""

from typing import TypedDict
from langgraph.graph import StateGraph, START, END

from extractor import (
    extract_elements,
    build_model,
    estimate_impact,
    suggest_controls,
    simulate_protection,
)


# Mets True pour DEMONTRER la boucle de verification (force un echec au 1er tour).
# Remets False pour les vrais lancements.
DEMO_FORCE_LOOP = False


# ---- 1. LE STATE : la memoire partagee qui circule entre les noeuds ----
class AgentState(TypedDict):
    description: str        # l'entree : la description du systeme
    data: dict              # le JSON extrait par Claude
    model: object           # le modele CySyMo
    risk_before: float
    risk_after: float
    verification_passed: bool
    attempts: int           # compteur pour eviter une boucle infinie


# ---- 2. LES NOEUDS : chaque etape devient une fonction (state -> state) ----

def node_extract(state: AgentState) -> AgentState:
    print(f"[NODE] Extraction (tentative {state['attempts'] + 1})...")
    state["data"] = extract_elements(state["description"])
    state["attempts"] += 1
    return state


def node_verify(state: AgentState) -> AgentState:
    """Auto-verification : l'agent relit le travail de l'extraction."""
    print("[NODE] Verification...")

    # --- DEMO : force un echec au 1er tour pour prouver que la boucle marche ---
    if DEMO_FORCE_LOOP and state["attempts"] < 2:
        print("   -> (demo) echec force, on reboucle")
        state["verification_passed"] = False
        return state

    data = state["data"]
    vulns = data.get("vulnerabilities", [])
    threats = data.get("threats", [])

    ok = True
    reasons = []

    # Regle 1 : il faut au moins une vulnerabilite et une menace
    if len(vulns) == 0:
        ok = False
        reasons.append("aucune vulnerabilite")
    if len(threats) == 0:
        ok = False
        reasons.append("aucune menace")

    # Regle 2 : chaque menace doit avoir un profil OCTAVE complet
    required = {"actor", "motive", "access", "outcome"}
    for t in threats:
        profile = t.get("octave_profile", {})
        if not required.issubset(profile.keys()):
            ok = False
            reasons.append(f"profil OCTAVE incomplet pour {t.get('id')}")

    state["verification_passed"] = ok
    if ok:
        print("   -> Verification OK")
    else:
        print("   -> Verification ECHOUEE:", ", ".join(reasons))
    return state


def node_build(state: AgentState) -> AgentState:
    print("[NODE] Construction du modele CySyMo...")
    state["model"] = build_model(state["data"])
    return state


def node_impact(state: AgentState) -> AgentState:
    print("[NODE] Estimation de l'impact...")
    state["model"] = estimate_impact(state["model"])
    return state


def node_controls(state: AgentState) -> AgentState:
    print("[NODE] Suggestion des controles NIST...")
    state["model"] = suggest_controls(state["model"])
    return state


def node_simulate(state: AgentState) -> AgentState:
    print("[NODE] Simulation de protection...")
    before, after = simulate_protection(state["model"])
    state["risk_before"] = before
    state["risk_after"] = after
    return state


# ---- 3. L'AIGUILLAGE : decide quoi faire apres la verification ----

def route_after_verify(state: AgentState) -> str:
    """
    Si la verification passe -> on continue vers 'build'.
    Si elle echoue -> on retourne a 'extract' (boucle), sauf si trop de tentatives.
    """
    if state["verification_passed"]:
        return "build"
    if state["attempts"] >= 3:        # garde-fou anti-boucle-infinie
        print("   -> 3 tentatives atteintes, on continue malgre tout.")
        return "build"
    print("   -> On relance l'extraction.")
    return "extract"


# ---- 4. CONSTRUCTION DU GRAPHE : on relie les noeuds ----

def build_agent(include_simulate: bool = True):
    graph = StateGraph(AgentState)

    graph.add_node("extract", node_extract)
    graph.add_node("verify", node_verify)
    graph.add_node("build", node_build)
    graph.add_node("impact", node_impact)
    graph.add_node("controls", node_controls)

    graph.add_edge(START, "extract")
    graph.add_edge("extract", "verify")
    graph.add_conditional_edges(
        "verify",
        route_after_verify,
        {"build": "build", "extract": "extract"},
    )
    graph.add_edge("build", "impact")
    graph.add_edge("impact", "controls")

    if include_simulate:
        graph.add_node("simulate", node_simulate)
        graph.add_edge("controls", "simulate")
        graph.add_edge("simulate", END)
    else:
        graph.add_edge("controls", END)

    return graph.compile()


# ---- 5. LANCEMENT ----

if __name__ == "__main__":
    description = (
        "An online shop. Customers log in with email and password. "
        "Their personal data and credit cards are stored in a database. "
        "A payment API processes the transactions."
    )

    agent = build_agent()

    # Schema de l'agent, genere automatiquement depuis le code (pour le rapport).
    # Colle la sortie sur https://mermaid.live
    print("\n--- SCHEMA DE L'AGENT (Mermaid) ---")
    print(agent.get_graph().draw_mermaid())
    print("--- fin du schema ---\n")

    # L'etat initial
    initial_state = {
        "description": description,
        "data": {},
        "model": None,
        "risk_before": 0.0,
        "risk_after": 0.0,
        "verification_passed": False,
        "attempts": 0,
    }

    # On lance l'agent : il parcourt le graphe tout seul
    final_state = agent.invoke(initial_state)

    model = final_state["model"]

    print("\n=== RESULTAT ===")
    print("Vulnerabilities:")
    for v in model.vulnerabilities:
        print(" ", v[0], ":", v[1])
        print("      NIST control:", v[2])

    print("\nThreats:")
    for t in model.threats:
        print(" ", t[0], ":", t[1])
        print("      OCTAVE profile:", t[2])

    print("\n=== RISK SIMULATION ===")
    print("  Risk BEFORE:", round(final_state["risk_before"], 4))
    print("  Risk AFTER NIST controls:", round(final_state["risk_after"], 4))
    reduction = 0
    if final_state["risk_before"]:
        reduction = round(
            (final_state["risk_before"] - final_state["risk_after"])
            / final_state["risk_before"] * 100, 1
        )
    print("  Risk reduction:", reduction, "%")