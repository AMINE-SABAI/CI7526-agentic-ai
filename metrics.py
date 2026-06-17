"""
metrics.py - Fonctions de calcul d'erreur pour l'evaluation.
Base sur les vraies sorties du systeme :
  - le risque R (risk_before) : un float entre 0 et 1  -> RMSE / MAE
  - les menaces extraites : une liste                  -> precision / recall
"""

import math


# ============================================================
#  PARTIE 1 : erreur sur le RISQUE R (un nombre entre 0 et 1)
# ============================================================

def squared_errors(predicted, reference):
    """
    Pour chaque systeme : (R_ia - R_reference)^2.
    predicted = liste des R sortis par ton agent (risk_before)
    reference = liste des R que tu as valides a la main
    Les deux listes ont la MEME longueur (un R par systeme teste).
    """
    if len(predicted) != len(reference):
        raise ValueError("Les deux listes doivent avoir la meme longueur")
    return [(p - r) ** 2 for p, r in zip(predicted, reference)]


def mse(predicted, reference):
    """Mean Squared Error : moyenne des erreurs au carre."""
    errors = squared_errors(predicted, reference)
    return sum(errors) / len(errors)


def rmse(predicted, reference):
    """Racine de la MSE. Meme echelle que R (donc lisible : 0.1 = ecart de 0.1 sur R)."""
    return math.sqrt(mse(predicted, reference))


def mae(predicted, reference):
    """Mean Absolute Error : moyenne des ecarts en valeur absolue."""
    if len(predicted) != len(reference):
        raise ValueError("Les deux listes doivent avoir la meme longueur")
    return sum(abs(p - r) for p, r in zip(predicted, reference)) / len(predicted)


# ============================================================
#  PARTIE 2 : precision / recall sur les MENACES (des listes)
# ============================================================
# Rappel : tes ids T1, T2... sont positionnels (cf. cysymo.py), donc on NE
# compare PAS les ids. On compare des "cles de sens" que TU definis a la main
# dans ta reference (ex : "sql_injection", "stolen_credentials"). Pour la sortie
# de l'agent, tu mappes chaque menace extraite vers une de ces cles.

def precision_recall(predicted_keys, reference_keys):
    """
    predicted_keys = ensemble des menaces trouvees par l'agent (cles de sens)
    reference_keys = ensemble des menaces de ta reference (cles de sens)
    Renvoie (precision, recall).
      precision = trouvees correctes / tout ce que l'agent a propose
      recall    = trouvees correctes / tout ce qui aurait du etre trouve
    """
    predicted = set(predicted_keys)
    reference = set(reference_keys)

    found = predicted & reference          # les bonnes (intersection)
    precision = len(found) / len(predicted) if predicted else 0.0
    recall    = len(found) / len(reference) if reference else 0.0
    return precision, recall


# ============================================================
#  TEST : lance-le pour voir les chiffres
# ============================================================
if __name__ == "__main__":
    # --- Exemple RISQUE : 3 systemes testes ---
    # R sorti par ton agent (le "Risk BEFORE" affiche dans agent.py)
    r_ia  = [0.63, 0.40, 0.85]
    # R que tu as valide a la main pour les memes systemes
    r_ref = [0.60, 0.45, 0.80]

    print("=== ERREUR SUR LE RISQUE R ===")
    print("Erreurs au carre :", squared_errors(r_ia, r_ref))
    print("MSE  :", round(mse(r_ia, r_ref), 4))
    print("RMSE :", round(rmse(r_ia, r_ref), 4))
    print("MAE  :", round(mae(r_ia, r_ref), 4))

    # --- Exemple MENACES : un systeme (la boutique en ligne) ---
    # Ce que l'agent a trouve (toi tu traduis ses menaces en cles de sens)
    agent_threats = ["sql_injection", "stolen_credentials", "ddos"]
    # Ta reference pour ce systeme
    ref_threats   = ["sql_injection", "stolen_credentials", "payment_fraud"]

    p, r = precision_recall(agent_threats, ref_threats)
    print("\n=== MENACES (boutique en ligne) ===")
    print("Precision :", round(p, 2), "(part des menaces proposees qui sont justes)")
    print("Recall    :", round(r, 2), "(part des vraies menaces que l'agent a trouvees)")