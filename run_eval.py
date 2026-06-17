"""
run_eval.py - Branche la VRAIE sortie de l'agent sur metrics.py.
On evalue les MENACES en les comparant aux categories OWASP qui s'appliquent
a la boutique en ligne.

Principe :
  - chaque menace de l'agent (T1..T6) est traduite en une categorie OWASP
  - le CORRIGE = les categories OWASP qui s'appliquent a CE systeme
  - on compare les deux avec precision / recall
"""

from metrics import precision_recall, rmse


# ---- 1. CE QUE L'AGENT A SORTI (run sur la boutique en ligne) ----
# Pour chaque menace, je note la categorie OWASP correspondante.
# None = aucune categorie OWASP (la menace sort du perimetre OWASP).
agent_threats = {
    "T1": "A07",   # vol d'identifiants / brute-force sur le login
    "T2": "A05",   # SQL injection
    "T3": "A01",   # abus de l'API de paiement (controle d'acces)
    "T4": "A01",   # insider qui accede a la base
    "T5": None,    # suppression ACCIDENTELLE -> hors perimetre OWASP (pas une attaque)
    "T6": None,    # DDoS -> PAS de categorie OWASP Top 10
}

# On garde uniquement les categories reellement couvertes (on enleve les None).
agent_categories = {cat for cat in agent_threats.values() if cat is not None}


# ---- 2. LE CORRIGE : categories OWASP qui s'appliquent a la boutique ----
# (login email/password, cartes en base, API paiement)
reference = {
    "A01",   # Broken Access Control
    "A04",   # Cryptographic Failures (cartes en base)
    "A05",   # Injection
    "A07",   # Authentication Failures (login)
}


# ---- 3. CALCUL ----
precision, recall = precision_recall(agent_categories, reference)

print("=== EVALUATION DES MENACES (boutique en ligne) ===")
print("Categories couvertes par l'agent :", sorted(agent_categories))
print("Categories du corrige (OWASP)     :", sorted(reference))
print()
print("Trouvees (communes) :", sorted(agent_categories & reference))
print("Ratees (manquees)   :", sorted(reference - agent_categories))
print("En trop (hors ref)  :", sorted(agent_categories - reference))
print()
print("Precision :", round(precision, 2))
print("Recall    :", round(recall, 2))


# ---- 4. LE RISQUE R (un seul systeme ici, donc juste pour memoire) ----
# Quand tu auras plusieurs systemes, tu rempliras ces deux listes.
r_agent = [0.4625]   # le "Risk BEFORE" sorti par agent.py
r_ref   = [0.4625]   # le R de reference (ici identique : meme entrees validees)
print()
print("=== RISQUE R ===")
print("RMSE sur R :", round(rmse(r_agent, r_ref), 4))