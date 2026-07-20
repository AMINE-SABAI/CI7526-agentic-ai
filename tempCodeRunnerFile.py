"""
risk_formulas.py - Selectable risk aggregations (Level B).

All three formulas use the SAME engine data: the exposure vector e, the impact
matrix AI and the attack-probability vector p. They only change HOW the values
are aggregated. This module never modifies cysymo.py: the supervisor's engine
keeps its own compute_risk(), which we reuse for the default "mean" formula.

Formulas:
  - "mean"  : R = ( sum_i sum_j  e_i * AI[i][j] * p_j ) / (m * n)   (CySyMo default, [0,1])
  - "total" : R = sum_i sum_j  e_i * AI[i][j] * p_j                 (raw un-normalised sum)
  - "max"   : R = max_{i,j}  e_i * AI[i][j] * p_j                   (worst single pair, [0,1])
"""

FORMULAS = {
    "mean": "Mean risk (CySyMo default)",
    "total": "Total risk (un-normalised)",
    "max": "Worst-case risk",
}


def _pairwise_terms(model):
    """Return the list of e_i * AI[i][j] * p_j over every (vuln, threat) pair."""
    terms = []
    for i, e_i in enumerate(model.e):
        for j, p_j in enumerate(model.p):
            terms.append(float(e_i) * float(model.AI[i][j]) * float(p_j))
    return terms


def compute_risk(model, formula="mean"):
    """Compute the risk with the chosen aggregation. Returns a float."""
    m = len(model.vulnerabilities)
    n = len(model.threats)
    if m == 0 or n == 0:
        return 0.0

    if formula == "mean":
        # Reuse the supervisor's untouched engine for the default.
        return model.compute_risk()

    terms = _pairwise_terms(model)
    if not terms:
        return 0.0

    if formula == "total":
        return sum(terms)
    if formula == "max":
        return max(terms)

    # Unknown formula -> fall back to the engine default.
    return model.compute_risk()


def normalised(model, formula, value):
    """Return value mapped to [0,1] for the risk-level badge and percentage."""
    m = len(model.vulnerabilities)
    n = len(model.threats)
    if m == 0 or n == 0:
        return 0.0
    if formula == "total":
        denom = float(m * n)
        return value / denom if denom else 0.0
    # mean and max are already in [0,1]
    return max(0.0, min(1.0, value))


def level(norm_value):
    """Map a [0,1] value to a risk level."""
    if norm_value < 0.34:
        return "Low"
    if norm_value < 0.67:
        return "Moderate"
    return "High"
