"""
cve.py — CVE/CVSS lookup via the NIST NVD API (Brique 2).

Public API:
  await lookup_cve(cve_id: str) -> dict

Returns:
  {
    "cve_id":      "CVE-2023-44487",
    "description": "...",
    "cvss_score":  7.5,          # base score 0-10, None if unavailable
    "severity":    "HIGH",       # LOW / MEDIUM / HIGH / CRITICAL
    "vector":      "CVSS:3.1/AV:N/...",
    "published":   "2023-10-10T...",
    "impact":      0.75,         # cvss_score / 10  → ready for A_I matrix
    "effectiveness_hint": 0.25   # suggested starting control effectiveness
  }

Or on error:
  {"error": "CVE-2023-XXXXX not found."}

Endpoint to register in backend.py:
  GET /api/cve/{cve_id}   →  api_cve_lookup(cve_id)
"""

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS  = {"User-Agent": "CySyMo/1.0 (academic research tool)"}
TIMEOUT  = 12  # seconds — NVD can be slow


def _extract_score(metrics: dict):
    """
    Extract CVSS base score, severity and vector string.
    Priority: v3.1 > v3.0 > v2.0
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if not entries:
            continue
        cvss = entries[0].get("cvssData", {})
        score    = cvss.get("baseScore")
        severity = cvss.get("baseSeverity") or entries[0].get("baseSeverity")
        vector   = cvss.get("vectorString")
        if score is not None:
            return float(score), str(severity or "").upper(), vector
    return None, None, None


async def lookup_cve(cve_id: str) -> dict:
    """
    Query the NVD REST API v2 and return a CySyMo-ready dict.
    Async — must be called from an async FastAPI endpoint.
    """
    cve_id = cve_id.strip().upper()

    # basic format validation
    if not cve_id.startswith("CVE-"):
        return {"error": f"Invalid CVE ID format: '{cve_id}'. Expected CVE-YYYY-NNNNN."}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                NVD_URL,
                params={"cveId": cve_id},
                headers=HEADERS,
            )
        resp.raise_for_status()
        data = resp.json()
    except httpx.TimeoutException:
        return {"error": "NVD API timed out. Try again in a few seconds."}
    except httpx.HTTPStatusError as e:
        return {"error": f"NVD API returned HTTP {e.response.status_code}."}
    except Exception as e:
        return {"error": f"NVD lookup failed: {e}"}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"error": f"{cve_id} not found in NVD database."}

    cve = vulns[0].get("cve", {})

    # English description
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "No English description available.",
    )

    # CVSS
    score, severity, vector = _extract_score(cve.get("metrics", {}))

    # Derived values for CySyMo
    impact = round(score / 10.0, 3) if score is not None else None

    # Suggest a conservative control effectiveness:
    # high CVSS → hard to control → lower effectiveness hint
    if score is not None:
        if score >= 9.0:
            eff_hint = 0.30
        elif score >= 7.0:
            eff_hint = 0.45
        elif score >= 4.0:
            eff_hint = 0.60
        else:
            eff_hint = 0.75
    else:
        eff_hint = 0.50

    return {
        "cve_id":             cve_id,
        "description":        description,
        "cvss_score":         score,
        "severity":           severity,
        "vector":             vector,
        "published":          cve.get("published", ""),
        "impact":             impact,           # [0,1] → use in A_I matrix
        "effectiveness_hint": eff_hint,         # [0,1] → suggested control strength
    }
