"""
profile.py — User profile / use case selector for CySyMo (Brique 6).

Three profiles are supported:
  - enterprise  : default, full feature set
  - academic    : same behaviour for now (future: stricter validation)
  - teaching    : same behaviour for now (future: guided mode)

At present all three profiles behave identically (enterprise logic applies).
This module exists for downward compatibility and future extension.

Endpoints to register in backend.py:
  GET  /api/profile        → returns current profile + available list
  POST /api/profile        → sets the profile   { "profile": "enterprise" }
"""

PROFILES = ["enterprise", "academic", "teaching"]
DEFAULT_PROFILE = "enterprise"

PROFILE_META = {
    "enterprise": {
        "label":       "Enterprise",
        "description": "Full risk assessment for production systems.",
        "icon":        "🏢",
    },
    "academic": {
        "label":       "Academic",
        "description": "Research and analysis context.",
        "icon":        "🎓",
    },
    "teaching": {
        "label":       "Learning & Teaching",
        "description": "Guided mode for learning cyber risk concepts.",
        "icon":        "📚",
    },
}

_current_profile: str = DEFAULT_PROFILE


def get_profile() -> dict:
    """Return the current profile name, label, and available profiles."""
    return {
        "profile":   _current_profile,
        "meta":      PROFILE_META[_current_profile],
        "available": [
            {"id": p, **PROFILE_META[p]} for p in PROFILES
        ],
    }


def set_profile(name: str) -> dict:
    """Set the active profile. Silently ignores unknown names."""
    global _current_profile
    if name in PROFILES:
        _current_profile = name
    return get_profile()
