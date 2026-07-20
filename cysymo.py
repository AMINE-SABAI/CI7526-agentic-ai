"""Core data model for the CySyMo package."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class RiskSimulation:
    """Placeholder for future simulation extensions."""

class CyberSystemModel:
    """
    Models cybersecurity risk using vulnerabilities, threats, assets and an impact matrix.
    
    Risk is computed as R = e * AI * p, normalised to a value between 0 and 1.
    """

    def __init__(self, m: int = 0, n: int = 0, randomize: bool = False) -> None:
        """
        Create a system with m vulnerabilities and n threats.
 
        Args:
            m: number of vulnerabilities. Defaults to 0 (empty system).
            n: number of threats. Defaults to 0 (empty system).
            randomize: if True, fills the impact matrix with random values in [0, 1].
        """

        self.vulnerabilities: list[list[Any]] = []
        self.threats: list[list[Any]] = []
        self.assets: list[list[Any]] = []
        self.e: list[float] = []
        self.p: list[float] = []
        self.AI: list[list[float]] = []

        if m < 0 or n < 0:
            raise ValueError("m and n must be non-negative")

        if m or n:
            self.init_system(m=m, n=n, randomize=randomize)

    def init_system(self, m: int = 0, n: int = 0, randomize: bool = False) -> None:
        """
        Initialise or reset the system with m vulnerabilities and n threats.

        Args:
            m: number of vulnerabilities.
            n: number of threats.
            randomize: if True, fills the impact matrix with random values in [0, 1].
        """

        if m < 0 or n < 0:
            raise ValueError("m and n must be non-negative")

        self.vulnerabilities = [[f"V{i+1}", f"Vulnerability {i+1}", []] for i in range(m)]
        self.threats = [[f"T{j+1}", f"Threat {j+1}", []] for j in range(n)]
        self.assets = []
        self.e = [1.0] * m
        self.p = [1.0] * n
        if randomize and m and n:
            self.AI = [[round(random.uniform(0.0, 1.0), 4) for _ in range(n)] for _ in range(m)]
        else:
            self.AI = [[0.0 for _ in range(n)] for _ in range(m)]

    def _find_index(self, items: list[list[Any]], item_id: str) -> int:
        for idx, item in enumerate(items):
            if item[0] == item_id:
                return idx
        raise ValueError(f"Unknown id: {item_id}")

    def _validate_unit_interval_vector(self, values: list[float], name: str) -> None:
        for v in values:
            if not 0.0 <= float(v) <= 1.0:
                raise ValueError(f"{name} values must be in [0, 1]")

    def add_vuln(self, v: list[Any]) -> None:
        """
        Add a vulnerability to the system.
 
        Args:
            v: [id, description, metrics]
        """
        if any(existing[0] == v[0] for existing in self.vulnerabilities):
            raise ValueError(f"Vulnerability id already exists: {v[0]}")
        self.vulnerabilities.append(v)
        cols = len(self.threats)
        self.AI.append([0.0 for _ in range(cols)])
        self.e.append(1.0)

    def edit_vuln(self, v: list[Any]) -> None:
        """
        Edit an existing vulnerability's metadata. Does not change the impact matrix.
 
        Args:
            v: [id, description, metrics]
        """
        idx = self._find_index(self.vulnerabilities, v[0])
        self.vulnerabilities[idx] = v

    def remove_vuln(self, vuln_id: str) -> None:
        """
        Remove a vulnerability by id. Also removes its row from the impact matrix.
 
        Args:
            vuln_id: id of the vulnerability to remove.
        """
        idx = self._find_index(self.vulnerabilities, vuln_id)
        self.vulnerabilities.pop(idx)
        self.e.pop(idx)
        self.AI.pop(idx)

    def add_threat(self, t: list[Any]) -> None:
        """
        Add a threat to the system.
 
        Args:
            t: [id, description, profile_info]
        """
        if any(existing[0] == t[0] for existing in self.threats):
            raise ValueError(f"Threat id already exists: {t[0]}")
        self.threats.append(t)
        for row in self.AI:
            row.append(0.0)
        self.p.append(1.0)

    def edit_threat(self, t: list[Any]) -> None:
        """
        Edit an existing threat's metadata. Does not change the impact matrix.
 
        Args:
            t: [id, description, profile_info]
        """
        idx = self._find_index(self.threats, t[0])
        self.threats[idx] = t

    def remove_threat(self, threat_id: str) -> None:
        """
        Remove a threat by id. Also removes its column from the impact matrix.

        Args:
            threat_id: id of the threat to remove.
        """
        idx = self._find_index(self.threats, threat_id)
        self.threats.pop(idx)
        self.p.pop(idx)
        for row in self.AI:
            row.pop(idx)

    def add_asset(self, a: list[Any]) -> None:
        """
        Add an asset to the system.

        Args:
            a: [id, description]
        """
        if any(existing[0] == a[0] for existing in self.assets):
            raise ValueError(f"Asset id already exists: {a[0]}")
        self.assets.append(a)

    def edit_asset(self, a: list[Any]) -> None:
        """
        Edit an existing asset's metadata.
 
        Args:
            a: [id, description]
        """
        idx = self._find_index(self.assets, a[0])
        self.assets[idx] = a

    def remove_asset(self, asset_id: str) -> None:
        """
        Remove an asset by id.

        Args:
            asset_id: id of the asset to remove.
        """
        idx = self._find_index(self.assets, asset_id)
        self.assets.pop(idx)

    def protect(self, c: list[float]) -> None:
        """
        Set the exposure level for each vulnerability.
 
        Args:
            c: list of floats in [0, 1]. 1.0 = fully controlled (patched), 0.0 = fully exposed.
        """
        if len(c) != len(self.vulnerabilities):
            raise ValueError("Control vector size must match number of vulnerabilities")
        self._validate_unit_interval_vector(c, "Control")
        self.e = [1.0 - float(v) for v in c]

    def attack(self, p: list[float]) -> None:
        """
        Set the attack probability for each threat.
 
        Args:
            p: list of floats in [0, 1]. 1.0 = certain attack, 0.0 = blocked.
        """
        if len(p) != len(self.threats):
            raise ValueError("Probability vector size must match number of threats")
        self._validate_unit_interval_vector(p, "Attack probability")
        self.p = [float(v) for v in p]

    def get_impact(self, vuln_id: str, threat_id: str) -> float:
        """
        Get the impact value for a vulnerability-threat pair.
 
        Args:
            vuln_id: vulnerability id.
            threat_id: threat id.
        Returns:
            float: impact value.
        """
        i = self._find_index(self.vulnerabilities, vuln_id)
        j = self._find_index(self.threats, threat_id)
        return float(self.AI[i][j])

    def set_impact(self, vuln_id: str, threat_id: str, value: float) -> None:
        """
        Set the impact value for a vulnerability-threat pair.
 
        Args:
            vuln_id: vulnerability id.
            threat_id: threat id.
            value: impact value to set.
        """
        i = self._find_index(self.vulnerabilities, vuln_id)
        j = self._find_index(self.threats, threat_id)
        self.AI[i][j] = float(value)

    def export_config(self) -> str:
        """
        Export the current system configuration as JSON text.

        Returns:
            str: JSON representation of the current configuration.
        """
        payload = {
            "vulnerabilities": self.vulnerabilities,
            "threats": self.threats,
            "assets": self.assets,
            "exposures": self.e,
            "attack_probabilities": self.p,
            "impact_matrix": self.AI,
        }
        config_json = json.dumps(payload, indent=2)
        print(config_json)
        return config_json

    def compute_risk(self) -> float:
        """
        Compute the overall system risk, normalised to [0, 1].
 
        Returns:
            float: 0.0 = no risk, 1.0 = maximum risk.
        """
        if len(self.AI) != len(self.e):
            raise ValueError("Matrix dimensions do not match exposure vector")
        for row in self.AI:
            if len(row) != len(self.p):
                raise ValueError("Matrix dimensions do not match probability vector")
        if not self.e or not self.p:
            return 0.0

        risk = 0.0
        for i, e_i in enumerate(self.e):
            for j, p_j in enumerate(self.p):
                risk += float(e_i) * float(self.AI[i][j]) * float(p_j)
        
        max_risk = float(len(self.vulnerabilities) * len(self.threats))
        if max_risk == 0.0:
            return 0.0
        
        return risk / max_risk