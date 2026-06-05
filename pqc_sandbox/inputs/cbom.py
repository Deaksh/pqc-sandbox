"""
Parse a Cryptographic Bill of Materials (CBOM) JSON file.
CBOM follows the CycloneDX schema extension for cryptographic assets.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pqc_sandbox.algorithms import MIGRATION_MAP


@dataclass
class CbomComponent:
    name: str
    version: str
    algorithm: str
    detected_classical: str
    recommended_pqc: list[str]


@dataclass
class CbomResult:
    source_file: str
    components: list[CbomComponent] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def unique_algorithms(self) -> list[str]:
        return list({c.detected_classical for c in self.components if c.detected_classical})


# Map CBOM/CycloneDX algorithm names → our internal names
_CBOM_ALGO_MAP: dict[str, str] = {
    "RSA": "RSA-2048 (PKCS#1 v1.5)",
    "RSA-2048": "RSA-2048 (PKCS#1 v1.5)",
    "RSA-4096": "RSA-4096 (PKCS#1 v1.5)",
    "EC": "ECDSA-P256",
    "ECDSA": "ECDSA-P256",
    "ECDH": "ECDH-P256",
    "ECDSA-P256": "ECDSA-P256",
    "ECDSA-P384": "ECDSA-P384",
    "ECDH-P256": "ECDH-P256",
    "ECDH-P384": "ECDH-P384",
    "ED25519": "Ed25519",
    "EdDSA": "Ed25519",
    # Modern PQC (already migrated — passthrough)
    "ML-KEM-768": "ML-KEM-768",
    "ML-DSA-65": "ML-DSA-65",
}


def _detect_algorithm(algo_str: str) -> str:
    s = algo_str.upper().strip()
    for key, val in _CBOM_ALGO_MAP.items():
        if key.upper() in s:
            return val
    return algo_str


def parse_cbom(path: str | Path) -> CbomResult:
    p = Path(path)
    raw: dict = json.loads(p.read_text(encoding="utf-8"))
    result = CbomResult(source_file=str(p), raw=raw)

    # CycloneDX CBOM structure: components[].cryptoProperties.algorithmProperties.primitive
    components: list[Any] = raw.get("components", [])
    for comp in components:
        name = comp.get("name", "unknown")
        version = comp.get("version", "")
        crypto = comp.get("cryptoProperties", {})
        algo_props = crypto.get("algorithmProperties", {})
        primitive = algo_props.get("primitive", "")
        curve = algo_props.get("curve", "")
        key_size = algo_props.get("keySize", "")

        raw_algo = comp.get("algorithm", primitive or name)
        detected = _detect_algorithm(str(raw_algo))
        recommended = MIGRATION_MAP.get(detected, [])

        result.components.append(CbomComponent(
            name=name,
            version=str(version),
            algorithm=raw_algo,
            detected_classical=detected,
            recommended_pqc=recommended,
        ))

    return result
