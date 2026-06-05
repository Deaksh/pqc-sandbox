"""
Parse SARIF 2.1.0 output from crypto-scanning tools (e.g. Semgrep, CodeQL, Cryptosense).
Extracts detected cryptographic findings and maps them to our algorithm catalogue.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from pqc_sandbox.algorithms import MIGRATION_MAP


@dataclass
class SarifFinding:
    rule_id: str
    message: str
    location: str
    detected_algorithm: str
    recommended_pqc: list[str]


@dataclass
class SarifResult:
    source_file: str
    tool_name: str
    findings: list[SarifFinding] = field(default_factory=list)

    @property
    def unique_algorithms(self) -> list[str]:
        return list({f.detected_algorithm for f in self.findings if f.detected_algorithm})


_RULE_ALGO_HINTS: dict[str, str] = {
    "rsa": "RSA-2048 (PKCS#1 v1.5)",
    "ecdsa": "ECDSA-P256",
    "ecdh": "ECDH-P256",
    "ed25519": "Ed25519",
    "dsa": "ECDSA-P256",
    "des": "RSA-2048 (PKCS#1 v1.5)",  # legacy hint
}


def _infer_algorithm(rule_id: str, message: str) -> str:
    combined = (rule_id + " " + message).lower()
    for hint, algo in _RULE_ALGO_HINTS.items():
        if hint in combined:
            return algo
    return "ECDSA-P256"  # conservative default


def parse_sarif(path: str | Path) -> SarifResult:
    p = Path(path)
    raw: dict = json.loads(p.read_text(encoding="utf-8"))

    tool_name = "unknown"
    findings: list[SarifFinding] = []

    for run in raw.get("runs", []):
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        tool_name = driver.get("name", "unknown")

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")

            locations = result.get("locations", [])
            loc_str = ""
            if locations:
                physical = locations[0].get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                loc_str = f"{artifact.get('uri', '')}:{region.get('startLine', '')}"

            detected = _infer_algorithm(rule_id, message)
            recommended = MIGRATION_MAP.get(detected, [])

            findings.append(SarifFinding(
                rule_id=rule_id,
                message=message,
                location=loc_str,
                detected_algorithm=detected,
                recommended_pqc=recommended,
            ))

    return SarifResult(
        source_file=str(p),
        tool_name=tool_name,
        findings=findings,
    )
