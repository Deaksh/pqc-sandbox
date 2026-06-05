"""
JSON output for CI/CD pipelines.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Optional

from pqc_sandbox.benchmarks.runner import ComparisonResult
from pqc_sandbox.compat.oracle import CompatReport
from pqc_sandbox.hybrid.simulator import HybridResult
from pqc_sandbox.scoring import MigrationScore


def generate_json(
    comparison: Optional[ComparisonResult] = None,
    compat: Optional[CompatReport] = None,
    hybrid: Optional[HybridResult] = None,
    score: Optional[MigrationScore] = None,
    output_path: Optional[Path] = None,
) -> str:
    doc: dict = {
        "pqc_sandbox_version": "0.1.0",
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "telemetry": False,
    }

    if comparison:
        cl, pq = comparison.classical, comparison.pqc
        doc["benchmark"] = {
            "classical": {
                "name": cl.algorithm,
                "keygen_ms": cl.keygen_ms,
                "op1_ms": cl.operation1_ms,
                "op2_ms": cl.operation2_ms,
                "public_key_bytes": cl.public_key_bytes,
                "private_key_bytes": cl.private_key_bytes,
                "artifact_bytes": cl.artifact_bytes,
            },
            "pqc": {
                "name": pq.algorithm,
                "keygen_ms": pq.keygen_ms,
                "op1_ms": pq.operation1_ms,
                "op2_ms": pq.operation2_ms,
                "public_key_bytes": pq.public_key_bytes,
                "private_key_bytes": pq.private_key_bytes,
                "artifact_bytes": pq.artifact_bytes,
                "oqs_used": pq.oqs_used,
            },
            "delta": {
                "keygen_ms": comparison.keygen_delta_ms,
                "op1_ms": comparison.op1_delta_ms,
                "op2_ms": comparison.op2_delta_ms,
                "public_key_bytes": comparison.pubkey_delta_bytes,
                "artifact_bytes": comparison.artifact_delta_bytes,
                "keygen_slowdown": comparison.keygen_slowdown,
                "op1_slowdown": comparison.op1_slowdown,
                "artifact_ratio": comparison.artifact_ratio,
            },
        }

    if hybrid:
        doc["hybrid"] = {
            "label": hybrid.label,
            "classical": hybrid.classical_name,
            "pqc": hybrid.pqc_name,
            "combined_pubkey_bytes": hybrid.combined_pubkey_bytes,
            "combined_artifact_bytes": hybrid.combined_artifact_bytes,
            "wire_overhead_bytes": hybrid.wire_overhead_bytes,
            "combined_keygen_ms": hybrid.combined_keygen_ms,
            "combined_op1_ms": hybrid.combined_op1_ms,
            "combined_op2_ms": hybrid.combined_op2_ms,
            "latency_overhead_vs_classical_ms": hybrid.latency_vs_classical_ms,
        }

    if compat:
        doc["compatibility"] = {
            "verdict": compat.verdict,
            "issues": [
                {
                    "severity": i.severity.value,
                    "category": i.category,
                    "title": i.title,
                    "detail": i.detail,
                    "mitigation": i.mitigation,
                }
                for i in compat.issues
            ],
        }

    if score:
        doc["score"] = {
            "value": score.score,
            "label": score.label,
            "badge_color": score.badge_color,
            "badge_url": score.badge_url,
            "badge_markdown": score.badge_markdown,
            "breakdown": score.breakdown,
            "rationale": score.rationale,
        }

    # CI exit code helper
    if compat:
        doc["ci"] = {
            "exit_code": 0 if compat.verdict == "GO" else (1 if compat.verdict == "CAUTION" else 2),
            "verdict": compat.verdict,
        }

    serialised = json.dumps(doc, indent=2)
    if output_path:
        Path(output_path).write_text(serialised, encoding="utf-8")
    return serialised
