"""
Migration Difficulty Score: 0 (trivial) → 100 (very hard).
Produces a badge-ready label: EASY / MODERATE / HARD / CRITICAL.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pqc_sandbox.benchmarks.runner import ComparisonResult
from pqc_sandbox.compat.oracle import CompatReport, Severity
from pqc_sandbox.hybrid.simulator import HybridResult


BADGE_COLORS = {
    "EASY":     "brightgreen",
    "MODERATE": "yellow",
    "HARD":     "orange",
    "CRITICAL": "red",
}


@dataclass
class MigrationScore:
    score: int              # 0–100
    label: str              # EASY | MODERATE | HARD | CRITICAL
    badge_color: str
    breakdown: dict[str, int]   # category → sub-score
    rationale: list[str]        # human-readable justification bullets

    @property
    def badge_url(self) -> str:
        encoded = self.label.replace(" ", "%20")
        color = self.badge_color
        return f"https://img.shields.io/badge/PQC%20Migration-{encoded}-{color}?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEyIDJMMiA3bDEwIDUgMTAtNS0xMC01ek0yIDE3bDEwIDUgMTAtNS0xMC01LTEwIDV6TTIgMTJsMTAgNSAxMC01LTEwLTUtMTAgNXoiIGZpbGw9IndoaXRlIi8+PC9zdmc+"

    @property
    def badge_markdown(self) -> str:
        return f"![PQC Migration: {self.label}]({self.badge_url})"


def compute_score(
    comparison: Optional[ComparisonResult] = None,
    compat: Optional[CompatReport] = None,
    hybrid: Optional[HybridResult] = None,
) -> MigrationScore:
    breakdown: dict[str, int] = {}
    rationale: list[str] = []

    # ── Size penalty (0–30 pts) ───────────────────────────────────────────────
    size_score = 0
    if comparison:
        ratio = comparison.artifact_ratio
        if ratio > 40:
            size_score = 30
            rationale.append(f"Signature/ciphertext is {ratio:.0f}× larger (very high)")
        elif ratio > 10:
            size_score = 20
            rationale.append(f"Artifact is {ratio:.0f}× larger (significant)")
        elif ratio > 3:
            size_score = 10
            rationale.append(f"Artifact is {ratio:.1f}× larger (moderate)")
        else:
            rationale.append(f"Artifact size increase is small ({ratio:.1f}×)")
    breakdown["size"] = size_score

    # ── Performance penalty (0–25 pts) ───────────────────────────────────────
    perf_score = 0
    if comparison:
        slowdown = max(comparison.op1_slowdown, comparison.op2_slowdown)
        if slowdown > 100:
            perf_score = 25
            rationale.append(f"Operation is {slowdown:.0f}× slower (critical for high-throughput)")
        elif slowdown > 10:
            perf_score = 15
            rationale.append(f"Operation is {slowdown:.0f}× slower (noticeable in load tests)")
        elif slowdown > 2:
            perf_score = 8
            rationale.append(f"Operation is {slowdown:.1f}× slower (acceptable for most workloads)")
        elif slowdown > 0:
            rationale.append(f"Performance change is minimal ({slowdown:.1f}×)")
    breakdown["performance"] = perf_score

    # ── Compatibility blockers (0–30 pts) ─────────────────────────────────────
    compat_score = 0
    if compat:
        blocked = [i for i in compat.issues if i.severity == Severity.BLOCKED]
        caution = [i for i in compat.issues if i.severity == Severity.CAUTION]
        compat_score += min(30, len(blocked) * 15 + len(caution) * 5)
        for issue in blocked:
            rationale.append(f"BLOCKED: {issue.title}")
        for issue in caution:
            rationale.append(f"CAUTION: {issue.title}")
    breakdown["compatibility"] = compat_score

    # ── Hybrid overhead (0–15 pts) ────────────────────────────────────────────
    hybrid_score = 0
    if hybrid:
        overhead_pct = hybrid.wire_overhead_bytes / max(hybrid.classical_bench.artifact_bytes, 1) * 100
        if overhead_pct > 5000:
            hybrid_score = 15
            rationale.append(f"Hybrid wire overhead is +{hybrid.wire_overhead_bytes:,} B ({overhead_pct:.0f}% increase)")
        elif overhead_pct > 1000:
            hybrid_score = 8
            rationale.append(f"Hybrid wire overhead is +{hybrid.wire_overhead_bytes:,} B (manageable)")
        else:
            hybrid_score = 3
            rationale.append(f"Hybrid overhead is small (+{hybrid.wire_overhead_bytes:,} B)")
    breakdown["hybrid"] = hybrid_score

    total = min(100, size_score + perf_score + compat_score + hybrid_score)

    if total <= 20:
        label = "EASY"
    elif total <= 45:
        label = "MODERATE"
    elif total <= 70:
        label = "HARD"
    else:
        label = "CRITICAL"

    return MigrationScore(
        score=total,
        label=label,
        badge_color=BADGE_COLORS[label],
        breakdown=breakdown,
        rationale=rationale,
    )
