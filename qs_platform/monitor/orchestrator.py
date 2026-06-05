"""
Multi-asset orchestrator: run migration-impact analysis across an org's asset inventory.

Accepts CBOM/SARIF from existing scanners — we do not rebuild scanning,
we consume their output and add the impact/compliance layer.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pqc_sandbox.algorithms import ALL_ALGORITHMS, MIGRATION_MAP
from pqc_sandbox.benchmarks.runner import run_comparison, ComparisonResult
from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints, Severity
from pqc_sandbox.hybrid.simulator import simulate_hybrid
from pqc_sandbox.scoring import compute_score, MigrationScore
from pqc_sandbox.inputs.tls_probe import probe_tls_endpoint
from pqc_sandbox.inputs.cbom import parse_cbom
from pqc_sandbox.inputs.sarif import parse_sarif

from qs_platform.api.models import (
    Asset, AssetType, ScanResult, ScanStatus, AlgorithmFinding,
    MigrationVerdict, OrgReadinessSnapshot, SystemReadiness, TeamReadiness,
)


@dataclass
class OrchestratorResult:
    scan: ScanResult
    comparisons: list[ComparisonResult]
    scores: list[MigrationScore]
    constraints_used: SystemConstraints


def _constraints_for_asset(asset: Asset) -> SystemConstraints:
    meta = asset.metadata
    return SystemConstraints(
        mtu_bytes=meta.get("mtu_bytes", 1500),
        tls_version=meta.get("tls_version", "1.3"),
        ram_kb=meta.get("ram_kb"),
        protocol=meta.get("protocol", "tls"),
        tags=asset.tags,
    )


def _scan_tls(asset: Asset, scan: ScanResult) -> list[AlgorithmFinding]:
    try:
        parts = asset.target.rsplit(":", 1)
        host = parts[0].replace("https://", "").replace("http://", "").rstrip("/")
        port = int(parts[1]) if len(parts) > 1 else 443
        probe = probe_tls_endpoint(host, port, timeout=10.0)
        findings = []
        if probe.detected_classical_kem:
            findings.append(AlgorithmFinding(
                classical_algorithm=probe.detected_classical_kem,
                location=f"{host}:{port} (TLS key exchange)",
                recommended_pqc=probe.recommended_kem,
                severity="HIGH",
            ))
        if probe.detected_classical_sign:
            findings.append(AlgorithmFinding(
                classical_algorithm=probe.detected_classical_sign,
                location=f"{host}:{port} (certificate signature)",
                recommended_pqc=probe.recommended_sign,
                severity="HIGH",
            ))
        return findings
    except Exception as exc:
        scan.error = f"TLS probe failed: {exc}"
        return []


def _scan_cbom(asset: Asset, scan: ScanResult) -> list[AlgorithmFinding]:
    try:
        result = parse_cbom(asset.target)
        return [
            AlgorithmFinding(
                classical_algorithm=c.detected_classical,
                location=c.name,
                recommended_pqc=c.recommended_pqc,
                severity="HIGH",
            )
            for c in result.components
            if c.recommended_pqc
        ]
    except Exception as exc:
        scan.error = f"CBOM parse failed: {exc}"
        return []


def _scan_sarif(asset: Asset, scan: ScanResult) -> list[AlgorithmFinding]:
    try:
        result = parse_sarif(asset.target)
        return [
            AlgorithmFinding(
                classical_algorithm=f.detected_algorithm,
                location=f.location,
                recommended_pqc=f.recommended_pqc,
                severity="HIGH",
            )
            for f in result.findings
            if f.recommended_pqc
        ]
    except Exception as exc:
        scan.error = f"SARIF parse failed: {exc}"
        return []


def scan_asset(asset: Asset, iterations: int = 20) -> OrchestratorResult:
    scan = ScanResult(
        asset_id=asset.id,
        org_id=asset.org_id,
        status=ScanStatus.RUNNING,
    )

    try:
        if asset.asset_type == AssetType.TLS_ENDPOINT:
            findings = _scan_tls(asset, scan)
        elif asset.asset_type == AssetType.CBOM_FILE:
            findings = _scan_cbom(asset, scan)
        elif asset.asset_type == AssetType.SARIF_FILE:
            findings = _scan_sarif(asset, scan)
        else:
            findings = []

        scan.algorithms_found = findings
        constraints = _constraints_for_asset(asset)

        comparisons: list[ComparisonResult] = []
        scores: list[MigrationScore] = []
        seen: set[str] = set()

        for finding in findings:
            classical = finding.classical_algorithm
            if not finding.recommended_pqc or classical in seen:
                continue
            seen.add(classical)
            pqc = finding.recommended_pqc[0]
            if classical not in ALL_ALGORITHMS or pqc not in ALL_ALGORITHMS:
                continue

            cmp = run_comparison(classical, pqc, iterations=iterations, force_simulate=True)
            compat = run_compat_check(ALL_ALGORITHMS[pqc], constraints)
            hybrid_result = None
            try:
                hybrid_result = simulate_hybrid(classical, pqc, iterations=iterations,
                                                 force_simulate=True)
            except ValueError:
                pass
            score = compute_score(comparison=cmp, compat=compat, hybrid=hybrid_result)
            comparisons.append(cmp)
            scores.append(score)

            scan.issues_blocked += sum(1 for i in compat.issues if i.severity == Severity.BLOCKED)
            scan.issues_caution += sum(1 for i in compat.issues if i.severity == Severity.CAUTION)

        # Aggregate verdict and score
        if scores:
            avg_score = sum(s.score for s in scores) / len(scores)
            scan.difficulty_score = int(avg_score)
            worst = max(scores, key=lambda s: s.score)
            scan.difficulty_label = worst.label
        else:
            scan.difficulty_score = 0
            scan.difficulty_label = "EASY"

        if scan.issues_blocked > 0:
            scan.verdict = MigrationVerdict.BLOCKED
        elif scan.issues_caution > 0:
            scan.verdict = MigrationVerdict.CAUTION
        else:
            scan.verdict = MigrationVerdict.GO

        scan.status = ScanStatus.COMPLETE
        scan.completed_at = datetime.datetime.utcnow()

        return OrchestratorResult(
            scan=scan,
            comparisons=comparisons,
            scores=scores,
            constraints_used=constraints,
        )

    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.error = str(exc)
        scan.completed_at = datetime.datetime.utcnow()
        return OrchestratorResult(scan=scan, comparisons=[], scores=[], constraints_used=SystemConstraints())


def scan_org(assets: list[Asset]) -> OrgReadinessSnapshot:
    """Run scan_asset across all assets and compute org-level readiness."""
    results: list[ScanResult] = []
    for asset in assets:
        r = scan_asset(asset)
        results.append(r.scan)

    go_count = sum(1 for r in results if r.verdict == MigrationVerdict.GO)
    caution_count = sum(1 for r in results if r.verdict == MigrationVerdict.CAUTION)
    blocked_count = sum(1 for r in results if r.verdict == MigrationVerdict.BLOCKED)
    scored = [r.difficulty_score for r in results if r.difficulty_score is not None]
    avg_score = sum(scored) / len(scored) if scored else 0.0
    total = len(results)
    readiness_pct = (go_count / total * 100) if total > 0 else 0.0

    # Per-team breakdown
    teams: dict[str, dict] = {}
    for asset, result in zip(assets, results):
        team = asset.team or "unassigned"
        if team not in teams:
            teams[team] = {"total": 0, "go": 0, "caution": 0, "blocked": 0, "scores": []}
        teams[team]["total"] += 1
        if result.verdict == MigrationVerdict.GO:
            teams[team]["go"] += 1
        elif result.verdict == MigrationVerdict.CAUTION:
            teams[team]["caution"] += 1
        else:
            teams[team]["blocked"] += 1
        if result.difficulty_score is not None:
            teams[team]["scores"].append(result.difficulty_score)

    team_readiness = {
        name: TeamReadiness(
            team=name,
            total=d["total"],
            go=d["go"],
            caution=d["caution"],
            blocked=d["blocked"],
            avg_score=sum(d["scores"]) / len(d["scores"]) if d["scores"] else 0.0,
        )
        for name, d in teams.items()
    }

    org_id = assets[0].org_id if assets else "unknown"
    return OrgReadinessSnapshot(
        org_id=org_id,
        total_assets=total,
        scanned_assets=total,
        go_count=go_count,
        caution_count=caution_count,
        blocked_count=blocked_count,
        avg_difficulty_score=avg_score,
        readiness_pct=readiness_pct,
        teams=team_readiness,
    )
