"""
Asset management routes: CRUD + trigger scans + investigation detail.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from qs_platform.api.deps import get_current_user
from qs_platform.api.models import Asset, AssetCreate, ScanResult, ScanStatus, User
from qs_platform.api import store
from qs_platform.monitor.orchestrator import scan_asset
from qs_platform.enterprise.audit import log_event

# Core library imports for the investigation engine
from pqc_sandbox.algorithms import ALL_ALGORITHMS, MIGRATION_MAP
from pqc_sandbox.benchmarks.runner import run_comparison
from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints
from pqc_sandbox.hybrid.simulator import simulate_hybrid
from pqc_sandbox.scoring import compute_score
from pqc_sandbox.report.config_diff import generate_config_diff

router = APIRouter(prefix="/assets", tags=["assets"])

# In-memory acknowledgement store (move to DB in production)
_acks: dict[str, dict[str, str]] = {}  # asset_id → {algorithm: note}


# ── Helpers ───────────────────────────────────────────────────────────────────

_WHY_VULNERABLE = {
    "ECDH-P256":             "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm on a cryptographically relevant quantum computer. An attacker harvesting today's traffic can decrypt it retroactively once quantum hardware matures (~2030–2035).",
    "ECDH-P384":             "Same as ECDH-P256. The larger curve only delays — it does not prevent — quantum attack.",
    "RSA-2048 (PKCS#1)":     "RSA integer factorisation is the textbook application of Shor's algorithm. 2048-bit RSA is expected to fall within hours on a fault-tolerant quantum computer with ~4,000 logical qubits.",
    "ECDSA-P256":            "ECDSA signature verification uses the elliptic-curve discrete-log problem, fully broken by Shor's algorithm. Every signature you've ever made with this key could be forged retroactively.",
    "ECDSA-P384":            "Same attack surface as ECDSA-P256. P-384 provides no meaningful quantum resistance.",
    "RSA-2048 (PKCS#1 v1.5)":"RSA-2048 signatures are broken by Shor's algorithm. Additionally, PKCS#1 v1.5 padding has classical vulnerabilities (Bleichenbacher attack).",
    "RSA-4096 (PKCS#1 v1.5)":"Larger key buys more classical security but zero additional quantum resistance.",
    "Ed25519":               "EdDSA over Curve25519 uses the elliptic-curve discrete-log problem. Broken by Shor's algorithm just like ECDSA.",
}

_NIST_STANDARD = {
    "ML-KEM-512": "NIST FIPS 203 (Aug 2024)", "ML-KEM-768": "NIST FIPS 203 (Aug 2024)",
    "ML-KEM-1024": "NIST FIPS 203 (Aug 2024)",
    "ML-DSA-44": "NIST FIPS 204 (Aug 2024)", "ML-DSA-65": "NIST FIPS 204 (Aug 2024)",
    "ML-DSA-87": "NIST FIPS 204 (Aug 2024)",
    "SLH-DSA-SHA2-128s": "NIST FIPS 205 (Aug 2024)", "SLH-DSA-SHA2-256s": "NIST FIPS 205 (Aug 2024)",
}


def _flag(ratio: float, bad_thresh: float, warn_thresh: float) -> str:
    if ratio >= bad_thresh:
        return "bad"
    if ratio >= warn_thresh:
        return "warn"
    return "ok"


def _build_finding_detail(
    classical_name: str,
    pqc_name: str,
    location: Optional[str],
    constraints: SystemConstraints,
    ack_note: Optional[str],
) -> dict[str, Any]:
    if classical_name not in ALL_ALGORITHMS or pqc_name not in ALL_ALGORITHMS:
        return {}

    cmp     = run_comparison(classical_name, pqc_name, iterations=20, force_simulate=True)
    compat  = run_compat_check(ALL_ALGORITHMS[pqc_name], constraints)
    hybrid  = None
    try:
        hybrid = simulate_hybrid(classical_name, pqc_name, iterations=20, force_simulate=True)
    except ValueError:
        pass
    score   = compute_score(comparison=cmp, compat=compat, hybrid=hybrid)
    c, p    = cmp.classical, cmp.pqc
    art_lbl = "Ciphertext" if p.category == "kem" else "Signature"
    op1_lbl = "Encapsulate" if p.category == "kem" else "Sign"
    op2_lbl = "Decapsulate" if p.category == "kem" else "Verify"

    def fmt_bytes(n: int) -> str:
        return f"{n/1024:.1f} KB" if n >= 1024 else f"{n} B"

    def ratio_str(r: float) -> str:
        return f"{r:.1f}×"

    benchmark_rows = [
        {"metric": "KeyGen",  "classical": f"{c.keygen_ms:.3f} ms", "pqc": f"{p.keygen_ms:.3f} ms",
         "delta": f"{cmp.keygen_delta_ms:+.3f} ms", "ratio": ratio_str(cmp.keygen_slowdown),
         "flag": _flag(cmp.keygen_slowdown, 10, 2)},
        {"metric": op1_lbl,   "classical": f"{c.operation1_ms:.3f} ms", "pqc": f"{p.operation1_ms:.3f} ms",
         "delta": f"{cmp.op1_delta_ms:+.3f} ms", "ratio": ratio_str(cmp.op1_slowdown),
         "flag": _flag(cmp.op1_slowdown, 10, 2)},
        {"metric": op2_lbl,   "classical": f"{c.operation2_ms:.3f} ms", "pqc": f"{p.operation2_ms:.3f} ms",
         "delta": f"{cmp.op2_delta_ms:+.3f} ms", "ratio": ratio_str(cmp.op2_slowdown),
         "flag": _flag(cmp.op2_slowdown, 10, 2)},
        {"metric": "Public Key","classical": fmt_bytes(c.public_key_bytes), "pqc": fmt_bytes(p.public_key_bytes),
         "delta": f"{cmp.pubkey_delta_bytes:+,} B", "ratio": ratio_str(cmp.pubkey_ratio),
         "flag": _flag(cmp.pubkey_ratio, 20, 5)},
        {"metric": art_lbl,   "classical": fmt_bytes(c.artifact_bytes),   "pqc": fmt_bytes(p.artifact_bytes),
         "delta": f"{cmp.artifact_delta_bytes:+,} B", "ratio": ratio_str(cmp.artifact_ratio),
         "flag": _flag(cmp.artifact_ratio, 20, 5)},
    ]
    if hybrid:
        benchmark_rows.append({
            "metric": "Hybrid wire overhead", "classical": "—",
            "pqc": fmt_bytes(hybrid.combined_artifact_bytes),
            "delta": f"+{hybrid.wire_overhead_bytes:,} B vs classical",
            "ratio": "—", "flag": "ok",
        })

    compat_issues = [
        {"severity": i.severity.value, "category": i.category,
         "title": i.title, "detail": i.detail, "mitigation": i.mitigation}
        for i in compat.issues
    ]

    config_diff = generate_config_diff(
        ALL_ALGORITHMS[classical_name], ALL_ALGORITHMS[pqc_name], framework="openssl"
    )

    return {
        "algorithm":     classical_name,
        "recommended_pqc": pqc_name,
        "location":      location,
        "standard":      _NIST_STANDARD.get(pqc_name, "NIST PQC"),
        "why_vulnerable": _WHY_VULNERABLE.get(classical_name, "Quantum-vulnerable classical algorithm."),
        "benchmark_rows": benchmark_rows,
        "compat_issues":  compat_issues,
        "config_diff":    config_diff,
        "verdict":        compat.verdict,
        "score":          score.score,
        "score_label":    score.label,
        "acknowledged":   ack_note is not None,
        "ack_note":       ack_note,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[Asset])
async def list_assets(
    team: Optional[str] = None,
    user: User = Depends(get_current_user),
):
    assets = store.list_assets(user.org_id)
    if team:
        assets = [a for a in assets if a.team == team]
    return assets


@router.post("", response_model=Asset, status_code=201)
async def create_asset(
    body: AssetCreate,
    user: User = Depends(get_current_user),
):
    asset = Asset(org_id=user.org_id, **body.model_dump())
    store.create_asset(asset)
    log_event(asset.org_id, user.id, "asset.create", "asset", asset.id,
              {"name": asset.name, "type": asset.asset_type})
    return asset


@router.get("/{asset_id}", response_model=Asset)
async def get_asset(asset_id: str, user: User = Depends(get_current_user)):
    asset = store.get_asset(asset_id)
    if not asset or asset.org_id != user.org_id:
        raise HTTPException(404, "Asset not found")
    return asset


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: str, user: User = Depends(get_current_user)):
    asset = store.get_asset(asset_id)
    if not asset or asset.org_id != user.org_id:
        raise HTTPException(404, "Asset not found")
    store.delete_asset(asset_id)
    log_event(asset.org_id, user.id, "asset.delete", "asset", asset_id)


@router.post("/{asset_id}/scan", response_model=ScanResult, status_code=202)
async def trigger_scan(
    asset_id: str,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
):
    asset = store.get_asset(asset_id)
    if not asset or asset.org_id != user.org_id:
        raise HTTPException(404, "Asset not found")

    pending = ScanResult(asset_id=asset_id, org_id=asset.org_id, status=ScanStatus.PENDING)
    store.save_scan(pending)
    log_event(asset.org_id, user.id, "asset.scan", "scan", pending.id, {"asset_name": asset.name})

    def _run():
        result = scan_asset(asset)
        result.scan.id = pending.id
        store.save_scan(result.scan)

    background_tasks.add_task(_run)
    return pending


@router.get("/{asset_id}/scans", response_model=list[ScanResult])
async def list_asset_scans(asset_id: str, user: User = Depends(get_current_user)):
    asset = store.get_asset(asset_id)
    if not asset or asset.org_id != user.org_id:
        raise HTTPException(404, "Asset not found")
    return store.list_scans(asset_id)


@router.get("/{asset_id}/detail")
async def get_asset_detail(asset_id: str, user: User = Depends(get_current_user)):
    """Full investigation payload: findings, benchmarks, compat reasons, config diffs."""
    asset = store.get_asset(asset_id)
    if not asset or asset.org_id != user.org_id:
        raise HTTPException(404, "Asset not found")

    scans = store.list_scans(asset_id)
    latest = scans[0] if scans else None

    constraints = SystemConstraints(
        mtu_bytes=asset.metadata.get("mtu_bytes", 1500),
        tls_version=asset.metadata.get("tls_version", "1.3"),
        ram_kb=asset.metadata.get("ram_kb"),
        protocol=asset.metadata.get("protocol", "tls"),
        tags=asset.tags,
    )

    findings = []
    asset_acks = _acks.get(asset_id, {})

    if latest and latest.algorithms_found:
        seen: set[str] = set()
        for f in latest.algorithms_found:
            if f.classical_algorithm in seen:
                continue
            seen.add(f.classical_algorithm)
            pqc = f.recommended_pqc[0] if f.recommended_pqc else None
            if not pqc:
                pqc_candidates = MIGRATION_MAP.get(f.classical_algorithm, [])
                pqc = pqc_candidates[0] if pqc_candidates else None
            if not pqc:
                continue
            detail = _build_finding_detail(
                f.classical_algorithm, pqc, f.location, constraints,
                asset_acks.get(f.classical_algorithm),
            )
            if detail:
                findings.append(detail)

    return {"asset": asset, "latest_scan": latest, "findings": findings}


class AcknowledgeRequest(BaseModel):
    scan_id: str
    algorithm: str
    note: str = ""


@router.post("/{asset_id}/acknowledge")
async def acknowledge_issue(
    asset_id: str,
    body: AcknowledgeRequest,
    user: User = Depends(get_current_user),
):
    asset = store.get_asset(asset_id)
    if not asset or asset.org_id != user.org_id:
        raise HTTPException(404, "Asset not found")

    if asset_id not in _acks:
        _acks[asset_id] = {}
    _acks[asset_id][body.algorithm] = body.note or "Acknowledged"
    log_event(asset.org_id, user.id, "finding.acknowledge", "asset", asset_id,
              {"algorithm": body.algorithm, "note": body.note})
    return {"ok": True}
