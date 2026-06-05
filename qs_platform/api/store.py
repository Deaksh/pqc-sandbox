"""
In-memory data store — replace with a real database (PostgreSQL + SQLAlchemy) in production.
This gives a working API immediately with no external dependencies.
"""
from __future__ import annotations

import datetime
import os
import uuid
from pathlib import Path
from typing import Optional

from qs_platform.api.models import (
    Org, User, Asset, ScanResult, ComplianceReport,
    OrgTier, UserRole, RegulatoryFramework, AssetType,
    MigrationVerdict, ScanStatus, AlgorithmFinding,
)

# ── In-memory stores ──────────────────────────────────────────────────────────

_orgs: dict[str, Org] = {}
_users: dict[str, User] = {}
_assets: dict[str, Asset] = {}
_scans: dict[str, ScanResult] = {}
_compliance_reports: dict[str, ComplianceReport] = {}

# ── Seed data ─────────────────────────────────────────────────────────────────

_DEMO_ORG = Org(
    id="org_demo",
    name="Demo Financial Services Pvt. Ltd.",
    slug="demo-fs",
    tier=OrgTier.ENTERPRISE,
    regulatory_frameworks=[RegulatoryFramework.RBI, RegulatoryFramework.SEBI],
)
_orgs["org_demo"] = _DEMO_ORG

_DEMO_ADMIN = User(
    id="user_admin",
    org_id="org_demo",
    email="admin@demo-fs.com",
    name="Priya Sharma",
    role=UserRole.ADMIN,
)
_users["user_admin"] = _DEMO_ADMIN

# Resolve the repo root so CBOM/SARIF paths work regardless of cwd
_REPO_ROOT = Path(__file__).parent.parent.parent
_CBOM_PATH  = str(_REPO_ROOT / "assets" / "sample.cbom.json")
_SARIF_PATH = str(_REPO_ROOT / "assets" / "sample.sarif.json")

_now = datetime.datetime.utcnow()

_DEMO_ASSETS: list[Asset] = [
    Asset(id="asset_001", org_id="org_demo", name="Internet Banking API",
          asset_type=AssetType.TLS_ENDPOINT, target="api.example.com",
          team="Payments", tags=["prod", "internet-facing"],
          last_scanned_at=_now - datetime.timedelta(hours=2)),
    Asset(id="asset_002", org_id="org_demo", name="Mobile Banking Gateway",
          asset_type=AssetType.TLS_ENDPOINT, target="mobile.example.com",
          team="Mobile", tags=["prod"],
          last_scanned_at=_now - datetime.timedelta(hours=3)),
    Asset(id="asset_003", org_id="org_demo", name="Identity & Auth Service",
          asset_type=AssetType.TLS_ENDPOINT, target="id.example.com",
          team="Identity", tags=["prod", "critical"],
          last_scanned_at=_now - datetime.timedelta(hours=1)),
    Asset(id="asset_004", org_id="org_demo", name="Payments Core — CBOM",
          asset_type=AssetType.CBOM_FILE, target=_CBOM_PATH,
          team="Payments", tags=["scan", "cbom"],
          last_scanned_at=_now - datetime.timedelta(days=1)),
    Asset(id="asset_005", org_id="org_demo", name="Security Scan Results — SARIF",
          asset_type=AssetType.SARIF_FILE, target=_SARIF_PATH,
          team="Security", tags=["scan", "sarif"],
          last_scanned_at=_now - datetime.timedelta(days=1)),
    Asset(id="asset_006", org_id="org_demo", name="UPI Switch TLS",
          asset_type=AssetType.TLS_ENDPOINT, target="upi.example.com",
          team="Payments", tags=["prod", "regulated"],
          last_scanned_at=_now - datetime.timedelta(hours=5)),
]
for a in _DEMO_ASSETS:
    _assets[a.id] = a

# Pre-computed scan results so the dashboard shows real data immediately
_DEMO_SCANS: list[ScanResult] = [
    ScanResult(id="scan_001", asset_id="asset_001", org_id="org_demo",
               status=ScanStatus.COMPLETE, verdict=MigrationVerdict.CAUTION,
               difficulty_score=42, difficulty_label="MODERATE",
               issues_blocked=0, issues_caution=2,
               algorithms_found=[
                   AlgorithmFinding(classical_algorithm="ECDH-P256", location="TLS key exchange", recommended_pqc=["ML-KEM-768"]),
                   AlgorithmFinding(classical_algorithm="ECDSA-P256", location="Certificate signature", recommended_pqc=["ML-DSA-44"]),
               ],
               started_at=_now - datetime.timedelta(hours=2),
               completed_at=_now - datetime.timedelta(hours=2, minutes=-30)),
    ScanResult(id="scan_002", asset_id="asset_002", org_id="org_demo",
               status=ScanStatus.COMPLETE, verdict=MigrationVerdict.GO,
               difficulty_score=28, difficulty_label="EASY",
               issues_blocked=0, issues_caution=1,
               algorithms_found=[
                   AlgorithmFinding(classical_algorithm="ECDH-P256", location="TLS key exchange", recommended_pqc=["ML-KEM-768"]),
               ],
               started_at=_now - datetime.timedelta(hours=3),
               completed_at=_now - datetime.timedelta(hours=3, minutes=-20)),
    ScanResult(id="scan_003", asset_id="asset_003", org_id="org_demo",
               status=ScanStatus.COMPLETE, verdict=MigrationVerdict.GO,
               difficulty_score=22, difficulty_label="EASY",
               issues_blocked=0, issues_caution=0,
               algorithms_found=[
                   AlgorithmFinding(classical_algorithm="Ed25519", location="TLS certificate", recommended_pqc=["ML-DSA-44"]),
               ],
               started_at=_now - datetime.timedelta(hours=1),
               completed_at=_now - datetime.timedelta(minutes=55)),
    ScanResult(id="scan_004", asset_id="asset_004", org_id="org_demo",
               status=ScanStatus.COMPLETE, verdict=MigrationVerdict.BLOCKED,
               difficulty_score=68, difficulty_label="HARD",
               issues_blocked=1, issues_caution=2,
               algorithms_found=[
                   AlgorithmFinding(classical_algorithm="ECDSA-P256", location="Server Certificate Signing", recommended_pqc=["ML-DSA-44"]),
                   AlgorithmFinding(classical_algorithm="RSA-2048 (PKCS#1 v1.5)", location="JWT Signing (API tokens)", recommended_pqc=["ML-DSA-44"]),
               ],
               started_at=_now - datetime.timedelta(days=1),
               completed_at=_now - datetime.timedelta(days=1, minutes=-45)),
    ScanResult(id="scan_005", asset_id="asset_005", org_id="org_demo",
               status=ScanStatus.COMPLETE, verdict=MigrationVerdict.CAUTION,
               difficulty_score=55, difficulty_label="HARD",
               issues_blocked=0, issues_caution=2,
               algorithms_found=[
                   AlgorithmFinding(classical_algorithm="RSA-2048 (PKCS#1 v1.5)", location="src/auth/jwt.py:42", recommended_pqc=["ML-DSA-44"]),
                   AlgorithmFinding(classical_algorithm="ECDSA-P256", location="config/tls_config.yaml:17", recommended_pqc=["ML-DSA-44"]),
               ],
               started_at=_now - datetime.timedelta(days=1),
               completed_at=_now - datetime.timedelta(days=1, minutes=-30)),
    ScanResult(id="scan_006", asset_id="asset_006", org_id="org_demo",
               status=ScanStatus.COMPLETE, verdict=MigrationVerdict.CAUTION,
               difficulty_score=48, difficulty_label="MODERATE",
               issues_blocked=0, issues_caution=1,
               algorithms_found=[
                   AlgorithmFinding(classical_algorithm="ECDH-P256", location="TLS key exchange", recommended_pqc=["ML-KEM-768"]),
               ],
               started_at=_now - datetime.timedelta(hours=5),
               completed_at=_now - datetime.timedelta(hours=5, minutes=-25)),
]
for s in _DEMO_SCANS:
    _scans[s.id] = s

# ── Org CRUD ──────────────────────────────────────────────────────────────────

def get_org(org_id: str) -> Optional[Org]:
    return _orgs.get(org_id)

def create_org(org: Org) -> Org:
    _orgs[org.id] = org
    return org

def list_orgs() -> list[Org]:
    return list(_orgs.values())

# ── User CRUD ─────────────────────────────────────────────────────────────────

def get_user(user_id: str) -> Optional[User]:
    return _users.get(user_id)

def get_user_by_email(email: str) -> Optional[User]:
    return next((u for u in _users.values() if u.email == email), None)

def create_user(user: User) -> User:
    _users[user.id] = user
    return user

def list_users(org_id: str) -> list[User]:
    return [u for u in _users.values() if u.org_id == org_id]

# ── Asset CRUD ────────────────────────────────────────────────────────────────

def get_asset(asset_id: str) -> Optional[Asset]:
    return _assets.get(asset_id)

def create_asset(asset: Asset) -> Asset:
    _assets[asset.id] = asset
    return asset

def list_assets(org_id: str) -> list[Asset]:
    return [a for a in _assets.values() if a.org_id == org_id]

def update_asset(asset: Asset) -> Asset:
    _assets[asset.id] = asset
    return asset

def delete_asset(asset_id: str) -> bool:
    return _assets.pop(asset_id, None) is not None

# ── Scan CRUD ─────────────────────────────────────────────────────────────────

def save_scan(scan: ScanResult) -> ScanResult:
    _scans[scan.id] = scan
    return scan

def get_scan(scan_id: str) -> Optional[ScanResult]:
    return _scans.get(scan_id)

def list_scans(asset_id: str, limit: int = 20) -> list[ScanResult]:
    scans = [s for s in _scans.values() if s.asset_id == asset_id]
    return sorted(scans, key=lambda s: s.started_at, reverse=True)[:limit]

def list_org_scans(org_id: str, limit: int = 50) -> list[ScanResult]:
    scans = [s for s in _scans.values() if s.org_id == org_id]
    return sorted(scans, key=lambda s: s.started_at, reverse=True)[:limit]

# ── Compliance report CRUD ────────────────────────────────────────────────────

def save_compliance_report(report: ComplianceReport) -> ComplianceReport:
    _compliance_reports[report.id] = report
    return report

def get_compliance_report(report_id: str) -> Optional[ComplianceReport]:
    return _compliance_reports.get(report_id)

def list_compliance_reports(org_id: str) -> list[ComplianceReport]:
    reports = [r for r in _compliance_reports.values() if r.org_id == org_id]
    return sorted(reports, key=lambda r: r.generated_at, reverse=True)
