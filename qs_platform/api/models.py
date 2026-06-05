"""
Pydantic models shared across the platform API.
These are the authoritative data shapes for the B2B platform.
"""
from __future__ import annotations

import datetime
import uuid
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────

class OrgTier(str, Enum):
    FREE = "free"          # OSS users, no auth
    PRO = "pro"            # Single org, unlimited assets
    ENTERPRISE = "enterprise"  # Multi-tenant, SSO, audit

class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class AssetType(str, Enum):
    TLS_ENDPOINT = "tls_endpoint"
    CODE_REPO = "code_repo"
    CBOM_FILE = "cbom_file"
    SARIF_FILE = "sarif_file"
    CONFIG_FILE = "config_file"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"

class MigrationVerdict(str, Enum):
    GO = "GO"
    CAUTION = "CAUTION"
    BLOCKED = "BLOCKED"

class RegulatoryFramework(str, Enum):
    RBI = "RBI"
    SEBI = "SEBI"
    CERT_IN = "CERT-In"
    DPDP = "DPDP"
    ISO27001 = "ISO27001"
    SOC2 = "SOC2"


# ── Org & Users ───────────────────────────────────────────────────────────────

class Org(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    slug: str
    tier: OrgTier = OrgTier.PRO
    regulatory_frameworks: list[RegulatoryFramework] = []
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    settings: dict[str, Any] = {}


class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    email: str
    name: str
    role: UserRole = UserRole.ANALYST
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    last_login: Optional[datetime.datetime] = None
    sso_subject: Optional[str] = None   # SAML/OIDC subject claim


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    user_id: str
    action: str             # e.g. "asset.scan", "report.generate", "user.invite"
    resource_type: str
    resource_id: str
    detail: dict[str, Any] = {}
    ip_address: Optional[str] = None
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)


# ── Assets ────────────────────────────────────────────────────────────────────

class Asset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    team: Optional[str] = None          # e.g. "payments", "identity"
    name: str
    asset_type: AssetType
    target: str                         # URL, path, or identifier
    tags: list[str] = []
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    last_scanned_at: Optional[datetime.datetime] = None
    scan_schedule: Optional[str] = None  # cron expression, e.g. "0 2 * * 1"
    metadata: dict[str, Any] = {}


class AssetCreate(BaseModel):
    name: str
    asset_type: AssetType
    target: str
    team: Optional[str] = None
    tags: list[str] = []
    scan_schedule: Optional[str] = None
    metadata: dict[str, Any] = {}


# ── Scan Results ──────────────────────────────────────────────────────────────

class AlgorithmFinding(BaseModel):
    classical_algorithm: str
    location: Optional[str] = None       # file:line or endpoint
    recommended_pqc: list[str] = []
    severity: str = "INFO"


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str
    org_id: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    completed_at: Optional[datetime.datetime] = None
    # Summary
    verdict: Optional[MigrationVerdict] = None
    difficulty_score: Optional[int] = None
    difficulty_label: Optional[str] = None
    # Findings
    algorithms_found: list[AlgorithmFinding] = []
    issues_blocked: int = 0
    issues_caution: int = 0
    # Full payload (stored as JSON blob)
    full_report: Optional[dict[str, Any]] = None
    error: Optional[str] = None


# ── Readiness & Dashboard ─────────────────────────────────────────────────────

class SystemReadiness(BaseModel):
    asset_id: str
    asset_name: str
    team: Optional[str]
    verdict: MigrationVerdict
    score: int
    score_label: str
    last_scanned: Optional[datetime.datetime]
    blocked_count: int
    caution_count: int


class OrgReadinessSnapshot(BaseModel):
    org_id: str
    snapshot_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    total_assets: int
    scanned_assets: int
    go_count: int
    caution_count: int
    blocked_count: int
    avg_difficulty_score: float
    readiness_pct: float           # % of assets at GO
    # Per-team breakdown
    teams: dict[str, "TeamReadiness"] = {}


class TeamReadiness(BaseModel):
    team: str
    total: int
    go: int
    caution: int
    blocked: int
    avg_score: float


# ── Compliance Reports ─────────────────────────────────────────────────────────

class ComplianceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    framework: RegulatoryFramework
    generated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    generated_by: str               # user id
    period_start: datetime.datetime
    period_end: datetime.datetime
    snapshot: OrgReadinessSnapshot
    html_content: str = ""
    # Attestation
    attested_by: Optional[str] = None
    attested_at: Optional[datetime.datetime] = None


# ── Monitoring ────────────────────────────────────────────────────────────────

class DriftAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    asset_id: str
    asset_name: str
    detected_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    alert_type: str           # "new_vulnerable_algo", "verdict_regression", "cert_expiry"
    detail: str
    severity: str = "HIGH"
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None


# ── API Responses ─────────────────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    page_size: int
    has_next: bool


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None
