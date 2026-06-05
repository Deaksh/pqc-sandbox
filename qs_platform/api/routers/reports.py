"""
Compliance report generation routes.
"""
from __future__ import annotations

import datetime

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from qs_platform.api.deps import get_current_user
from qs_platform.api.models import (
    ComplianceReport, OrgReadinessSnapshot, RegulatoryFramework,
    TeamReadiness, MigrationVerdict, User,
)
from qs_platform.api import store
from qs_platform.compliance.renderer import render_compliance_html
from qs_platform.enterprise.audit import log_event

router = APIRouter(prefix="/reports", tags=["reports"])


class GenerateReportRequest(BaseModel):
    framework: RegulatoryFramework
    period_days: int = 30
    config: dict = {}


def _build_snapshot(org_id: str) -> OrgReadinessSnapshot:
    """Aggregate latest scan results into an org-level snapshot."""
    assets = store.list_assets(org_id)
    scans = store.list_org_scans(org_id)

    latest: dict[str, store.ScanResult] = {}
    for scan in scans:
        if scan.asset_id not in latest:
            latest[scan.asset_id] = scan

    go = caution = blocked = 0
    scores: list[float] = []
    teams: dict[str, dict] = {}

    for asset in assets:
        scan = latest.get(asset.id)
        if not scan:
            continue
        team = asset.team or "unassigned"
        if team not in teams:
            teams[team] = {"total": 0, "go": 0, "caution": 0, "blocked": 0, "scores": []}
        teams[team]["total"] += 1
        if scan.verdict == MigrationVerdict.GO:
            go += 1
            teams[team]["go"] += 1
        elif scan.verdict == MigrationVerdict.CAUTION:
            caution += 1
            teams[team]["caution"] += 1
        elif scan.verdict == MigrationVerdict.BLOCKED:
            blocked += 1
            teams[team]["blocked"] += 1
        if scan.difficulty_score is not None:
            scores.append(float(scan.difficulty_score))
            teams[team]["scores"].append(float(scan.difficulty_score))

    total = len(assets)
    scanned = len(latest)
    avg_score = sum(scores) / len(scores) if scores else 0.0
    readiness_pct = (go / total * 100) if total > 0 else 0.0

    return OrgReadinessSnapshot(
        org_id=org_id,
        total_assets=total,
        scanned_assets=scanned,
        go_count=go,
        caution_count=caution,
        blocked_count=blocked,
        avg_difficulty_score=avg_score,
        readiness_pct=readiness_pct,
        teams={
            name: TeamReadiness(
                team=name,
                total=d["total"],
                go=d["go"],
                caution=d["caution"],
                blocked=d["blocked"],
                avg_score=sum(d["scores"]) / len(d["scores"]) if d["scores"] else 0.0,
            )
            for name, d in teams.items()
        },
    )


@router.get("/dashboard/snapshot", response_model=OrgReadinessSnapshot)
async def get_dashboard_snapshot(user: User = Depends(get_current_user)):
    return _build_snapshot(user.org_id)


@router.get("/frameworks")
async def list_frameworks():
    """Return the full global regulatory framework catalogue."""
    from qs_platform.compliance.frameworks import FRAMEWORKS
    return [
        {
            "id": f.id, "name": f.name, "short": f.short,
            "jurisdiction": f.jurisdiction, "flag": f.jurisdiction_flag,
            "status": f.status, "deadline": f.deadline,
            "mandate_type": f.mandate_type, "body": f.body,
            "key_requirements": f.key_requirements,
            "reference": f.reference, "description": f.description,
        }
        for f in FRAMEWORKS
    ]


@router.post("", response_model=ComplianceReport, status_code=201)
async def generate_report(
    body: GenerateReportRequest,
    user: User = Depends(get_current_user),
):
    org = store.get_org(user.org_id)
    if not org:
        raise HTTPException(404, "Org not found")

    snapshot = _build_snapshot(org.id)
    now = datetime.datetime.utcnow()

    cfg = {"org_name": org.name}
    cfg.update(body.config)

    html = render_compliance_html(body.framework, snapshot, cfg)

    report = ComplianceReport(
        org_id=org.id,
        framework=body.framework,
        generated_by=user.id,
        period_start=now - datetime.timedelta(days=body.period_days),
        period_end=now,
        snapshot=snapshot,
        html_content=html,
    )
    store.save_compliance_report(report)
    log_event(org.id, user.id, "report.generate", "report", report.id,
              {"framework": body.framework.value})

    return report


@router.get("", response_model=list[ComplianceReport])
async def list_reports(user: User = Depends(get_current_user)):
    reports = store.list_compliance_reports(user.org_id)
    return [r.model_copy(update={"html_content": ""}) for r in reports]


@router.get("/{report_id}/html")
async def get_report_html(
    report_id: str,
    user: User = Depends(get_current_user),
):
    report = store.get_compliance_report(report_id)
    if not report or report.org_id != user.org_id:
        raise HTTPException(404, "Report not found")
    return Response(content=report.html_content, media_type="text/html")
