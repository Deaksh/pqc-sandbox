"""
Vendor risk management routes.
"""
from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from qs_platform.api.deps import get_current_user
from qs_platform.api.models import User
from qs_platform.vendor.tracker import VendorRiskTracker, Vendor

router = APIRouter(prefix="/vendors", tags=["vendors"])

# In-memory tracker per org (replace with DB-backed in production)
_trackers: dict[str, VendorRiskTracker] = {}

def _get_tracker(org_id: str) -> VendorRiskTracker:
    if org_id not in _trackers:
        t = VendorRiskTracker(org_id)
        # Seed with realistic demo vendors for the demo org
        if org_id == "org_demo":
            _seed_demo(t)
        _trackers[org_id] = t
    return _trackers[org_id]

def _seed_demo(tracker: VendorRiskTracker) -> None:
    demo_vendors = [
        Vendor(id="v1", name="Razorpay",      endpoint="razorpay.com",   category="payment",  criticality="critical", org_id="org_demo", team="Payments"),
        Vendor(id="v2", name="AWS ACM",        endpoint="aws.amazon.com", category="cloud",    criticality="critical", org_id="org_demo", team="Platform"),
        Vendor(id="v3", name="DigiCert CA",    endpoint="digicert.com",   category="ca",       criticality="critical", org_id="org_demo", team="Security"),
        Vendor(id="v4", name="Thales Luna HSM",endpoint="thales.com",     category="hsm",      criticality="critical", org_id="org_demo", team="Security"),
        Vendor(id="v5", name="Cloudflare CDN", endpoint="cloudflare.com", category="saas",     criticality="high",     org_id="org_demo", team="Platform"),
        Vendor(id="v6", name="NPCI / UPI",     endpoint="npci.org.in",    category="payment",  criticality="critical", org_id="org_demo", team="Payments"),
        Vendor(id="v7", name="Let's Encrypt",  endpoint="letsencrypt.org",category="ca",       criticality="high",     org_id="org_demo", team="Security"),
    ]
    for v in demo_vendors:
        tracker.add_vendor(v)


class AddVendorRequest(BaseModel):
    name: str
    endpoint: str
    category: str = "saas"
    criticality: str = "high"
    team: Optional[str] = None
    notes: str = ""


@router.get("")
async def list_vendors(user: User = Depends(get_current_user)):
    tracker = _get_tracker(user.org_id)
    return [
        {"id": v.id, "name": v.name, "endpoint": v.endpoint,
         "category": v.category, "criticality": v.criticality,
         "team": v.team, "notes": v.notes}
        for v in tracker._vendors.values()
    ]


@router.post("", status_code=201)
async def add_vendor(body: AddVendorRequest, user: User = Depends(get_current_user)):
    tracker = _get_tracker(user.org_id)
    vendor = Vendor(
        id=str(uuid.uuid4()),
        org_id=user.org_id,
        **body.model_dump(),
    )
    tracker.add_vendor(vendor)
    return {"id": vendor.id, "name": vendor.name}


@router.get("/assess")
async def assess_all_vendors(user: User = Depends(get_current_user)):
    """Probe all vendor TLS endpoints and return risk assessment."""
    tracker = _get_tracker(user.org_id)
    # Use stored risks if already assessed (avoid re-probing on every request)
    if tracker._risks:
        risks = list(tracker._risks.values())
    else:
        # Use roadmap-only assessment (no live probe) for speed in demo
        for vendor_id in tracker._vendors:
            try:
                tracker.assess_vendor(vendor_id)
            except Exception:
                pass
        risks = list(tracker._risks.values())

    return {
        "summary": tracker.summary(),
        "vendors": [
            {
                "id":                   r.vendor.id,
                "name":                 r.vendor.name,
                "endpoint":             r.vendor.endpoint,
                "category":             r.vendor.category,
                "criticality":          r.vendor.criticality,
                "team":                 r.vendor.team,
                "status":               r.status_label,
                "risk_level":           r.risk_level,
                "is_blocking":          r.is_blocking,
                "pqc_support":          r.pqc_support_level,
                "pqc_tls_ready":        r.pqc_tls_ready,
                "expected_full":        r.expected_full_support,
                "roadmap_notes":        r.roadmap_notes,
                "recommendation":       r.recommendation,
                "current_tls_version":  r.current_tls_version,
                "handshake_ms":         r.handshake_ms,
                "probe_error":          r.probe_error,
                "reference":            r.roadmap_reference,
            }
            for r in risks
        ],
    }


@router.get("/summary")
async def vendor_summary(user: User = Depends(get_current_user)):
    tracker = _get_tracker(user.org_id)
    if not tracker._risks:
        # Return counts from vendor list without live assessment
        vendors = list(tracker._vendors.values())
        return {
            "total_vendors": len(vendors),
            "assessed": 0,
            "blocking": 0,
            "ready": 0,
            "partial": 0,
            "planned": 0,
            "unknown": len(vendors),
        }
    return tracker.summary()
