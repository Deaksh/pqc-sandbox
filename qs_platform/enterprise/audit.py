"""
Audit logging — append-only event log for enterprise compliance.
In production: ship to a SIEM or append-only database table.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Optional

from qs_platform.api.models import AuditEvent

_AUDIT_LOG: list[AuditEvent] = []   # in-memory for stub; replace with DB


def log_event(
    org_id: str,
    user_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    detail: Optional[dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> AuditEvent:
    event = AuditEvent(
        org_id=org_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail or {},
        ip_address=ip_address,
    )
    _AUDIT_LOG.append(event)
    return event


def get_events(
    org_id: str,
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    since: Optional[datetime.datetime] = None,
    limit: int = 100,
) -> list[AuditEvent]:
    events = [e for e in _AUDIT_LOG if e.org_id == org_id]
    if user_id:
        events = [e for e in events if e.user_id == user_id]
    if action:
        events = [e for e in events if e.action == action]
    if since:
        events = [e for e in events if e.timestamp >= since]
    return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]


def export_audit_log(org_id: str, output_path: Path) -> None:
    events = get_events(org_id, limit=10_000)
    lines = [json.dumps(e.model_dump(), default=str) for e in events]
    output_path.write_text("\n".join(lines), encoding="utf-8")
