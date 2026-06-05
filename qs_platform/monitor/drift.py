"""
Drift detection: compare successive scan results to flag regressions.
A new vulnerable algorithm introduced in a code commit → alert.
A verdict that regressed from GO → CAUTION or BLOCKED → alert.
"""
from __future__ import annotations

import datetime
from typing import Optional

from qs_platform.api.models import ScanResult, DriftAlert, MigrationVerdict


_VERDICT_ORDER = {MigrationVerdict.GO: 0, MigrationVerdict.CAUTION: 1, MigrationVerdict.BLOCKED: 2}


class DriftDetector:
    def __init__(self, org_id: str):
        self.org_id = org_id
        self._alerts: list[DriftAlert] = []

    def compare(
        self,
        prev: ScanResult,
        curr: ScanResult,
        asset_name: str,
    ) -> list[DriftAlert]:
        alerts: list[DriftAlert] = []

        # Verdict regression
        prev_order = _VERDICT_ORDER.get(prev.verdict or MigrationVerdict.GO, 0)
        curr_order = _VERDICT_ORDER.get(curr.verdict or MigrationVerdict.GO, 0)
        if curr_order > prev_order:
            alerts.append(DriftAlert(
                org_id=self.org_id,
                asset_id=curr.asset_id,
                asset_name=asset_name,
                alert_type="verdict_regression",
                detail=(
                    f"Verdict regressed from {prev.verdict} to {curr.verdict}. "
                    f"New blocked issues: {curr.issues_blocked - prev.issues_blocked}, "
                    f"new caution issues: {curr.issues_caution - prev.issues_caution}."
                ),
                severity="HIGH" if curr.verdict == MigrationVerdict.BLOCKED else "MEDIUM",
            ))

        # New vulnerable algorithms discovered
        prev_algos = {f.classical_algorithm for f in (prev.algorithms_found or [])}
        curr_algos = {f.classical_algorithm for f in (curr.algorithms_found or [])}
        new_algos = curr_algos - prev_algos
        for algo in new_algos:
            alerts.append(DriftAlert(
                org_id=self.org_id,
                asset_id=curr.asset_id,
                asset_name=asset_name,
                alert_type="new_vulnerable_algo",
                detail=f"New quantum-vulnerable algorithm detected: {algo}. This was not present in the previous scan.",
                severity="HIGH",
            ))

        self._alerts.extend(alerts)
        return alerts

    def get_alerts(
        self,
        since: Optional[datetime.datetime] = None,
        unacknowledged_only: bool = False,
    ) -> list[DriftAlert]:
        result = self._alerts
        if since:
            result = [a for a in result if a.detected_at >= since]
        if unacknowledged_only:
            result = [a for a in result if not a.acknowledged]
        return sorted(result, key=lambda a: a.detected_at, reverse=True)

    def acknowledge(self, alert_id: str, user_id: str) -> bool:
        for alert in self._alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                alert.acknowledged_by = user_id
                return True
        return False
