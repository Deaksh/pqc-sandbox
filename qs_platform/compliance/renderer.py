"""
Generic compliance report renderer — dispatch to the correct framework template.
"""
from __future__ import annotations

from qs_platform.api.models import ComplianceReport, RegulatoryFramework, OrgReadinessSnapshot
from qs_platform.compliance.rbi import generate_rbi_report, RBIReportConfig


def render_compliance_html(
    framework: RegulatoryFramework,
    snapshot: OrgReadinessSnapshot,
    config: dict,
) -> str:
    if framework == RegulatoryFramework.RBI:
        rbi_cfg = RBIReportConfig(**{k: v for k, v in config.items() if k in RBIReportConfig.__dataclass_fields__})
        return generate_rbi_report(snapshot, rbi_cfg)
    elif framework == RegulatoryFramework.SEBI:
        return _stub_report("SEBI CSCRF 2024", snapshot, config)
    elif framework == RegulatoryFramework.CERT_IN:
        return _stub_report("CERT-In Directions 2022", snapshot, config)
    elif framework == RegulatoryFramework.DPDP:
        return _stub_report("Digital Personal Data Protection Act 2023", snapshot, config)
    else:
        return _stub_report(framework.value, snapshot, config)


def _stub_report(framework_name: str, snapshot: OrgReadinessSnapshot, config: dict) -> str:
    org = config.get("org_name", "Organisation")
    return f"""<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px">
<h1>{framework_name} — PQC Compliance Report</h1>
<p>Organisation: <strong>{org}</strong></p>
<p>Readiness: <strong>{snapshot.readiness_pct:.0f}%</strong> ({snapshot.go_count} GO / {snapshot.caution_count} CAUTION / {snapshot.blocked_count} BLOCKED)</p>
<p><em>Full {framework_name} template coming soon. Use the RBI template as a reference implementation.</em></p>
</body></html>"""
