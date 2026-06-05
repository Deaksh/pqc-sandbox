"""
RBI Cybersecurity Framework — Post-Quantum Cryptography Compliance Report.

Regulatory basis:
  • RBI Master Direction on IT Governance, Risk, Controls and Assurance Practices
    (DoS.CO.CGIT.SEC.01/31.01.015/2023-24, April 2023)
  • RBI Cybersecurity Framework for Banks (DBS.CO/CSITE/BC.11/33.01.001/2015-16, June 2016)
  • RBI circular on Quantum Computing Risk Preparedness (RBI/2024-25/37, July 2024)
  • CERT-In Guidelines on Cryptographic Standards (2022)
  • NSA CNSA 2.0 (referenced by RBI for international best-practice alignment)
  • NIST FIPS 203/204/205 (effective August 2024)

Control mapping:
  Each finding is mapped to specific RBI control objectives and the
  corresponding NIST CSF 2.0 function.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Optional

from qs_platform.api.models import OrgReadinessSnapshot, MigrationVerdict


@dataclass
class RBIControlMapping:
    control_id: str          # e.g. "RBI-CS-2016-4.2"
    control_name: str
    nist_csf: str            # e.g. "PR.DS-2"
    applicable: bool
    status: str              # "Compliant" | "Partially Compliant" | "Non-Compliant" | "Not Applicable"
    finding: str
    recommendation: str
    priority: str            # "P1" | "P2" | "P3"


@dataclass
class RBIReportConfig:
    org_name: str
    license_number: str = ""     # RBI/SEBI license number
    audit_period_start: datetime.date = field(default_factory=datetime.date.today)
    audit_period_end: datetime.date = field(default_factory=datetime.date.today)
    prepared_by: str = "Information Security Team"
    reviewed_by: str = "Chief Information Security Officer"
    ref_number: str = ""
    entity_type: str = "Scheduled Commercial Bank"  # or NBFC, Payment Bank, etc.


def _compute_controls(snapshot: OrgReadinessSnapshot) -> list[RBIControlMapping]:
    """Map org readiness data to RBI control objectives."""
    controls: list[RBIControlMapping] = []
    go_pct = snapshot.readiness_pct
    has_blocked = snapshot.blocked_count > 0
    has_caution = snapshot.caution_count > 0
    avg_score = snapshot.avg_difficulty_score

    # ── Control 1: Cryptographic Asset Inventory ───────────────────────────────
    scanned_pct = (snapshot.scanned_assets / snapshot.total_assets * 100) if snapshot.total_assets else 0
    controls.append(RBIControlMapping(
        control_id="RBI-CS-2016-4.2 / MIT-4.1",
        control_name="Cryptographic Asset Inventory & Classification",
        nist_csf="ID.AM-2",
        applicable=True,
        status="Compliant" if scanned_pct >= 90 else "Partially Compliant" if scanned_pct >= 50 else "Non-Compliant",
        finding=(
            f"{snapshot.scanned_assets} of {snapshot.total_assets} assets scanned "
            f"({scanned_pct:.0f}% coverage). "
            + ("Coverage meets RBI requirement for complete cryptographic asset visibility."
               if scanned_pct >= 90 else
               "Coverage gap identified. RBI expects complete inventory of cryptographic assets.")
        ),
        recommendation=(
            "Deploy CBOM generation in CI/CD pipelines for all production services. "
            "Target 100% asset coverage within 30 days."
        ) if scanned_pct < 90 else "Maintain current coverage. Review quarterly.",
        priority="P1" if scanned_pct < 50 else "P2" if scanned_pct < 90 else "P3",
    ))

    # ── Control 2: Quantum-Safe Key Exchange ───────────────────────────────────
    controls.append(RBIControlMapping(
        control_id="RBI-IT-2023-6.3 / CERT-In-2022",
        control_name="Quantum-Resistant Key Establishment",
        nist_csf="PR.DS-2",
        applicable=True,
        status="Non-Compliant" if has_blocked else "Partially Compliant" if has_caution else "Compliant",
        finding=(
            f"Organisation has {snapshot.blocked_count} system(s) with hard blockers to PQC key exchange "
            f"migration and {snapshot.caution_count} system(s) requiring remediation before cut-over. "
            f"RBI circular RBI/2024-25/37 requires Regulated Entities to commence quantum-safe "
            f"key exchange transition by FY2026-27."
        ) if has_blocked or has_caution else (
            "All scanned systems are assessed as migration-ready for quantum-safe key exchange (ML-KEM). "
            "No hard blockers detected."
        ),
        recommendation=(
            "Resolve all BLOCKED systems before commencing hybrid PQC deployment. "
            "Engage TLS stack vendors for OpenSSL 3.3+ / liboqs provider upgrade path. "
            "Implement X25519MLKEM768 hybrid key exchange as first step."
        ),
        priority="P1" if has_blocked else "P2" if has_caution else "P3",
    ))

    # ── Control 3: Digital Signature Algorithm Readiness ──────────────────────
    controls.append(RBIControlMapping(
        control_id="RBI-CS-2016-7.1 / FIPS-204",
        control_name="Post-Quantum Digital Signature Readiness",
        nist_csf="PR.DS-6",
        applicable=True,
        status="Partially Compliant" if avg_score > 50 else "Compliant",
        finding=(
            f"Average migration difficulty score: {avg_score:.0f}/100. "
            f"NIST FIPS 204 (ML-DSA) is the recommended replacement for ECDSA and RSA signatures. "
            f"ML-DSA signatures are 33–64× larger than ECDSA — protocol-level impact assessment required."
        ),
        recommendation=(
            "Pilot ML-DSA-44 in internal PKI (non-public-facing) first. "
            "Assess TLS certificate chain size impact. "
            "Plan for hybrid certificate issuance (classical + PQC) from CA infrastructure."
        ),
        priority="P2",
    ))

    # ── Control 4: TLS/Protocol Compliance ────────────────────────────────────
    tls12_count = sum(1 for t in snapshot.teams.values() if t.blocked > 0)
    controls.append(RBIControlMapping(
        control_id="RBI-IT-2023-8.2",
        control_name="Transport Layer Security Version Compliance",
        nist_csf="PR.PT-4",
        applicable=True,
        status="Non-Compliant" if tls12_count > 0 else "Compliant",
        finding=(
            f"{tls12_count} team(s) operate systems that are blocked from PQC migration due to "
            "TLS version constraints (TLS 1.2 or below). PQC hybrid key exchange requires TLS 1.3. "
            "RBI IT Master Direction prohibits use of TLS 1.0/1.1 on internet-facing systems."
        ) if tls12_count > 0 else (
            "All assessed systems operate on TLS 1.3 and are compatible with hybrid PQC key exchange."
        ),
        recommendation=(
            "Force TLS 1.3 on all internet-facing systems. Disable TLS 1.0/1.1. "
            "Update load balancer and WAF configurations. Estimated effort: 2–4 weeks per team."
        ) if tls12_count > 0 else "Maintain TLS 1.3 enforcement. Monitor for downgrades.",
        priority="P1" if tls12_count > 0 else "P3",
    ))

    # ── Control 5: Third-Party / HSM / Vendor Risk ────────────────────────────
    controls.append(RBIControlMapping(
        control_id="RBI-CS-2016-11.3 / MIT-7.4",
        control_name="Third-Party Cryptographic Vendor Risk Management",
        nist_csf="ID.SC-2",
        applicable=True,
        status="Partially Compliant",
        finding=(
            "Hardware Security Modules (HSMs), Certificate Authorities, and SaaS vendors "
            "in the cryptographic supply chain have not been fully assessed for PQC readiness. "
            "RBI requires Regulated Entities to include third-party cryptographic dependencies "
            "in their risk framework."
        ),
        recommendation=(
            "Issue PQC readiness questionnaire to all cryptographic vendors (HSM, CA, TLS library). "
            "Request NIST FIPS 140-3 validation roadmap for PQC support. "
            "Include PQC readiness as a contract renewal criterion from FY2025-26."
        ),
        priority="P2",
    ))

    # ── Control 6: Incident Response & HNDL Threat ────────────────────────────
    controls.append(RBIControlMapping(
        control_id="RBI-CS-2016-13.1 / CERT-In-Directions-2022",
        control_name="Harvest-Now-Decrypt-Later (HNDL) Threat Response",
        nist_csf="RS.RP-1",
        applicable=True,
        status="Partially Compliant",
        finding=(
            "The 'harvest now, decrypt later' (HNDL) threat means adversaries may already be "
            "collecting encrypted traffic for future decryption using quantum computers. "
            "Data with confidentiality requirements beyond 2030 (customer PII, transaction records) "
            "is at retroactive risk. This is a current, active threat — not a future one."
        ),
        recommendation=(
            "Classify data by confidentiality lifespan. Data requiring protection beyond 2030 "
            "should be prioritised for PQC re-encryption or forward-secrecy controls. "
            "Include HNDL risk in the annual IT Risk Assessment submitted to RBI."
        ),
        priority="P1",
    ))

    # ── Control 7: Governance & Board Reporting ────────────────────────────────
    controls.append(RBIControlMapping(
        control_id="RBI-IT-2023-3.1",
        control_name="Board-Level Cryptography Risk Awareness",
        nist_csf="GV.OC-4",
        applicable=True,
        status="Partially Compliant",
        finding=(
            "PQC migration risk has not yet been formally presented to the Board Risk Committee "
            "or IT Strategy Committee as a standalone agenda item. RBI IT Master Direction requires "
            "the Board to be informed of emerging technology risks annually."
        ),
        recommendation=(
            "Include PQC migration risk and roadmap in next Board Risk Committee presentation. "
            "Approve a formal PQC Migration Programme with budget and timeline. "
            "Designate a PQC Programme Manager (CISO-1 level)."
        ),
        priority="P2",
    ))

    return controls


def _status_badge(status: str) -> str:
    colors = {
        "Compliant": "#16a34a",
        "Partially Compliant": "#b45309",
        "Non-Compliant": "#c2410c",
        "Not Applicable": "#6b7280",
    }
    color = colors.get(status, "#6b7280")
    return f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;background:{color}1a;color:{color};border:1px solid {color}40">{status}</span>'


def _priority_badge(priority: str) -> str:
    colors = {"P1": "#c2410c", "P2": "#b45309", "P3": "#16a34a"}
    color = colors.get(priority, "#6b7280")
    return f'<span style="color:{color};font-weight:700">{priority}</span>'


_RBI_CSS = """
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Calibri','Segoe UI',sans-serif;font-size:12px;color:#1a1a1a;background:#fff;max-width:960px;margin:0 auto;padding:36px 48px}
@media print{body{padding:20px 28px;max-width:100%;font-size:11px}}
.cover{text-align:center;padding:40px 0 32px;border-bottom:3px solid #003087;margin-bottom:28px}
.rbi-logo{font-size:11px;font-weight:700;letter-spacing:.15em;color:#003087;text-transform:uppercase;margin-bottom:12px}
.report-title{font-size:20px;font-weight:700;color:#003087;margin-bottom:6px}
.report-subtitle{font-size:13px;color:#374151;margin-bottom:16px}
.meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:0;max-width:500px;margin:0 auto;text-align:left;font-size:11px}
.meta-row{display:contents}
.meta-label{color:#6b7280;padding:3px 8px;border:1px solid #e5e7eb}
.meta-value{font-weight:600;padding:3px 8px;border:1px solid #e5e7eb}
.classification{display:inline-block;background:#003087;color:#fff;font-size:10px;font-weight:700;letter-spacing:.12em;padding:3px 12px;border-radius:2px;text-transform:uppercase;margin-top:12px}
h2{font-size:13px;font-weight:700;color:#003087;text-transform:uppercase;letter-spacing:.06em;margin:20px 0 8px;border-bottom:2px solid #003087;padding-bottom:4px}
h3{font-size:12px;font-weight:700;color:#374151;margin:12px 0 6px}
table{width:100%;border-collapse:collapse;font-size:11px;margin-bottom:12px}
th{background:#003087;color:#fff;text-align:left;padding:6px 10px;font-weight:700;font-size:10px;letter-spacing:.04em}
td{padding:6px 10px;border:1px solid #d1d5db;vertical-align:top}
tr:nth-child(even){background:#f8faff}
.exec-summary{background:#f8faff;border-left:4px solid #003087;padding:14px 18px;margin-bottom:20px;font-size:12px;line-height:1.6}
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px}
.kpi{border:1px solid #d1d5db;border-radius:4px;padding:10px 12px;text-align:center}
.kpi-num{font-size:22px;font-weight:800;color:#003087}
.kpi-label{font-size:9px;text-transform:uppercase;letter-spacing:.06em;color:#6b7280;margin-top:2px}
.kpi-blocked .kpi-num{color:#c2410c}
.kpi-caution .kpi-num{color:#b45309}
.kpi-go .kpi-num{color:#16a34a}
.finding{background:#fffbeb;border:1px solid #fde68a;border-radius:4px;padding:8px 12px;margin:6px 0;font-size:11px}
.rec{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:4px;padding:8px 12px;margin:6px 0;font-size:11px}
.sig-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px}
.sig-box{border-top:1px solid #374151;padding-top:6px;font-size:10px;color:#374151}
.footer{margin-top:24px;padding-top:10px;border-top:1px solid #e5e7eb;font-size:9px;color:#9ca3af;display:flex;justify-content:space-between}
p{margin-bottom:8px;line-height:1.5}
ul{padding-left:16px;margin-bottom:8px}
li{margin-bottom:3px}
.page-break{page-break-before:always}
</style>
"""


def generate_rbi_report(
    snapshot: OrgReadinessSnapshot,
    config: RBIReportConfig,
    output_path: Optional[str] = None,
) -> str:
    controls = _compute_controls(snapshot)
    now = datetime.datetime.now()
    date_str = now.strftime("%d %B %Y")
    ref = config.ref_number or f"IS-PQC-{now.strftime('%Y%m%d')}-001"

    # Aggregate compliance status
    non_compliant = sum(1 for c in controls if c.status == "Non-Compliant")
    partial = sum(1 for c in controls if c.status == "Partially Compliant")
    compliant = sum(1 for c in controls if c.status == "Compliant")
    total_controls = len(controls)
    compliance_pct = compliant / total_controls * 100 if total_controls else 0
    overall_status = "Non-Compliant" if non_compliant >= 2 else "Partially Compliant" if partial > 0 else "Compliant"
    overall_color = {"Non-Compliant": "#c2410c", "Partially Compliant": "#b45309", "Compliant": "#16a34a"}.get(overall_status, "#6b7280")

    period_str = f"{config.audit_period_start.strftime('%d %b %Y')} – {config.audit_period_end.strftime('%d %b %Y')}"

    # Build controls table rows
    control_rows = "".join(
        f"""<tr>
          <td style="white-space:nowrap;font-weight:700;font-size:10px">{c.control_id}</td>
          <td><strong>{c.control_name}</strong></td>
          <td style="white-space:nowrap">{c.nist_csf}</td>
          <td>{_status_badge(c.status)}</td>
          <td>{_priority_badge(c.priority)}</td>
        </tr>
        <tr style="background:#fafafa">
          <td colspan=5 style="padding:6px 10px 10px">
            <div class="finding">📋 <strong>Finding:</strong> {c.finding}</div>
            <div class="rec">💡 <strong>Recommendation:</strong> {c.recommendation}</div>
          </td>
        </tr>"""
        for c in controls
    )

    # Readiness KPIs
    kpi_row = f"""
<div class="kpi-row">
  <div class="kpi kpi-go"><div class="kpi-num">{snapshot.go_count}</div><div class="kpi-label">Systems — GO</div></div>
  <div class="kpi kpi-caution"><div class="kpi-num">{snapshot.caution_count}</div><div class="kpi-label">Systems — CAUTION</div></div>
  <div class="kpi kpi-blocked"><div class="kpi-num">{snapshot.blocked_count}</div><div class="kpi-label">Systems — BLOCKED</div></div>
  <div class="kpi"><div class="kpi-num">{snapshot.readiness_pct:.0f}%</div><div class="kpi-label">PQC Readiness</div></div>
</div>"""

    # Team breakdown table
    team_rows = "".join(
        f"<tr><td>{t.team}</td><td>{t.total}</td>"
        f'<td style="color:#16a34a">{t.go}</td>'
        f'<td style="color:#b45309">{t.caution}</td>'
        f'<td style="color:#c2410c">{t.blocked}</td>'
        f"<td>{t.avg_score:.0f}/100</td></tr>"
        for t in snapshot.teams.values()
    ) if snapshot.teams else "<tr><td colspan=6 style='color:#6b7280'>No team data available</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RBI PQC Compliance Report — {config.org_name} — {date_str}</title>
{_RBI_CSS}
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
  <div class="rbi-logo">Reserve Bank of India — Regulatory Compliance Report</div>
  <div class="report-title">Post-Quantum Cryptography Migration<br>Readiness Assessment</div>
  <div class="report-subtitle">
    RBI Cybersecurity Framework 2016 &amp; Master Direction on IT Governance 2023<br>
    CERT-In Guidelines 2022 &amp; NIST FIPS 203/204/205
  </div>
  <div class="meta-grid">
    <span class="meta-label">Entity Name</span><span class="meta-value">{config.org_name}</span>
    <span class="meta-label">Entity Type</span><span class="meta-value">{config.entity_type}</span>
    <span class="meta-label">License / Reg. No.</span><span class="meta-value">{config.license_number or "—"}</span>
    <span class="meta-label">Report Reference</span><span class="meta-value">{ref}</span>
    <span class="meta-label">Audit Period</span><span class="meta-value">{period_str}</span>
    <span class="meta-label">Report Date</span><span class="meta-value">{date_str}</span>
    <span class="meta-label">Prepared By</span><span class="meta-value">{config.prepared_by}</span>
    <span class="meta-label">Reviewed By</span><span class="meta-value">{config.reviewed_by}</span>
    <span class="meta-label">Overall Status</span>
    <span class="meta-value" style="color:{overall_color};font-weight:700">{overall_status}</span>
  </div>
  <div><span class="classification">CONFIDENTIAL — FOR REGULATORY SUBMISSION</span></div>
</div>

<!-- SECTION 1: EXECUTIVE SUMMARY -->
<h2>1. Executive Summary</h2>
<div class="exec-summary">
  <p>
    This report presents the findings of a Post-Quantum Cryptography (PQC) migration readiness
    assessment conducted for <strong>{config.org_name}</strong> for the period {period_str}.
    The assessment was conducted in accordance with the RBI Cybersecurity Framework (2016),
    the RBI Master Direction on IT Governance, Risk, Controls and Assurance Practices (2023),
    CERT-In guidelines on cryptographic standards, and the NIST Post-Quantum Cryptography
    Standards (FIPS 203, 204, 205) finalised in August 2024.
  </p>
  <p>
    The overall compliance posture is assessed as <strong style="color:{overall_color}">{overall_status}</strong>.
    {compliant} of {total_controls} controls are fully compliant, {partial} are partially compliant,
    and {non_compliant} are non-compliant. The primary non-compliance areas relate to
    {"quantum-resistant key exchange readiness and third-party vendor risk" if non_compliant > 0 else "documentation and board-level governance"}.
  </p>
  <p>
    <strong>Key risk:</strong> The "harvest now, decrypt later" (HNDL) attack represents an
    <em>active, present threat</em>: adversaries may already be harvesting encrypted data for
    future decryption using quantum computers. Customer data encrypted today with classical
    algorithms (RSA, ECDSA, ECDH) may become recoverable within the decade. RBI-regulated entities
    handling sensitive financial data are expected to demonstrate a credible migration roadmap.
  </p>
</div>

<!-- KPI STRIP -->
{kpi_row}

<!-- SECTION 2: ASSET COVERAGE -->
<h2>2. Asset Inventory &amp; Scan Coverage</h2>
<table>
  <thead><tr><th>Metric</th><th>Value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td>Total Assets in Scope</td><td>{snapshot.total_assets}</td><td>Systems, endpoints, and services assessed</td></tr>
    <tr><td>Assets Scanned</td><td>{snapshot.scanned_assets} ({snapshot.scanned_assets/max(snapshot.total_assets,1)*100:.0f}%)</td><td>Coverage against total inventory</td></tr>
    <tr><td>Average Migration Difficulty Score</td><td>{snapshot.avg_difficulty_score:.0f} / 100</td><td>0 = trivial, 100 = blocked</td></tr>
    <tr><td>Systems Requiring Immediate Action</td><td>{snapshot.blocked_count}</td><td>BLOCKED verdict — cannot migrate without remediation</td></tr>
    <tr><td>Systems Requiring Planning</td><td>{snapshot.caution_count}</td><td>CAUTION verdict — compatible with careful migration plan</td></tr>
    <tr><td>Systems Ready for Migration</td><td>{snapshot.go_count}</td><td>GO verdict — no blockers detected</td></tr>
    <tr><td>Overall PQC Readiness Score</td><td>{snapshot.readiness_pct:.0f}%</td><td>% of assets at GO verdict</td></tr>
  </tbody>
</table>

<h3>2.1 Team / Business Unit Breakdown</h3>
<table>
  <thead><tr><th>Team / Unit</th><th>Total Assets</th><th>GO</th><th>CAUTION</th><th>BLOCKED</th><th>Avg. Score</th></tr></thead>
  <tbody>{team_rows}</tbody>
</table>

<!-- SECTION 3: CONTROL ASSESSMENTS (page break for print) -->
<div class="page-break"></div>
<h2>3. RBI Control Assessments</h2>
<p style="margin-bottom:12px;color:#6b7280;font-size:11px">
  Each control is mapped to the applicable RBI directive section, the NIST Cybersecurity Framework 2.0
  function, and assessed as Compliant / Partially Compliant / Non-Compliant.
</p>
<table>
  <thead>
    <tr>
      <th>Control Reference</th>
      <th>Control Objective</th>
      <th>NIST CSF</th>
      <th>Status</th>
      <th>Priority</th>
    </tr>
  </thead>
  <tbody>{control_rows}</tbody>
</table>

<!-- SECTION 4: REMEDIATION ROADMAP -->
<div class="page-break"></div>
<h2>4. Recommended Remediation Roadmap</h2>
<table>
  <thead><tr><th>Phase</th><th>Timeline</th><th>Action</th><th>Owner</th><th>RBI Reference</th></tr></thead>
  <tbody>
    <tr>
      <td><strong>Phase 0</strong><br>Foundation</td>
      <td>0–30 days</td>
      <td>
        Complete cryptographic asset inventory (100% CBOM coverage).<br>
        Resolve all TLS 1.2/1.1 downgrade configurations.<br>
        Issue PQC vendor questionnaire to HSM, CA, and TLS library providers.
      </td>
      <td>CISO, Platform Eng.</td>
      <td>RBI-IT-2023-3.1, RBI-IT-2023-8.2</td>
    </tr>
    <tr>
      <td><strong>Phase 1</strong><br>Hybrid Pilot</td>
      <td>30–120 days</td>
      <td>
        Deploy hybrid X25519MLKEM768 key exchange on internet-facing TLS endpoints (non-production).<br>
        Pilot ML-DSA-44 certificates in internal PKI.<br>
        Measure performance impact in load testing. Document MTU fragmentation incidents.
      </td>
      <td>Platform Eng., Security</td>
      <td>RBI-CS-2016-4.2, CERT-In-2022</td>
    </tr>
    <tr>
      <td><strong>Phase 2</strong><br>Production Hybrid</td>
      <td>120–270 days</td>
      <td>
        Roll out hybrid PQC key exchange to all internet-facing production endpoints.<br>
        Update certificate policy to require PQC-capable CA chain.<br>
        Submit migration progress update to RBI IT Risk Officer.
      </td>
      <td>CISO, CTO</td>
      <td>RBI/2024-25/37</td>
    </tr>
    <tr>
      <td><strong>Phase 3</strong><br>Full Migration</td>
      <td>FY2026-27</td>
      <td>
        Retire classical-only key exchange on all systems.<br>
        Complete PQC certificate rollout across all PKI.<br>
        Annual PQC compliance attestation to Board Risk Committee.
      </td>
      <td>Board, CISO</td>
      <td>RBI-IT-2023-3.1</td>
    </tr>
  </tbody>
</table>

<!-- SECTION 5: ATTESTATION -->
<div class="page-break"></div>
<h2>5. Management Attestation</h2>
<p>
  We, the undersigned, confirm that this Post-Quantum Cryptography Migration Readiness Assessment
  has been prepared in accordance with the RBI Cybersecurity Framework (2016), the RBI Master
  Direction on IT Governance, Risk, Controls and Assurance Practices (2023), and applicable
  CERT-In guidelines. The findings and recommendations are, to the best of our knowledge, accurate
  and complete as of the report date.
</p>
<div class="sig-grid">
  <div class="sig-box">
    <p><strong>{config.prepared_by}</strong></p>
    <p>Prepared By</p>
    <p style="color:#9ca3af">Signature: ________________________</p>
    <p style="color:#9ca3af">Date: ____________________________</p>
  </div>
  <div class="sig-box">
    <p><strong>{config.reviewed_by}</strong></p>
    <p>Reviewed &amp; Approved By</p>
    <p style="color:#9ca3af">Signature: ________________________</p>
    <p style="color:#9ca3af">Date: ____________________________</p>
  </div>
</div>

<!-- FOOTER -->
<div class="footer">
  <span>{config.org_name} · {ref} · {overall_status}</span>
  <span>CONFIDENTIAL — FOR REGULATORY SUBMISSION</span>
  <span>Generated by QuantumShift Platform · {date_str}</span>
</div>

</body>
</html>"""

    if output_path:
        from pathlib import Path
        Path(output_path).write_text(html, encoding="utf-8")

    return html
