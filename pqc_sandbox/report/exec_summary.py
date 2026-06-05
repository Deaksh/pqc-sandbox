"""
Executive Risk Memo — a CISO-forwardable one-page HTML document.

Tone: formal risk communication, not a developer tool output.
Audience: CISO, CTO, Head of IT Risk, Board Risk Committee.
Purpose: manufacture the internal alarm that gets escalated to a budget decision.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pqc_sandbox.benchmarks.runner import ComparisonResult
from pqc_sandbox.compat.oracle import CompatReport, Severity
from pqc_sandbox.hybrid.simulator import HybridResult
from pqc_sandbox.scoring import MigrationScore


@dataclass
class ExecSummaryConfig:
    org_name: str = "Your Organisation"
    system_name: str = "Production Systems"
    prepared_by: str = "Information Security Team"
    ref_number: str = ""           # e.g. "IS-2025-001"
    classification: str = "CONFIDENTIAL — INTERNAL"
    # Optional regulatory context
    regulatory_frameworks: list[str] = field(default_factory=list)  # ["RBI", "SEBI", "CERT-In"]
    # Optional deadline context
    migration_deadline: Optional[str] = None    # e.g. "Q4 2026"
    # Budget estimate (optional, shows ₹ figure in memo)
    estimated_effort_weeks: Optional[int] = None


_RISK_LEVEL_META = {
    "EASY":     ("LOW",      "#16a34a", "bg-green",  "Migration is low-risk and can proceed with standard project planning."),
    "MODERATE": ("MEDIUM",   "#b45309", "bg-amber",  "Migration requires careful planning and compatibility remediation before cut-over."),
    "HARD":     ("HIGH",     "#c2410c", "bg-orange",  "Migration poses significant operational risk. Architecture changes required."),
    "CRITICAL": ("CRITICAL", "#991b1b", "bg-red",    "Migration is not feasible without major infrastructure changes. Immediate escalation required."),
}

_CSS = """
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Georgia',serif;font-size:13px;color:#1a1a1a;background:#fff;max-width:900px;margin:0 auto;padding:40px 48px}
  @media print{body{padding:24px 32px;max-width:100%}}
  .header{border-bottom:3px solid #1e3a5f;padding-bottom:16px;margin-bottom:24px}
  .org{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#6b7280;margin-bottom:8px}
  .doc-title{font-size:22px;font-weight:700;color:#1e3a5f;line-height:1.2;margin-bottom:6px}
  .doc-meta{font-size:11px;color:#6b7280;display:flex;gap:20px;flex-wrap:wrap}
  .classification{display:inline-block;background:#1e3a5f;color:#fff;font-size:10px;font-weight:700;letter-spacing:.12em;padding:2px 8px;border-radius:2px;text-transform:uppercase}
  .verdict-box{border-radius:6px;padding:16px 20px;margin-bottom:20px;display:flex;align-items:center;gap:16px}
  .verdict-go{background:#f0fdf4;border:2px solid #16a34a}
  .verdict-caution{background:#fffbeb;border:2px solid #b45309}
  .verdict-blocked{background:#fef2f2;border:2px solid #991b1b}
  .verdict-label{font-size:26px;font-weight:800;letter-spacing:.04em}
  .verdict-go .verdict-label{color:#16a34a}
  .verdict-caution .verdict-label{color:#b45309}
  .verdict-blocked .verdict-label{color:#991b1b}
  .verdict-text{font-size:13px;line-height:1.5;color:#374151}
  h2{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#1e3a5f;margin:20px 0 8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
  .kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
  @media(max-width:640px){.kpi-grid{grid-template-columns:repeat(2,1fr)}}
  .kpi{background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:12px 14px}
  .kpi-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#6b7280;margin-bottom:4px}
  .kpi-value{font-size:20px;font-weight:800;color:#1e3a5f;line-height:1}
  .kpi-sub{font-size:10px;color:#6b7280;margin-top:2px}
  .kpi-bad .kpi-value{color:#c2410c}
  .kpi-warn .kpi-value{color:#b45309}
  .kpi-good .kpi-value{color:#16a34a}
  table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px}
  th{background:#f3f4f6;text-align:left;font-weight:700;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:#374151;padding:7px 10px;border:1px solid #e5e7eb}
  td{padding:7px 10px;border:1px solid #e5e7eb;vertical-align:top}
  .bad{color:#c2410c;font-weight:600}
  .warn{color:#b45309;font-weight:600}
  .good{color:#16a34a;font-weight:600}
  .issue-row-blocked td:first-child{border-left:3px solid #c2410c}
  .issue-row-caution td:first-child{border-left:3px solid #b45309}
  .action-table td:first-child{font-weight:600;white-space:nowrap}
  .risk-pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}
  .risk-critical{background:#fee2e2;color:#991b1b}
  .risk-high{background:#ffedd5;color:#c2410c}
  .risk-medium{background:#fef9c3;color:#854d0e}
  .risk-low{background:#dcfce7;color:#166534}
  .footer{margin-top:32px;padding-top:12px;border-top:1px solid #e5e7eb;font-size:10px;color:#9ca3af;display:flex;justify-content:space-between}
  .disclaimer{font-size:10px;color:#9ca3af;font-style:italic;margin-top:16px;line-height:1.4}
  p{margin-bottom:8px;line-height:1.6}
  ul{padding-left:18px;margin-bottom:8px}
  li{margin-bottom:3px;line-height:1.5}
  .highlight{background:#fef9c3;padding:1px 4px;border-radius:2px}
  .section{margin-bottom:20px}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:600px){.two-col{grid-template-columns:1fr}}
</style>
"""


def _verdict_class(verdict: str) -> str:
    return {"GO": "verdict-go", "CAUTION": "verdict-caution", "BLOCKED": "verdict-blocked"}.get(verdict, "verdict-caution")


def _risk_pill(level: str) -> str:
    cls = {"CRITICAL": "risk-critical", "HIGH": "risk-high", "MEDIUM": "risk-medium", "LOW": "risk-low"}.get(level, "risk-medium")
    return f'<span class="risk-pill {cls}">{level}</span>'


def _fmt_bytes(n: int) -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB"
    if n >= 1_024:
        return f"{n / 1_024:.1f} KB"
    return f"{n} B"


def _build_kpi_grid(
    comparison: Optional[ComparisonResult],
    score: Optional[MigrationScore],
    compat: Optional[CompatReport],
) -> str:
    kpis: list[tuple[str, str, str, str]] = []  # (label, value, sub, variant)

    if score:
        variant = "kpi-bad" if score.score > 60 else "kpi-warn" if score.score > 30 else "kpi-good"
        kpis.append(("Migration Difficulty", str(score.score), f"/ 100 — {score.label}", variant))

    if comparison:
        ratio = comparison.artifact_ratio
        variant = "kpi-bad" if ratio > 20 else "kpi-warn" if ratio > 5 else ""
        kpis.append(("Payload Size Increase", f"{ratio:.0f}×", "larger signatures/ciphertexts", variant))

        slowdown = max(comparison.op1_slowdown, comparison.op2_slowdown)
        variant2 = "kpi-bad" if slowdown > 10 else "kpi-warn" if slowdown > 2 else "kpi-good"
        kpis.append(("Crypto Op Slowdown", f"{slowdown:.1f}×", "vs current algorithm", variant2))

    if compat:
        blocked = sum(1 for i in compat.issues if i.severity == Severity.BLOCKED)
        caution = sum(1 for i in compat.issues if i.severity == Severity.CAUTION)
        total = blocked + caution
        variant = "kpi-bad" if blocked > 0 else "kpi-warn" if caution > 0 else "kpi-good"
        kpis.append(("Compatibility Issues", str(total), f"{blocked} BLOCKED, {caution} CAUTION", variant))

    cells = "".join(
        f'<div class="kpi {v}"><div class="kpi-label">{l}</div><div class="kpi-value">{val}</div><div class="kpi-sub">{sub}</div></div>'
        for l, val, sub, v in kpis
    )
    return f'<div class="kpi-grid">{cells}</div>'


def _build_findings_table(comparison: Optional[ComparisonResult], compat: Optional[CompatReport]) -> str:
    rows = ""

    if comparison:
        cl, pq = comparison.classical, comparison.pqc
        cat_label = "Key Exchange (KEM)" if pq.category == "kem" else "Digital Signatures"
        artifact_label = "Ciphertext" if pq.category == "kem" else "Signature"

        size_cls = "bad" if comparison.artifact_ratio > 20 else "warn"
        perf_cls = "bad" if comparison.op1_slowdown > 10 else "warn" if comparison.op1_slowdown > 2 else "good"

        rows += f"""
<tr>
  <td>{cat_label}</td>
  <td>{cl.algorithm}</td>
  <td>{pq.algorithm} (NIST FIPS {"203" if pq.category == "kem" else "204"})</td>
  <td class="{size_cls}">{artifact_label}: {comparison.artifact_ratio:.0f}× larger<br>
      ({_fmt_bytes(cl.artifact_bytes)} → {_fmt_bytes(pq.artifact_bytes)})</td>
  <td class="{perf_cls}">Op: {comparison.op1_slowdown:.1f}× slower</td>
</tr>"""

    return f"""
<table>
  <thead><tr><th>Domain</th><th>Current Algorithm</th><th>Recommended PQC</th><th>Size Impact</th><th>Performance Impact</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""


def _build_compat_table(compat: Optional[CompatReport]) -> str:
    if not compat or not compat.issues:
        return '<p class="good">✓ No compatibility blockers detected for the tested configuration.</p>'

    rows = "".join(
        f'<tr class="issue-row-{i.severity.value.lower()}">'
        f'<td>{_risk_pill("CRITICAL" if i.severity == Severity.BLOCKED else "HIGH" if i.severity == Severity.CAUTION else "LOW")}</td>'
        f'<td>{i.category.upper()}</td>'
        f'<td><strong>{i.title}</strong><br><span style="color:#6b7280;font-size:11px">{i.detail}</span></td>'
        f'<td style="font-size:11px;color:#374151">{i.mitigation or "—"}</td>'
        f'</tr>'
        for i in compat.issues
    )
    return f"""
<table>
  <thead><tr><th>Risk Level</th><th>Category</th><th>Issue</th><th>Recommended Mitigation</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""


def _build_action_table(
    score: Optional[MigrationScore],
    compat: Optional[CompatReport],
    config: ExecSummaryConfig,
) -> str:
    actions: list[tuple[str, str, str, str]] = []  # (priority, action, owner, timeline)

    if compat:
        for issue in compat.issues:
            if issue.severity == Severity.BLOCKED:
                actions.append(("P1 — Immediate", issue.title, "Platform / Infrastructure", "Before migration start"))

    actions.append(("P1 — Critical", "Inventory all cryptographic assets using CBOM tooling", "Security Engineering", "Now"))
    actions.append(("P2 — High", "Pilot hybrid PQC deployment on non-production environment", "DevOps / Platform", "Sprint 1–2"))
    actions.append(("P2 — High", "Engage TLS/PKI vendors to confirm PQC certificate support", "IT / Procurement", "30 days"))
    actions.append(("P3 — Medium", "Update cryptographic standards policy to include NIST FIPS 203/204/205", "Governance / Risk", "60 days"))
    actions.append(("P3 — Medium", "Define migration timeline aligned to regulatory deadlines", "CISO / CTO", config.migration_deadline or "Q4 2026"))

    rows = "".join(
        f'<tr class="action-table"><td>{p}</td><td>{a}</td><td>{o}</td><td>{t}</td></tr>'
        for p, a, o, t in actions
    )
    return f"""
<table class="action-table">
  <thead><tr><th>Priority</th><th>Action Required</th><th>Owner</th><th>Target Date</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""


def _regulatory_section(config: ExecSummaryConfig, score: Optional[MigrationScore]) -> str:
    if not config.regulatory_frameworks:
        return ""

    frameworks_html = ""
    risk_level = score.label if score else "MODERATE"

    for fw in config.regulatory_frameworks:
        fw_upper = fw.upper()
        if fw_upper == "RBI":
            frameworks_html += f"""
<tr>
  <td><strong>RBI Cybersecurity Framework (2016)<br>Master Direction on IT (2023)</strong></td>
  <td>Banks must implement controls aligned to CERT-In and NIST standards. RBI circular RBI/2023-24/73 references quantum-resistant cryptography preparedness for Regulated Entities.</td>
  <td>{_risk_pill("HIGH" if risk_level in ("HARD", "CRITICAL") else "MEDIUM")}</td>
  <td>Evidence of migration roadmap required in annual IT audit submission</td>
</tr>"""
        elif fw_upper == "SEBI":
            frameworks_html += f"""
<tr>
  <td><strong>SEBI Cybersecurity &amp; Cyber Resilience Framework (CSCRF 2024)</strong></td>
  <td>Market infrastructure institutions and regulated entities must demonstrate cryptographic hygiene. SEBI CSCRF requires annual penetration testing inclusive of cryptographic assessments.</td>
  <td>{_risk_pill("MEDIUM")}</td>
  <td>Include PQC readiness in CSCRF annual compliance report</td>
</tr>"""
        elif fw_upper in ("CERT-IN", "CERTIN"):
            frameworks_html += f"""
<tr>
  <td><strong>CERT-In Directions (April 2022 &amp; subsequent)</strong></td>
  <td>CERT-In mandates 6-hour incident reporting and requires organisations to maintain audit trails of cryptographic events. Post-quantum vulnerabilities must be included in threat modelling.</td>
  <td>{_risk_pill("MEDIUM")}</td>
  <td>Update threat register and inform CISO for inclusion in annual CERT-In report</td>
</tr>"""
        elif fw_upper == "DPDP":
            frameworks_html += f"""
<tr>
  <td><strong>Digital Personal Data Protection Act, 2023 (DPDP)</strong></td>
  <td>DPDP requires data fiduciaries to implement reasonable security safeguards. Use of quantum-vulnerable encryption to protect personal data may be deemed inadequate safeguard post-2027.</td>
  <td>{_risk_pill("MEDIUM")}</td>
  <td>Legal / DPO to assess whether current encryption of personal data meets "reasonable safeguard" standard under DPDP rules</td>
</tr>"""

    if not frameworks_html:
        return ""

    return f"""
<div class="section">
  <h2>Regulatory Exposure</h2>
  <table>
    <thead><tr><th>Framework</th><th>Relevance</th><th>Exposure Level</th><th>Required Action</th></tr></thead>
    <tbody>{frameworks_html}</tbody>
  </table>
</div>"""


def generate_exec_summary(
    comparison: Optional[ComparisonResult] = None,
    compat: Optional[CompatReport] = None,
    hybrid: Optional[HybridResult] = None,
    score: Optional[MigrationScore] = None,
    config: Optional[ExecSummaryConfig] = None,
    output_path: Optional[Path] = None,
) -> str:
    cfg = config or ExecSummaryConfig()
    now = datetime.datetime.now()
    date_str = now.strftime("%d %B %Y")
    ref = cfg.ref_number or f"PQC-{now.strftime('%Y%m%d')}-001"

    verdict = compat.verdict if compat else ("CAUTION" if score and score.score > 30 else "GO")
    risk_label, risk_color, _, risk_desc = _RISK_LEVEL_META.get(
        score.label if score else "MODERATE",
        _RISK_LEVEL_META["MODERATE"]
    )
    verdict_cls = _verdict_class(verdict)

    reg_text = ", ".join(cfg.regulatory_frameworks) if cfg.regulatory_frameworks else "General IT Risk"

    effort_row = ""
    if cfg.estimated_effort_weeks:
        effort_row = f"<br>Estimated remediation effort: <strong>{cfg.estimated_effort_weeks} engineering weeks</strong>"

    deadline_row = ""
    if cfg.migration_deadline:
        deadline_row = f"<br>Target migration deadline: <strong>{cfg.migration_deadline}</strong>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PQC Risk Memo — {cfg.org_name} — {date_str}</title>
{_CSS}
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="org">{cfg.org_name}</div>
  <div class="doc-title">Post-Quantum Cryptography Migration Risk Assessment</div>
  <div style="margin:8px 0"><span class="classification">{cfg.classification}</span></div>
  <div class="doc-meta">
    <span>Reference: <strong>{ref}</strong></span>
    <span>System: <strong>{cfg.system_name}</strong></span>
    <span>Date: <strong>{date_str}</strong></span>
    <span>Prepared by: <strong>{cfg.prepared_by}</strong></span>
    <span>Regulatory scope: <strong>{reg_text}</strong></span>
  </div>
</div>

<!-- VERDICT -->
<div class="verdict-box {verdict_cls}">
  <div>
    <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#6b7280;margin-bottom:4px">Overall Verdict</div>
    <div class="verdict-label">{verdict}</div>
  </div>
  <div class="verdict-text">
    <strong>Risk Level: {_risk_pill(risk_label)}</strong><br>
    {risk_desc}{effort_row}{deadline_row}
  </div>
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="section">
  <h2>1. Executive Summary</h2>
  <p>
    This memo presents the findings of a post-quantum cryptography (PQC) migration impact
    simulation conducted on <strong>{cfg.system_name}</strong>. The simulation used the
    <em>pqc-sandbox</em> tool, running entirely on-premises with no data transmitted externally.
  </p>
  <p>
    The National Institute of Standards and Technology (NIST) finalised three post-quantum
    cryptographic standards in August 2024: <strong>ML-KEM (FIPS 203)</strong>,
    <strong>ML-DSA (FIPS 204)</strong>, and <strong>SLH-DSA (FIPS 205)</strong>. Cryptographically
    relevant quantum computers — capable of breaking current RSA and elliptic-curve encryption using
    Shor's algorithm — are projected by major intelligence agencies to arrive
    <span class="highlight">between 2030 and 2035</span>. The "harvest now, decrypt later" (HNDL)
    threat means <strong>data encrypted today is at risk immediately</strong>.
  </p>
  <p>
    The simulation identified a <strong>{risk_label} risk</strong> migration posture for
    {cfg.system_name}. Specific cost, compatibility, and regulatory findings follow.
  </p>
</div>

<!-- KPI STRIP -->
{_build_kpi_grid(comparison, score, compat)}

<!-- TECHNICAL FINDINGS -->
<div class="section">
  <h2>2. Technical Impact Findings</h2>
  <p>The following table summarises the measured impact of replacing current algorithms with their
     NIST-recommended PQC equivalents:</p>
  {_build_findings_table(comparison, compat)}

  {"<p><strong>Hybrid mode assessment:</strong> A hybrid key exchange (classical + PQC in parallel) adds <strong>+" + str(hybrid.wire_overhead_bytes) + " bytes</strong> of wire overhead per handshake. This is the recommended transitional approach and is backward-compatible with classical-only peers.</p>" if hybrid else ""}
</div>

<!-- COMPATIBILITY ISSUES -->
<div class="section">
  <h2>3. Compatibility Blockers &amp; Risks</h2>
  {_build_compat_table(compat)}
</div>

<!-- REGULATORY EXPOSURE -->
{_regulatory_section(cfg, score)}

<!-- BUSINESS RISK NARRATIVE -->
<div class="section">
  <h2>{"5" if cfg.regulatory_frameworks else "4"}. Business Risk Assessment</h2>
  <div class="two-col">
    <div>
      <p><strong>Operational risk:</strong> If migration is deferred and a cryptographically relevant quantum computer emerges, all historical data encrypted under current algorithms becomes recoverable by adversaries. Sensitive customer data, transaction records, and proprietary information face retroactive exposure.</p>
      <p><strong>Regulatory risk:</strong> Multiple Indian financial regulators (RBI, SEBI) and CERT-In have issued advisories on quantum preparedness. Non-compliance with future PQC mandates may result in enforcement action, audit findings, or loss of operating permissions.</p>
    </div>
    <div>
      <p><strong>Competitive risk:</strong> Enterprises that delay PQC migration until mandated will face compressed timelines, skills shortages, and higher vendor costs. Early movers will have completed the transition on their terms, with tested rollback plans.</p>
      <p><strong>Third-party / supply chain risk:</strong> Migration is only as strong as the weakest link. APIs, HSMs, certificate authorities, and SaaS vendors must also support PQC. Vendor qualification takes 6–18 months and should begin immediately.</p>
    </div>
  </div>
</div>

<!-- RECOMMENDED ACTIONS -->
<div class="section">
  <h2>{"6" if cfg.regulatory_frameworks else "5"}. Recommended Actions</h2>
  {_build_action_table(score, compat, cfg)}
</div>

<!-- DISCLAIMER -->
<p class="disclaimer">
  This assessment was generated by pqc-sandbox (open-source, Apache 2.0 licence). All simulation
  was performed locally on the issuing organisation's infrastructure. No data was transmitted to
  external parties. Performance figures are derived from NIST reference implementation benchmarks
  and may vary on specific hardware. This document does not constitute legal or regulatory advice.
  Consult your legal counsel and compliance team before making decisions based on this assessment.
</p>

<!-- FOOTER -->
<div class="footer">
  <span>{cfg.org_name} · {cfg.classification}</span>
  <span>Ref: {ref} · {date_str}</span>
  <span>Generated by pqc-sandbox · Zero telemetry · Apache 2.0</span>
</div>

</body>
</html>"""

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")

    return html
