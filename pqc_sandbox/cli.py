"""
pqc-sandbox CLI — entry point.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_algorithms(classical: Optional[str], pqc: Optional[str]) -> tuple[str, str]:
    from pqc_sandbox.algorithms import ALL_ALGORITHMS, MIGRATION_MAP
    if classical and not pqc:
        pqc_candidates = MIGRATION_MAP.get(classical, [])
        if not pqc_candidates:
            raise click.UsageError(f"No known PQC replacement for '{classical}'. Use --pqc to specify one.")
        pqc = pqc_candidates[0]
        console.print(f"  [dim]Auto-selected PQC replacement:[/dim] [cyan]{pqc}[/cyan]")
    if classical not in ALL_ALGORITHMS:
        raise click.UsageError(f"Unknown algorithm '{classical}'. Run `pqc-sandbox list` to see options.")
    if pqc not in ALL_ALGORITHMS:
        raise click.UsageError(f"Unknown algorithm '{pqc}'. Run `pqc-sandbox list` to see options.")
    return classical, pqc


def _build_constraints(
    mtu: int,
    tls_ver: str,
    ram_kb: Optional[int],
    protocol: str,
    tags: tuple[str, ...],
):
    from pqc_sandbox.compat.oracle import SystemConstraints
    return SystemConstraints(
        mtu_bytes=mtu,
        tls_version=tls_ver,
        protocol=protocol,
        ram_kb=ram_kb,
        tags=list(tags),
    )


# ── CLI group ─────────────────────────────────────────────────────────────────

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option("0.1.0", prog_name="pqc-sandbox")
def main() -> None:
    """
    \b
    pqc-sandbox — Simulate a post-quantum cryptography migration in 60 seconds.

    \b
    Zero cloud. Zero telemetry. Runs fully local.

    \b
    Quick start:
      pqc-sandbox demo                          # 60-second wow demo
      pqc-sandbox compare --classical ECDH-P256 # auto-pick PQC replacement
      pqc-sandbox scan tls example.com          # probe a live endpoint
      pqc-sandbox scan git                      # scan current repo for vulnerable crypto
      pqc-sandbox list                          # show all supported algorithms
    """


# ── demo ──────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--scenario", "-s", default=0, type=int, show_default=True,
              help="Demo scenario index (0=web API, 1=IoT, 2=legacy TLS 1.2)")
@click.option("--html", "output_html", default=None, type=click.Path(),
              help="Save HTML impact report to this path")
@click.option("--json", "output_json", default=None, type=click.Path(),
              help="Save JSON report to this path")
@click.option("--exec-report", "output_exec", default=None, type=click.Path(),
              help="Save executive risk memo to this path (default: pqc_risk_memo_demo.html)")
def demo(scenario: int, output_html: Optional[str], output_json: Optional[str],
         output_exec: Optional[str]) -> None:
    """Run the 60-second demo: see PQC migration impact with zero setup."""
    from pqc_sandbox.demo.runner import run_demo
    run_demo(console, output_html=output_html, output_json=output_json,
             output_exec=output_exec, scenario_index=scenario)


# ── compare ───────────────────────────────────────────────────────────────────

@main.command()
@click.option("--classical", "-c", required=True,
              help="Classical algorithm name (e.g. 'ECDH-P256', 'ECDSA-P256', 'RSA-2048 (PKCS#1 v1.5)')")
@click.option("--pqc", "-p", default=None,
              help="PQC replacement algorithm name (auto-selected if omitted)")
@click.option("--iterations", "-n", default=50, show_default=True,
              help="Number of benchmark iterations")
@click.option("--hybrid/--no-hybrid", default=True, show_default=True,
              help="Also simulate hybrid (classical+PQC) mode")
@click.option("--mtu", default=1500, show_default=True, help="Network MTU in bytes")
@click.option("--tls-version", "tls_ver", default="1.3", show_default=True,
              type=click.Choice(["1.0", "1.1", "1.2", "1.3"]))
@click.option("--ram-kb", default=None, type=int,
              help="Device RAM in KB (omit = unconstrained desktop)")
@click.option("--protocol", default="tls", show_default=True,
              type=click.Choice(["tls", "ssh", "cms", "jwt", "dnssec", "custom"]))
@click.option("--tag", "tags", multiple=True, help="Device tags: embedded, iot, hsm, legacy-tls-stack, openssl-1")
@click.option("--html", "output_html", default=None, type=click.Path(),
              help="Save HTML report")
@click.option("--json", "output_json", default=None, type=click.Path(),
              help="Save JSON report (CI/CD)")
@click.option("--diff", "output_diff", default=None, type=click.Path(),
              help="Save config diff to file")
@click.option("--diff-format", "diff_fmt", default="openssl", show_default=True,
              type=click.Choice(["openssl", "nginx", "sshd", "go-tls", "python"]),
              help="Config diff format")
@click.option("--simulate/--no-simulate", default=False,
              help="Force simulated mode even if liboqs is installed")
@click.option("--ci", is_flag=True, default=False,
              help="CI mode: exit 1 on CAUTION, exit 2 on BLOCKED")
def compare(
    classical: str,
    pqc: Optional[str],
    iterations: int,
    hybrid: bool,
    mtu: int,
    tls_ver: str,
    ram_kb: Optional[int],
    protocol: str,
    tags: tuple[str, ...],
    output_html: Optional[str],
    output_json: Optional[str],
    output_diff: Optional[str],
    diff_fmt: str,
    simulate: bool,
    ci: bool,
) -> None:
    """Compare a classical algorithm against its PQC replacement."""
    from pqc_sandbox.algorithms import ALL_ALGORITHMS
    from pqc_sandbox.benchmarks.runner import run_comparison
    from pqc_sandbox.compat.oracle import run_compat_check
    from pqc_sandbox.hybrid.simulator import simulate_hybrid
    from pqc_sandbox.scoring import compute_score
    from pqc_sandbox.report.terminal import print_report
    from pqc_sandbox.report.html_gen import generate_html
    from pqc_sandbox.report.json_out import generate_json
    from pqc_sandbox.report.config_diff import generate_config_diff

    classical, pqc = _resolve_algorithms(classical, pqc)
    constraints = _build_constraints(mtu, tls_ver, ram_kb, protocol, tags)

    console.print(f"\n  Benchmarking [bold]{classical}[/bold] vs [bold]{pqc}[/bold] ...")
    comparison = run_comparison(classical, pqc, iterations=iterations, force_simulate=simulate)

    hybrid_result = None
    if hybrid:
        try:
            hybrid_result = simulate_hybrid(classical, pqc, iterations=iterations, force_simulate=simulate)
        except ValueError as e:
            console.print(f"  [yellow]Hybrid skipped:[/yellow] {e}")

    pqc_profile = ALL_ALGORITHMS[pqc]
    compat_report = run_compat_check(pqc_profile, constraints)
    score = compute_score(comparison=comparison, compat=compat_report, hybrid=hybrid_result)

    print_report(
        comparison=comparison,
        compat=compat_report,
        hybrid=hybrid_result,
        score=score,
        console=console,
    )

    if output_html:
        generate_html(comparison, compat_report, hybrid_result, score, Path(output_html))
        console.print(f"[green]✓[/green] HTML → [cyan]{output_html}[/cyan]")

    if output_json:
        generate_json(comparison, compat_report, hybrid_result, score, Path(output_json))
        console.print(f"[green]✓[/green] JSON → [cyan]{output_json}[/cyan]")

    if output_diff:
        c_profile = ALL_ALGORITHMS[classical]
        diff_text = generate_config_diff(c_profile, pqc_profile, framework=diff_fmt)
        Path(output_diff).write_text(diff_text, encoding="utf-8")
        console.print(f"[green]✓[/green] Config diff → [cyan]{output_diff}[/cyan]")

    if ci:
        verdicts = {"GO": 0, "CAUTION": 1, "BLOCKED": 2}
        sys.exit(verdicts.get(compat_report.verdict, 0))


# ── scan ──────────────────────────────────────────────────────────────────────

@main.group()
def scan() -> None:
    """Scan an input source to detect classical algorithms and recommend PQC replacements."""


@scan.command("tls")
@click.argument("host")
@click.option("--port", "-p", default=443, show_default=True)
@click.option("--mtu", default=1500, show_default=True)
@click.option("--compare/--no-compare", "do_compare", default=True,
              help="Run side-by-side benchmark for detected algorithms")
@click.option("--html", "output_html", default=None, type=click.Path())
@click.option("--json", "output_json", default=None, type=click.Path())
def scan_tls(
    host: str, port: int, mtu: int, do_compare: bool,
    output_html: Optional[str], output_json: Optional[str],
) -> None:
    """Probe a live TLS endpoint and simulate PQC migration."""
    from pqc_sandbox.inputs.tls_probe import probe_tls_endpoint
    from pqc_sandbox.algorithms import ALL_ALGORITHMS
    from pqc_sandbox.benchmarks.runner import run_comparison
    from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints
    from pqc_sandbox.hybrid.simulator import simulate_hybrid
    from pqc_sandbox.scoring import compute_score
    from pqc_sandbox.report.terminal import print_report
    from pqc_sandbox.report.html_gen import generate_html
    from pqc_sandbox.report.json_out import generate_json

    console.print(f"\n  Probing [bold]{host}:{port}[/bold] ...")
    try:
        probe = probe_tls_endpoint(host, port)
    except Exception as e:
        console.print(f"[red]✗ TLS probe failed:[/red] {e}")
        sys.exit(1)

    t = Table(title=f"TLS Endpoint: {host}:{port}", box=box.ROUNDED)
    t.add_column("Property", style="bold")
    t.add_column("Value")
    t.add_row("TLS Version", probe.tls_version)
    t.add_row("Cipher Suite", probe.cipher_name)
    t.add_row("Key Exchange", probe.key_exchange)
    t.add_row("Cert Subject", probe.cert_subject)
    t.add_row("Cert Sig Alg", probe.cert_sig_alg)
    t.add_row("Cert Expiry", probe.cert_expiry)
    t.add_row("Handshake", f"{probe.handshake_ms:.1f} ms")
    if probe.recommended_kem:
        t.add_row("Recommended KEM", ", ".join(probe.recommended_kem))
    if probe.recommended_sign:
        t.add_row("Recommended Sign", ", ".join(probe.recommended_sign))
    console.print(t)
    console.print()

    if do_compare and probe.detected_classical_kem and probe.recommended_kem:
        constraints = SystemConstraints(
            mtu_bytes=mtu,
            tls_version=probe.tls_version.replace("TLSv", "").replace("v", ""),
        )
        comparison = run_comparison(probe.detected_classical_kem, probe.recommended_kem[0],
                                    iterations=30, force_simulate=True)
        compat = run_compat_check(ALL_ALGORITHMS[probe.recommended_kem[0]], constraints)
        hybrid_result = None
        try:
            hybrid_result = simulate_hybrid(probe.detected_classical_kem, probe.recommended_kem[0],
                                            iterations=30, force_simulate=True)
        except ValueError:
            pass
        score = compute_score(comparison=comparison, compat=compat, hybrid=hybrid_result)
        print_report(comparison=comparison, compat=compat, hybrid=hybrid_result, score=score, console=console)

        if output_html:
            generate_html(comparison, compat, hybrid_result, score, Path(output_html))
            console.print(f"[green]✓[/green] HTML → [cyan]{output_html}[/cyan]")
        if output_json:
            generate_json(comparison, compat, hybrid_result, score, Path(output_json))
            console.print(f"[green]✓[/green] JSON → [cyan]{output_json}[/cyan]")


@scan.command("cbom")
@click.argument("cbom_file", type=click.Path(exists=True))
@click.option("--html", "output_html", default=None, type=click.Path())
@click.option("--json", "output_json", default=None, type=click.Path())
def scan_cbom(cbom_file: str, output_html: Optional[str], output_json: Optional[str]) -> None:
    """Parse a CBOM (CycloneDX) file and simulate PQC migration for each algorithm."""
    from pqc_sandbox.inputs.cbom import parse_cbom
    from pqc_sandbox.algorithms import ALL_ALGORITHMS
    from pqc_sandbox.benchmarks.runner import run_comparison
    from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints
    from pqc_sandbox.scoring import compute_score
    from pqc_sandbox.report.terminal import print_report

    result = parse_cbom(cbom_file)
    console.print(f"\n  Parsed CBOM: [bold]{cbom_file}[/bold]")
    console.print(f"  Found [cyan]{len(result.components)}[/cyan] cryptographic components\n")

    t = Table(title="CBOM Components", box=box.ROUNDED)
    t.add_column("Component", style="bold")
    t.add_column("Detected Algorithm")
    t.add_column("Recommended PQC")
    for comp in result.components:
        t.add_row(comp.name, comp.detected_classical, ", ".join(comp.recommended_pqc) or "—")
    console.print(t)
    console.print()

    seen: set[str] = set()
    for comp in result.components:
        classical = comp.detected_classical
        if not comp.recommended_pqc or classical in seen:
            continue
        seen.add(classical)
        pqc = comp.recommended_pqc[0]
        if classical not in ALL_ALGORITHMS or pqc not in ALL_ALGORITHMS:
            continue
        comparison = run_comparison(classical, pqc, iterations=20, force_simulate=True)
        compat = run_compat_check(ALL_ALGORITHMS[pqc], SystemConstraints())
        score = compute_score(comparison=comparison, compat=compat)
        print_report(comparison=comparison, compat=compat, score=score, console=console)


@scan.command("sarif")
@click.argument("sarif_file", type=click.Path(exists=True))
def scan_sarif(sarif_file: str) -> None:
    """Parse SARIF output from a crypto scanner and recommend PQC replacements."""
    from pqc_sandbox.inputs.sarif import parse_sarif
    from pqc_sandbox.algorithms import ALL_ALGORITHMS
    from pqc_sandbox.benchmarks.runner import run_comparison
    from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints
    from pqc_sandbox.scoring import compute_score
    from pqc_sandbox.report.terminal import print_report

    result = parse_sarif(sarif_file)
    console.print(f"\n  Parsed SARIF from [bold]{result.tool_name}[/bold]: {sarif_file}")
    console.print(f"  Found [cyan]{len(result.findings)}[/cyan] findings\n")

    t = Table(title="SARIF Findings", box=box.ROUNDED)
    t.add_column("Rule ID", style="bold")
    t.add_column("Location")
    t.add_column("Detected Algorithm")
    t.add_column("Recommended PQC")
    for f in result.findings:
        t.add_row(f.rule_id, f.location, f.detected_algorithm, ", ".join(f.recommended_pqc) or "—")
    console.print(t)
    console.print()

    seen: set[str] = set()
    for f in result.findings:
        classical = f.detected_algorithm
        if not f.recommended_pqc or classical in seen:
            continue
        seen.add(classical)
        pqc = f.recommended_pqc[0]
        if classical not in ALL_ALGORITHMS or pqc not in ALL_ALGORITHMS:
            continue
        comparison = run_comparison(classical, pqc, iterations=20, force_simulate=True)
        compat = run_compat_check(ALL_ALGORITHMS[pqc], SystemConstraints())
        score = compute_score(comparison=comparison, compat=compat)
        print_report(comparison=comparison, compat=compat, score=score, console=console)


# ── list ──────────────────────────────────────────────────────────────────────

@main.command("list")
@click.option("--category", "-c", default=None, type=click.Choice(["kem", "sign"]))
@click.option("--pqc-only", is_flag=True, default=False)
@click.option("--classical-only", is_flag=True, default=False)
def list_algorithms(
    category: Optional[str], pqc_only: bool, classical_only: bool
) -> None:
    """List all supported algorithms."""
    from pqc_sandbox.algorithms import ALL_ALGORITHMS, MIGRATION_MAP

    algos = list(ALL_ALGORITHMS.values())
    if category:
        algos = [a for a in algos if a.category == category]
    if pqc_only:
        algos = [a for a in algos if a.is_pqc]
    if classical_only:
        algos = [a for a in algos if not a.is_pqc]

    t = Table(title="Supported Algorithms", box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Name", style="bold")
    t.add_column("Category")
    t.add_column("PQC?")
    t.add_column("Standard")
    t.add_column("Security Level")
    t.add_column("Public Key")
    t.add_column("Artifact Size")
    t.add_column("Replaces")

    for a in algos:
        art = a.ciphertext_bytes if a.category == "kem" else a.signature_bytes
        pqc_mark = "[green]✓ PQC[/green]" if a.is_pqc else "[dim]classical[/dim]"
        replaces = ""
        if not a.is_pqc:
            for c, ps in MIGRATION_MAP.items():
                if c == a.name:
                    pass
            replacements = [k for k, v in MIGRATION_MAP.items() if a.name in v]
            replaces = ", ".join(replacements) if replacements else "—"
        else:
            replaces = a.classical_equivalent or "—"

        t.add_row(
            a.name,
            a.category,
            pqc_mark,
            a.standard,
            str(a.security_level),
            f"{a.public_key_bytes:,} B",
            f"{art:,} B" if art else "—",
            replaces,
        )

    console.print(t)
    console.print()
    console.print("  [dim]Use these names with --classical / --pqc flags.[/dim]")


# ── diff ──────────────────────────────────────────────────────────────────────

@main.command("diff")
@click.option("--classical", "-c", required=True)
@click.option("--pqc", "-p", default=None)
@click.option("--format", "fmt", default="openssl", show_default=True,
              type=click.Choice(["openssl", "nginx", "sshd", "go-tls", "python"]))
@click.option("--output", "-o", default=None, type=click.Path())
def diff_cmd(
    classical: str, pqc: Optional[str], fmt: str, output: Optional[str]
) -> None:
    """Print copy-paste config diff for a migration."""
    from pqc_sandbox.algorithms import ALL_ALGORITHMS
    from pqc_sandbox.report.config_diff import generate_config_diff

    classical, pqc = _resolve_algorithms(classical, pqc)
    c_profile = ALL_ALGORITHMS[classical]
    p_profile = ALL_ALGORITHMS[pqc]

    diff_text = generate_config_diff(c_profile, p_profile, framework=fmt)
    if output:
        Path(output).write_text(diff_text, encoding="utf-8")
        console.print(f"[green]✓[/green] Saved to [cyan]{output}[/cyan]")
    else:
        console.print(diff_text)


# ── badge ─────────────────────────────────────────────────────────────────────

@main.command("badge")
@click.option("--classical", "-c", required=True)
@click.option("--pqc", "-p", default=None)
@click.option("--mtu", default=1500)
@click.option("--tls-version", "tls_ver", default="1.3")
@click.option("--ram-kb", default=None, type=int)
def badge_cmd(
    classical: str, pqc: Optional[str], mtu: int, tls_ver: str, ram_kb: Optional[int]
) -> None:
    """Generate the Migration Difficulty Score badge URL and markdown."""
    from pqc_sandbox.algorithms import ALL_ALGORITHMS
    from pqc_sandbox.benchmarks.runner import run_comparison
    from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints
    from pqc_sandbox.hybrid.simulator import simulate_hybrid
    from pqc_sandbox.scoring import compute_score

    classical, pqc = _resolve_algorithms(classical, pqc)
    constraints = SystemConstraints(mtu_bytes=mtu, tls_version=tls_ver, ram_kb=ram_kb)

    comparison = run_comparison(classical, pqc, iterations=30, force_simulate=True)
    compat = run_compat_check(ALL_ALGORITHMS[pqc], constraints)
    hybrid_result = None
    try:
        hybrid_result = simulate_hybrid(classical, pqc, iterations=30, force_simulate=True)
    except ValueError:
        pass
    score = compute_score(comparison=comparison, compat=compat, hybrid=hybrid_result)

    console.print()
    console.print(f"  Score: [bold]{score.score}/100[/bold] — [bold]{score.label}[/bold]")
    console.print()
    console.print("  [bold]Badge URL:[/bold]")
    console.print(f"  {score.badge_url}")
    console.print()
    console.print("  [bold]Badge Markdown:[/bold]")
    console.print(f"  {score.badge_markdown}")
    console.print()


# ── exec-report ───────────────────────────────────────────────────────────────

@main.command("exec-report")
@click.option("--classical", "-c", required=True,
              help="Classical algorithm name (e.g. 'ECDH-P256')")
@click.option("--pqc", "-p", default=None, help="PQC replacement (auto-selected if omitted)")
@click.option("--output", "-o", default="pqc_risk_memo.html", show_default=True,
              type=click.Path(), help="Output HTML file path")
@click.option("--org", default="Your Organisation", help="Organisation name for the memo header")
@click.option("--system", "system_name", default="Production Systems",
              help="System or asset name")
@click.option("--prepared-by", default="Information Security Team")
@click.option("--ref", "ref_number", default="", help="Reference number (e.g. IS-2025-001)")
@click.option("--classification", default="CONFIDENTIAL — INTERNAL")
@click.option("--framework", "frameworks", multiple=True,
              type=click.Choice(["RBI", "SEBI", "CERT-In", "DPDP"], case_sensitive=False),
              help="Regulatory frameworks to include (repeat for multiple)")
@click.option("--deadline", "migration_deadline", default=None,
              help="Target migration deadline (e.g. 'Q4 2026')")
@click.option("--effort-weeks", default=None, type=int,
              help="Estimated remediation effort in engineering weeks")
@click.option("--mtu", default=1500, show_default=True)
@click.option("--tls-version", "tls_ver", default="1.3", show_default=True,
              type=click.Choice(["1.0", "1.1", "1.2", "1.3"]))
@click.option("--ram-kb", default=None, type=int)
@click.option("--protocol", default="tls", show_default=True,
              type=click.Choice(["tls", "ssh", "cms", "jwt", "dnssec", "custom"]))
@click.option("--tag", "tags", multiple=True)
def exec_report_cmd(
    classical: str,
    pqc: Optional[str],
    output: str,
    org: str,
    system_name: str,
    prepared_by: str,
    ref_number: str,
    classification: str,
    frameworks: tuple[str, ...],
    migration_deadline: Optional[str],
    effort_weeks: Optional[int],
    mtu: int,
    tls_ver: str,
    ram_kb: Optional[int],
    protocol: str,
    tags: tuple[str, ...],
) -> None:
    """Generate a CISO-forwardable executive risk memo (HTML).

    This is the artifact a security engineer sends to their boss.
    It reads like a risk memo, not a developer tool output.

    \b
    Examples:
      pqc-sandbox exec-report --classical "ECDSA-P256" --org "Acme Bank" --framework RBI --framework SEBI
      pqc-sandbox exec-report --classical "ECDH-P256" --org "MyFintech" --deadline "Q2 2026" -o memo.html
    """
    from pqc_sandbox.algorithms import ALL_ALGORITHMS
    from pqc_sandbox.benchmarks.runner import run_comparison
    from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints
    from pqc_sandbox.hybrid.simulator import simulate_hybrid
    from pqc_sandbox.scoring import compute_score
    from pqc_sandbox.report.exec_summary import generate_exec_summary, ExecSummaryConfig

    classical, pqc = _resolve_algorithms(classical, pqc)
    constraints = _build_constraints(mtu, tls_ver, ram_kb, protocol, tags)

    console.print(f"\n  Building executive risk memo for [bold]{org}[/bold] ...")
    console.print(f"  Simulating: [cyan]{classical}[/cyan] → [cyan]{pqc}[/cyan]\n")

    comparison = run_comparison(classical, pqc, iterations=30, force_simulate=True)
    compat = run_compat_check(ALL_ALGORITHMS[pqc], constraints)
    hybrid_result = None
    try:
        hybrid_result = simulate_hybrid(classical, pqc, iterations=30, force_simulate=True)
    except ValueError:
        pass
    score = compute_score(comparison=comparison, compat=compat, hybrid=hybrid_result)

    cfg = ExecSummaryConfig(
        org_name=org,
        system_name=system_name,
        prepared_by=prepared_by,
        ref_number=ref_number,
        classification=classification,
        regulatory_frameworks=list(frameworks),
        migration_deadline=migration_deadline,
        estimated_effort_weeks=effort_weeks,
    )

    out_path = Path(output)
    generate_exec_summary(
        comparison=comparison,
        compat=compat,
        hybrid=hybrid_result,
        score=score,
        config=cfg,
        output_path=out_path,
    )

    console.print(f"[green]✓[/green] Executive risk memo saved to [bold cyan]{out_path}[/bold cyan]")
    console.print()
    console.print(f"  Verdict: [bold]{compat.verdict}[/bold]  ·  Score: [bold]{score.score}/100 — {score.label}[/bold]")
    console.print()
    console.print("  [dim]Forward this file to your CISO, CTO, or Board Risk Committee.[/dim]")
    console.print("  [dim]It opens in any browser and prints cleanly to PDF.[/dim]")
    console.print()


# ── scan git ──────────────────────────────────────────────────────────────────

@scan.command("git")
@click.option("--base", default="HEAD~1", show_default=True,
              help="Base git ref to diff against (branch name, commit SHA, HEAD~N)")
@click.option("--repo", default=".", show_default=True,
              help="Path to the git repository root")
@click.option("--full", is_flag=True, default=False,
              help="Scan whole repo, not just changed lines")
@click.option("--json", "output_json", default=None, type=click.Path(),
              help="Write JSON results to file (for CI/CD)")
@click.option("--comment", default=None, type=click.Path(),
              help="Write GitHub/GitLab PR comment markdown to file")
@click.option("--ci", is_flag=True, default=False,
              help="Exit 1 on CAUTION, exit 2 on BLOCKED (for CI gates)")
def scan_git(
    base: str,
    repo: str,
    full: bool,
    output_json: Optional[str],
    comment: Optional[str],
    ci: bool,
) -> None:
    """Scan a git repo (or PR diff) for quantum-vulnerable crypto.

    \b
    Examples:
      pqc-sandbox scan git                        # scan changes vs HEAD~1
      pqc-sandbox scan git --base main            # scan changes vs main branch
      pqc-sandbox scan git --full                 # scan entire repo
      pqc-sandbox scan git --ci                   # exit 2 if BLOCKED (CI gate)
      pqc-sandbox scan git --comment pr.md        # write PR comment to file
    """
    import json as _json
    from rich.table import Table
    from rich import box as rbox
    from pqc_sandbox.integrations.git_scanner import scan_pr
    from pqc_sandbox.integrations.pr_comment import generate_pr_comment

    mode = "full repo" if full else f"diff vs {base}"
    console.print(f"\n  Scanning [bold]{repo}[/bold] ({mode}) for quantum-vulnerable crypto ...\n")

    result = scan_pr(repo_path=repo, base_ref=base, scan_whole_repo=full)

    if result.error:
        console.print(f"  [yellow]Warning:[/yellow] {result.error}")

    # Terminal output
    verdict_style = {"GO": "bold green", "CAUTION": "bold yellow", "BLOCKED": "bold red"}
    verdict_icon  = {"GO": "✓", "CAUTION": "⚠", "BLOCKED": "✗"}
    vstyle = verdict_style.get(result.verdict, "bold")
    vicon  = verdict_icon.get(result.verdict, "·")

    console.print(f"  [{vstyle}]{vicon} {result.verdict}[/{vstyle}]  "
                  f"— {len(result.new_findings)} finding(s) in "
                  f"{result.files_scanned} file(s), {result.lines_scanned:,} lines scanned\n")

    if result.new_findings:
        t = Table(box=rbox.ROUNDED, header_style="bold cyan", show_header=True)
        t.add_column("Severity",  style="bold", width=10)
        t.add_column("Location",  style="dim")
        t.add_column("Algorithm", style="yellow")
        t.add_column("Description")
        t.add_column("Recommended PQC", style="cyan")

        sev_style = {"HIGH": "red", "MEDIUM": "yellow", "INFO": "dim"}
        for f in result.new_findings:
            ss = sev_style.get(f.severity, "")
            pqc = ", ".join(f.recommended_pqc[:2]) if f.recommended_pqc else "—"
            t.add_row(
                f"[{ss}]{f.severity}[/{ss}]",
                f.location,
                f.algorithm,
                f.description[:60],
                pqc,
            )
        console.print(t)
        console.print()

        console.print("  [dim]Add[/dim] [bold]# pqc-sandbox: ignore[/bold] [dim]on a line to suppress a finding.[/dim]")
        console.print()

    # JSON output
    if output_json:
        data = {
            "verdict": result.verdict,
            "findings": [
                {"file": f.file, "line": f.line, "code": f.code,
                 "algorithm": f.algorithm, "severity": f.severity,
                 "description": f.description, "recommended_pqc": f.recommended_pqc}
                for f in result.new_findings
            ],
            "stats": {
                "files_scanned": result.files_scanned,
                "lines_scanned": result.lines_scanned,
                "new_findings": len(result.new_findings),
            },
        }
        Path(output_json).write_text(_json.dumps(data, indent=2))
        console.print(f"[green]✓[/green] JSON → [cyan]{output_json}[/cyan]")

    # PR comment markdown
    if comment:
        md = generate_pr_comment(result)
        Path(comment).write_text(md)
        console.print(f"[green]✓[/green] PR comment → [cyan]{comment}[/cyan]")

    if ci:
        exit_codes = {"GO": 0, "CAUTION": 1, "BLOCKED": 2}
        sys.exit(exit_codes.get(result.verdict, 0))


# ── simulate command ──────────────────────────────────────────────────────────

@main.command("simulate")
@click.argument("endpoint")
@click.option("--port",    "-p",  default=443, show_default=True,
              help="TLS port to probe.")
@click.option("--kem",     default="ML-KEM-768", show_default=True,
              help="PQC KEM algorithm to simulate.")
@click.option("--sig",     default="ML-DSA-44",  show_default=True,
              help="PQC signature algorithm to simulate.")
@click.option("--no-hybrid", "no_hybrid", is_flag=True, default=False,
              help="Simulate PQC-only (no classical hybrid). Not recommended.")
@click.option("--json",    "output_json", is_flag=True, default=False,
              help="Output JSON instead of terminal report.")
@click.option("--out",     default=None, type=click.Path(),
              help="Write report to file (JSON if --json, else HTML).")
@click.option("--ci",      is_flag=True, default=False,
              help="CI mode: exit 0=GO, 1=CAUTION, 2=BLOCKED.")
@click.option("--timeout", default=8.0, show_default=True, type=float,
              help="Connection timeout in seconds.")
def simulate_cmd(endpoint, port, kem, sig, no_hybrid, output_json, out, ci, timeout):
    """
    Simulate a PQC migration on ENDPOINT and prove what will break.

    Probes the live TLS endpoint, then replays the handshake with PQC
    algorithm sizes to show exactly which components will fail in production
    — and hands you the fix.

    \b
    Examples:
      pqc-sandbox simulate api.mybank.com
      pqc-sandbox simulate api.mybank.com --kem ML-KEM-1024 --sig ML-DSA-65
      pqc-sandbox simulate internal.service:8443 --json --ci
    """
    from pqc_sandbox.simulation.tls_sim import simulate_endpoint
    from pqc_sandbox.simulation.report import render_terminal, render_json

    hybrid = not no_hybrid

    console.print()
    console.print(f"  [dim]Probing[/dim] [bold]{endpoint}:{port}[/bold] [dim]…[/dim]")

    try:
        report = simulate_endpoint(
            hostname=endpoint,
            port=port,
            target_kem=kem,
            target_sig=sig,
            hybrid=hybrid,
            timeout=timeout,
        )
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        if ci:
            sys.exit(2)
        return

    if output_json:
        json_str = render_json(report)
        if out:
            from pathlib import Path as _Path
            _Path(out).write_text(json_str)
            console.print(f"[green]✓[/green] JSON → [cyan]{out}[/cyan]")
        else:
            print(json_str)
    else:
        render_terminal(report, console)
        if out:
            # Write HTML version
            from pathlib import Path as _Path
            from pqc_sandbox.simulation.html_report import render_html
            html = render_html(report)
            _Path(out).write_text(html)
            console.print(f"[green]✓[/green] HTML report → [cyan]{out}[/cyan]")

    if ci:
        exit_codes = {"GO": 0, "CAUTION": 1, "BLOCKED": 2}
        sys.exit(exit_codes.get(report.verdict, 0))
