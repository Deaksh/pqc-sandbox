"""
Dry-run report renderer — terminal (Rich) and JSON output.

The primary artifact is an engineer's pre-migration dry-run report:
exactly what will break, ranked by blast radius, with the fix for each.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich import box
from rich.text import Text

if TYPE_CHECKING:
    from pqc_sandbox.simulation.breakage import DryRunReport, BreakageProof

_VERDICT_STYLE = {
    "BLOCKED": ("red",    "✗ BLOCKED"),
    "CAUTION": ("yellow", "⚠ CAUTION"),
    "GO":      ("green",  "✓ GO"),
}

_SEV_STYLE = {
    "BLOCKED": "bold red",
    "CAUTION": "bold yellow",
    "INFO":    "bold blue",
}


def render_terminal(report: "DryRunReport", console: Console | None = None) -> None:
    """Print the dry-run report to the terminal with Rich formatting."""
    if console is None:
        console = Console()

    probe = report.probe
    kem_label = f"X25519+{report.target_kem}" if report.hybrid else report.target_kem

    # ── Header ────────────────────────────────────────────────────────────────
    console.print()
    console.rule(f"[bold]PQC Migration Dry-Run[/bold]  ·  {report.endpoint}:{report.port}", style="dim")
    console.print()

    # Probe summary table
    if probe:
        tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        tbl.add_column("key",   style="dim", width=22)
        tbl.add_column("value", style="bold")

        tbl.add_row("Current TLS",     probe.tls_version)
        tbl.add_row("Current KEM",     probe.kem)
        tbl.add_row("Cert sig",        probe.sig_alg)
        tbl.add_row("Cert chain",      f"{probe.total_cert_bytes:,} bytes (estimated)")
        tbl.add_row("Path MTU",        f"{probe.mtu:,} bytes")
        tbl.add_row("Migrating to",    f"{kem_label}  +  {report.target_sig}")
        if probe.error:
            tbl.add_row("[yellow]Probe note[/yellow]", f"[dim]{probe.error}[/dim]")

        console.print(tbl)
    console.print()

    # ── Verdict banner ────────────────────────────────────────────────────────
    color, label = _VERDICT_STYLE[report.verdict]
    blocked_n = len(report.blocked)
    caution_n = len(report.cautions)
    total_n   = len(report.breaks)

    verdict_text = (
        f"[bold {color}]{label}[/bold {color}]  "
        f"[dim]—[/dim]  "
        f"[bold]{total_n} break{'s' if total_n != 1 else ''}[/bold] found  "
        f"([red]{blocked_n} BLOCKED[/red]  [yellow]{caution_n} CAUTION[/yellow])  "
        f"·  estimated fix effort: [bold]{report.total_effort()}[/bold]"
    )
    console.print(Panel(verdict_text, box=box.ROUNDED, border_style=color))
    console.print()

    if not report.breaks:
        console.print("[green]No migration blockers detected for this endpoint.[/green]")
        console.print("[dim]Run with --all to include informational checks.[/dim]")
        return

    # ── Breakage proofs ───────────────────────────────────────────────────────
    for i, brk in enumerate(report.breaks, 1):
        sev_style = _SEV_STYLE[brk.severity.value]
        sim_tag = "[dim](simulated)[/dim]" if brk.simulated else "[green](measured)[/green]"

        # Section header
        console.print(Rule(
            f"[{sev_style}]{brk.severity.value} {i}/{total_n}[/{sev_style}]  "
            f"[bold]{brk.title}[/bold]  {sim_tag}",
            style="dim"
        ))
        console.print()

        # Component + mechanism
        console.print(f"  [bold]Component:[/bold]  {brk.component}")
        console.print()
        console.print(f"  [bold]Why this breaks:[/bold]")
        for line in brk.mechanism.split(". "):
            if line.strip():
                console.print(f"    {line.strip()}.")
        console.print()

        # Evidence block
        console.print("  [bold]Evidence:[/bold]")
        for line in brk.evidence.strip().splitlines():
            console.print(f"  [cyan]{line}[/cyan]")
        console.print()

        # Blast radius
        console.print("  [bold]Blast radius:[/bold]")
        for item in brk.blast_radius:
            console.print(f"    [dim]•[/dim] {item}")
        console.print()

        # Fix
        console.print(f"  [bold]Fix[/bold]  [dim](effort: {brk.effort})[/dim]")
        console.print(Syntax(brk.fix, "nginx", theme="monokai", line_numbers=False,
                              background_color="default", indent_guides=False))
        console.print()

    # ── Footer ────────────────────────────────────────────────────────────────
    console.print(Rule(style="dim"))
    console.print(
        f"[dim]All size measurements use NIST FIPS 203/204 final parameters. "
        f"Simulated findings use exact algorithm sizes; run with --liboqs for live key operations.[/dim]"
    )
    console.print()


def render_json(report: "DryRunReport") -> str:
    """Render the dry-run report as JSON for CI/CD consumption."""
    probe = report.probe
    exit_code = {"BLOCKED": 2, "CAUTION": 1, "GO": 0}[report.verdict]

    return json.dumps({
        "verdict":       report.verdict,
        "exit_code":     exit_code,
        "endpoint":      report.endpoint,
        "port":          report.port,
        "migration": {
            "target_kem": report.target_kem,
            "target_sig": report.target_sig,
            "hybrid":     report.hybrid,
        },
        "probe": {
            "tls_version":    probe.tls_version if probe else "unknown",
            "current_kem":    probe.kem if probe else "unknown",
            "current_sig":    probe.sig_alg if probe else "unknown",
            "cert_chain_bytes": probe.total_cert_bytes if probe else 0,
            "mtu":            probe.mtu if probe else 1500,
            "error":          probe.error if probe else None,
        } if probe else {},
        "breaks": [
            {
                "id":           b.id,
                "title":        b.title,
                "component":    b.component,
                "severity":     b.severity.value,
                "mechanism":    b.mechanism,
                "evidence":     b.evidence,
                "blast_radius": b.blast_radius,
                "fix":          b.fix,
                "effort":       b.effort,
                "simulated":    b.simulated,
            }
            for b in report.breaks
        ],
        "summary": {
            "total_breaks":   len(report.breaks),
            "blocked":        len(report.blocked),
            "cautions":       len(report.cautions),
            "total_effort":   report.total_effort(),
        },
    }, indent=2)
