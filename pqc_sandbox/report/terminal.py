"""
Rich terminal report renderer.
"""
from __future__ import annotations

from typing import Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pqc_sandbox.benchmarks.runner import ComparisonResult
from pqc_sandbox.compat.oracle import CompatReport, Severity
from pqc_sandbox.hybrid.simulator import HybridResult
from pqc_sandbox.scoring import MigrationScore

VERDICT_STYLE = {
    "GO":      ("bold green", "✓ GO"),
    "CAUTION": ("bold yellow", "⚠ CAUTION"),
    "BLOCKED": ("bold red", "✗ BLOCKED"),
}

_CONSOLE = Console()


def _fmt_bytes(n: int) -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB"
    if n >= 1_024:
        return f"{n / 1_024:.1f} KB"
    return f"{n} B"


def _fmt_delta(n: float, unit: str = "", positive_is_bad: bool = True) -> str:
    prefix = "+" if n >= 0 else ""
    style = "red" if (n > 0 and positive_is_bad) or (n < 0 and not positive_is_bad) else "green"
    return f"[{style}]{prefix}{n:.2f}{unit}[/{style}]"


def _fmt_int_delta(n: int, unit: str = "", positive_is_bad: bool = True) -> str:
    prefix = "+" if n >= 0 else ""
    style = "red" if (n > 0 and positive_is_bad) else "green"
    return f"[{style}]{prefix}{n:,}{unit}[/{style}]"


def print_report(
    comparison: Optional[ComparisonResult] = None,
    compat: Optional[CompatReport] = None,
    hybrid: Optional[HybridResult] = None,
    score: Optional[MigrationScore] = None,
    console: Optional[Console] = None,
) -> None:
    c = console or _CONSOLE

    c.print()
    c.rule("[bold cyan]pqc-sandbox  ·  Post-Quantum Migration Impact Report[/bold cyan]")
    c.print()

    # ── Benchmark comparison table ──────────────────────────────────────────
    if comparison:
        cl = comparison.classical
        pq = comparison.pqc

        t = Table(
            title=f"[bold]Side-by-Side Benchmark:[/bold] {cl.algorithm} vs {pq.algorithm}",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        t.add_column("Metric", style="bold")
        t.add_column(f"Classical\n{cl.algorithm}", justify="right")
        t.add_column(f"PQC\n{pq.algorithm}", justify="right")
        t.add_column("Delta", justify="right")
        t.add_column("Ratio", justify="right")

        def add_timing(label: str, c_ms: float, p_ms: float) -> None:
            ratio = p_ms / c_ms if c_ms > 0 else 0
            ratio_str = f"[red]{ratio:.1f}×[/red]" if ratio > 2 else f"[green]{ratio:.1f}×[/green]"
            t.add_row(
                label,
                f"{c_ms:.3f} ms",
                f"{p_ms:.3f} ms",
                _fmt_delta(p_ms - c_ms, " ms"),
                ratio_str,
            )

        def add_size(label: str, c_b: int, p_b: int) -> None:
            ratio = p_b / c_b if c_b > 0 else 0
            ratio_str = f"[red]{ratio:.1f}×[/red]" if ratio > 3 else f"[green]{ratio:.1f}×[/green]"
            t.add_row(
                label,
                _fmt_bytes(c_b),
                _fmt_bytes(p_b),
                _fmt_int_delta(p_b - c_b, " B"),
                ratio_str,
            )

        add_timing("KeyGen", cl.keygen_ms, pq.keygen_ms)
        if pq.category == "kem":
            add_timing("Encapsulate", cl.operation1_ms, pq.operation1_ms)
            add_timing("Decapsulate", cl.operation2_ms, pq.operation2_ms)
        else:
            add_timing("Sign", cl.operation1_ms, pq.operation1_ms)
            add_timing("Verify", cl.operation2_ms, pq.operation2_ms)

        t.add_section()
        add_size("Public Key", cl.public_key_bytes, pq.public_key_bytes)
        add_size("Private Key", cl.private_key_bytes, pq.private_key_bytes)
        if pq.category == "kem":
            add_size("Ciphertext", cl.artifact_bytes, pq.artifact_bytes)
        else:
            add_size("Signature", cl.artifact_bytes, pq.artifact_bytes)

        source = "[dim](liboqs)[/dim]" if pq.oqs_used else "[dim](simulated)[/dim]"
        c.print(t)
        c.print(f"  Benchmark source: {source}", style="dim")
        if pq.error:
            c.print(f"  [yellow]Note:[/yellow] {pq.error}", style="dim")
        c.print()

    # ── Hybrid mode panel ───────────────────────────────────────────────────
    if hybrid:
        ht = Table(
            title=f"[bold]Hybrid Mode:[/bold] {hybrid.label}",
            box=box.SIMPLE,
            header_style="bold magenta",
        )
        ht.add_column("Component", style="bold")
        ht.add_column("Keygen (ms)", justify="right")
        ht.add_column("Op1 (ms)", justify="right")
        ht.add_column("Op2 (ms)", justify="right")
        ht.add_column("Wire artifact", justify="right")

        ht.add_row(
            hybrid.classical_name,
            f"{hybrid.classical_bench.keygen_ms:.3f}",
            f"{hybrid.classical_bench.operation1_ms:.3f}",
            f"{hybrid.classical_bench.operation2_ms:.3f}",
            _fmt_bytes(hybrid.classical_bench.artifact_bytes),
        )
        ht.add_row(
            hybrid.pqc_name,
            f"{hybrid.pqc_bench.keygen_ms:.3f}",
            f"{hybrid.pqc_bench.operation1_ms:.3f}",
            f"{hybrid.pqc_bench.operation2_ms:.3f}",
            _fmt_bytes(hybrid.pqc_bench.artifact_bytes),
        )
        ht.add_section()
        ht.add_row(
            "[bold]HYBRID TOTAL[/bold]",
            f"[bold]{hybrid.combined_keygen_ms:.3f}[/bold]",
            f"[bold]{hybrid.combined_op1_ms:.3f}[/bold]",
            f"[bold]{hybrid.combined_op2_ms:.3f}[/bold]",
            f"[bold]{_fmt_bytes(hybrid.combined_artifact_bytes)}[/bold]",
        )
        ht.add_row(
            "  vs. classical alone",
            "",
            _fmt_delta(hybrid.latency_vs_classical_ms, " ms"),
            "",
            _fmt_int_delta(hybrid.wire_overhead_bytes, " B"),
        )

        c.print(ht)
        c.print()

    # ── Compatibility issues ────────────────────────────────────────────────
    if compat:
        style_map = {
            Severity.BLOCKED: "bold red",
            Severity.CAUTION: "bold yellow",
            Severity.INFO:    "cyan",
            Severity.OK:      "green",
        }
        icon_map = {
            Severity.BLOCKED: "✗",
            Severity.CAUTION: "⚠",
            Severity.INFO:    "ℹ",
            Severity.OK:      "✓",
        }
        if compat.issues:
            c.print(Panel(
                "\n".join(
                    f"[{style_map[i.severity]}]{icon_map[i.severity]} [{i.category.upper()}] {i.title}[/{style_map[i.severity]}]\n"
                    f"   {i.detail}\n"
                    + (f"   [dim]Mitigation:[/dim] {i.mitigation}" if i.mitigation else "")
                    for i in compat.issues
                ),
                title="[bold]Compatibility Issues[/bold]",
                border_style="yellow",
            ))
        else:
            c.print(Panel("[green]✓ No compatibility issues detected.[/green]",
                          title="Compatibility", border_style="green"))
        c.print()

    # ── Verdict & score ─────────────────────────────────────────────────────
    if score:
        label_style, label_text = ("bold green", f"● SCORE {score.score}/100 — {score.label}")
        if score.label == "MODERATE":
            label_style = "bold yellow"
        elif score.label == "HARD":
            label_style = "bold dark_orange"
        elif score.label == "CRITICAL":
            label_style = "bold red"

        score_lines = [f"[{label_style}]{label_text}[/{label_style}]", ""]
        for bullet in score.rationale:
            score_lines.append(f"  • {bullet}")
        score_lines += [
            "",
            f"[dim]Badge markdown:[/dim]",
            f"[cyan]{score.badge_markdown}[/cyan]",
        ]
        c.print(Panel(
            "\n".join(score_lines),
            title="[bold]Migration Difficulty Score[/bold]",
            border_style="cyan",
        ))

    if compat:
        verdict = compat.verdict
        vstyle, vtext = VERDICT_STYLE.get(verdict, ("bold", verdict))
        c.print()
        c.rule()
        c.print(f"  [{vstyle}]{vtext}[/{vstyle}]", justify="center")
        c.rule()

    c.print()
