"""
`pqc-sandbox demo` — the 60-second wow moment.
Simulates a full migration on a bundled sample app scenario with no external deps.
"""
from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from pqc_sandbox.algorithms import ALL_ALGORITHMS
from pqc_sandbox.benchmarks.runner import run_comparison
from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints
from pqc_sandbox.hybrid.simulator import simulate_hybrid
from pqc_sandbox.scoring import compute_score
from pqc_sandbox.report.terminal import print_report
from pqc_sandbox.report.html_gen import generate_html
from pqc_sandbox.report.json_out import generate_json
from pqc_sandbox.report.config_diff import generate_config_diff
from pqc_sandbox.report.exec_summary import generate_exec_summary, ExecSummaryConfig


_DEMO_SCENARIOS = [
    {
        "name": "Web API Server (ECDSA-P256 → ML-DSA-44)",
        "classical_kem": "ECDH-P256",
        "classical_sign": "ECDSA-P256",
        "pqc_kem": "ML-KEM-768",
        "pqc_sign": "ML-DSA-44",
        "constraints": SystemConstraints(
            mtu_bytes=1500,
            tls_version="1.3",
            protocol="tls",
            tags=[],
        ),
        "framework": "openssl",
    },
    {
        "name": "IoT / Embedded Device (256 KB RAM)",
        "classical_kem": "ECDH-P256",
        "classical_sign": "ECDSA-P256",
        "pqc_kem": "ML-KEM-512",
        "pqc_sign": "ML-DSA-44",
        "constraints": SystemConstraints(
            mtu_bytes=1500,
            tls_version="1.3",
            protocol="tls",
            ram_kb=256,
            cpu_arch="armv7",
            tags=["embedded", "iot"],
        ),
        "framework": "openssl",
    },
    {
        "name": "Legacy TLS 1.2 Endpoint",
        "classical_kem": "ECDH-P256",
        "classical_sign": "RSA-2048 (PKCS#1 v1.5)",
        "pqc_kem": "ML-KEM-768",
        "pqc_sign": "ML-DSA-65",
        "constraints": SystemConstraints(
            mtu_bytes=1500,
            tls_version="1.2",
            protocol="tls",
            tags=["legacy-tls-stack"],
        ),
        "framework": "nginx",
    },
]


def run_demo(
    console: Console,
    output_html: str | None = None,
    output_json: str | None = None,
    output_exec: str | None = None,
    scenario_index: int = 0,
) -> None:
    scenario = _DEMO_SCENARIOS[scenario_index % len(_DEMO_SCENARIOS)]
    c_kem = scenario["classical_kem"]
    c_sign = scenario["classical_sign"]
    p_kem = scenario["pqc_kem"]
    p_sign = scenario["pqc_sign"]
    constraints = scenario["constraints"]
    framework = scenario["framework"]

    console.print()
    console.rule(f"[bold cyan]pqc-sandbox demo — {scenario['name']}[/bold cyan]")
    console.print()
    console.print("  [dim]Zero cloud · Zero telemetry · Runs entirely on your machine[/dim]")
    console.print()

    steps = [
        "Benchmarking KEM algorithms ...",
        "Benchmarking signature algorithms ...",
        "Simulating hybrid key exchange ...",
        "Running compatibility oracle ...",
        "Computing migration difficulty score ...",
        "Generating reports ...",
    ]

    results: dict = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("", total=len(steps))

        progress.update(task, description=steps[0])
        kem_cmp = run_comparison(c_kem, p_kem, iterations=30, force_simulate=True)
        time.sleep(0.3)
        progress.advance(task)

        progress.update(task, description=steps[1])
        sign_cmp = run_comparison(c_sign, p_sign, iterations=30, force_simulate=True)
        time.sleep(0.3)
        progress.advance(task)

        progress.update(task, description=steps[2])
        hybrid_result = simulate_hybrid(c_kem, p_kem, iterations=30, force_simulate=True)
        time.sleep(0.3)
        progress.advance(task)

        progress.update(task, description=steps[3])
        kem_compat = run_compat_check(ALL_ALGORITHMS[p_kem], constraints)
        sign_compat = run_compat_check(ALL_ALGORITHMS[p_sign], constraints)
        # Merge issues into one report (use kem_compat as primary)
        kem_compat.issues.extend(sign_compat.issues)
        kem_compat.__post_init__()
        time.sleep(0.3)
        progress.advance(task)

        progress.update(task, description=steps[4])
        score = compute_score(comparison=kem_cmp, compat=kem_compat, hybrid=hybrid_result)
        time.sleep(0.2)
        progress.advance(task)

        progress.update(task, description=steps[5])
        time.sleep(0.2)
        progress.advance(task)

    # Print KEM comparison
    print_report(comparison=kem_cmp, console=console)
    print_report(comparison=sign_cmp, console=console)
    print_report(hybrid=hybrid_result, compat=kem_compat, score=score, console=console)

    # Config diff
    console.print()
    console.rule("[bold]Copy-paste Config Diff[/bold]")
    console.print()
    diff = generate_config_diff(ALL_ALGORITHMS[c_kem], ALL_ALGORITHMS[p_kem], framework=framework)
    console.print(diff, style="dim")
    console.print()

    if output_html:
        html_path = Path(output_html)
        generate_html(
            comparison=kem_cmp,
            compat=kem_compat,
            hybrid=hybrid_result,
            score=score,
            output_path=html_path,
        )
        console.print(f"[green]✓[/green] HTML report saved to [cyan]{html_path}[/cyan]")

    if output_json:
        json_path = Path(output_json)
        generate_json(
            comparison=kem_cmp,
            compat=kem_compat,
            hybrid=hybrid_result,
            score=score,
            output_path=json_path,
        )
        console.print(f"[green]✓[/green] JSON report saved to [cyan]{json_path}[/cyan]")

    exec_path = Path(output_exec) if output_exec else Path("pqc_risk_memo_demo.html")
    exec_cfg = ExecSummaryConfig(
        org_name="Demo Organisation",
        system_name=scenario["name"],
        prepared_by="pqc-sandbox demo",
        regulatory_frameworks=["RBI", "CERT-In"],
        migration_deadline="Q4 2026",
    )
    generate_exec_summary(
        comparison=kem_cmp,
        compat=kem_compat,
        hybrid=hybrid_result,
        score=score,
        config=exec_cfg,
        output_path=exec_path,
    )
    console.print(f"[green]✓[/green] Executive risk memo saved to [cyan]{exec_path}[/cyan]")
    console.print("  [dim]→ Forward this to your CISO / CTO. Opens in browser, prints to PDF.[/dim]")

    console.print()
    console.rule("[dim]pqc-sandbox · Apache 2.0 · https://github.com/pqc-sandbox/pqc-sandbox[/dim]")
    console.print()
