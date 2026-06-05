"""
Hybrid key exchange / signature simulation.

In hybrid mode the handshake carries BOTH the classical and PQC key material.
The shared secret is derived by combining (via HKDF or XOR) the outputs of both.
This is the recommended NIST transitional approach (CNSA 2.0).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pqc_sandbox.algorithms import (
    AlgorithmProfile,
    ALL_ALGORITHMS,
    HYBRID_COMBOS,
)
from pqc_sandbox.benchmarks.runner import BenchmarkResult, run_benchmark


@dataclass
class HybridResult:
    classical_name: str
    pqc_name: str
    label: str

    # Combined sizes (bytes)
    combined_pubkey_bytes: int
    combined_privkey_bytes: int
    combined_artifact_bytes: int   # ciphertext or sig
    wire_overhead_bytes: int       # extra bytes vs pure classical

    # Combined timing (ms) — hybrid is classical + pqc, sequentially
    combined_keygen_ms: float
    combined_op1_ms: float         # encap+encap or sign+sign
    combined_op2_ms: float         # decap+decap or verify+verify

    # Per-component benchmarks
    classical_bench: BenchmarkResult
    pqc_bench: BenchmarkResult

    # KDF overhead (negligible, shown for completeness)
    kdf_overhead_ms: float = 0.05

    oqs_used: bool = False
    error: Optional[str] = None

    @property
    def category(self) -> str:
        return self.classical_bench.category

    @property
    def total_op1_ms(self) -> float:
        return self.combined_op1_ms + self.kdf_overhead_ms

    @property
    def latency_vs_classical_ms(self) -> float:
        return self.combined_op1_ms - self.classical_bench.operation1_ms


def simulate_hybrid(
    classical_name: str,
    pqc_name: str,
    iterations: int = 50,
    force_simulate: bool = False,
) -> HybridResult:
    c_profile = ALL_ALGORITHMS.get(classical_name)
    p_profile = ALL_ALGORITHMS.get(pqc_name)
    if c_profile is None:
        raise ValueError(f"Unknown classical algorithm: {classical_name!r}")
    if p_profile is None:
        raise ValueError(f"Unknown PQC algorithm: {pqc_name!r}")
    if c_profile.category != p_profile.category:
        raise ValueError(
            f"Category mismatch: {classical_name} is {c_profile.category}, "
            f"{pqc_name} is {p_profile.category}"
        )

    label = HYBRID_COMBOS.get((classical_name, pqc_name), f"{classical_name}+{pqc_name}")

    c_bench = run_benchmark(classical_name, iterations, force_simulate)
    p_bench = run_benchmark(pqc_name, iterations, force_simulate)

    # Hybrid wire format: both key shares concatenated + 4-byte length framing each
    FRAME = 4
    combined_pubkey = c_profile.public_key_bytes + p_profile.public_key_bytes + FRAME * 2
    combined_privkey = c_profile.private_key_bytes + p_profile.private_key_bytes
    if c_profile.category == "kem":
        combined_artifact = c_profile.ciphertext_bytes + p_profile.ciphertext_bytes + FRAME * 2
    else:
        combined_artifact = c_profile.signature_bytes + p_profile.signature_bytes + FRAME * 2

    classical_only_artifact = (
        c_profile.ciphertext_bytes if c_profile.category == "kem" else c_profile.signature_bytes
    )
    wire_overhead = combined_artifact - classical_only_artifact

    # Timings: both operations run sequentially in the hybrid handshake
    combined_keygen = c_bench.keygen_ms + p_bench.keygen_ms
    combined_op1 = c_bench.operation1_ms + p_bench.operation1_ms
    combined_op2 = c_bench.operation2_ms + p_bench.operation2_ms

    error = c_bench.error or p_bench.error

    return HybridResult(
        classical_name=classical_name,
        pqc_name=pqc_name,
        label=label,
        combined_pubkey_bytes=combined_pubkey,
        combined_privkey_bytes=combined_privkey,
        combined_artifact_bytes=combined_artifact,
        wire_overhead_bytes=wire_overhead,
        combined_keygen_ms=combined_keygen,
        combined_op1_ms=combined_op1,
        combined_op2_ms=combined_op2,
        classical_bench=c_bench,
        pqc_bench=p_bench,
        oqs_used=c_bench.oqs_used or p_bench.oqs_used,
        error=error,
    )
