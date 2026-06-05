"""
Benchmark engine: runs keygen / encap / decap (or sign / verify) loops
using either liboqs-python (when installed) or pure-Python simulated timing
derived from published NIST reference benchmarks.
"""
from __future__ import annotations

import math
import os
import statistics
import time
from dataclasses import dataclass, field
from typing import Optional

import psutil

from pqc_sandbox.algorithms import AlgorithmProfile, ALL_ALGORITHMS

# Attempt to import liboqs; fall back to simulation mode.
try:
    import oqs  # type: ignore
    _OQS_AVAILABLE = True
except ImportError:
    _OQS_AVAILABLE = False

# Warmup + measurement iterations
_WARMUP = 3
_ITERS = 50


@dataclass
class BenchmarkResult:
    algorithm: str
    category: str           # kem | sign
    is_pqc: bool
    # Timing (ms per op, median over _ITERS)
    keygen_ms: float
    operation1_ms: float    # encap or sign
    operation2_ms: float    # decap or verify
    # Sizes (bytes)
    public_key_bytes: int
    private_key_bytes: int
    artifact_bytes: int     # ciphertext or signature
    # System
    cpu_percent: float
    rss_delta_kb: int
    # Source
    oqs_used: bool
    iterations: int = _ITERS
    error: Optional[str] = None
    raw_keygen_ms: list[float] = field(default_factory=list)
    raw_op1_ms: list[float] = field(default_factory=list)
    raw_op2_ms: list[float] = field(default_factory=list)

    @property
    def keygen_ops_sec(self) -> float:
        return 1_000 / self.keygen_ms if self.keygen_ms > 0 else 0.0

    @property
    def op1_ops_sec(self) -> float:
        return 1_000 / self.operation1_ms if self.operation1_ms > 0 else 0.0

    @property
    def op2_ops_sec(self) -> float:
        return 1_000 / self.operation2_ms if self.operation2_ms > 0 else 0.0


def _median_ms(times_ns: list[int]) -> float:
    return statistics.median(times_ns) / 1_000_000


def _run_oqs_kem(oqs_name: str, iters: int) -> tuple[list[int], list[int], list[int], int, int, int]:
    keygen_ns: list[int] = []
    encap_ns: list[int] = []
    decap_ns: list[int] = []
    pub_len = priv_len = ct_len = 0

    for i in range(iters + _WARMUP):
        with oqs.KeyEncapsulation(oqs_name) as kem:
            t0 = time.perf_counter_ns()
            pub = kem.generate_keypair()
            t1 = time.perf_counter_ns()
            ct, ss = kem.encap_secret(pub)
            t2 = time.perf_counter_ns()
            kem.decap_secret(ct)
            t3 = time.perf_counter_ns()

            if i >= _WARMUP:
                keygen_ns.append(t1 - t0)
                encap_ns.append(t2 - t1)
                decap_ns.append(t3 - t2)
                pub_len = len(pub)
                priv_len = kem.details["length_secret_key"]
                ct_len = len(ct)

    return keygen_ns, encap_ns, decap_ns, pub_len, priv_len, ct_len


def _run_oqs_sign(oqs_name: str, iters: int) -> tuple[list[int], list[int], list[int], int, int, int]:
    keygen_ns: list[int] = []
    sign_ns: list[int] = []
    verify_ns: list[int] = []
    pub_len = priv_len = sig_len = 0
    msg = b"pqc-sandbox benchmark message" * 4

    for i in range(iters + _WARMUP):
        with oqs.Signature(oqs_name) as signer:
            t0 = time.perf_counter_ns()
            pub = signer.generate_keypair()
            t1 = time.perf_counter_ns()
            sig = signer.sign(msg)
            t2 = time.perf_counter_ns()
            signer.verify(msg, sig, pub)
            t3 = time.perf_counter_ns()

            if i >= _WARMUP:
                keygen_ns.append(t1 - t0)
                sign_ns.append(t2 - t1)
                verify_ns.append(t3 - t2)
                pub_len = len(pub)
                priv_len = signer.details["length_secret_key"]
                sig_len = len(sig)

    return keygen_ns, sign_ns, verify_ns, pub_len, priv_len, sig_len


def _simulate_kem(profile: AlgorithmProfile, iters: int) -> tuple[list[int], list[int], list[int], int, int, int]:
    """Return synthetic timings derived from published ops/sec baselines with ±5% jitter."""
    import random
    rng = random.Random(42)

    def _times(ops_sec: float) -> list[int]:
        base_ns = int(1_000_000_000 / max(ops_sec, 1))
        return [int(base_ns * rng.uniform(0.95, 1.05)) for _ in range(iters)]

    kg = _times(profile.keygen_ops_sec)
    en = _times(profile.encap_ops_sec)
    de = _times(profile.decap_ops_sec)
    return kg, en, de, profile.public_key_bytes, profile.private_key_bytes, profile.ciphertext_bytes


def _simulate_sign(profile: AlgorithmProfile, iters: int) -> tuple[list[int], list[int], list[int], int, int, int]:
    import random
    rng = random.Random(42)

    def _times(ops_sec: float) -> list[int]:
        base_ns = int(1_000_000_000 / max(ops_sec, 1))
        return [int(base_ns * rng.uniform(0.95, 1.05)) for _ in range(iters)]

    kg = _times(profile.keygen_ops_sec)
    sg = _times(profile.encap_ops_sec)
    vf = _times(profile.decap_ops_sec)
    return kg, sg, vf, profile.public_key_bytes, profile.private_key_bytes, profile.signature_bytes


def run_benchmark(
    algorithm_name: str,
    iterations: int = _ITERS,
    force_simulate: bool = False,
) -> BenchmarkResult:
    profile = ALL_ALGORITHMS.get(algorithm_name)
    if profile is None:
        raise ValueError(f"Unknown algorithm: {algorithm_name!r}")

    proc = psutil.Process(os.getpid())
    rss_before = proc.memory_info().rss
    cpu_before = psutil.cpu_percent(interval=None)

    use_oqs = _OQS_AVAILABLE and not force_simulate and profile.oqs_name is not None
    error: Optional[str] = None

    try:
        if use_oqs:
            if profile.category == "kem":
                kg, op1, op2, pub, priv, art = _run_oqs_kem(profile.oqs_name, iterations)
            else:
                kg, op1, op2, pub, priv, art = _run_oqs_sign(profile.oqs_name, iterations)
        else:
            if profile.category == "kem":
                kg, op1, op2, pub, priv, art = _simulate_kem(profile, iterations)
            else:
                kg, op1, op2, pub, priv, art = _simulate_sign(profile, iterations)
            if not _OQS_AVAILABLE:
                error = "liboqs not installed — using simulated timings from NIST benchmarks"
    except Exception as exc:
        error = f"OQS error ({exc}), falling back to simulation"
        use_oqs = False
        if profile.category == "kem":
            kg, op1, op2, pub, priv, art = _simulate_kem(profile, iterations)
        else:
            kg, op1, op2, pub, priv, art = _simulate_sign(profile, iterations)

    rss_after = proc.memory_info().rss
    cpu_after = psutil.cpu_percent(interval=None)

    return BenchmarkResult(
        algorithm=algorithm_name,
        category=profile.category,
        is_pqc=profile.is_pqc,
        keygen_ms=_median_ms(kg),
        operation1_ms=_median_ms(op1),
        operation2_ms=_median_ms(op2),
        public_key_bytes=pub,
        private_key_bytes=priv,
        artifact_bytes=art,
        cpu_percent=max(0.0, cpu_after - cpu_before),
        rss_delta_kb=max(0, (rss_after - rss_before) // 1_024),
        oqs_used=use_oqs,
        iterations=iterations,
        error=error,
        raw_keygen_ms=[t / 1_000_000 for t in kg],
        raw_op1_ms=[t / 1_000_000 for t in op1],
        raw_op2_ms=[t / 1_000_000 for t in op2],
    )


@dataclass
class ComparisonResult:
    classical: BenchmarkResult
    pqc: BenchmarkResult
    # Deltas (pqc - classical)
    keygen_delta_ms: float = 0.0
    op1_delta_ms: float = 0.0
    op2_delta_ms: float = 0.0
    pubkey_delta_bytes: int = 0
    artifact_delta_bytes: int = 0
    privkey_delta_bytes: int = 0
    keygen_slowdown: float = 1.0   # pqc / classical ratio
    op1_slowdown: float = 1.0
    op2_slowdown: float = 1.0
    pubkey_ratio: float = 1.0
    artifact_ratio: float = 1.0

    def __post_init__(self) -> None:
        c, p = self.classical, self.pqc
        self.keygen_delta_ms = p.keygen_ms - c.keygen_ms
        self.op1_delta_ms = p.operation1_ms - c.operation1_ms
        self.op2_delta_ms = p.operation2_ms - c.operation2_ms
        self.pubkey_delta_bytes = p.public_key_bytes - c.public_key_bytes
        self.artifact_delta_bytes = p.artifact_bytes - c.artifact_bytes
        self.privkey_delta_bytes = p.private_key_bytes - c.private_key_bytes
        self.keygen_slowdown = _safe_ratio(p.keygen_ms, c.keygen_ms)
        self.op1_slowdown = _safe_ratio(p.operation1_ms, c.operation1_ms)
        self.op2_slowdown = _safe_ratio(p.operation2_ms, c.operation2_ms)
        self.pubkey_ratio = _safe_ratio(p.public_key_bytes, c.public_key_bytes)
        self.artifact_ratio = _safe_ratio(p.artifact_bytes, c.artifact_bytes)


def _safe_ratio(a: float, b: float) -> float:
    return a / b if b > 0 else math.inf


def run_comparison(
    classical_name: str,
    pqc_name: str,
    iterations: int = _ITERS,
    force_simulate: bool = False,
) -> ComparisonResult:
    classical = run_benchmark(classical_name, iterations, force_simulate)
    pqc = run_benchmark(pqc_name, iterations, force_simulate)
    return ComparisonResult(classical=classical, pqc=pqc)
