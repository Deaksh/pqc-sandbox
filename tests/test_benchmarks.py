"""Tests for the benchmark engine (simulated mode — no liboqs required)."""
import pytest
from pqc_sandbox.benchmarks.runner import run_benchmark, run_comparison, ComparisonResult


def test_benchmark_classical_kem():
    r = run_benchmark("ECDH-P256", iterations=5, force_simulate=True)
    assert r.keygen_ms > 0
    assert r.operation1_ms > 0
    assert r.public_key_bytes == 65
    assert r.category == "kem"
    assert not r.is_pqc


def test_benchmark_pqc_kem():
    r = run_benchmark("ML-KEM-768", iterations=5, force_simulate=True)
    assert r.keygen_ms > 0
    assert r.public_key_bytes == 1_184
    assert r.is_pqc
    assert r.category == "kem"


def test_benchmark_classical_sign():
    r = run_benchmark("ECDSA-P256", iterations=5, force_simulate=True)
    assert r.category == "sign"
    assert r.artifact_bytes == 72


def test_benchmark_pqc_sign():
    r = run_benchmark("ML-DSA-65", iterations=5, force_simulate=True)
    assert r.category == "sign"
    assert r.artifact_bytes == 3_293
    assert r.is_pqc


def test_comparison_kem():
    cmp = run_comparison("ECDH-P256", "ML-KEM-768", iterations=5, force_simulate=True)
    assert isinstance(cmp, ComparisonResult)
    # ML-KEM-768 public key is much larger than ECDH-P256
    assert cmp.pubkey_delta_bytes > 0
    assert cmp.artifact_ratio > 5


def test_comparison_sign():
    cmp = run_comparison("ECDSA-P256", "ML-DSA-44", iterations=5, force_simulate=True)
    # ML-DSA-44 signature is ~34x larger than ECDSA
    assert cmp.artifact_ratio > 10


def test_unknown_algorithm():
    with pytest.raises(ValueError, match="Unknown algorithm"):
        run_benchmark("SomeRandomAlgo", iterations=5, force_simulate=True)
