"""Tests for hybrid simulation."""
import pytest
from pqc_sandbox.hybrid.simulator import simulate_hybrid


def test_hybrid_kem():
    r = simulate_hybrid("ECDH-P256", "ML-KEM-768", iterations=5, force_simulate=True)
    assert r.combined_artifact_bytes > r.classical_bench.artifact_bytes
    assert r.combined_artifact_bytes > r.pqc_bench.artifact_bytes
    assert r.wire_overhead_bytes > 0
    assert r.combined_op1_ms > 0


def test_hybrid_label():
    r = simulate_hybrid("ECDH-P256", "ML-KEM-768", iterations=5, force_simulate=True)
    assert "ML-KEM" in r.label or "P256" in r.label


def test_hybrid_category_mismatch():
    with pytest.raises(ValueError, match="Category mismatch"):
        simulate_hybrid("ECDH-P256", "ML-DSA-65", iterations=5, force_simulate=True)
