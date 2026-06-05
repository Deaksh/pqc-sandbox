"""Tests for the migration difficulty scoring."""
from pqc_sandbox.benchmarks.runner import run_comparison
from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints
from pqc_sandbox.hybrid.simulator import simulate_hybrid
from pqc_sandbox.scoring import compute_score
from pqc_sandbox.algorithms import ALL_ALGORITHMS


def test_score_range():
    cmp = run_comparison("ECDH-P256", "ML-KEM-768", iterations=5, force_simulate=True)
    compat = run_compat_check(ALL_ALGORITHMS["ML-KEM-768"], SystemConstraints())
    score = compute_score(comparison=cmp, compat=compat)
    assert 0 <= score.score <= 100
    assert score.label in ("EASY", "MODERATE", "HARD", "CRITICAL")


def test_blocked_increases_score():
    compat_blocked = run_compat_check(
        ALL_ALGORITHMS["ML-KEM-768"],
        SystemConstraints(tls_version="1.0"),
    )
    compat_ok = run_compat_check(
        ALL_ALGORITHMS["ML-KEM-768"],
        SystemConstraints(tls_version="1.3"),
    )
    cmp = run_comparison("ECDH-P256", "ML-KEM-768", iterations=5, force_simulate=True)
    score_blocked = compute_score(comparison=cmp, compat=compat_blocked)
    score_ok = compute_score(comparison=cmp, compat=compat_ok)
    assert score_blocked.score >= score_ok.score


def test_badge_markdown_format():
    cmp = run_comparison("ECDH-P256", "ML-KEM-768", iterations=5, force_simulate=True)
    score = compute_score(comparison=cmp)
    md = score.badge_markdown
    assert md.startswith("![PQC Migration:")
    assert "shields.io" in score.badge_url


def test_slh_dsa_sign_score_high():
    # SLH-DSA is slow to sign — should score higher than ML-DSA
    cmp_slh = run_comparison("ECDSA-P256", "SLH-DSA-SHA2-128s", iterations=5, force_simulate=True)
    cmp_mldsa = run_comparison("ECDSA-P256", "ML-DSA-44", iterations=5, force_simulate=True)
    score_slh = compute_score(comparison=cmp_slh)
    score_mldsa = compute_score(comparison=cmp_mldsa)
    # SLH-DSA should score harder due to larger sig and slower signing
    assert score_slh.score >= score_mldsa.score
