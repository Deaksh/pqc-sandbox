"""Tests for the compatibility oracle."""
import pytest
from pqc_sandbox.compat.oracle import run_compat_check, SystemConstraints, Severity
from pqc_sandbox.algorithms import ALL_ALGORITHMS


def test_no_issues_default():
    profile = ALL_ALGORITHMS["ML-KEM-768"]
    report = run_compat_check(profile, SystemConstraints())
    assert report.verdict in ("GO", "CAUTION", "BLOCKED")


def test_tls_12_caution():
    profile = ALL_ALGORITHMS["ML-KEM-768"]
    report = run_compat_check(profile, SystemConstraints(tls_version="1.2"))
    severities = {i.severity for i in report.issues}
    assert Severity.CAUTION in severities


def test_tls_10_blocked():
    profile = ALL_ALGORITHMS["ML-KEM-768"]
    report = run_compat_check(profile, SystemConstraints(tls_version="1.0"))
    assert report.verdict == "BLOCKED"


def test_low_ram_blocked():
    # SLH-DSA needs ~256 KB stack — a 64 KB device cannot run it
    profile = ALL_ALGORITHMS["SLH-DSA-SHA2-128s"]
    report = run_compat_check(profile, SystemConstraints(ram_kb=64))
    assert report.verdict == "BLOCKED"


def test_dnssec_blocked():
    profile = ALL_ALGORITHMS["ML-DSA-65"]
    report = run_compat_check(profile, SystemConstraints(protocol="dnssec"))
    assert report.verdict == "BLOCKED"


def test_legacy_stack_blocked():
    profile = ALL_ALGORITHMS["ML-KEM-768"]
    report = run_compat_check(
        profile,
        SystemConstraints(tags=["legacy-tls-stack", "openssl-1"]),
    )
    assert report.verdict == "BLOCKED"


def test_mtu_caution():
    profile = ALL_ALGORITHMS["ML-KEM-1024"]
    # Very tight MTU — ML-KEM-1024 ClientHello won't fit
    report = run_compat_check(profile, SystemConstraints(mtu_bytes=576))
    severities = {i.severity for i in report.issues}
    assert Severity.CAUTION in severities or Severity.BLOCKED in severities
