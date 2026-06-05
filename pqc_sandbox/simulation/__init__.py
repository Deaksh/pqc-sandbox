"""
pqc_sandbox.simulation — TLS handshake simulation engine.

Proves what actually breaks when you migrate to PQC, before you migrate.
"""
from pqc_sandbox.simulation.breakage import BreakageProof, DryRunReport, Severity
from pqc_sandbox.simulation.tls_sim import simulate_endpoint

__all__ = ["BreakageProof", "DryRunReport", "Severity", "simulate_endpoint"]
