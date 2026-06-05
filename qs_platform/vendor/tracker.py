"""
Vendor/supply-chain PQC risk tracker.

The key insight: a bank's PQC migration is blocked if their payment processor,
HSM vendor, CA, or SaaS API doesn't support PQC. This module tracks that.

For each vendor:
  - Probe their TLS endpoint to detect their current crypto
  - Check their announced PQC roadmap (from our knowledge base + manual input)
  - Flag which vendors are BLOCKING your migration
  - Track roadmap commitments and expected dates
"""
from __future__ import annotations

import datetime
import ssl
import socket
from dataclasses import dataclass, field
from typing import Optional

from pqc_sandbox.inputs.tls_probe import probe_tls_endpoint


# ── Known vendor PQC roadmaps (public information) ────────────────────────────

_VENDOR_ROADMAPS: dict[str, dict] = {
    "aws.amazon.com": {
        "pqc_support": "partial",
        "tls_pqc": True,
        "notes": "AWS supports X25519Kyber768 (hybrid) in ACM and CloudFront as of 2024. S2N-TLS has ML-KEM support.",
        "expected_full": "2025",
        "reference": "https://aws.amazon.com/security/post-quantum-cryptography/",
    },
    "cloud.google.com": {
        "pqc_support": "partial",
        "tls_pqc": True,
        "notes": "Google has deployed X25519Kyber768 in Chrome and internal infrastructure. GCP TLS support in preview.",
        "expected_full": "2025",
        "reference": "https://cloud.google.com/blog/products/identity-security/post-quantum-cryptography",
    },
    "azure.microsoft.com": {
        "pqc_support": "partial",
        "tls_pqc": False,
        "notes": "Microsoft has PQC in research phase. Azure TLS PQC support not yet GA.",
        "expected_full": "2026",
        "reference": "https://www.microsoft.com/en-us/security/blog/2023/07/18/pqc-preparations/",
    },
    "cloudflare.com": {
        "pqc_support": "yes",
        "tls_pqc": True,
        "notes": "Cloudflare supports X25519Kyber768 hybrid KEM in TLS 1.3. ML-KEM-768 support added in 2024.",
        "expected_full": "2024",
        "reference": "https://blog.cloudflare.com/post-quantum-for-all/",
    },
    "letsencrypt.org": {
        "pqc_support": "planned",
        "tls_pqc": False,
        "notes": "Let's Encrypt has not yet issued PQC certificates. Tracking NIST standards, expected 2026.",
        "expected_full": "2026",
        "reference": "https://letsencrypt.org/post-quantum/",
    },
    "digicert.com": {
        "pqc_support": "partial",
        "tls_pqc": False,
        "notes": "DigiCert offers PQC trial certificates. Production PQC cert issuance planned 2025-2026.",
        "expected_full": "2026",
        "reference": "https://www.digicert.com/blog/what-is-post-quantum-cryptography",
    },
    "entrust.com": {
        "pqc_support": "partial",
        "tls_pqc": False,
        "notes": "Entrust has PQC-ready PKI in beta. CA/Browser Forum PQC cert profile still being standardised.",
        "expected_full": "2026",
        "reference": "https://www.entrust.com/digital-security/certificate-solutions/resources/white-papers/post-quantum",
    },
    "stripe.com": {
        "pqc_support": "none",
        "tls_pqc": False,
        "notes": "Stripe has not announced PQC TLS support. Standard classical TLS 1.3 as of 2025.",
        "expected_full": "unknown",
        "reference": "",
    },
    "razorpay.com": {
        "pqc_support": "none",
        "tls_pqc": False,
        "notes": "Razorpay has not announced PQC support. RBI requirements may force timeline.",
        "expected_full": "unknown",
        "reference": "",
    },
    "payu.in": {
        "pqc_support": "none",
        "tls_pqc": False,
        "notes": "PayU India has not announced PQC support.",
        "expected_full": "unknown",
        "reference": "",
    },
    "npci.org.in": {
        "pqc_support": "planned",
        "tls_pqc": False,
        "notes": "NPCI (UPI, IMPS, NFS) is expected to require PQC support per RBI mandate. Timeline TBD.",
        "expected_full": "FY2027",
        "reference": "https://www.npci.org.in/",
    },
    # HSM vendors
    "thales.com": {
        "pqc_support": "partial",
        "tls_pqc": False,
        "notes": "Thales Luna HSM 7.x supports ML-KEM and ML-DSA in firmware 7.8+. FIPS 140-3 validation in progress.",
        "expected_full": "2025",
        "reference": "https://cpl.thalesgroup.com/encryption/post-quantum-security",
    },
    "ncipher.com": {
        "pqc_support": "partial",
        "tls_pqc": False,
        "notes": "nShield HSMs have PQC support in experimental mode. Production readiness 2026.",
        "expected_full": "2026",
        "reference": "",
    },
    "utimaco.com": {
        "pqc_support": "partial",
        "tls_pqc": False,
        "notes": "Utimaco SecurityServer and CryptoServer products have PQC support in development.",
        "expected_full": "2026",
        "reference": "https://utimaco.com/products/post-quantum-cryptography",
    },
}

_SUPPORT_LEVEL_ORDER = {"yes": 0, "partial": 1, "planned": 2, "none": 3, "unknown": 4}
_BLOCKING_THRESHOLD  = {"none", "unknown"}


@dataclass
class Vendor:
    id: str
    name: str
    endpoint: str                   # TLS hostname to probe
    category: str                   # "payment", "ca", "hsm", "cloud", "saas", "api"
    criticality: str                # "critical" | "high" | "medium" | "low"
    org_id: str
    team: Optional[str] = None
    notes: str = ""
    added_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)


@dataclass
class VendorRisk:
    vendor: Vendor
    # Live probe results
    current_tls_version: str = "unknown"
    current_cipher: str     = "unknown"
    current_algorithm: str  = "unknown"
    handshake_ms: float     = 0.0
    probe_error: Optional[str] = None
    # Roadmap
    pqc_support_level: str  = "unknown"   # yes | partial | planned | none | unknown
    pqc_tls_ready: bool     = False
    roadmap_notes: str      = ""
    expected_full_support: str = "unknown"
    roadmap_reference: str  = ""
    # Assessment
    is_blocking: bool       = False
    risk_level: str         = "MEDIUM"    # CRITICAL | HIGH | MEDIUM | LOW
    recommendation: str     = ""

    @property
    def status_label(self) -> str:
        if self.is_blocking:
            return "BLOCKING"
        if self.pqc_support_level == "yes":
            return "READY"
        if self.pqc_support_level == "partial":
            return "PARTIAL"
        if self.pqc_support_level == "planned":
            return "PLANNED"
        return "UNKNOWN"


class VendorRiskTracker:
    def __init__(self, org_id: str):
        self.org_id = org_id
        self._vendors: dict[str, Vendor] = {}
        self._risks:   dict[str, VendorRisk] = {}

    def add_vendor(self, vendor: Vendor) -> None:
        self._vendors[vendor.id] = vendor

    def assess_vendor(self, vendor_id: str) -> VendorRisk:
        vendor = self._vendors.get(vendor_id)
        if not vendor:
            raise ValueError(f"Unknown vendor: {vendor_id}")

        risk = VendorRisk(vendor=vendor)

        # 1. Live TLS probe
        try:
            probe = probe_tls_endpoint(vendor.endpoint, timeout=8.0)
            risk.current_tls_version = probe.tls_version
            risk.current_cipher      = probe.cipher_name
            risk.current_algorithm   = probe.detected_classical_kem or "unknown"
            risk.handshake_ms        = probe.handshake_ms
        except Exception as e:
            risk.probe_error = str(e)

        # 2. Known roadmap lookup
        domain = vendor.endpoint.lower().lstrip("www.").split("/")[0]
        roadmap = None
        for known_domain, data in _VENDOR_ROADMAPS.items():
            if known_domain in domain or domain in known_domain:
                roadmap = data
                break

        if roadmap:
            risk.pqc_support_level    = roadmap.get("pqc_support", "unknown")
            risk.pqc_tls_ready        = roadmap.get("tls_pqc", False)
            risk.roadmap_notes        = roadmap.get("notes", "")
            risk.expected_full_support = roadmap.get("expected_full", "unknown")
            risk.roadmap_reference    = roadmap.get("reference", "")
        else:
            risk.pqc_support_level = "unknown"
            risk.roadmap_notes     = "No known PQC roadmap. Contact vendor directly."

        # 3. Risk assessment
        is_critical = vendor.criticality == "critical"
        is_blocking_level = risk.pqc_support_level in _BLOCKING_THRESHOLD

        risk.is_blocking = is_critical and is_blocking_level

        if risk.is_blocking:
            risk.risk_level = "CRITICAL"
            risk.recommendation = (
                f"This is a critical vendor with no known PQC roadmap. "
                f"Your migration is BLOCKED until {vendor.name} supports PQC. "
                f"Action: issue a formal PQC readiness questionnaire to {vendor.name} "
                f"and include PQC support as a contract renewal requirement."
            )
        elif is_blocking_level:
            risk.risk_level = "HIGH"
            risk.recommendation = (
                f"{vendor.name} has no known PQC roadmap. "
                f"Escalate to your account manager. "
                f"Include PQC support in next contract renewal."
            )
        elif risk.pqc_support_level == "planned":
            risk.risk_level = "MEDIUM"
            risk.recommendation = (
                f"PQC support is planned for {risk.expected_full_support}. "
                f"Monitor their roadmap and align your migration timeline."
            )
        else:
            risk.risk_level = "LOW"
            risk.recommendation = "Vendor has PQC support. Validate in staging before production rollout."

        self._risks[vendor_id] = risk
        return risk

    def assess_all(self) -> list[VendorRisk]:
        return [self.assess_vendor(vid) for vid in self._vendors]

    def blocking_vendors(self) -> list[VendorRisk]:
        return [r for r in self._risks.values() if r.is_blocking]

    def summary(self) -> dict:
        risks = list(self._risks.values())
        return {
            "total_vendors": len(self._vendors),
            "assessed":      len(risks),
            "blocking":      sum(1 for r in risks if r.is_blocking),
            "ready":         sum(1 for r in risks if r.pqc_support_level == "yes"),
            "partial":       sum(1 for r in risks if r.pqc_support_level == "partial"),
            "planned":       sum(1 for r in risks if r.pqc_support_level == "planned"),
            "unknown":       sum(1 for r in risks if r.pqc_support_level in ("none", "unknown")),
        }
