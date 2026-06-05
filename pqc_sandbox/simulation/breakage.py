"""
Breakage proof dataclasses — the core output of a simulation.

A BreakageProof is not a warning. It is a concrete, measured/simulated
demonstration that a specific component will fail in production after a PQC
migration, with the mechanism, the evidence, the blast radius, and the fix.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    BLOCKED = "BLOCKED"   # Will definitely fail in production
    CAUTION = "CAUTION"   # Will fail depending on your exact config
    INFO    = "INFO"      # Worth knowing, won't cause outage


# ── Algorithm size constants (NIST FIPS 203/204/205 final) ───────────────────

PQC_SIZES = {
    # ML-KEM (FIPS 203)
    "ML-KEM-512":  {"pk": 800,  "ct": 768,  "ss": 32},
    "ML-KEM-768":  {"pk": 1184, "ct": 1088, "ss": 32},
    "ML-KEM-1024": {"pk": 1568, "ct": 1568, "ss": 32},

    # ML-DSA (FIPS 204)
    "ML-DSA-44":   {"pk": 1312, "sig": 2420},
    "ML-DSA-65":   {"pk": 1952, "sig": 3293},
    "ML-DSA-87":   {"pk": 2592, "sig": 4595},

    # SLH-DSA (FIPS 205)
    "SLH-DSA-128s": {"pk": 32,  "sig": 7856},
    "SLH-DSA-128f": {"pk": 32,  "sig": 17088},
    "SLH-DSA-256s": {"pk": 64,  "sig": 29792},

    # Classical (for comparison)
    "X25519":       {"pk": 32,  "ct": 32,  "ss": 32},
    "ECDSA-P256":   {"pk": 64,  "sig": 72},
    "RSA-2048":     {"pk": 256, "sig": 256},
    "Ed25519":      {"pk": 32,  "sig": 64},
}

# Hybrid combos: classical + PQC
HYBRID_SIZES = {
    "X25519+ML-KEM-768":  {"pk": 32 + 1184, "ct": 32 + 1088},   # 1216 / 1120
    "P256+ML-KEM-768":    {"pk": 64 + 1184, "ct": 64 + 1088},   # 1248 / 1152
    "X25519+ML-KEM-1024": {"pk": 32 + 1568, "ct": 32 + 1568},   # 1600 / 1600
}

# TLS record / packet constants
ETHERNET_MTU       = 1500    # standard Ethernet
JUMBO_FRAME_MTU    = 9000    # jumbo frames (EC2, datacenter)
IP_HEADER          = 20      # IPv4 header bytes
TCP_HEADER         = 20      # TCP header bytes
TLS_RECORD_HEADER  = 5       # TLS record header bytes
TLS_RECORD_MAC     = 16      # AEAD tag bytes
TLS_USABLE         = ETHERNET_MTU - IP_HEADER - TCP_HEADER - TLS_RECORD_HEADER - TLS_RECORD_MAC  # 1439

# DNS
DNS_UDP_LIMIT      = 1232    # EDNS0 with fragmentation-safe limit (RFC 8945)
DNS_TCP_LIMIT      = 65535

# JWT / HTTP headers
HTTP_HEADER_COMMON = 8192    # 8KB — nginx, AWS ALB, many proxies
HTTP_HEADER_LARGE  = 16384   # 16KB — some configs

# TLS ClientHello structure overhead (without key share)
TLS_CH_BASE        = 50      # record header + handshake type + version
TLS_CH_SESSION     = 33      # session ID (1 + 32)
TLS_CH_CIPHERS     = 14      # common cipher suite list
TLS_CH_EXT_HEADER  = 9       # extensions length header
TLS_CH_SNI_OVERHEAD = 9      # SNI extension type + length headers
TLS_CH_SUPPORTED_GROUPS = 12 # supported_groups extension
TLS_CH_SIG_ALGS    = 26      # signature_algorithms extension
TLS_CH_KEY_SHARE_OVERHEAD = 8  # key_share extension header

TLS_CH_OVERHEAD = (TLS_CH_BASE + TLS_CH_SESSION + TLS_CH_CIPHERS +
                   TLS_CH_EXT_HEADER + TLS_CH_SNI_OVERHEAD +
                   TLS_CH_SUPPORTED_GROUPS + TLS_CH_SIG_ALGS +
                   TLS_CH_KEY_SHARE_OVERHEAD)  # ~161 bytes


@dataclass
class BreakageProof:
    """
    A concrete, measured/simulated proof that a specific component will break.

    Not a warning. Not a check result. A proof: component + mechanism +
    evidence + blast_radius + fix.
    """
    id:           str              # machine-readable id
    title:        str              # "TLS ClientHello fragmentation"
    component:    str              # "Load balancer / TLS terminator"
    mechanism:    str              # Why it breaks (technical, 1-2 sentences)
    evidence:     str              # The measured/simulated numbers
    blast_radius: list[str]        # Downstream components affected
    severity:     Severity
    fix:          str              # Copy-paste config diff
    effort:       str = "< 1 hour"
    simulated:    bool = True      # True = simulated; False = actually tested

    def severity_icon(self) -> str:
        return {"BLOCKED": "✗", "CAUTION": "⚠", "INFO": "ℹ"}[self.severity.value]

    def severity_color(self) -> str:
        return {"BLOCKED": "red", "CAUTION": "yellow", "INFO": "blue"}[self.severity.value]


@dataclass
class ProbeResult:
    """What we learned from actually connecting to the endpoint."""
    hostname:       str
    port:           int
    tls_version:    str              # "TLSv1.3"
    cipher:         str              # "TLS_AES_256_GCM_SHA384"
    kem:            str              # "X25519" (inferred)
    sig_alg:        str              # "ECDSA" (from cert)
    cert_chain_pem: list[bytes]      # raw DER bytes per cert
    cert_sizes:     list[int]        # bytes per cert in chain
    total_cert_bytes: int
    leaf_cn:        str
    mtu:            int              # detected or default
    error:          Optional[str] = None


@dataclass
class DryRunReport:
    """
    The primary artifact of a simulation.

    An engineer's pre-migration dry-run: exactly what will break, ranked by
    blast radius, with the fix for each item.
    """
    endpoint:     str
    port:         int
    probe:        Optional[ProbeResult]

    # Migration target
    target_kem:   str   = "ML-KEM-768"
    target_sig:   str   = "ML-DSA-44"
    hybrid:       bool  = True     # X25519+ML-KEM-768 (recommended transitional)

    # Findings
    breaks:       list[BreakageProof] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if any(b.severity == Severity.BLOCKED for b in self.breaks):
            return "BLOCKED"
        if any(b.severity == Severity.CAUTION for b in self.breaks):
            return "CAUTION"
        return "GO"

    @property
    def blocked(self) -> list[BreakageProof]:
        return [b for b in self.breaks if b.severity == Severity.BLOCKED]

    @property
    def cautions(self) -> list[BreakageProof]:
        return [b for b in self.breaks if b.severity == Severity.CAUTION]

    @property
    def infos(self) -> list[BreakageProof]:
        return [b for b in self.breaks if b.severity == Severity.INFO]

    def total_effort(self) -> str:
        """Rough total fix effort across all breaks."""
        if not self.breaks:
            return "None"
        hours = sum(
            {"< 1 hour": 0.5, "1–2 hours": 1.5, "2–4 hours": 3,
             "4–8 hours": 6, "1–2 days": 12, "1+ weeks": 40}.get(b.effort, 3)
            for b in self.breaks if b.severity != Severity.INFO
        )
        if hours < 1:   return "< 1 hour"
        if hours < 4:   return f"{int(hours)}–{int(hours)+2} hours"
        if hours < 16:  return f"{int(hours//2)*2}–{int(hours//2)*2+4} hours"
        return f"{int(hours//8)} day(s)"
