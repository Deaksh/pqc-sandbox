"""
Compatibility Oracle: given system constraints + target PQC algorithm,
flag what will break and why.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from pqc_sandbox.algorithms import AlgorithmProfile, ALL_ALGORITHMS


class Severity(str, Enum):
    BLOCKED = "BLOCKED"
    CAUTION = "CAUTION"
    INFO = "INFO"
    OK = "OK"


@dataclass
class CompatIssue:
    severity: Severity
    category: str           # "mtu", "memory", "tls-version", "protocol", etc.
    title: str
    detail: str
    mitigation: Optional[str] = None


@dataclass
class SystemConstraints:
    # Network
    mtu_bytes: int = 1500
    tls_version: str = "1.3"           # "1.0", "1.1", "1.2", "1.3"
    # Compute
    ram_kb: Optional[int] = None       # None = unconstrained desktop
    cpu_arch: str = "x86_64"           # "x86_64", "arm64", "armv7", "rv32"
    # Protocol
    protocol: str = "tls"              # "tls", "ssh", "cms", "jwt", "dnssec", "custom"
    max_cert_bytes: Optional[int] = None
    max_packet_bytes: Optional[int] = None
    # PKI / chain
    chain_depth: int = 3
    # Env tags
    tags: list[str] = field(default_factory=list)  # e.g. ["embedded", "iot", "hsm"]


# Typical TLS 1.3 ClientHello overhead before key share: ~300 bytes
_TLS_HELLO_OVERHEAD = 300
# Typical TLS record header: 5 bytes
_TLS_RECORD_HDR = 5
# SSH KEX_INIT overhead per side: ~350 bytes
_SSH_OVERHEAD = 350


def _tls_version_ok(constraints: SystemConstraints) -> list[CompatIssue]:
    issues: list[CompatIssue] = []
    ver = constraints.tls_version
    if ver in ("1.0", "1.1"):
        issues.append(CompatIssue(
            severity=Severity.BLOCKED,
            category="tls-version",
            title=f"TLS {ver} cannot support PQC key exchange",
            detail=(
                f"TLS {ver} lacks the 'supported_groups' extension needed for hybrid PQC "
                "key exchange. PQC key exchange requires TLS 1.3 (RFC 8446)."
            ),
            mitigation="Upgrade to TLS 1.3 before attempting PQC migration.",
        ))
    elif ver == "1.2":
        issues.append(CompatIssue(
            severity=Severity.CAUTION,
            category="tls-version",
            title="TLS 1.2 supports hybrid KEM only via non-standard extensions",
            detail=(
                "RFC 8701 hybrid key exchange (IETF draft-ietf-tls-hybrid-design) requires "
                "TLS 1.3. TLS 1.2 can carry PQC certs in the chain but cannot do hybrid KEX."
            ),
            mitigation="Prefer TLS 1.3. If TLS 1.2 must be kept, use PQC for cert chain only.",
        ))
    return issues


def _mtu_issues(constraints: SystemConstraints, profile: AlgorithmProfile) -> list[CompatIssue]:
    issues: list[CompatIssue] = []
    proto = constraints.protocol

    if proto == "tls" and profile.category == "kem":
        # KeyShare in ClientHello: public_key_bytes + ~40 bytes framing per share
        key_share_size = profile.public_key_bytes + 40
        hello_total = _TLS_HELLO_OVERHEAD + key_share_size + _TLS_RECORD_HDR
        if hello_total > constraints.mtu_bytes:
            issues.append(CompatIssue(
                severity=Severity.CAUTION,
                category="mtu",
                title=f"ML-KEM ClientHello ({hello_total} B) exceeds MTU ({constraints.mtu_bytes} B)",
                detail=(
                    f"The TLS 1.3 ClientHello with {profile.name} key share requires ~{hello_total} bytes "
                    f"but your MTU is {constraints.mtu_bytes} bytes. IP fragmentation or TCP segmentation "
                    "will kick in, adding latency. Some middleboxes drop oversized initial packets."
                ),
                mitigation=(
                    "Enable TCP MSS clamping. Set MTU ≥ 1600 bytes or use QUIC (MTU probing built-in). "
                    "Consider ML-KEM-512 (ClientHello ~1 KB) instead of ML-KEM-768/1024."
                ),
            ))

    if proto == "tls" and profile.category == "sign":
        # Certificate containing PQC public key + signature
        cert_size = profile.public_key_bytes + profile.signature_bytes + 300  # ASN.1 overhead
        if constraints.max_cert_bytes and cert_size > constraints.max_cert_bytes:
            issues.append(CompatIssue(
                severity=Severity.CAUTION,
                category="mtu",
                title=f"PQC certificate ({cert_size} B) exceeds max cert size ({constraints.max_cert_bytes} B)",
                detail=(
                    f"An X.509 certificate using {profile.name} will be ~{cert_size:,} bytes. "
                    "Some TLS stacks reject certificates above a fixed limit."
                ),
                mitigation="Check your TLS library's max certificate buffer. Consider ML-DSA-44 (smallest ML-DSA).",
            ))
        # TLS CertificateVerify message containing the PQC signature
        if profile.signature_bytes + 50 > constraints.mtu_bytes:
            issues.append(CompatIssue(
                severity=Severity.CAUTION,
                category="mtu",
                title=f"CertificateVerify message ({profile.signature_bytes + 50:,} B) spans multiple MTU packets",
                detail=(
                    f"The TLS 1.3 CertificateVerify message with {profile.name} signature is "
                    f"~{profile.signature_bytes + 50:,} bytes — {(profile.signature_bytes + 50) // constraints.mtu_bytes + 1} "
                    f"packets at MTU {constraints.mtu_bytes}. This is expected but adds one round-trip on lossy links."
                ),
                mitigation="Acceptable for most deployments. Use Jumbo Frames (MTU 9000) in datacenter settings.",
            ))

    if proto == "ssh" and profile.category == "kem":
        kex_size = profile.public_key_bytes + _SSH_OVERHEAD
        if kex_size > 32_768:
            issues.append(CompatIssue(
                severity=Severity.CAUTION,
                category="mtu",
                title=f"SSH KEX message ({kex_size:,} B) exceeds SSH max packet recommendation",
                detail="RFC 4253 allows up to 35,000 bytes per SSH packet, but some clients limit to 32 KB.",
                mitigation="Ensure SSH server and client support SSH_MSG_KEX_ECDH_REPLY extension for PQC.",
            ))

    return issues


def _memory_issues(constraints: SystemConstraints, profile: AlgorithmProfile) -> list[CompatIssue]:
    issues: list[CompatIssue] = []
    if constraints.ram_kb is None:
        return issues

    stack_kb = profile.stack_bytes // 1_024
    if stack_kb > constraints.ram_kb * 0.5:
        issues.append(CompatIssue(
            severity=Severity.BLOCKED,
            category="memory",
            title=f"{profile.name} needs ~{stack_kb} KB stack — device has only {constraints.ram_kb} KB RAM",
            detail=(
                f"{profile.name} peak stack usage is ~{stack_kb} KB. Your device has {constraints.ram_kb} KB "
                "total RAM, leaving less than 50% for the runtime, OS, and application. "
                "This will cause stack overflow or OOM on resource-constrained devices."
            ),
            mitigation=(
                "Use ML-KEM-512 or ML-DSA-44 (lowest memory variants). "
                "For deeply embedded targets, consider a dedicated PQC coprocessor. "
                "SLH-DSA should be avoided on devices with < 512 KB RAM."
            ),
        ))
    elif stack_kb > constraints.ram_kb * 0.25:
        issues.append(CompatIssue(
            severity=Severity.CAUTION,
            category="memory",
            title=f"{profile.name} uses ~{stack_kb} KB stack on a {constraints.ram_kb} KB device",
            detail=(
                f"Stack usage ({stack_kb} KB) is 25–50% of total device RAM. "
                "This is feasible but leaves little headroom for other tasks."
            ),
            mitigation="Profile actual peak stack usage with your RTOS. Consider static allocation.",
        ))

    return issues


def _protocol_issues(constraints: SystemConstraints, profile: AlgorithmProfile) -> list[CompatIssue]:
    issues: list[CompatIssue] = []
    proto = constraints.protocol

    if proto == "dnssec" and profile.category == "sign":
        if profile.signature_bytes > 1_232:
            # DNS UDP payload limit
            issues.append(CompatIssue(
                severity=Severity.BLOCKED,
                category="protocol",
                title=f"DNSSEC RRSIG with {profile.name} ({profile.signature_bytes:,} B) cannot fit in DNS UDP",
                detail=(
                    f"DNS UDP responses are limited to 1,232 bytes (RFC 9460 SVCB/HTTPS cap). "
                    f"An {profile.name} RRSIG alone is {profile.signature_bytes:,} bytes — "
                    "it requires DNS-over-TCP fallback for every signed response."
                ),
                mitigation=(
                    "Evaluate dnssec-signzone with PQC only for zones that can tolerate TCP fallback. "
                    "Watch IETF DPRIVE / DNSSEC-PQC WG for standardised approaches."
                ),
            ))

    if proto == "jwt" and profile.category == "sign":
        b64_size = int(profile.signature_bytes * 4 / 3) + 4
        if b64_size > 8_192:
            issues.append(CompatIssue(
                severity=Severity.CAUTION,
                category="protocol",
                title=f"JWT with {profile.name} signature is ~{b64_size:,} bytes base64",
                detail=(
                    f"The JWT signature field alone will be ~{b64_size:,} bytes in base64. "
                    "Many HTTP servers, proxies, and CDNs have default header size limits of 8 KB."
                ),
                mitigation="Switch to compact binary token formats (CWT / CBOR) for PQC-signed tokens.",
            ))

    if proto == "cms" and profile.category == "sign":
        cms_size = profile.signature_bytes + profile.public_key_bytes + 500
        issues.append(CompatIssue(
            severity=Severity.INFO,
            category="protocol",
            title=f"CMS SignedData with {profile.name} will be ~{cms_size:,} bytes",
            detail=(
                f"Signature: {profile.signature_bytes:,} B + public key: {profile.public_key_bytes:,} B + "
                "ASN.1 overhead ~500 B. Ensure your CMS parser supports DER-encoded objects > 64 KB."
            ),
            mitigation="Test with OpenSSL 3.3+ which has FIPS 204/205 support in the provider model.",
        ))

    if "hsm" in constraints.tags and profile.category in ("kem", "sign"):
        issues.append(CompatIssue(
            severity=Severity.CAUTION,
            category="hsm",
            title="HSM may not support this PQC algorithm yet",
            detail=(
                f"Hardware Security Modules typically lag 12–24 months behind NIST standards. "
                f"Verify that your HSM vendor has released firmware supporting {profile.name} "
                "(FIPS 140-3 modules with PQC support began shipping in 2025)."
            ),
            mitigation="Check vendor roadmap. Use software PQC with HSM for classical key wrapping as interim.",
        ))

    return issues


def _tls_stack_issues(constraints: SystemConstraints, profile: AlgorithmProfile) -> list[CompatIssue]:
    issues: list[CompatIssue] = []
    if constraints.protocol != "tls":
        return issues
    if "legacy-tls-stack" in constraints.tags or "openssl-1" in constraints.tags:
        issues.append(CompatIssue(
            severity=Severity.BLOCKED,
            category="tls-stack",
            title="OpenSSL < 3.x does not support PQC via the provider API",
            detail=(
                "PQC support in OpenSSL is delivered through the OQS Provider (OpenSSL 3.0+). "
                "OpenSSL 1.1.x has no PQC support and reached EOL in September 2023."
            ),
            mitigation="Upgrade to OpenSSL 3.3+ and install the OQS Provider. Use BoringSSL or liboqs-based forks as alternatives.",
        ))
    return issues


@dataclass
class CompatReport:
    algorithm: str
    constraints: SystemConstraints
    issues: list[CompatIssue]
    verdict: str = "GO"             # GO | CAUTION | BLOCKED

    def __post_init__(self) -> None:
        severities = {i.severity for i in self.issues}
        if Severity.BLOCKED in severities:
            self.verdict = "BLOCKED"
        elif Severity.CAUTION in severities:
            self.verdict = "CAUTION"
        else:
            self.verdict = "GO"


class CompatOracle:
    def __init__(self, constraints: SystemConstraints) -> None:
        self.constraints = constraints

    def check(self, algorithm_name: str) -> CompatReport:
        profile = ALL_ALGORITHMS.get(algorithm_name)
        if profile is None:
            raise ValueError(f"Unknown algorithm: {algorithm_name!r}")
        return run_compat_check(profile, self.constraints)


def run_compat_check(
    profile: AlgorithmProfile,
    constraints: SystemConstraints,
) -> CompatReport:
    issues: list[CompatIssue] = []
    issues.extend(_tls_version_ok(constraints))
    issues.extend(_mtu_issues(constraints, profile))
    issues.extend(_memory_issues(constraints, profile))
    issues.extend(_protocol_issues(constraints, profile))
    issues.extend(_tls_stack_issues(constraints, profile))
    return CompatReport(
        algorithm=profile.name,
        constraints=constraints,
        issues=issues,
    )
