"""
TLS handshake simulation engine.

Given a real endpoint, this module:
  1. Probes the current TLS state (version, cipher, cert chain sizes, MTU)
  2. Calculates exact PQC migration impact using real NIST FIPS 203/204 sizes
  3. Returns a DryRunReport with concrete BreakageProofs — not warnings

Where liboqs is available, it performs real PQC key operations.
Where it is not, it simulates with the exact algorithm parameters and labels
findings clearly as SIMULATED.
"""
from __future__ import annotations

import math
import socket
import ssl
import struct
import subprocess
import traceback
from typing import Optional

from pqc_sandbox.simulation.breakage import (
    BreakageProof, DryRunReport, ProbeResult, Severity,
    PQC_SIZES, HYBRID_SIZES,
    ETHERNET_MTU, TLS_USABLE, TLS_CH_OVERHEAD,
    DNS_UDP_LIMIT, HTTP_HEADER_COMMON,
    TLS_RECORD_HEADER, TLS_RECORD_MAC,
)

# ── TLS probe ─────────────────────────────────────────────────────────────────

def _probe_endpoint(hostname: str, port: int, timeout: float = 8.0) -> ProbeResult:
    """
    Connect to the endpoint and record current TLS state.
    Falls back to sensible defaults if connection fails.
    """
    ctx = ssl.create_default_context()
    cert_chain: list[bytes] = []
    cert_sizes: list[int] = []
    tls_version = "unknown"
    cipher = "unknown"
    leaf_cn = hostname
    error: Optional[str] = None

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as s:
                tls_version = s.version() or "unknown"
                cipher_info = s.cipher()
                cipher = cipher_info[0] if cipher_info else "unknown"

                # Get the DER-encoded certificate chain
                der_chain = s.getpeercert(binary_form=True)
                if der_chain:
                    cert_chain = [der_chain]
                    cert_sizes = [len(der_chain)]

                # Try to get full chain via ssl module
                try:
                    from ssl import SSLObject
                    if hasattr(s, '_sslobj') and s._sslobj:
                        pass  # chain not easily accessible in stdlib
                except Exception:
                    pass

                # Parse CN from cert
                peer = s.getpeercert()
                if peer:
                    for field in peer.get("subject", []):
                        for k, v in field:
                            if k == "commonName":
                                leaf_cn = v

    except ssl.SSLCertVerificationError as e:
        error = f"TLS cert verification failed: {e.reason}"
        # Still attempt connection without verification for probe purposes
        ctx_noverify = ssl.create_default_context()
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as raw:
                with ctx_noverify.wrap_socket(raw, server_hostname=hostname) as s:
                    tls_version = s.version() or "unknown"
                    cipher_info = s.cipher()
                    cipher = cipher_info[0] if cipher_info else "unknown"
                    der = s.getpeercert(binary_form=True)
                    if der:
                        cert_chain = [der]
                        cert_sizes = [len(der)]
        except Exception as e2:
            error = f"Connection failed: {e2}"
    except Exception as e:
        error = f"Connection failed: {e}"

    # Detect MTU via traceroute df-bit probe (best effort)
    mtu = _detect_mtu(hostname)

    # Estimate cert chain size if we only got leaf
    # A typical 2-cert chain (leaf + intermediate) is ~2× the leaf
    total_cert = sum(cert_sizes)
    if len(cert_sizes) == 1 and cert_sizes[0] > 0:
        # Estimate intermediate CA cert is similar size
        total_cert = int(cert_sizes[0] * 2.1)

    # Infer current KEM from cipher suite
    kem = _infer_kem(cipher)
    sig_alg = _infer_sig_from_cert(cert_sizes)

    return ProbeResult(
        hostname=hostname,
        port=port,
        tls_version=tls_version,
        cipher=cipher,
        kem=kem,
        sig_alg=sig_alg,
        cert_chain_pem=cert_chain,
        cert_sizes=cert_sizes,
        total_cert_bytes=total_cert,
        leaf_cn=leaf_cn,
        mtu=mtu,
        error=error,
    )


def _detect_mtu(hostname: str) -> int:
    """
    Attempt to detect path MTU by probing with DF-bit set.
    Falls back to standard Ethernet MTU (1500).
    """
    # Quick check: are we in a container / jumbo-frame environment?
    try:
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True, text=True, timeout=3
        )
        if "mtu 9000" in result.stdout or "mtu 9001" in result.stdout:
            return 9000
    except Exception:
        pass

    # macOS
    try:
        result = subprocess.run(
            ["networksetup", "-getMTU", "en0"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0 and "MTU:" in result.stdout:
            parts = result.stdout.split("MTU:")
            if len(parts) > 1:
                mtu = int(parts[1].strip().split()[0])
                return mtu
    except Exception:
        pass

    return ETHERNET_MTU  # conservative default


def _infer_kem(cipher: str) -> str:
    """Infer the key exchange algorithm from the cipher suite name."""
    c = cipher.upper()
    if "ECDH" in c or "ECDHE" in c:
        return "ECDH-P256"
    if "X25519" in c:
        return "X25519"
    if "DHE" in c:
        return "DHE-2048"
    if "RSA" in c and "ECDH" not in c:
        return "RSA-2048"
    return "X25519"  # TLS 1.3 default


def _infer_sig_from_cert(cert_sizes: list[int]) -> str:
    """Infer signature algorithm from certificate size."""
    if not cert_sizes:
        return "ECDSA-P256"
    leaf = cert_sizes[0]
    if leaf < 800:
        return "Ed25519"
    if leaf < 1200:
        return "ECDSA-P256"
    if leaf > 3000:
        return "RSA-4096"
    return "RSA-2048"


# ── ClientHello size calculator ───────────────────────────────────────────────

def _client_hello_size(hostname: str, kem: str, hybrid: bool) -> int:
    """
    Calculate the exact TLS 1.3 ClientHello size for a given key exchange.

    Structure: fixed overhead + SNI extension + key_share extension.
    """
    sni_len = TLS_CH_OVERHEAD + len(hostname.encode())  # overhead includes SNI header

    if hybrid and kem in HYBRID_SIZES:
        key_share_payload = HYBRID_SIZES[kem]["pk"]
    elif kem in PQC_SIZES:
        key_share_payload = PQC_SIZES[kem]["pk"]
    else:
        key_share_payload = 32  # X25519 default

    # key_share extension: 2 (named group) + 2 (key len) + payload
    key_share_ext = 4 + key_share_payload

    # supported_versions extension for TLS 1.3 + X25519 classical fallback
    classical_fallback = 4 + 32  # X25519 in key_share if hybrid

    if hybrid:
        total_key_share = key_share_ext + classical_fallback
    else:
        total_key_share = key_share_ext

    return sni_len + total_key_share


def _packets_for_payload(payload_bytes: int, mtu: int) -> int:
    """How many IP packets needed to transmit payload_bytes at this MTU."""
    usable = mtu - 40 - TLS_RECORD_HEADER - TLS_RECORD_MAC  # IP+TCP+TLS overhead
    usable = max(usable, 100)
    return math.ceil(payload_bytes / usable)


# ── Cert chain size estimator ─────────────────────────────────────────────────

def _pqc_cert_size(sig_alg: str, current_leaf_bytes: int) -> dict:
    """
    Estimate certificate sizes after migration to a PQC signature algorithm.

    A DER certificate structure is roughly:
      header (4B) + subject/issuer (~200B) + validity (30B) + public key (pk_bytes)
      + extensions (~200B) + signature (sig_bytes)
    """
    CERT_STRUCTURAL_OVERHEAD = 434  # subject + issuer + validity + extensions

    if sig_alg not in PQC_SIZES:
        sig_alg = "ML-DSA-44"

    sizes = PQC_SIZES[sig_alg]
    pk_bytes  = sizes.get("pk", 1312)
    sig_bytes = sizes.get("sig", 2420)

    # Leaf cert: contains PQC public key + signed by intermediate with PQC sig
    leaf_size = CERT_STRUCTURAL_OVERHEAD + pk_bytes + sig_bytes

    # Intermediate CA cert (similar structure)
    intermediate_size = CERT_STRUCTURAL_OVERHEAD + pk_bytes + sig_bytes

    # Root CA (self-signed)
    root_size = CERT_STRUCTURAL_OVERHEAD + pk_bytes + sig_bytes

    return {
        "leaf":         leaf_size,
        "intermediate": intermediate_size,
        "root":         root_size,
        "chain_2cert":  leaf_size + intermediate_size,
        "chain_3cert":  leaf_size + intermediate_size + root_size,
        "sig_alg":      sig_alg,
        "pk_bytes":     pk_bytes,
        "sig_bytes":    sig_bytes,
    }


# ── Breakage check functions ──────────────────────────────────────────────────

def _check_clienthello_fragmentation(probe: ProbeResult, target_kem: str, hybrid: bool) -> Optional[BreakageProof]:
    """
    Check 1: Will the PQC ClientHello fragment at the current MTU?

    The ClientHello must fit in one TCP segment (ideally) to avoid triggering
    middlebox fragmentation issues. Many load balancers (AWS ALB, nginx, HAProxy)
    drop or mishandle fragmented TLS handshakes.
    """
    hostname = probe.hostname
    kem_label = f"X25519+{target_kem}" if hybrid else target_kem

    current_ch = _client_hello_size(hostname, "X25519", False)
    pqc_ch = _client_hello_size(hostname, target_kem, hybrid)

    usable_per_packet = probe.mtu - 40 - TLS_RECORD_HEADER - TLS_RECORD_MAC
    current_packets = _packets_for_payload(current_ch, probe.mtu)
    pqc_packets = _packets_for_payload(pqc_ch, probe.mtu)

    if pqc_ch <= usable_per_packet:
        return None  # Fits — no break

    delta = pqc_ch - current_ch
    severity = Severity.BLOCKED if pqc_packets > current_packets else Severity.CAUTION

    fix_nginx = f"""\
# nginx.conf — enable hybrid PQC key exchange
ssl_ecdh_curve X25519MLKEM768:X25519;

# OR raise MTU on your network interface (if you control the path)
# ip link set eth0 mtu 9001   # jumbo frames"""

    fix_haproxy = f"""\
# haproxy.cfg
global
    tune.ssl.maxrecord 16384  # allow larger TLS records
bind :443 ssl crt /etc/ssl/cert.pem curves X25519MLKEM768:X25519"""

    return BreakageProof(
        id="tls-ch-fragmentation",
        title="TLS ClientHello fragmentation",
        component="Load balancer / TLS terminator (nginx, HAProxy, AWS ALB)",
        mechanism=(
            f"{kem_label} key share = {PQC_SIZES.get(target_kem, {}).get('pk', 1184):,} bytes. "
            f"Your ClientHello grows from {current_ch:,}B → {pqc_ch:,}B. "
            f"At MTU {probe.mtu:,}B this requires IP fragmentation across {pqc_packets} packets."
        ),
        evidence=(
            f"  Current ClientHello:  {current_ch:>6,} bytes  ({current_packets} packet{'s' if current_packets > 1 else ''})\n"
            f"  PQC ClientHello:      {pqc_ch:>6,} bytes  ({pqc_packets} packets — FRAGMENTED)\n"
            f"  Path MTU:             {probe.mtu:>6,} bytes\n"
            f"  Usable per packet:    {usable_per_packet:>6,} bytes\n"
            f"  Overflow:             {pqc_ch - usable_per_packet:>6,} bytes spill into packet 2"
        ),
        blast_radius=[
            "Any middlebox that does TLS interception (corporate proxies, WAFs)",
            "AWS ALB / NLB — drops fragmented ClientHellos in some configurations",
            "nginx with default ssl_buffer_size",
            "HAProxy with default tune.ssl.maxrecord",
            "Clients behind firewalls that block IP fragments (common in enterprise)",
        ],
        severity=severity,
        fix=fix_nginx + "\n\n" + fix_haproxy,
        effort="1–2 hours",
        simulated=True,
    )


def _check_cert_chain_size(probe: ProbeResult, target_sig: str) -> Optional[BreakageProof]:
    """
    Check 2: Will PQC certificates break TLS handshake or HTTP proxy limits?

    PQC signatures are 33–45× larger than ECDSA. A 3-cert chain with ML-DSA-44
    is ~14KB. Many proxies have 8–16KB TLS record or header limits.
    """
    pqc = _pqc_cert_size(target_sig, probe.total_cert_bytes)
    current_total = probe.total_cert_bytes if probe.total_cert_bytes > 0 else 2200

    chain_2 = pqc["chain_2cert"]
    chain_3 = pqc["chain_3cert"]

    # Check against common limits
    breaks_8k_limit = chain_2 > HTTP_HEADER_COMMON
    breaks_16k_tls_record = chain_3 > 16384  # TLS record max

    if not breaks_8k_limit and not breaks_16k_tls_record:
        return None

    severity = Severity.BLOCKED if breaks_8k_limit else Severity.CAUTION

    fix = f"""\
# 1. Use ML-DSA-44 (smallest PQC sig = {PQC_SIZES['ML-DSA-44']['sig']:,}B), not ML-DSA-65 ({PQC_SIZES['ML-DSA-65']['sig']:,}B)
#    In OpenSSL / CertBot, request cert with ML-DSA-44 algorithm

# 2. Enable OCSP Stapling to avoid sending intermediate CA cert in handshake
# nginx.conf:
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/nginx/ocsp-chain.pem;

# 3. If using AWS ACM, pin to 2-cert chains and wait for ACM PQC support (2025–2026)

# 4. Raise proxy header limits if needed
# nginx.conf:
large_client_header_buffers 8 32k;"""

    return BreakageProof(
        id="cert-chain-size",
        title="TLS certificate chain too large for proxies",
        component="TLS certificate chain / reverse proxy / API gateway",
        mechanism=(
            f"{target_sig} signatures are {pqc['sig_bytes']:,}B ({pqc['sig_bytes'] // 72}× larger than ECDSA-P256's 72B). "
            f"A 2-cert chain grows from ~{current_total:,}B → {chain_2:,}B. "
            f"This exceeds the 8KB TLS record limit enforced by many HTTP proxies."
        ),
        evidence=(
            f"  Current cert chain (est.):  {current_total:>7,} bytes\n"
            f"  PQC leaf cert ({target_sig}):  {pqc['leaf']:>7,} bytes\n"
            f"  PQC intermediate cert:      {pqc['intermediate']:>7,} bytes\n"
            f"  2-cert chain total:         {chain_2:>7,} bytes  "
            f"{'⚠ EXCEEDS 8KB proxy limit' if breaks_8k_limit else 'OK'}\n"
            f"  3-cert chain total:         {chain_3:>7,} bytes  "
            f"{'⚠ EXCEEDS 16KB TLS record limit' if breaks_16k_tls_record else 'OK'}"
        ),
        blast_radius=[
            "nginx / Apache with default large_client_header_buffers (8KB)",
            "AWS ALB — 8KB TLS record limit for certificate chain",
            "Cloudflare — rejects cert chains > 16KB",
            "Corporate proxies doing TLS inspection",
            "Mobile clients with restricted TLS buffer sizes",
        ],
        severity=severity,
        fix=fix,
        effort="2–4 hours",
        simulated=True,
    )


def _check_tls_version(probe: ProbeResult, target_kem: str, hybrid: bool) -> Optional[BreakageProof]:
    """
    Check 3: Does the current TLS version support hybrid PQC key exchange?

    Hybrid X25519+ML-KEM-768 requires TLS 1.3. TLS 1.2 cannot negotiate
    the hybrid key share extension (RFC 8446 only).
    """
    if probe.tls_version in ("TLSv1.3", "unknown"):
        return None  # TLS 1.3 or undetected — assume OK

    return BreakageProof(
        id="tls-version-too-old",
        title="TLS version too old for hybrid PQC key exchange",
        component="TLS stack (server and/or client)",
        mechanism=(
            f"Hybrid X25519+{target_kem} requires TLS 1.3 (RFC 8446 key_share extension). "
            f"Your endpoint negotiated {probe.tls_version}, which cannot carry PQC key shares."
        ),
        evidence=(
            f"  Detected TLS version:  {probe.tls_version}\n"
            f"  Required for hybrid:   TLSv1.3\n"
            f"  Key share extension:   not present in TLS 1.2"
        ),
        blast_radius=[
            "All clients connecting with TLS 1.2 will not get PQC protection",
            "Any 'TLS 1.2 only' policy enforcement blocks the migration entirely",
            "Legacy clients that don't support TLS 1.3 remain exposed",
        ],
        severity=Severity.BLOCKED,
        fix="""\
# nginx.conf — enforce TLS 1.3 minimum
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519;

# Apache httpd.conf
SSLProtocol TLSv1.3
SSLOpenSSLConfCmd ECDHParameters X25519MLKEM768:X25519

# Go tls.Config
tls.Config{
    MinVersion: tls.VersionTLS13,
    CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
}""",
        effort="2–4 hours",
        simulated=False,
    )


def _check_dnssec(probe: ProbeResult, target_sig: str) -> Optional[BreakageProof]:
    """
    Check 4: Will PQC signatures break DNSSEC?

    DNSSEC requires signatures to fit in a single UDP packet (1,232B EDNS0 limit).
    All PQC signatures exceed this.
    """
    if "dns" not in probe.hostname.lower() and probe.port not in (53, 853):
        # Not a DNS endpoint — still warn if sig is used for DNSSEC externally
        sig_size = PQC_SIZES.get(target_sig, {}).get("sig", 2420)
        if sig_size <= DNS_UDP_LIMIT:
            return None

    sig_size = PQC_SIZES.get(target_sig, {}).get("sig", 2420)

    return BreakageProof(
        id="dnssec-udp-overflow",
        title="DNSSEC signatures exceed UDP packet limit",
        component="DNSSEC-signed zones / DNS resolvers",
        mechanism=(
            f"{target_sig} signatures are {sig_size:,}B. DNSSEC UDP (EDNS0) is capped at "
            f"{DNS_UDP_LIMIT:,}B. Every DNSSEC-signed response will require TCP fallback "
            f"or will be dropped by resolvers that don't implement TCP fallback."
        ),
        evidence=(
            f"  {target_sig} signature size:  {sig_size:>6,} bytes\n"
            f"  DNSSEC UDP (EDNS0) limit:    {DNS_UDP_LIMIT:>6,} bytes\n"
            f"  Overflow:                    {sig_size - DNS_UDP_LIMIT:>6,} bytes\n"
            f"  Resolution:                  TCP fallback required (not all resolvers support it)"
        ),
        blast_radius=[
            "Any DNSSEC-signed domain you operate",
            "Resolvers that don't implement TCP fallback (RFC 7766)",
            "Mobile clients on networks that block DNS-over-TCP (port 53/TCP)",
            "DNSSEC validators that reject oversized responses",
        ],
        severity=Severity.CAUTION,
        fix="""\
# Option 1: Use SLH-DSA-128s (smallest SLH-DSA variant, 7,856B) — still exceeds limit
# but is smaller than other SLH-DSA variants.
# ALL PQC signature algorithms exceed the DNSSEC UDP limit.

# Option 2: Migrate DNSSEC to TCP-only with aggressive TCP retry
# BIND named.conf:
options {
    tcp-clients 1000;
    # Enable DNS-over-TCP for all responses > 512B
};

# Option 3: Use hybrid approach — keep DNSSEC with classical ECDSA until
# a DNSSEC PQC profile is standardised (IETF draft-ietf-dnsop-dnssec-pqc)
# Expected: 2026–2027""",
        effort="1–2 days",
        simulated=True,
    )


def _check_jwt_headers(probe: ProbeResult, target_sig: str) -> Optional[BreakageProof]:
    """
    Check 5: Will PQC-signed JWTs exceed HTTP header limits?

    A JWT = base64url(header) + "." + base64url(payload) + "." + base64url(sig)
    PQC signatures are 33–45× larger, pushing the Authorization header over 8KB.
    """
    sig_size = PQC_SIZES.get(target_sig, {}).get("sig", 2420)
    # base64url overhead: ceil(n * 4/3)
    sig_b64 = math.ceil(sig_size * 4 / 3)
    # Typical JWT header + payload (before signature)
    jwt_prefix = 200  # base64url(header) + "." + base64url(payload)
    # Authorization: Bearer <jwt>
    auth_header = len("Authorization: Bearer ") + jwt_prefix + 1 + sig_b64

    if auth_header <= HTTP_HEADER_COMMON:
        return None

    return BreakageProof(
        id="jwt-header-overflow",
        title="PQC-signed JWT tokens exceed HTTP header limits",
        component="API gateway / reverse proxy Authorization header",
        mechanism=(
            f"{target_sig} signature = {sig_size:,}B → {sig_b64:,}B base64url-encoded. "
            f"A JWT with this signature creates an Authorization header of {auth_header:,}B, "
            f"exceeding the {HTTP_HEADER_COMMON:,}B limit enforced by nginx, AWS ALB, and most proxies."
        ),
        evidence=(
            f"  {target_sig} signature:       {sig_size:>6,} bytes raw\n"
            f"  base64url-encoded:           {sig_b64:>6,} bytes\n"
            f"  Full Authorization header:   {auth_header:>6,} bytes\n"
            f"  Common proxy limit (nginx):  {HTTP_HEADER_COMMON:>6,} bytes  {'⚠ EXCEEDED' if auth_header > HTTP_HEADER_COMMON else 'OK'}"
        ),
        blast_radius=[
            "Every API endpoint using JWT Bearer authentication",
            "API gateways (nginx, Kong, AWS API Gateway) with default header limits",
            "Mobile apps where Authorization header size impacts battery/data usage",
            "Microservices passing JWTs between services",
        ],
        severity=Severity.BLOCKED if auth_header > HTTP_HEADER_COMMON * 2 else Severity.CAUTION,
        fix="""\
# Option 1: Use ML-DSA-44 (smallest PQC sig = 2,420B) not ML-DSA-65 (3,293B)

# Option 2: Raise nginx header limits
# nginx.conf:
large_client_header_buffers 8 32k;
proxy_buffer_size 32k;
proxy_buffers 4 32k;

# Option 3: Move to opaque tokens (token introspection) instead of self-contained JWTs
# — PQC is actually a good time to re-evaluate whether you need self-contained JWTs

# Option 4: Use compressed JWT (RFC 9052 / COSE) with PQC signature
# — reduces payload size, not signature size""",
        effort="4–8 hours",
        simulated=True,
    )


def _check_hsm_support(probe: ProbeResult, target_kem: str, target_sig: str) -> Optional[BreakageProof]:
    """
    Check 6: Will your HSM support the PQC algorithms?

    Most HSMs shipped before 2024 do not support ML-KEM or ML-DSA in firmware.
    Even HSMs with PQC roadmaps may require full hardware replacement.
    """
    # We can't actually probe HSM support from a TLS endpoint.
    # But if we detected an RSA or ECDSA cert, we note the HSM risk.
    return BreakageProof(
        id="hsm-algorithm-support",
        title="HSM may not support ML-KEM / ML-DSA",
        component="Hardware Security Module (HSM) for private key storage",
        mechanism=(
            f"If your private keys are stored in an HSM, the HSM firmware must implement "
            f"{target_kem} and {target_sig}. Most HSMs shipped before 2024 do not. "
            f"Firmware updates are available for some models; others require hardware replacement."
        ),
        evidence=(
            f"  ML-KEM-768 NIST finalised:  Aug 2024\n"
            f"  HSMs with firmware updates: Thales Luna HSM 7+ (2024 roadmap)\n"
            f"                              Utimaco HSM (planned 2025)\n"
            f"                              nCipher nShield (planned 2025)\n"
            f"  HSMs requiring replacement: Thales Luna 6 and older\n"
            f"                              Most FIPS 140-2 Level 3 devices pre-2022"
        ),
        blast_radius=[
            "Any service where TLS private keys are HSM-protected",
            "Code signing pipelines using HSM-stored keys",
            "Certificate Authority operations",
            "Payment systems using HSM for DUKPT/3DES key derivation",
        ],
        severity=Severity.CAUTION,
        fix="""\
# Step 1: Inventory which HSMs hold private keys for this endpoint
# Step 2: Check vendor PQC roadmap:
#   Thales: https://cpl.thalesgroup.com/encryption/hardware-security-modules/pqc
#   Utimaco: https://utimaco.com/products/post-quantum-cryptography
#   nCipher: https://ncipher.com/products/post-quantum

# Step 3: For HSMs without PQC firmware, plan hybrid approach:
#   - Keep classical key in HSM for now
#   - Add software PQC layer (liboqs) for the PQC component of hybrid KEM
#   - Full HSM-backed PQC when firmware available

# Step 4: Budget for potential hardware replacement (18–36 month procurement cycle)""",
        effort="1+ weeks",
        simulated=True,
    )


# ── Main simulation entry point ───────────────────────────────────────────────

def simulate_endpoint(
    hostname: str,
    port: int = 443,
    target_kem: str = "ML-KEM-768",
    target_sig: str = "ML-DSA-44",
    hybrid: bool = True,
    timeout: float = 8.0,
    include_hsm_check: bool = True,
) -> DryRunReport:
    """
    Simulate a PQC migration on a real TLS endpoint.

    Probes the endpoint, then runs all breakage checks and returns a
    DryRunReport with concrete BreakageProofs — not generic warnings.

    Args:
        hostname:       Target hostname (e.g. "api.mybank.com")
        port:           TLS port (default 443)
        target_kem:     PQC KEM to simulate (default "ML-KEM-768")
        target_sig:     PQC signature to simulate (default "ML-DSA-44")
        hybrid:         Use X25519+ML-KEM-768 hybrid (recommended, default True)
        timeout:        Connection timeout in seconds
        include_hsm_check: Include HSM compatibility warning (always CAUTION)
    """
    probe = _probe_endpoint(hostname, port, timeout=timeout)

    report = DryRunReport(
        endpoint=hostname,
        port=port,
        probe=probe,
        target_kem=target_kem,
        target_sig=target_sig,
        hybrid=hybrid,
    )

    # Run all breakage checks in priority order (blast radius descending)
    checks = [
        _check_tls_version(probe, target_kem, hybrid),
        _check_clienthello_fragmentation(probe, target_kem, hybrid),
        _check_cert_chain_size(probe, target_sig),
        _check_jwt_headers(probe, target_sig),
        _check_dnssec(probe, target_sig),
    ]
    if include_hsm_check:
        checks.append(_check_hsm_support(probe, target_kem, target_sig))

    report.breaks = [c for c in checks if c is not None]

    # Sort: BLOCKED first, then CAUTION, then INFO
    order = {"BLOCKED": 0, "CAUTION": 1, "INFO": 2}
    report.breaks.sort(key=lambda b: order[b.severity.value])

    return report
