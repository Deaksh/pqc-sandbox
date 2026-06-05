"""
Probe a live TLS endpoint to detect its current cipher suite and key exchange algorithm.
Uses stdlib ssl — no liboqs needed here; we only read the negotiated parameters.
"""
from __future__ import annotations

import ssl
import socket
import time
from dataclasses import dataclass
from typing import Optional

from pqc_sandbox.algorithms import MIGRATION_MAP


@dataclass
class TLSProbeResult:
    host: str
    port: int
    tls_version: str
    cipher_name: str
    key_exchange: str           # best-effort guess from cipher name
    cert_sig_alg: str
    cert_subject: str
    cert_expiry: str
    handshake_ms: float
    # Detected classical algorithms
    detected_classical_kem: Optional[str] = None
    detected_classical_sign: Optional[str] = None
    # Recommended PQC replacements
    recommended_kem: list[str] = None          # type: ignore[assignment]
    recommended_sign: list[str] = None         # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.recommended_kem is None:
            self.recommended_kem = []
        if self.recommended_sign is None:
            self.recommended_sign = []


_CIPHER_TO_KEX: dict[str, str] = {
    "ECDHE": "ECDH-P256",
    "ECDH":  "ECDH-P256",
    "DHE":   "RSA-2048 (PKCS#1)",
    "DH":    "RSA-2048 (PKCS#1)",
    "RSA":   "RSA-2048 (PKCS#1)",
}

_SIG_ALG_MAP: dict[str, str] = {
    "sha256WithRSAEncryption": "RSA-2048 (PKCS#1 v1.5)",
    "sha384WithRSAEncryption": "RSA-4096 (PKCS#1 v1.5)",
    "sha512WithRSAEncryption": "RSA-4096 (PKCS#1 v1.5)",
    "ecdsa-with-SHA256":       "ECDSA-P256",
    "ecdsa-with-SHA384":       "ECDSA-P384",
    "ecdsa-with-SHA512":       "ECDSA-P384",
    "id-ecPublicKey":          "ECDSA-P256",
    "ED25519":                 "Ed25519",
    "ED448":                   "Ed25519",
}


def probe_tls_endpoint(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
) -> TLSProbeResult:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    t0 = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            elapsed_ms = (time.perf_counter() - t0) * 1_000
            tls_ver = tls_sock.version() or "unknown"
            cipher = tls_sock.cipher()
            cipher_name = cipher[0] if cipher else "unknown"
            cert = tls_sock.getpeercert(binary_form=False) or {}

    # Best-effort KEX detection from cipher suite name
    kex = "ECDH-P256"
    for prefix, mapped in _CIPHER_TO_KEX.items():
        if cipher_name.startswith(prefix):
            kex = mapped
            break

    # Signature algorithm from cert
    sig_alg_raw = cert.get("signatureAlgorithm", "unknown")
    # Python ssl returns the sig alg as a plain string
    if isinstance(sig_alg_raw, str):
        sig_str = sig_alg_raw
    else:
        sig_str = str(sig_alg_raw)

    cert_sig = sig_str
    detected_sign = None
    for raw_key, mapped in _SIG_ALG_MAP.items():
        if raw_key.lower() in sig_str.lower():
            detected_sign = mapped
            break

    subject_dict: dict = {}
    for rdn in cert.get("subject", []):
        for k, v in rdn:
            subject_dict[k] = v
    subject = subject_dict.get("commonName", str(cert.get("subject", "")))

    expiry = cert.get("notAfter", "unknown")

    recommended_kem = MIGRATION_MAP.get(kex, [])
    recommended_sign = MIGRATION_MAP.get(detected_sign or "", [])

    return TLSProbeResult(
        host=host,
        port=port,
        tls_version=tls_ver,
        cipher_name=cipher_name,
        key_exchange=kex,
        cert_sig_alg=cert_sig,
        cert_subject=subject,
        cert_expiry=expiry,
        handshake_ms=elapsed_ms,
        detected_classical_kem=kex,
        detected_classical_sign=detected_sign,
        recommended_kem=recommended_kem,
        recommended_sign=recommended_sign,
    )
