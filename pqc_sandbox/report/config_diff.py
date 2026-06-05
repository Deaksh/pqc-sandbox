"""
Generate copy-paste-able config diffs for common frameworks.
"""
from __future__ import annotations

from pqc_sandbox.algorithms import AlgorithmProfile


_OPENSSL_KEM_MAP = {
    "ML-KEM-512":  "mlkem512",
    "ML-KEM-768":  "mlkem768",
    "ML-KEM-1024": "mlkem1024",
}
_OPENSSL_SIGN_MAP = {
    "ML-DSA-44": "mldsa44",
    "ML-DSA-65": "mldsa65",
    "ML-DSA-87": "mldsa87",
    "SLH-DSA-SHA2-128s": "slhdsa_sha2_128s",
    "SLH-DSA-SHA2-256s": "slhdsa_sha2_256s",
}
_NGINX_GROUP_MAP = {
    "ML-KEM-512":  "X25519MLKEM512",
    "ML-KEM-768":  "X25519MLKEM768",
    "ML-KEM-1024": "P384MLKEM1024",
}


def generate_config_diff(
    classical_profile: AlgorithmProfile,
    pqc_profile: AlgorithmProfile,
    framework: str = "openssl",
) -> str:
    lines: list[str] = []

    if framework == "openssl":
        lines += _openssl_diff(classical_profile, pqc_profile)
    elif framework == "nginx":
        lines += _nginx_diff(classical_profile, pqc_profile)
    elif framework == "sshd":
        lines += _sshd_diff(classical_profile, pqc_profile)
    elif framework == "go-tls":
        lines += _go_tls_diff(classical_profile, pqc_profile)
    elif framework == "python":
        lines += _python_diff(classical_profile, pqc_profile)
    else:
        lines.append(f"# Framework '{framework}' not yet supported.")
        lines.append(f"# Supported: openssl, nginx, sshd, go-tls, python")

    return "\n".join(lines)


def _openssl_diff(c: AlgorithmProfile, p: AlgorithmProfile) -> list[str]:
    lines = [
        "# ── OpenSSL 3.3+ config diff (openssl.cnf) ──────────────────────────────",
        "# Requires: openssl-oqs-provider installed",
        "# Install:  pip install oqs-provider  OR  build from https://github.com/open-quantum-safe/oqs-provider",
        "",
        "[openssl_init]",
        "providers = provider_sect",
        "",
        "[provider_sect]",
        "default = default_sect",
        "oqsprovider = oqsprovider_sect",
        "",
        "[oqsprovider_sect]",
        "activate = 1",
        "",
    ]

    if p.category == "kem":
        classical_group = "P256" if "256" in c.name else "P384"
        pqc_group = _OPENSSL_KEM_MAP.get(p.name, p.name.lower())
        hybrid_group = f"{classical_group}_{pqc_group}"
        lines += [
            "[system_default_sect]",
            "# Before (classical only):",
            f"# Groups = {classical_group}:P384:X25519",
            "",
            "# After (hybrid PQC — drop-in, backward-compatible):",
            f"Groups = {hybrid_group}:{classical_group}:P384:X25519",
            "",
            "# After (PQC-only — future state):",
            f"# Groups = {pqc_group}",
        ]
    else:
        classical_alg = c.name.lower().replace("-", "").replace(" ", "").replace("(", "").replace(")", "").replace("#", "")
        pqc_alg = _OPENSSL_SIGN_MAP.get(p.name, p.name.lower())
        lines += [
            "# Sign algorithm selection (used when generating keys/certs):",
            "# Before:",
            f"# default_md = sha256",
            f"# Private key type: {c.name}",
            "",
            "# After — generate PQC certificate:",
            f"# openssl genpkey -algorithm {pqc_alg} -out pqc_key.pem",
            f"# openssl req -new -key pqc_key.pem -out pqc_csr.pem",
            f"# openssl x509 -req -in pqc_csr.pem -signkey pqc_key.pem -out pqc_cert.pem",
        ]

    lines += [
        "",
        "# Test hybrid handshake:",
        "# openssl s_client -connect localhost:443 -groups X25519MLKEM768",
    ]
    return lines


def _nginx_diff(c: AlgorithmProfile, p: AlgorithmProfile) -> list[str]:
    classical_curve = "X25519:P-256"
    pqc_group = _NGINX_GROUP_MAP.get(p.name, "X25519MLKEM768")
    return [
        "# ── nginx.conf diff (TLS section) ───────────────────────────────────────",
        "# Requires: nginx built with OQS-OpenSSL or nginx-oqs fork",
        "",
        "server {",
        "    listen 443 ssl;",
        "",
        "    # Before:",
        f"#   ssl_ecdh_curve {classical_curve};",
        "",
        "    # After (hybrid — recommended transitional step):",
        f"    ssl_ecdh_curve {pqc_group}:{classical_curve};",
        "",
        "    ssl_protocols TLSv1.3;   # required for PQC key exchange",
        "    ssl_prefer_server_ciphers off;",
        "}",
        "",
        "# Validate: openssl s_client -connect yourhost:443 -groups X25519MLKEM768",
    ]


def _sshd_diff(c: AlgorithmProfile, p: AlgorithmProfile) -> list[str]:
    return [
        "# ── sshd_config diff ─────────────────────────────────────────────────────",
        "# Requires: OpenSSH 9.0+ (built with liboqs support)",
        "# Or: OQS-OpenSSH fork at https://github.com/open-quantum-safe/openssh",
        "",
        "# Before:",
        "# KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256",
        "",
        "# After (hybrid PQC — add at front, keeps classical fallback):",
        "KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,ecdh-sha2-nistp256",
        "",
        "# After (PQC-only — remove classical KEX):",
        "# KexAlgorithms mlkem768x25519-sha256",
        "",
        "# Host keys — add PQC host key alongside classical:",
        "# ssh-keygen -t mldsa65 -f /etc/ssh/ssh_host_mldsa65_key",
        "HostKey /etc/ssh/ssh_host_ed25519_key",
        "HostKey /etc/ssh/ssh_host_mldsa65_key    # new",
    ]


def _go_tls_diff(c: AlgorithmProfile, p: AlgorithmProfile) -> list[str]:
    return [
        "// ── Go TLS config diff ───────────────────────────────────────────────────",
        "// Requires: golang.org/x/crypto (post-quantum support added in 2024)",
        "// Or: cloudflare/go fork with ML-KEM support",
        "",
        "import (",
        '    "crypto/tls"',
        '    "golang.org/x/crypto/mlkem"   // go get golang.org/x/crypto',
        ")",
        "",
        "// Before:",
        "// cfg := &tls.Config{}",
        "",
        "// After — enable hybrid ML-KEM key exchange:",
        "cfg := &tls.Config{",
        "    // Go 1.23+ enables X25519MLKEM768 by default in experiments",
        "    // Force-enable via GODEBUG=tlsmlkem=1 environment variable",
        "    // Or set CurvePreferences explicitly:",
        "    CurvePreferences: []tls.CurveID{",
        "        tls.X25519MLKEM768,   // hybrid: X25519 + ML-KEM-768",
        "        tls.X25519,           // classical fallback",
        "        tls.CurveP256,",
        "    },",
        "    MinVersion: tls.VersionTLS13,",
        "}",
        "",
        "// Environment variable shortcut (no code change):",
        "// GODEBUG=tlsmlkem=1 ./your-binary",
    ]


def _python_diff(c: AlgorithmProfile, p: AlgorithmProfile) -> list[str]:
    return [
        "# ── Python (cryptography / liboqs) diff ──────────────────────────────────",
        "# pip install liboqs-python cryptography",
        "",
        "# Before (classical ECDH):",
        "# from cryptography.hazmat.primitives.asymmetric.ec import (",
        "#     generate_private_key, ECDH, SECP256R1)",
        "# key = generate_private_key(SECP256R1())",
        "# shared = key.exchange(ECDH(), peer_public_key)",
        "",
        "# After (ML-KEM via liboqs):",
        "import oqs",
        "",
        "# Server-side (encapsulate)",
        f"with oqs.KeyEncapsulation('{p.name}') as server:",
        "    public_key = server.generate_keypair()",
        "    # send public_key to client",
        "",
        "    # Client-side (receives public_key, encapsulates)",
        f"    with oqs.KeyEncapsulation('{p.name}') as client:",
        "        ciphertext, client_shared = client.encap_secret(public_key)",
        "        # send ciphertext to server",
        "",
        "    # Server decapsulates",
        "    server_shared = server.decap_secret(ciphertext)",
        "    assert client_shared == server_shared   # shared secret established",
        "",
        "# For hybrid: derive final key from both classical + PQC shared secrets:",
        "# from cryptography.hazmat.primitives.kdf.hkdf import HKDF",
        "# from cryptography.hazmat.primitives import hashes",
        "# final_key = HKDF(hashes.SHA256(), 32, None, b'hybrid').derive(",
        "#     classical_shared + pqc_shared)",
    ]
