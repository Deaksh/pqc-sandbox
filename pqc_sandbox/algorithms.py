"""
Algorithm catalogue: classical vs. PQC mappings, key sizes, signature sizes, security levels.
All size constants are in bytes unless noted.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AlgorithmProfile:
    name: str
    category: str                   # "kem" | "sign" | "hash"
    standard: str                   # e.g. "NIST FIPS 203"
    security_level: int             # NIST security level 1-5
    public_key_bytes: int
    private_key_bytes: int
    # KEM-specific
    ciphertext_bytes: int = 0
    shared_secret_bytes: int = 0
    # Sign-specific
    signature_bytes: int = 0
    # Performance hints (relative, ops/sec on modern x86)
    keygen_ops_sec: float = 0.0
    encap_ops_sec: float = 0.0      # or sign_ops_sec for sign algos
    decap_ops_sec: float = 0.0      # or verify_ops_sec
    # Memory
    stack_bytes: int = 0
    # OQS internal name
    oqs_name: Optional[str] = None
    # Classical analogue
    classical_equivalent: Optional[str] = None
    # Is this a PQC algorithm?
    is_pqc: bool = False
    tags: list[str] = field(default_factory=list)


# ── Classical KEMs / Key Exchange ──────────────────────────────────────────────

ECDH_P256 = AlgorithmProfile(
    name="ECDH-P256",
    category="kem",
    standard="NIST SP 800-56A",
    security_level=3,
    public_key_bytes=65,
    private_key_bytes=32,
    ciphertext_bytes=65,
    shared_secret_bytes=32,
    keygen_ops_sec=14_000,
    encap_ops_sec=14_000,
    decap_ops_sec=14_000,
    stack_bytes=4_096,
    tags=["tls", "widely-deployed"],
)

ECDH_P384 = AlgorithmProfile(
    name="ECDH-P384",
    category="kem",
    standard="NIST SP 800-56A",
    security_level=5,
    public_key_bytes=97,
    private_key_bytes=48,
    ciphertext_bytes=97,
    shared_secret_bytes=48,
    keygen_ops_sec=5_500,
    encap_ops_sec=5_500,
    decap_ops_sec=5_500,
    stack_bytes=6_144,
    tags=["tls"],
)

RSA2048_KEM = AlgorithmProfile(
    name="RSA-2048 (PKCS#1)",
    category="kem",
    standard="PKCS#1",
    security_level=2,
    public_key_bytes=256,
    private_key_bytes=1_192,
    ciphertext_bytes=256,
    shared_secret_bytes=48,
    keygen_ops_sec=40,
    encap_ops_sec=30_000,
    decap_ops_sec=1_200,
    stack_bytes=16_384,
    tags=["legacy", "tls"],
)

# ── Classical Signatures ───────────────────────────────────────────────────────

ECDSA_P256 = AlgorithmProfile(
    name="ECDSA-P256",
    category="sign",
    standard="FIPS 186-5",
    security_level=3,
    public_key_bytes=65,
    private_key_bytes=32,
    signature_bytes=72,            # DER max
    keygen_ops_sec=14_000,
    encap_ops_sec=5_500,           # sign
    decap_ops_sec=9_000,           # verify
    stack_bytes=4_096,
    tags=["tls", "code-signing", "widely-deployed"],
)

ECDSA_P384 = AlgorithmProfile(
    name="ECDSA-P384",
    category="sign",
    standard="FIPS 186-5",
    security_level=5,
    public_key_bytes=97,
    private_key_bytes=48,
    signature_bytes=104,
    keygen_ops_sec=5_500,
    encap_ops_sec=2_400,
    decap_ops_sec=3_500,
    stack_bytes=6_144,
    tags=["tls", "gov"],
)

RSA2048_SIGN = AlgorithmProfile(
    name="RSA-2048 (PKCS#1 v1.5)",
    category="sign",
    standard="PKCS#1 v1.5",
    security_level=2,
    public_key_bytes=256,
    private_key_bytes=1_192,
    signature_bytes=256,
    keygen_ops_sec=40,
    encap_ops_sec=1_200,           # sign
    decap_ops_sec=30_000,          # verify
    stack_bytes=16_384,
    tags=["legacy", "tls", "code-signing"],
)

RSA4096_SIGN = AlgorithmProfile(
    name="RSA-4096 (PKCS#1 v1.5)",
    category="sign",
    standard="PKCS#1 v1.5",
    security_level=4,
    public_key_bytes=512,
    private_key_bytes=2_360,
    signature_bytes=512,
    keygen_ops_sec=5,
    encap_ops_sec=300,
    decap_ops_sec=60_000,
    stack_bytes=32_768,
    tags=["legacy"],
)

ED25519 = AlgorithmProfile(
    name="Ed25519",
    category="sign",
    standard="RFC 8032",
    security_level=3,
    public_key_bytes=32,
    private_key_bytes=64,
    signature_bytes=64,
    keygen_ops_sec=40_000,
    encap_ops_sec=25_000,
    decap_ops_sec=10_000,
    stack_bytes=2_048,
    tags=["modern", "ssh", "tls"],
)

# ── PQC KEMs (NIST FIPS 203 – ML-KEM) ─────────────────────────────────────────

ML_KEM_512 = AlgorithmProfile(
    name="ML-KEM-512",
    category="kem",
    standard="NIST FIPS 203",
    security_level=1,
    public_key_bytes=800,
    private_key_bytes=1_632,
    ciphertext_bytes=768,
    shared_secret_bytes=32,
    keygen_ops_sec=50_000,
    encap_ops_sec=40_000,
    decap_ops_sec=40_000,
    stack_bytes=8_192,
    oqs_name="ML-KEM-512",
    classical_equivalent="ECDH-P256",
    is_pqc=True,
    tags=["pqc", "kem", "kyber", "nist-fips-203"],
)

ML_KEM_768 = AlgorithmProfile(
    name="ML-KEM-768",
    category="kem",
    standard="NIST FIPS 203",
    security_level=3,
    public_key_bytes=1_184,
    private_key_bytes=2_400,
    ciphertext_bytes=1_088,
    shared_secret_bytes=32,
    keygen_ops_sec=30_000,
    encap_ops_sec=28_000,
    decap_ops_sec=28_000,
    stack_bytes=12_288,
    oqs_name="ML-KEM-768",
    classical_equivalent="ECDH-P256",
    is_pqc=True,
    tags=["pqc", "kem", "kyber", "nist-fips-203", "recommended"],
)

ML_KEM_1024 = AlgorithmProfile(
    name="ML-KEM-1024",
    category="kem",
    standard="NIST FIPS 203",
    security_level=5,
    public_key_bytes=1_568,
    private_key_bytes=3_168,
    ciphertext_bytes=1_568,
    shared_secret_bytes=32,
    keygen_ops_sec=20_000,
    encap_ops_sec=18_000,
    decap_ops_sec=18_000,
    stack_bytes=16_384,
    oqs_name="ML-KEM-1024",
    classical_equivalent="ECDH-P384",
    is_pqc=True,
    tags=["pqc", "kem", "kyber", "nist-fips-203"],
)

# ── PQC Signatures (NIST FIPS 204 – ML-DSA) ───────────────────────────────────

ML_DSA_44 = AlgorithmProfile(
    name="ML-DSA-44",
    category="sign",
    standard="NIST FIPS 204",
    security_level=2,
    public_key_bytes=1_312,
    private_key_bytes=2_528,
    signature_bytes=2_420,
    keygen_ops_sec=8_000,
    encap_ops_sec=3_000,
    decap_ops_sec=5_000,
    stack_bytes=32_768,
    oqs_name="ML-DSA-44",
    classical_equivalent="ECDSA-P256",
    is_pqc=True,
    tags=["pqc", "sign", "dilithium", "nist-fips-204"],
)

ML_DSA_65 = AlgorithmProfile(
    name="ML-DSA-65",
    category="sign",
    standard="NIST FIPS 204",
    security_level=3,
    public_key_bytes=1_952,
    private_key_bytes=4_000,
    signature_bytes=3_293,
    keygen_ops_sec=5_000,
    encap_ops_sec=2_000,
    decap_ops_sec=3_500,
    stack_bytes=40_960,
    oqs_name="ML-DSA-65",
    classical_equivalent="ECDSA-P384",
    is_pqc=True,
    tags=["pqc", "sign", "dilithium", "nist-fips-204", "recommended"],
)

ML_DSA_87 = AlgorithmProfile(
    name="ML-DSA-87",
    category="sign",
    standard="NIST FIPS 204",
    security_level=5,
    public_key_bytes=2_592,
    private_key_bytes=4_864,
    signature_bytes=4_595,
    keygen_ops_sec=3_000,
    encap_ops_sec=1_500,
    decap_ops_sec=2_000,
    stack_bytes=49_152,
    oqs_name="ML-DSA-87",
    classical_equivalent="ECDSA-P384",
    is_pqc=True,
    tags=["pqc", "sign", "dilithium", "nist-fips-204"],
)

# ── PQC Signatures (NIST FIPS 205 – SLH-DSA) ──────────────────────────────────
# Hash-based: very large sigs, slow sign, fast verify, stateless

SLH_DSA_SHA2_128S = AlgorithmProfile(
    name="SLH-DSA-SHA2-128s",
    category="sign",
    standard="NIST FIPS 205",
    security_level=1,
    public_key_bytes=32,
    private_key_bytes=64,
    signature_bytes=7_856,
    keygen_ops_sec=200,
    encap_ops_sec=8,               # signing is very slow
    decap_ops_sec=280,
    stack_bytes=262_144,           # ~256 KB – problematic for embedded
    oqs_name="SPHINCS+-SHA2-128s-simple",
    classical_equivalent="ECDSA-P256",
    is_pqc=True,
    tags=["pqc", "sign", "sphincs", "nist-fips-205", "hash-based", "conservative"],
)

SLH_DSA_SHA2_128F = AlgorithmProfile(
    name="SLH-DSA-SHA2-128f",
    category="sign",
    standard="NIST FIPS 205",
    security_level=1,
    public_key_bytes=32,
    private_key_bytes=64,
    signature_bytes=17_088,
    keygen_ops_sec=2_000,
    encap_ops_sec=100,
    decap_ops_sec=150,
    stack_bytes=131_072,
    oqs_name="SPHINCS+-SHA2-128f-simple",
    classical_equivalent="ECDSA-P256",
    is_pqc=True,
    tags=["pqc", "sign", "sphincs", "nist-fips-205", "hash-based"],
)

SLH_DSA_SHA2_256S = AlgorithmProfile(
    name="SLH-DSA-SHA2-256s",
    category="sign",
    standard="NIST FIPS 205",
    security_level=5,
    public_key_bytes=64,
    private_key_bytes=128,
    signature_bytes=29_792,
    keygen_ops_sec=50,
    encap_ops_sec=2,
    decap_ops_sec=60,
    stack_bytes=524_288,           # ~512 KB
    oqs_name="SPHINCS+-SHA2-256s-simple",
    classical_equivalent="ECDSA-P384",
    is_pqc=True,
    tags=["pqc", "sign", "sphincs", "nist-fips-205", "hash-based", "conservative"],
)

# ── Registries ─────────────────────────────────────────────────────────────────

ALL_ALGORITHMS: dict[str, AlgorithmProfile] = {
    a.name: a for a in [
        ECDH_P256, ECDH_P384, RSA2048_KEM,
        ECDSA_P256, ECDSA_P384, RSA2048_SIGN, RSA4096_SIGN, ED25519,
        ML_KEM_512, ML_KEM_768, ML_KEM_1024,
        ML_DSA_44, ML_DSA_65, ML_DSA_87,
        SLH_DSA_SHA2_128S, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_256S,
    ]
}

# Recommended classical → PQC migration map
MIGRATION_MAP: dict[str, list[str]] = {
    "ECDH-P256":             ["ML-KEM-768"],
    "ECDH-P384":             ["ML-KEM-1024"],
    "RSA-2048 (PKCS#1)":     ["ML-KEM-768"],
    "ECDSA-P256":            ["ML-DSA-44", "SLH-DSA-SHA2-128s"],
    "ECDSA-P384":            ["ML-DSA-65", "SLH-DSA-SHA2-256s"],
    "RSA-2048 (PKCS#1 v1.5)":["ML-DSA-44"],
    "RSA-4096 (PKCS#1 v1.5)":["ML-DSA-87"],
    "Ed25519":               ["ML-DSA-44"],
}

# Hybrid combo definitions: (classical, pqc) → hybrid label
HYBRID_COMBOS: dict[tuple[str, str], str] = {
    ("ECDH-P256", "ML-KEM-768"):  "X25519MLKEM768 / P256+ML-KEM-768",
    ("ECDH-P384", "ML-KEM-1024"): "P384+ML-KEM-1024",
    ("ECDSA-P256", "ML-DSA-44"):  "P256+ML-DSA-44",
    ("ECDSA-P384", "ML-DSA-65"):  "P384+ML-DSA-65",
    ("Ed25519",    "ML-DSA-44"):  "Ed25519+ML-DSA-44",
}
