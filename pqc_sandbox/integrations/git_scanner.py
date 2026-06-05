"""
Git diff scanner: detect quantum-vulnerable crypto introduced in a PR/commit.

Scans changed files for:
  - Hardcoded algorithm names (RSA, ECDSA, ECDH, Ed25519)
  - TLS configuration (ssl_protocols, SSLContext, tls_version)
  - Key generation patterns (key.generate_private_key, crypto.generateKey)
  - Certificate config (signature_hash_algorithm, key_type)
  - Common library calls (OpenSSL, cryptography, pyca, node:crypto)

Returns findings with file:line context, severity, and recommended PQC replacement.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pqc_sandbox.algorithms import MIGRATION_MAP


# ── Pattern catalogue ─────────────────────────────────────────────────────────

@dataclass
class CryptoPattern:
    pattern: re.Pattern
    algorithm: str          # maps to MIGRATION_MAP key
    category: str           # "kem" | "sign" | "tls-config" | "key-gen"
    severity: str           # "HIGH" | "MEDIUM" | "INFO"
    description: str


_PATTERNS: list[CryptoPattern] = [
    # RSA key generation
    CryptoPattern(re.compile(r'rsa\.generate_private_key|RSA\.generate|generateKeyPair.*rsa|new\s+RSA\b|KeyPairGenerator\.getInstance\("RSA"\)', re.I),
                  "RSA-2048 (PKCS#1 v1.5)", "key-gen", "HIGH",
                  "RSA key generation — quantum-vulnerable"),
    CryptoPattern(re.compile(r'rsa[_\-]?(2048|4096|1024)', re.I),
                  "RSA-2048 (PKCS#1 v1.5)", "key-gen", "HIGH",
                  "Explicit RSA key size — quantum-vulnerable"),

    # ECDSA / ECDH
    CryptoPattern(re.compile(r'ec\.generate_private_key|ECDSA|ecdsa|P-?256|P-?384|secp256r1|prime256v1|nistp256', re.I),
                  "ECDSA-P256", "sign", "HIGH",
                  "ECDSA/EC key — quantum-vulnerable"),
    CryptoPattern(re.compile(r'ECDH|ecdh|KeyAgreement.*EC|crypto\.createECDH', re.I),
                  "ECDH-P256", "kem", "HIGH",
                  "ECDH key exchange — quantum-vulnerable"),

    # Ed25519
    CryptoPattern(re.compile(r'Ed25519|ed25519|EdDSA|edwards25519', re.I),
                  "Ed25519", "sign", "HIGH",
                  "Ed25519 signature — quantum-vulnerable"),

    # TLS version config
    CryptoPattern(re.compile(r'TLSv1\.[012][^3]|ssl\.PROTOCOL_TLS|SSLv3|TLS_1_[012](?!_3)\b', re.I),
                  "ECDH-P256", "tls-config", "HIGH",
                  "TLS < 1.3 configured — cannot support hybrid PQC key exchange"),

    # OpenSSL explicit curves
    CryptoPattern(re.compile(r'ssl_ecdh_curve\s+(prime256v1|secp384r1|X25519)\s*;', re.I),
                  "ECDH-P256", "tls-config", "MEDIUM",
                  "Explicit classical ECDH curve — replace with X25519MLKEM768 hybrid"),

    # JWT algorithm config
    CryptoPattern(re.compile(r'algorithm["\s:=]+(RS256|RS384|RS512|ES256|ES384|ES512|HS256)', re.I),
                  "RSA-2048 (PKCS#1 v1.5)", "sign", "MEDIUM",
                  "JWT algorithm uses classical signature — quantum-vulnerable"),

    # X.509 / certificate
    CryptoPattern(re.compile(r'signature_hash_algorithm.*SHA256|SHA256WithRSA|sha256WithRSAEncryption', re.I),
                  "RSA-2048 (PKCS#1 v1.5)", "sign", "MEDIUM",
                  "Certificate configured with classical RSA signature"),

    # Python cryptography library
    CryptoPattern(re.compile(r'from cryptography.*import.*(RSA|ECDSA|ECDH|EllipticCurve)', ),
                  "ECDSA-P256", "sign", "HIGH",
                  "Cryptography library import for classical algorithm"),

    # Node.js / JS
    CryptoPattern(re.compile(r'crypto\.createSign\("(RSA|EC)|subtle\.sign.*"ECDSA"', re.I),
                  "ECDSA-P256", "sign", "HIGH",
                  "Node.js classical crypto sign call"),

    # Java
    CryptoPattern(re.compile(r'Signature\.getInstance\("(SHA.*withRSA|SHA.*withECDSA)', re.I),
                  "ECDSA-P256", "sign", "HIGH",
                  "Java JCE classical signature algorithm"),

    # Go
    CryptoPattern(re.compile(r'elliptic\.(P256|P384)|rsa\.GenerateKey|ecdsa\.GenerateKey', ),
                  "ECDSA-P256", "sign", "HIGH",
                  "Go stdlib classical crypto call"),
]

# File extensions to scan (skip binaries, generated files, etc.)
_SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.kt',
    '.rs', '.c', '.cpp', '.h', '.rb', '.php', '.cs',
    '.conf', '.yaml', '.yml', '.json', '.toml', '.ini', '.env',
    '.tf', '.hcl',   # Terraform
}

_SKIP_DIRS = {
    'node_modules', '.git', 'vendor', '__pycache__', '.venv',
    'dist', 'build', '.next', 'coverage',
}

def _should_skip(filepath: str) -> bool:
    """Skip files inside known non-application directories."""
    parts = filepath.replace("\\", "/").split("/")
    return any(p in _SKIP_DIRS for p in parts)


@dataclass
class CryptoFinding:
    file: str
    line: int
    code: str                       # the matched line (stripped)
    algorithm: str
    category: str
    severity: str
    description: str
    recommended_pqc: list[str] = field(default_factory=list)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class GitScanResult:
    findings: list[CryptoFinding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    new_findings: list[CryptoFinding] = field(default_factory=list)   # in diff only
    all_findings: list[CryptoFinding] = field(default_factory=list)   # whole repo
    error: Optional[str] = None

    @property
    def verdict(self) -> str:
        if any(f.severity == "HIGH" for f in self.new_findings):
            return "BLOCKED"
        if any(f.severity == "MEDIUM" for f in self.new_findings):
            return "CAUTION"
        return "GO"

    @property
    def unique_algorithms(self) -> list[str]:
        return list({f.algorithm for f in self.new_findings})


def _scan_content(content: str, filepath: str) -> list[CryptoFinding]:
    findings: list[CryptoFinding] = []
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or stripped.startswith('//'):
            continue
        for pat in _PATTERNS:
            if pat.pattern.search(line):
                findings.append(CryptoFinding(
                    file=filepath,
                    line=i,
                    code=stripped[:120],
                    algorithm=pat.algorithm,
                    category=pat.category,
                    severity=pat.severity,
                    description=pat.description,
                    recommended_pqc=MIGRATION_MAP.get(pat.algorithm, []),
                ))
                break  # one finding per line
    return findings


def _ref_exists(ref: str) -> bool:
    """Check whether a git ref (branch, tag, SHA) exists."""
    r = subprocess.run(
        ["git", "rev-parse", "--verify", ref],
        capture_output=True, timeout=10,
    )
    return r.returncode == 0


def _get_changed_files(base_ref: str = "HEAD~1") -> tuple[list[str], str, set[str]]:
    """
    Return (all_changed_files, effective_base_ref, staged_only_files).
    staged_only_files: files that are staged but not yet committed (need --cached diff).
    Falls back gracefully when base_ref doesn't exist.
    """
    effective = base_ref
    if not _ref_exists(base_ref):
        effective = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", effective, "HEAD"],
            capture_output=True, text=True, timeout=30,
        )
        committed_files = [f.strip() for f in result.stdout.splitlines() if f.strip()]

        staged = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True, timeout=30,
        )
        staged_files = [f.strip() for f in staged.stdout.splitlines() if f.strip()]

        # Files that are staged-only (not in committed diff) need --cached diff
        staged_only = set(staged_files) - set(committed_files)
        all_files = list(dict.fromkeys(committed_files + staged_files))
        return all_files, effective, staged_only
    except Exception:
        return [], effective, set()


def _get_diff_lines(filepath: str, base_ref: str, staged: bool = False) -> list[tuple[int, str]]:
    """Return (line_number, content) for lines ADDED in the diff.
    staged=True uses --cached to diff the index against HEAD (for uncommitted staged files).
    """
    try:
        if staged:
            cmd = ["git", "diff", "--cached", "HEAD", "--", filepath]
        else:
            cmd = ["git", "diff", base_ref, "HEAD", "--", filepath]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30,)
        added: list[tuple[int, str]] = []
        current_line = 0
        for line in result.stdout.splitlines():
            if line.startswith("@@"):
                # @@ -old_start,old_count +new_start,new_count @@
                m = re.search(r'\+(\d+)', line)
                if m:
                    current_line = int(m.group(1)) - 1
            elif line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                added.append((current_line, line[1:]))
            elif not line.startswith("-"):
                current_line += 1
        return added
    except Exception:
        return []


def scan_pr(
    repo_path: str = ".",
    base_ref: str = "HEAD~1",
    scan_whole_repo: bool = False,
) -> GitScanResult:
    """
    Scan a git repo for quantum-vulnerable crypto.

    In PR mode (default): only reports findings in CHANGED lines.
    In full-repo mode: scans all files.
    """
    result = GitScanResult()
    repo = Path(repo_path)

    if scan_whole_repo:
        # Scan every file in repo
        for path in repo.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            if _should_skip(str(path.relative_to(repo))):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                rel = str(path.relative_to(repo))
                findings = _scan_content(content, rel)
                result.all_findings.extend(findings)
                result.files_scanned += 1
                result.lines_scanned += content.count("\n")
            except Exception:
                continue
        result.findings = result.all_findings
        result.new_findings = result.all_findings
        return result

    # PR mode: only scan changed files, only flag added lines
    changed, effective_base, staged_only = _get_changed_files(base_ref)
    if not changed:
        result.error = (
            "No changed files detected. "
            "Try --full to scan the whole repo, or make a commit first."
        )
        return result

    if effective_base != base_ref:
        result.error = (
            f"Ref '{base_ref}' not found — scanned all tracked files vs empty tree. "
            "This is normal on a repo with a single commit."
        )

    for filepath in changed:
        full_path = repo / filepath
        if not full_path.exists():
            continue
        if full_path.suffix.lower() not in _SCAN_EXTENSIONS:
            continue
        if _should_skip(filepath):
            continue

        is_staged = filepath in staged_only
        added_lines = _get_diff_lines(filepath, effective_base, staged=is_staged)
        result.files_scanned += 1

        for line_no, line_content in added_lines:
            result.lines_scanned += 1
            for pat in _PATTERNS:
                if pat.pattern.search(line_content):
                    finding = CryptoFinding(
                        file=filepath,
                        line=line_no,
                        code=line_content.strip()[:120],
                        algorithm=pat.algorithm,
                        category=pat.category,
                        severity=pat.severity,
                        description=pat.description,
                        recommended_pqc=MIGRATION_MAP.get(pat.algorithm, []),
                    )
                    result.new_findings.append(finding)
                    break

    result.findings = result.new_findings
    return result
