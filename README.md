# pqc-sandbox

**See exactly what breaks when you migrate to post-quantum cryptography — before you migrate.**

[![PyPI version](https://img.shields.io/pypi/v/pqc-sandbox)](https://pypi.org/project/pqc-sandbox/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Zero Telemetry](https://img.shields.io/badge/telemetry-zero-brightgreen)](https://github.com/Deaksh/pqc-sandbox)

---

## The problem

You've been told to migrate to post-quantum cryptography (ML-KEM, ML-DSA — NIST FIPS 203/204). You can't find out what breaks without trying it in production. So you're not trying it.

pqc-sandbox solves this: **simulate the migration on your real endpoints, get the exact list of what will fail and why, before touching a single config file.**

---

## Try it now

```bash
pip install pqc-sandbox
pqc-sandbox simulate your-api.com
```

Output on a real endpoint:

```
Probing api.example.com:443 …

  Current TLS    TLSv1.3
  Current KEM    X25519
  Cert sig       ECDSA-P256
  Cert chain     2,121 bytes (estimated)
  Path MTU       1,500 bytes
  Migrating to   X25519+ML-KEM-768  +  ML-DSA-44

╭─────────────────────────────────────────────────────────────────────╮
│ ✗ BLOCKED — 3 breaks found (1 BLOCKED  2 CAUTION) · effort: 6 days │
╰─────────────────────────────────────────────────────────────────────╯

── BLOCKED 1/3  TLS certificate chain too large for proxies ──────────

  Component:   TLS certificate chain / reverse proxy / API gateway

  Why this breaks:
    ML-DSA-44 signatures are 2,420B (33× larger than ECDSA-P256's 72B).
    A 2-cert chain grows from ~2,121B → 8,332B.
    This exceeds the 8KB limit enforced by nginx, AWS ALB, and most proxies.

  Evidence:
    Current cert chain:    2,121 bytes
    PQC leaf cert:         4,166 bytes
    PQC intermediate:      4,166 bytes
    2-cert chain total:    8,332 bytes  ⚠ EXCEEDS 8KB proxy limit

  Blast radius:
    • nginx / Apache with default large_client_header_buffers
    • AWS ALB — 8KB TLS record limit for certificate chain
    • Cloudflare — rejects cert chains > 16KB
    • Corporate proxies doing TLS inspection

  Fix  (2–4 hours)
    ssl_stapling on;
    ssl_stapling_verify on;
    large_client_header_buffers 8 32k;

── CAUTION 2/3  DNSSEC signatures exceed UDP packet limit ────────────
── CAUTION 3/3  HSM may not support ML-KEM / ML-DSA ─────────────────

All size measurements use NIST FIPS 203/204 final parameters.
```

Not warnings. Not a score. **Exact components, exact sizes, exact fixes.**

---

## What it finds

| Check | What breaks | Example |
|---|---|---|
| **ClientHello fragmentation** | Load balancer drops fragmented TLS handshakes | ML-KEM-768 key share = 1,184B → ClientHello exceeds 1,500B MTU |
| **Certificate chain size** | Proxy header limits | ML-DSA-44 cert chain = 8.3KB, nginx limit = 8KB |
| **TLS version** | TLS 1.2 can't carry hybrid PQC key shares | Hybrid X25519+ML-KEM requires TLS 1.3 |
| **DNSSEC** | DNS responses fragment / resolvers drop them | ML-DSA-44 sig = 2,420B, EDNS0 UDP limit = 1,232B |
| **JWT / HTTP headers** | Auth tokens overflow API gateway limits | PQC sig → 3,228B base64 → Authorization header > 8KB |
| **HSM firmware** | Hardware can't generate/verify PQC keys | Most HSMs shipped before 2024 don't support ML-KEM |

For every break: **the component, the mechanism, the measured evidence, the blast radius, and the copy-paste fix.**

---

## Installation

```bash
pip install pqc-sandbox
```

No system dependencies. No API keys. No account required. Runs entirely on your machine.

### With real NIST reference implementations (optional)

```bash
pip install pqc-sandbox[oqs]
# Requires liboqs: https://github.com/open-quantum-safe/liboqs
```

---

## Commands

### `simulate` — the flagship

```bash
# Simulate PQC migration on a live endpoint
pqc-sandbox simulate api.yourcompany.com

# Specific port, different algorithms
pqc-sandbox simulate api.yourcompany.com --port 8443 --kem ML-KEM-1024 --sig ML-DSA-65

# JSON output for CI/CD (exit 0=GO, 1=CAUTION, 2=BLOCKED)
pqc-sandbox simulate api.yourcompany.com --json --ci

# Save HTML report
pqc-sandbox simulate api.yourcompany.com --out migration-report.html
```

### `demo` — 60-second overview

```bash
pqc-sandbox demo                    # web API scenario
pqc-sandbox demo --scenario 1       # IoT / embedded device (256KB RAM)
pqc-sandbox demo --scenario 2       # legacy TLS 1.2 endpoint
```

### `compare` — algorithm-level benchmark

```bash
pqc-sandbox compare --classical ECDSA-P256          # auto-selects ML-DSA-44
pqc-sandbox compare --classical ECDH-P256 --pqc ML-KEM-768 --mtu 1500
pqc-sandbox compare --classical RSA-2048 --ci       # CI/CD mode
```

### `scan git` — CI/CD gate for PRs

```bash
# Block PRs that introduce RSA/ECDSA/ECDH patterns
pqc-sandbox scan git --base main --ci
# exit 2 if BLOCKED, posts a PR comment explaining what was found
```

Drop-in GitHub Action in `pqc_sandbox/integrations/github_action_template.yml`.

### Other commands

```bash
pqc-sandbox diff --classical ECDH-P256 --format nginx   # config diff
pqc-sandbox scan tls example.com                        # probe live endpoint
pqc-sandbox scan cbom cryptographic-bom.json            # CycloneDX CBOM input
pqc-sandbox scan sarif crypto-findings.sarif            # SARIF 2.1.0 input
pqc-sandbox badge --classical ECDSA-P256                # README badge
pqc-sandbox list                                        # all 17 algorithms
```

---

## The size problem

This migration is different from past algorithm transitions. The size increases are **structural** — they break infrastructure, not just slow it down:

```
                    Public key    Signature / Ciphertext
ECDSA-P256          65 B          72 B
ML-DSA-44        1,312 B       2,420 B    ← 33× larger
ML-DSA-65        1,952 B       3,293 B    ← 45× larger
SLH-DSA-128s        32 B       7,856 B    ← 109× larger

ECDH-P256 key share:    32 B
ML-KEM-768 key share: 1,184 B             ← 37× larger
```

A TLS ClientHello that fits in one 1,500B MTU packet will fragment. DNSSEC responses will require TCP fallback. JWT tokens will overflow HTTP header limits. `pqc-sandbox simulate` finds these before they find you in production.

---

## Using as a library

```python
from pqc_sandbox.simulation import simulate_endpoint

report = simulate_endpoint("api.yourcompany.com", port=443)

print(f"Verdict: {report.verdict}")   # BLOCKED / CAUTION / GO
for break_ in report.breaks:
    print(f"\n{break_.severity.value}: {break_.title}")
    print(f"  Component:  {break_.component}")
    print(f"  Evidence:   {break_.evidence}")
    print(f"  Fix:        {break_.fix[:80]}...")
```

---

## CI/CD integration

```yaml
# .github/workflows/pqc-check.yml
- name: PQC migration dry-run
  run: |
    pip install pqc-sandbox
    pqc-sandbox simulate ${{ env.API_ENDPOINT }} --json --ci
    # exits 2 (BLOCKED) if migration would break production
```

Or scan PRs for newly introduced vulnerable crypto:

```yaml
- name: Scan PR for vulnerable crypto
  run: pqc-sandbox scan git --base ${{ github.base_ref }} --ci
```

---

## Privacy & trust

```
Zero cloud   — all analysis runs on your hardware
Zero telemetry — no data leaves your machine
Zero accounts  — no sign-up, no API keys
Open source    — Apache 2.0, audit everything
```

---

## References

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/)
- [IETF TLS Hybrid Key Exchange](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
