# QuantumShift Platform

**Proprietary B2B compliance layer built on the open-source [pqc-sandbox](../README.md) core.**

> License: Proprietary — see [LICENSE](LICENSE).
> The `pqc_sandbox/` module at the repo root is Apache 2.0.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  QuantumShift Platform (this directory — proprietary)    │
│                                                          │
│  platform/api/          FastAPI REST API                 │
│  platform/compliance/   Regulatory report templates      │
│  platform/monitor/      Multi-asset orchestration        │
│  platform/enterprise/   RBAC, audit log, SSO stubs       │
│  platform/dashboard/    Next.js web dashboard            │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │  pqc_sandbox (Apache 2.0 open core)              │   │
│  │  benchmarks · compat · hybrid · scoring · report │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

## Quick start (development)

### API server
```bash
pip install fastapi uvicorn pydantic
pip install -e ..   # installs pqc_sandbox core

cd /path/to/repo
uvicorn platform.api.main:app --reload --port 8080
# Docs: http://localhost:8080/docs
```

### Dashboard
```bash
cd platform/dashboard
npm install
npm run dev
# Opens: http://localhost:3000
```

## Regulatory frameworks implemented

| Framework | Status | File |
|-----------|--------|------|
| RBI Cybersecurity Framework 2016 + IT Master Direction 2023 | ✅ Full | `compliance/rbi.py` |
| SEBI CSCRF 2024 | Stub | `compliance/renderer.py` |
| CERT-In Directions 2022 | Stub | `compliance/renderer.py` |
| DPDP Act 2023 | Stub | `compliance/renderer.py` |

## Open-core boundary

| Feature | Open Source (pqc_sandbox) | Platform (proprietary) |
|---------|--------------------------|------------------------|
| Single-asset benchmark + compat check | ✅ | — |
| Executive risk memo | ✅ | — |
| CI/CD JSON output | ✅ | — |
| Multi-asset inventory | — | ✅ |
| Org-level readiness dashboard | — | ✅ |
| Regulatory compliance reports (RBI/SEBI) | — | ✅ |
| Continuous monitoring + drift alerts | — | ✅ |
| RBAC, audit log, SSO | — | ✅ |

## License boundary

This `platform/` directory is **proprietary**. The `pqc_sandbox/` module is **Apache 2.0**.

Do not include `platform/` code in open-source distributions.
