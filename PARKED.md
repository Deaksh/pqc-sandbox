# Parked — Phase 2 (Do Not Build Until Wedge Proves Pull)

These modules exist in the repo and are NOT deleted. They return to active
development only after the simulation wedge has demonstrated user pull
(engineers run `pqc-sandbox simulate`, hit a real break, share it).

## What's parked and why

| Module | Why parked |
|---|---|
| `qs_platform/discovery/` | Auto-discovery (CT logs, DNS, AWS ACM, k8s). Existing scanners own this. Not a reason anyone adopts. |
| `qs_platform/vendor/` | Vendor risk tracker. A vitamin, not a painkiller. |
| `qs_platform/compliance/` (except RBI) | 9 stubbed frameworks. Compliance reports are a byproduct of simulation results, not a product. |
| `qs_platform/` auth / multi-tenancy | Do not build B2B SaaS infra before one user has felt the wedge. |
| `pqc_sandbox/report/exec_summary.py` | CISO compliance memo. Secondary view only — regenerate from DryRunReport. |

## The 10x test (apply before adding anything)

> "Does this make the infra engineer's pre-migration dry-run 10x better,
> or is it surface area?"

Surface area examples (do not build): another compliance framework, another
inventory view, another dashboard widget, vendor questionnaire templates,
SSO/API key management.

Wedge-deepening examples (do build): actual liboqs handshake replay,
embedded device RAM simulation, load-balancer-specific breakage detection,
shareable simulation result links.

## The user we are building for

A single, specific user: an infra/platform engineer who has been told to
migrate to post-quantum cryptography and is afraid to, because they cannot
discover what will break without trying it in production.

Their "oh thank god" moment:
> "I ran this, it showed me my HSM/load-balancer/embedded fleet will break
> BEFORE I touched production, and it handed me the fix."

Every decision serves that moment.
