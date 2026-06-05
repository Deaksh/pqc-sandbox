# Forum Announcement Templates

Copy-paste these. Customise the `[brackets]`. Post in the order listed — HN first for credibility.

---

## 1. Hacker News — Show HN

**Title:** Show HN: pqc-sandbox – simulate a post-quantum crypto migration before committing to it

**Body:**
```
I built pqc-sandbox, a CLI tool that lets you see the real-world cost of migrating 
to ML-KEM/ML-DSA/SLH-DSA before touching any production code.

The problem: NIST finalised PQC standards in Aug 2024. Regulators (NSA, RBI, DORA) 
are asking for migration roadmaps. But nobody knows what it actually costs them 
until they try — and by then they've already broken things.

What it does in 60 seconds:
  pip install pqc-sandbox && pqc-sandbox demo

Output:
  - Side-by-side benchmark: ECDH-P256 vs ML-KEM-768 (ML-DSA-44 vs ECDSA-P256)
  - Compat oracle: "Your MTU can't fit the ML-KEM ClientHello" / "TLS 1.2 can't do hybrid KEX"
  - Migration difficulty score (0-100) + README badge
  - HTML exec summary designed to be forwarded to a CISO (not a dev tool output)
  - JSON output for CI/CD pipelines

The size numbers are the real story:
  ECDSA signature:    72 bytes
  ML-DSA-44 sig:   2,420 bytes  (+33×)
  ML-DSA-65 sig:   3,293 bytes  (+45×)
  SLH-DSA-256s:   29,792 bytes  (+413×)

These are structural changes that fragment DNS UDP packets, overflow JWT header 
limits, and exceed embedded device RAM. pqc-sandbox finds these before you find 
them in prod.

It runs fully local — zero telemetry, zero cloud, no API keys. Enterprise trust 
requirement.

GitHub: https://github.com/pqc-sandbox/pqc-sandbox
Apache 2.0.

Happy to answer questions about the PQC compatibility landscape or the tool.
```

**Best time to post:** Tuesday–Thursday, 9–11am ET (2:30–4:30pm IST)

**Tags to use:** None (HN doesn't have tags, but mention in comments: post-quantum, cryptography, security, nist)

---

## 2. Reddit — r/netsec

**Title:** I built a tool that simulates your PQC migration before you commit to it — shows what breaks (MTU, RAM, TLS version) and by how much

**Body:**
```
NIST finalised ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) in 
August 2024. Regulators are starting to ask for migration roadmaps. But most teams 
have no idea what a migration will actually cost them.

I built pqc-sandbox to answer that question without touching production.

**What it does:**

```bash
pip install pqc-sandbox
pqc-sandbox demo          # 60-second demo, no setup
pqc-sandbox compare --classical ECDSA-P256  # auto-picks ML-DSA-44 as replacement
```

For each algorithm pair, you get:
- **Benchmark**: key sizes, signature/ciphertext sizes, latency delta
- **Compat oracle**: checks MTU limits, TLS version support, device RAM, DNSSEC 
  UDP limits, JWT header limits, HSM support
- **Score**: 0-100 migration difficulty
- **Config diff**: OpenSSL / nginx / sshd / Go TLS / Python — copy-paste ready
- **Exec summary**: one-page HTML formatted as a risk memo, not a dev tool

**The thing that surprises people most:**

ML-DSA signatures are 33–45× larger than ECDSA. That single fact breaks:
- DNSSEC (1232B UDP limit)  
- JWT tokens (8KB HTTP header limit)
- TLS cert chains on some proxies
- CMS/S/MIME parsers with fixed buffers

pqc-sandbox finds these before you hit them.

Zero telemetry. Fully local. Apache 2.0.

GitHub: [link] | Feedback very welcome, especially edge cases I haven't thought of.
```

**Also post to:** r/cryptography, r/sysadmin (focus on the ops angle), r/devops

---

## 3. Reddit — r/IndiaFintech / r/india (business angle)

**Title:** Built a tool to help Indian banks prepare for the RBI's post-quantum crypto requirements

**Body:**
```
RBI has started asking regulated entities about their quantum cryptography 
preparedness (circular RBI/2024-25/37). Most security teams don't know where 
to start.

I built pqc-sandbox — it points at your TLS endpoints or CBOM files and 
produces an RBI-mapped compliance report showing which controls you're 
compliant on and which need work.

Free CLI (open source), paid platform for teams that need org-wide tracking 
and audit trails.

Would love feedback from anyone in banking/fintech security on:
1. Is the RBI control mapping accurate?
2. What's missing from the compliance report?
3. Would a tool like this be useful internally?

Happy to give free access to anyone who wants to try it on their infrastructure.
```

---

## 4. LinkedIn — for CISOs (post from personal profile, not company page)

**Post:**
```
I've been thinking about a question I've heard from CISOs a lot lately:

"RBI wants a PQC migration roadmap by next quarter. Where do I even start?"

The challenge isn't knowing what to do. It's knowing what it will cost you 
before you commit.

ML-DSA (the new signature standard) produces signatures 33× larger than ECDSA.
That single fact can:
  → Fragment your DNSSEC responses (UDP limit: 1232 bytes)
  → Overflow JWT header limits in your API gateway
  → Break TLS cert chains on legacy proxies
  → Exceed RAM on your IoT/embedded devices

None of this is obvious until you try it — and by then you've broken production.

I built a tool that simulates this on your actual systems in 60 seconds and 
produces an RBI-formatted compliance report. Zero cloud, zero telemetry — it 
runs on your own machine.

Free: github.com/pqc-sandbox/pqc-sandbox
Enterprise platform: [landing page link]

Happy to give a demo to anyone working on PQC migration planning.
What's your biggest concern about the migration? 👇

#CISO #Cybersecurity #PostQuantum #RBI #FinancialServices #PQC
```

**Target:** Tag 3-5 specific CISOs from Indian banks you know. Post on Tuesday morning IST.

---

## 5. LinkedIn — for security engineers (technical angle)

**Post:**
```
If you're thinking about migrating to ML-KEM or ML-DSA, here's what nobody 
tells you upfront:

ML-KEM-768's public key is 1,184 bytes. Your TLS 1.3 ClientHello will now 
be ~1,529 bytes — which doesn't fit in a 1500-byte MTU. IP fragmentation 
kicks in. Some middleboxes drop oversized initial packets.

ML-DSA-65 signatures are 3,293 bytes. That's a CertificateVerify message 
spanning 3 MTU packets on every TLS handshake.

This is why I built pqc-sandbox — a CLI that finds these problems before 
you find them in production.

pqc-sandbox compare --classical "ECDSA-P256" --mtu 1500 --tls-version 1.3

It benchmarks the algorithm pair, runs 15+ compatibility checks, and outputs:
- A score (0-100) and verdict (GO / CAUTION / BLOCKED)
- A config diff for OpenSSL/nginx/sshd/Go/Python
- A JSON output for CI/CD integration (exit code: 0=GO, 1=CAUTION, 2=BLOCKED)

Apache 2.0, fully local, no telemetry.

Try it: pip install pqc-sandbox

#Security #Cryptography #PostQuantum #TLS #DevSecOps
```

---

## 6. Security community forums / mailing lists

**OWASP Community (post to OWASP Slack #appsec-community):**
```
Hey all — I built a tool that might be useful for the PQC migration work 
many of us are planning.

pqc-sandbox: simulate a PQC migration on your systems before committing to it.
Points at TLS endpoints or CBOM/SARIF from your existing scanners, 
runs compatibility checks, produces compliance reports for RBI/NIST/DORA.

Free/open source: pip install pqc-sandbox
It positions as "the missing second half" — after your crypto scanner finds 
the algorithms, pqc-sandbox tells you the migration cost.

GitHub: [link] — Apache 2.0. Happy to take PRs for edge cases.
```

**ISACA / DSCI (India) forums:**
Focus on the RBI compliance angle. Offer to present at the next DSCI summit.

**Cloud Security Alliance (CSA) Slack:**
```
Working on PQC migration tooling — built a free CLI that simulates migration 
impact (latency, payload size, compat) and produces NIST/RBI compliance reports. 
Zero telemetry, fully local. Would love feedback from anyone doing CSF 2.0 
assessments that include quantum risk.

github.com/pqc-sandbox/pqc-sandbox
```

---

## 7. Product Hunt launch (when you're ready)

**Tagline:** "See what post-quantum migration actually costs before you commit"

**First comment (from maker):**
```
Hey PH! I built this after spending months trying to answer a deceptively 
simple question: "If we switch from ECDSA to ML-DSA, what breaks?"

The answer turned out to be surprisingly non-obvious. ML-DSA signatures are 
33× larger — which fragments DNSSEC UDP responses, overflows JWT headers, 
and breaks TLS cert chains on some proxies. And nobody finds this out until 
they're already in the migration.

pqc-sandbox runs the simulation locally (zero telemetry) and gives you:
- A migration difficulty score (0-100)  
- Specific things that will break and why
- A copy-paste config diff to fix them
- A one-page risk memo formatted for a CISO inbox

The enterprise version adds org-wide tracking, RBI/SEBI/NIST compliance 
reports, and continuous monitoring to catch new vulnerable crypto in PRs.

Try the free CLI: pip install pqc-sandbox && pqc-sandbox demo

Happy to answer any questions about the PQC landscape!
```

---

## 8. Email outreach to security teams

**Subject:** Free tool: simulate your PQC migration before it breaks production

**Body:**
```
Hi [Name],

I noticed [Company] uses [ECDH/ECDSA/RSA] for [TLS/signing/KEM] — I found 
this via your job postings / public cert / etc.

NIST finalised the PQC replacement standards in August 2024. Most teams are 
now getting questions from regulators/leadership about migration timelines but 
don't have concrete answers yet.

I built pqc-sandbox to help with exactly this:

  pip install pqc-sandbox && pqc-sandbox demo

It benchmarks your current algorithms against their PQC replacements, finds 
compatibility blockers (MTU limits, TLS version, device RAM), and produces 
a one-page risk memo you can forward to your CISO.

Takes 60 seconds. Runs entirely locally — no data leaves your machine.

If you're a regulated entity (bank, NBFC, payments), I can also generate an 
RBI-mapped compliance report showing your current gap vs the IT Master 
Direction requirements.

Would this be useful? Happy to do a 20-minute demo if you'd like to see it 
on your own infrastructure.

[Your name]
```

**Target list:**
- CISOs / Head of InfoSec at Indian banks (LinkedIn, conference speakers)
- Security engineers at fintech companies on AngelList/LinkedIn
- DSCI members
- OWASP India chapter members
