"""
Generate PR comment markdown from a GitScanResult.
Works for GitHub, GitLab, and Bitbucket (all support standard markdown).
"""
from __future__ import annotations

from pqc_sandbox.integrations.git_scanner import GitScanResult, CryptoFinding


_SEVERITY_ICON = {"HIGH": "🔴", "MEDIUM": "🟡", "INFO": "🔵"}
_VERDICT_HEADER = {
    "GO":      ("✅", "GO — No new quantum-vulnerable crypto detected"),
    "CAUTION": ("⚠️", "CAUTION — New quantum-vulnerable crypto found"),
    "BLOCKED": ("🚫", "BLOCKED — Critical quantum-vulnerable crypto introduced"),
}


def generate_pr_comment(result: GitScanResult, repo_name: str = "") -> str:
    icon, headline = _VERDICT_HEADER.get(result.verdict, _VERDICT_HEADER["GO"])

    lines: list[str] = [
        f"## {icon} pqc-sandbox: {headline}",
        "",
        "> 🔒 **Zero telemetry** — this analysis ran entirely in CI, no data sent externally.",
        "",
    ]

    if result.error:
        lines += [f"⚠️ Scanner warning: `{result.error}`", ""]

    if not result.new_findings:
        lines += [
            "No quantum-vulnerable cryptographic algorithms detected in the changed lines of this PR.",
            "",
            "<details>",
            f"<summary>Scan stats</summary>",
            "",
            f"- Files scanned: **{result.files_scanned}**",
            f"- Lines scanned: **{result.lines_scanned:,}**",
            f"- Findings: **0**",
            "",
            "</details>",
        ]
        return "\n".join(lines)

    # Group by severity
    high   = [f for f in result.new_findings if f.severity == "HIGH"]
    medium = [f for f in result.new_findings if f.severity == "MEDIUM"]

    if high or medium:
        lines += [
            "### Findings in this PR",
            "",
            "| Severity | File | Algorithm detected | Recommended replacement |",
            "|---|---|---|---|",
        ]
        for f in result.new_findings:
            icon_s   = _SEVERITY_ICON.get(f.severity, "⚪")
            pqc      = ", ".join(f.recommended_pqc[:2]) if f.recommended_pqc else "—"
            lines.append(f"| {icon_s} **{f.severity}** | `{f.location}` | `{f.algorithm}` | `{pqc}` |")

        lines += [""]

    # Detail section for each finding
    lines += ["<details>", "<summary>Full finding details</summary>", ""]
    for f in result.new_findings:
        pqc_list = "\n".join(f"  - `{p}`" for p in f.recommended_pqc) or "  - No known replacement"
        lines += [
            f"#### `{f.location}` — {f.algorithm}",
            "",
            f"**Detected:** `{f.code}`",
            "",
            f"**Why this is a problem:** {f.description}",
            "",
            f"**Recommended PQC replacement (NIST FIPS 203/204/205):**",
            pqc_list,
            "",
            "---",
            "",
        ]
    lines += ["</details>", ""]

    # What to do
    lines += [
        "### What to do",
        "",
    ]
    if result.verdict == "BLOCKED":
        lines += [
            "**This PR introduces quantum-vulnerable cryptography that will require migration.**",
            "",
            "Options:",
            "1. **Replace now** — swap to the NIST PQC algorithm (see recommendations above)",
            "2. **Hybrid mode** — deploy classical + PQC in parallel (backward-compatible, recommended transitional approach)",
            "3. **Acknowledge** — if this is intentional/legacy, add `pqc-sandbox: ignore` comment on the flagged line",
            "",
        ]
    else:
        lines += [
            "Review the flagged lines. If intentional, add `# pqc-sandbox: ignore` to suppress.",
            "",
        ]

    # Footer
    lines += [
        "<details>",
        "<summary>Scan stats & about</summary>",
        "",
        f"- Files scanned: **{result.files_scanned}**",
        f"- Lines in diff scanned: **{result.lines_scanned:,}**",
        f"- New findings: **{len(result.new_findings)}**",
        f"- Verdict: **{result.verdict}**",
        "",
        "Run locally: `pip install pqc-sandbox && pqc-sandbox scan git`",
        "",
        "Powered by [pqc-sandbox](https://github.com/pqc-sandbox/pqc-sandbox) (Apache 2.0) · Zero telemetry",
        "</details>",
    ]

    return "\n".join(lines)


def post_github_comment(
    comment: str,
    repo: str,
    pr_number: int,
    token: str,
) -> bool:
    """Post the comment to a GitHub PR. Returns True on success."""
    try:
        import urllib.request, json
        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        data = json.dumps({"body": comment}).encode()
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status in (200, 201)
    except Exception as e:
        print(f"Failed to post GitHub comment: {e}")
        return False
