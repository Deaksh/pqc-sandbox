"""
Pre-commit hook: block commits that introduce quantum-vulnerable crypto.

Install:
  pip install pre-commit pqc-sandbox
  Add to .pre-commit-config.yaml:

  repos:
    - repo: https://github.com/pqc-sandbox/pqc-sandbox
      rev: v0.1.0
      hooks:
        - id: pqc-sandbox
          name: PQC crypto scan
          language: python
          entry: pqc-sandbox-pre-commit
          pass_filenames: true
          types: [python, javascript, typescript, go, java, yaml, toml]
"""
from __future__ import annotations

import sys
from pathlib import Path

from pqc_sandbox.integrations.git_scanner import _scan_content, _SCAN_EXTENSIONS


def main() -> int:
    """Entry point for the pre-commit hook. sys.argv[1:] = staged file paths."""
    files = sys.argv[1:]
    if not files:
        return 0

    all_findings = []
    for filepath in files:
        p = Path(filepath)
        if p.suffix.lower() not in _SCAN_EXTENSIONS:
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        findings = _scan_content(content, filepath)
        # Filter out lines with inline ignore comment
        findings = [f for f in findings if "pqc-sandbox: ignore" not in f.code]
        all_findings.extend(findings)

    if not all_findings:
        return 0

    print("\n🔴 pqc-sandbox: quantum-vulnerable crypto detected in staged files\n")
    high = [f for f in all_findings if f.severity == "HIGH"]
    medium = [f for f in all_findings if f.severity == "MEDIUM"]

    for f in all_findings:
        icon = "🔴" if f.severity == "HIGH" else "🟡"
        pqc = f.recommended_pqc[0] if f.recommended_pqc else "see NIST FIPS 203/204"
        print(f"  {icon} {f.location}: {f.algorithm}")
        print(f"     {f.description}")
        print(f"     Recommended replacement: {pqc}")
        print()

    print("To suppress a specific line, add: # pqc-sandbox: ignore")
    print("To run the full analysis:         pqc-sandbox scan git --full")
    print()

    # Block commit only on HIGH findings
    return 2 if high else 1


if __name__ == "__main__":
    sys.exit(main())
