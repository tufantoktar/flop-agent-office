#!/usr/bin/env python3
"""Refuse to stage files whose *name* indicates secret material.

Content scanning can be fooled by encoding; a filename check cannot. This runs
alongside the content scanner, not instead of it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secret_scan import scan_name  # noqa: E402


def main(argv: list[str]) -> int:
    findings = []
    for raw in argv:
        findings.extend(scan_name(Path(raw).as_posix()))
    if findings:
        print("BLOCKED - these paths must never be committed:", file=sys.stderr)
        for f in findings:
            print(f"  {f.path}  [{f.rule_id}]", file=sys.stderr)
        print(
            "\nMove the file outside the repository (default: ~/.flopoffice/keys/) "
            "and reference it via FLOPOFFICE_KEYSTORE.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
