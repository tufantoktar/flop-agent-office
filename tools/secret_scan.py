#!/usr/bin/env python3
"""Secret scanner for flop-agent-office.

Runs in three places: pre-commit (staged files), CI (whole tree), and the
security test suite (synthetic fixtures).

Design notes
------------
* The scanner never contains a complete secret literal itself. Every pattern is
  assembled from fragments at import time, so this file cannot trip its own
  rules and does not need a self-exemption.
* Findings report the file, line number and rule id only. The matched text is
  NEVER printed -- printing it would move the secret into CI logs, which is the
  exact failure the scanner exists to prevent.
* Exit code 1 on any finding.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# --- pattern fragments (assembled so no full literal exists in this file) ---
_DASHES = "-" * 5
_BEGIN = _DASHES + "BEGIN "
_PRIV = "PRIVATE KEY" + _DASHES

BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".whl",
    ".so", ".dylib", ".dll", ".sqlite", ".sqlite3", ".db", ".ico", ".woff",
    ".woff2", ".ttf", ".otf",
}

SKIP_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules",
    ".ruff_cache", "build", "dist", ".mypy_cache",
}

# Filenames that must never be tracked at all, regardless of content.
FORBIDDEN_NAME_PATTERNS = [
    ("file.private-key", re.compile(r".*\.(pem|key|jwk|p8|pk8|p12|pfx|keystore)$", re.I)),
    # Key-shaped basenames, but NOT ordinary source/doc files that merely
    # contain the word (identity/keystore.py must pass).
    ("file.keystore", re.compile(
        r"(^|/)(keystore|identity\.pem|id_ed25519|id_rsa)[^/]*$"
        r"(?<!\.py)(?<!\.pyi)(?<!\.md)(?<!\.txt)(?<!\.rst)(?<!\.toml)"
        r"(?<!\.yaml)(?<!\.yml)(?<!\.json)(?<!\.cfg)(?<!\.ini)",
        re.I,
    )),
    ("file.dotenv", re.compile(r"(^|/)\.env(\.[^/]+)?$")),
]
# .env.example is the one deliberate exception.
FORBIDDEN_NAME_ALLOW = re.compile(r"(^|/)\.env\.example$")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern[str]
    note: str


RULES: list[Rule] = [
    Rule(
        "pem.private-key-block",
        re.compile(re.escape(_BEGIN) + r"(?:[A-Z0-9 ]+ )?" + re.escape(_PRIV)),
        "PEM private key block",
    ),
    Rule(
        "openssh.private-key",
        re.compile(r"b3BlbnNz" + r"aC1rZXktdjE"),  # base64 of the openssh key header
        "OpenSSH private key body",
    ),
    Rule(
        "jwk.private-params",
        # A JWK with OKP/EC/RSA key type AND a private parameter "d".
        re.compile(r"\"kty\"\s*:\s*\"(OKP|EC|RSA)\"[\s\S]{0,400}?\"d\"\s*:\s*\"[A-Za-z0-9_\-]{20,}\""),
        "JWK containing a private 'd' parameter",
    ),
    Rule(
        "jwk.private-params-reversed",
        re.compile(r"\"d\"\s*:\s*\"[A-Za-z0-9_\-]{20,}\"[\s\S]{0,400}?\"kty\"\s*:\s*\"(OKP|EC|RSA)\""),
        "JWK containing a private 'd' parameter",
    ),
    Rule(
        "seed.mnemonic-phrase",
        # A whole line consisting of exactly 12 or 24 bare lowercase words,
        # single-space separated, with no punctuation at all. Ordinary prose
        # carries commas, capitals or longer words and does not match; this
        # keeps the rule from crying wolf on docstrings.
        re.compile(
            r"^[ \t]*(?:[a-z]{3,8} ){11}[a-z]{3,8}[ \t]*$"
            r"|^[ \t]*(?:[a-z]{3,8} ){23}[a-z]{3,8}[ \t]*$",
            re.MULTILINE,
        ),
        "possible BIP39 mnemonic (12/24 words)",
    ),
    Rule(
        "apikey.openai",
        re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{20,}"),
        "OpenAI-style API key",
    ),
    Rule(
        "apikey.anthropic",
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        "Anthropic API key",
    ),
    Rule(
        "apikey.github",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
        "GitHub token",
    ),
    Rule(
        "apikey.aws",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![0-9A-Z])"),
        "AWS access key id",
    ),
    Rule(
        "passphrase.assignment",
        re.compile(
            r"(?i)\b(passphrase|password|secret|private_key|seed_phrase|mnemonic)\b"
            r"\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']"
        ),
        "hardcoded passphrase/secret assignment",
    ),
]

# Lines carrying this marker are intentional, inert examples (docs, tests).
ALLOW_MARKER = "flopoffice:allow-secret-pattern"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule_id: str
    note: str

    def render(self) -> str:
        # Deliberately does not include the matched text.
        return f"{self.path}:{self.line}: [{self.rule_id}] {self.note}"


def scan_text(text: str, path: str = "<memory>") -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            if ALLOW_MARKER in line:
                continue
            findings.append(Finding(path, line_no, rule.rule_id, rule.note))
    return findings


def scan_name(rel_path: str) -> list[Finding]:
    if FORBIDDEN_NAME_ALLOW.search(rel_path):
        return []
    out = []
    for rule_id, pattern in FORBIDDEN_NAME_PATTERNS:
        if pattern.search(rel_path):
            out.append(Finding(rel_path, 0, rule_id, "secret-bearing filename must not be tracked"))
    return out


def scan_file(path: Path, root: Path) -> list[Finding]:
    rel = path.relative_to(root).as_posix() if path.is_absolute() else path.as_posix()
    findings = scan_name(rel)
    if path.suffix.lower() in BINARY_SUFFIXES:
        return findings
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return findings
    findings.extend(scan_text(text, rel))
    return findings


def iter_tree(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        yield p


def staged_files(root: Path) -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=root, capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [root / line for line in out.splitlines() if line and (root / line).is_file()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan for secret material.")
    ap.add_argument("paths", nargs="*", help="files to scan (pre-commit passes these)")
    ap.add_argument("--all", action="store_true", help="scan the whole working tree")
    ap.add_argument("--staged", action="store_true", help="scan git-staged files")
    ap.add_argument("--root", default=".", help="repository root")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    if args.all:
        targets = list(iter_tree(root))
    elif args.staged:
        targets = staged_files(root)
    elif args.paths:
        targets = [Path(p).resolve() for p in args.paths]
    else:
        targets = list(iter_tree(root))

    findings: list[Finding] = []
    for path in targets:
        if not path.exists() or not path.is_file():
            continue
        findings.extend(scan_file(path, root))

    if findings:
        print(f"SECRET SCAN: FAIL — {len(findings)} finding(s)", file=sys.stderr)
        for f in findings:
            print("  " + f.render(), file=sys.stderr)
        print(
            "\nMatched text is intentionally not shown. Inspect the file locally.\n"
            f"If a match is a deliberate inert example, add the marker '{ALLOW_MARKER}' "
            "to that line.",
            file=sys.stderr,
        )
        return 1

    print(f"SECRET SCAN: PASS — {len(targets)} file(s) scanned, 0 findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
