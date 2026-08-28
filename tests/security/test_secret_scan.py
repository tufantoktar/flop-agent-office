"""Secret scanner behaviour (required test 17) and repository hygiene.

Every "secret" in this file is a synthetic, inert fixture assembled from
fragments at runtime. Nothing here is, or was ever, a real credential.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.secret_scan import ALLOW_MARKER, main, scan_name, scan_text

# Assembled at runtime so this file never contains a complete pattern literal.
DASHES = "-" * 5
FAKE_PEM = (
    DASHES + "BEGIN " + "PRIVATE " + "KEY" + DASHES + "\n"
    "MC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    + DASHES + "END " + "PRIVATE " + "KEY" + DASHES
)
FAKE_OPENSSH = DASHES + "BEGIN " + "OPENSSH " + "PRIVATE " + "KEY" + DASHES
FAKE_JWK = '{"kty":"OKP","crv":"Ed25519","x":"' + "A" * 43 + '","d":"' + "B" * 43 + '"}'
FAKE_MNEMONIC = " ".join(
    ["abandon", "ability", "able", "about", "above", "absent",
     "absorb", "abstract", "absurd", "abuse", "access", "accident"]
)
FAKE_OPENAI = "sk-" + "A" * 40
FAKE_ANTHROPIC = "sk-ant-" + "B" * 40
FAKE_GITHUB = "ghp_" + "C" * 36
FAKE_AWS = "AKIA" + "D" * 16
FAKE_ASSIGNMENT = 'passphrase = "correct-horse-battery"'  # flopoffice:allow-secret-pattern


# --- 17. the scanner rejects private-key fixture patterns -----------------
@pytest.mark.parametrize(
    ("fixture", "rule"),
    [
        (FAKE_PEM, "pem.private-key-block"),
        (FAKE_OPENSSH, "pem.private-key-block"),
        (FAKE_JWK, "jwk.private-params"),
        (FAKE_MNEMONIC, "seed.mnemonic-phrase"),
        (FAKE_OPENAI, "apikey.openai"),
        (FAKE_ANTHROPIC, "apikey.anthropic"),
        (FAKE_GITHUB, "apikey.github"),
        (FAKE_AWS, "apikey.aws"),
        (FAKE_ASSIGNMENT, "passphrase.assignment"),
    ],
)
def test_scanner_flags_secret_shaped_content(fixture: str, rule: str) -> None:
    findings = scan_text(fixture, "fixture.txt")
    assert findings, f"scanner missed {rule}"
    assert rule in {f.rule_id for f in findings}


def test_scanner_flags_a_private_key_file_written_to_disk(tmp_path: Path) -> None:
    target = tmp_path / "leaked.txt"
    target.write_text(FAKE_PEM, encoding="utf-8")
    assert main(["--root", str(tmp_path), str(target)]) == 1


def test_scanner_never_prints_the_matched_text(tmp_path: Path, capsys) -> None:
    target = tmp_path / "leaked.txt"
    target.write_text(FAKE_OPENAI, encoding="utf-8")
    main(["--root", str(tmp_path), str(target)])
    captured = capsys.readouterr()
    assert FAKE_OPENAI not in captured.out + captured.err
    assert "apikey.openai" in captured.err


def test_scanner_passes_clean_content() -> None:
    clean = (
        "def sign(payload: bytes) -> str:\n"
        "    return encode_signature(handle.sign(payload))\n"
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\n"
    )
    assert scan_text(clean, "clean.py") == []


def test_public_did_is_not_treated_as_a_secret() -> None:
    """A public DID is a public artefact; flagging it would train people to ignore alarms."""
    assert scan_text(
        "ROOT_AGENT_DID=did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "config.env",
    ) == []


def test_allow_marker_suppresses_a_deliberate_example() -> None:
    line = FAKE_OPENAI + "  # " + ALLOW_MARKER
    assert scan_text(line, "docs.md") == []


# --- filename rules --------------------------------------------------------
@pytest.mark.parametrize(
    "name",
    [
        "identity.pem", "root.key", "agent.jwk", "keystore.json.p12",
        ".env", ".env.local", "keys/id_ed25519", "secrets/agent.p8",
    ],
)
def test_secret_shaped_filenames_are_blocked(name: str) -> None:
    assert scan_name(name), f"{name} should be blocked"


def test_env_example_is_allowed() -> None:
    assert scan_name(".env.example") == []


# --- repository hygiene ----------------------------------------------------
def test_working_tree_is_clean(repo_root: Path) -> None:
    """The whole repository must pass the scanner."""
    assert main(["--root", str(repo_root), "--all"]) == 0


def test_gitignore_blocks_required_patterns(repo_root: Path) -> None:
    content = (repo_root / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
        "*.key", "*.pem", "*.jwk", ".env", ".env.*", "secrets/", "keys/",
        "*.sqlite", "*.sqlite3",
    ):
        assert pattern in content, f".gitignore is missing {pattern}"
    assert "!.env.example" in content


def test_no_key_or_database_files_are_present(repo_root: Path) -> None:
    offenders = [
        path.relative_to(repo_root).as_posix()
        for path in repo_root.rglob("*")
        if path.is_file()
        and ".venv" not in path.parts
        and path.suffix in {".pem", ".key", ".jwk", ".p8", ".p12", ".sqlite", ".sqlite3"}
    ]
    assert not offenders, f"secret-bearing files present in the tree: {offenders}"


# --- regression: the .gitignore must never swallow source files -----------
def test_no_source_file_is_gitignored(repo_root: Path) -> None:
    """M1 lost identity/keystore.py to a bare `keystore*` glob.

    Git applies an unanchored pattern to basenames at any depth, so one line in
    .gitignore silently excluded a module from the initial commit and a fresh
    clone could not import the package. The hygiene machinery ate a source file
    and every local test still passed, because the file was on disk.

    This asserts the shape of that failure, not the one instance of it: no
    tracked-worthy source or documentation file anywhere may be ignored.
    """
    import subprocess  # noqa: PLC0415

    candidates = [
        path
        for pattern in ("*.py", "*.md", "*.toml", "*.yaml", "*.yml", "*.json")
        for path in repo_root.rglob(pattern)
        if path.is_file()
        and not any(part in {".venv", ".git", "__pycache__", "build", "dist",
                             ".pytest_cache", "node_modules"}
                    for part in path.parts)
    ]
    assert candidates, "sanity: the glob found nothing"

    relative = [p.relative_to(repo_root).as_posix() for p in candidates]
    result = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=repo_root, input="\n".join(relative),
        capture_output=True, text=True,
    )
    ignored = [line for line in result.stdout.splitlines() if line.strip()]
    assert not ignored, (
        "these source/doc files are gitignored and would be missing from a clone: "
        f"{ignored}"
    )


def test_every_python_package_module_is_tracked_or_trackable(repo_root: Path) -> None:
    """A module that exists on disk but not in git makes local tests lie."""
    import subprocess  # noqa: PLC0415

    tracked = set(
        subprocess.run(["git", "ls-files"], cwd=repo_root,
                       capture_output=True, text=True).stdout.split()
    )
    on_disk = {
        p.relative_to(repo_root).as_posix()
        for package in ("identity", "technocore", "proof", "storage", "config",
                        "flopoffice", "tools")
        for p in (repo_root / package).rglob("*.py")
        if "__pycache__" not in p.parts
    }
    untracked = sorted(on_disk - tracked)
    # New files this milestone adds are legitimately untracked until staged; what
    # must never happen is a file git refuses to track at all.
    unstageable = [
        path for path in untracked
        if subprocess.run(["git", "check-ignore", "-q", path], cwd=repo_root).returncode == 0
    ]
    assert not unstageable, f"modules git will not track: {unstageable}"
