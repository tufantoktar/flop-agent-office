"""The committed public ROOT_AGENT_DID (M1.2).

Every assertion here concerns *public* data. No test in this file loads a
keystore, constructs a signer, or reaches the network -- and several assert
positively that none of those happen.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from config.public_identity import ENV_OVERRIDE, ROOT_AGENT, ROOT_AGENT_DID
from config.settings import ConfigError, load
from identity.did import DidKey, decode_did_key, encode_did_key, is_valid_did_key

OTHER_VALID_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


# --- 1. the committed default loads --------------------------------------
def test_committed_did_is_a_valid_ed25519_did_key() -> None:
    assert is_valid_did_key(ROOT_AGENT_DID)
    raw = decode_did_key(ROOT_AGENT_DID)
    assert len(raw) == 32
    assert encode_did_key(raw) == ROOT_AGENT_DID, "must round-trip byte-exactly"
    assert isinstance(ROOT_AGENT, DidKey)
    assert ROOT_AGENT.did == ROOT_AGENT_DID


def test_committed_did_is_validated_at_import() -> None:
    """A malformed edit fails at import, not at whatever later call site."""
    import importlib  # noqa: PLC0415

    module = importlib.import_module("config.public_identity")
    assert isinstance(module.ROOT_AGENT, DidKey)


def test_settings_loads_the_committed_did_with_no_environment() -> None:
    settings = load({})
    assert settings.root_agent_did.did == ROOT_AGENT_DID
    assert settings.root_agent_did_source == "committed"


def test_public_key_is_recoverable_and_usable() -> None:
    """A did:key embeds a public key -- that is why it is safe to commit."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PublicKey,
    )

    assert isinstance(ROOT_AGENT.public_key, Ed25519PublicKey)


# --- 2. environment override ---------------------------------------------
def test_environment_override_replaces_the_committed_did() -> None:
    settings = load({ENV_OVERRIDE: OTHER_VALID_DID})
    assert settings.root_agent_did.did == OTHER_VALID_DID
    assert settings.root_agent_did_source == "environment"


def test_blank_or_whitespace_override_falls_back_to_committed() -> None:
    """There is always exactly one identity; an empty override is not a third state."""
    for blank in ("", "   ", "\t"):
        settings = load({ENV_OVERRIDE: blank})
        assert settings.root_agent_did.did == ROOT_AGENT_DID
        assert settings.root_agent_did_source == "committed"


def test_override_is_trimmed_but_not_otherwise_rewritten() -> None:
    settings = load({ENV_OVERRIDE: f"  {OTHER_VALID_DID}  "})
    assert settings.root_agent_did.did == OTHER_VALID_DID


# --- 3/4. strict validation, and the override cannot bypass it ------------
@pytest.mark.parametrize(
    "bad",
    [
        "not-a-did",
        "did:web:example.com",
        "did:key:",
        "did:key:q6MkhaXgBZ",                       # wrong multibase prefix
        "did:key:z0OIl",                            # outside the base58 alphabet
        ROOT_AGENT_DID[:-1],                        # truncated
        ROOT_AGENT_DID + "A",                       # extended
        ROOT_AGENT_DID.upper(),                     # case-mangled
        ROOT_AGENT_DID.replace("did:key:", "DID:KEY:"),
    ],
)
def test_malformed_override_is_rejected(bad: str) -> None:
    with pytest.raises(ConfigError, match="did:key"):
        load({ENV_OVERRIDE: bad})


def test_non_ed25519_did_key_is_rejected() -> None:
    """A structurally valid did:key with the wrong multicodec must not pass."""
    from identity.did import _b58encode  # noqa: PLC0415

    # secp256k1-pub is 0xE7 0x01; p256-pub is 0x80 0x24. Neither is Ed25519.
    for prefix, keylen in ((b"\xe7\x01", 33), (b"\x80\x24", 33)):
        did = "did:key:z" + _b58encode(prefix + b"\x02" * keylen)
        assert not is_valid_did_key(did)
        with pytest.raises(ConfigError, match="did:key"):
            load({ENV_OVERRIDE: did})


def test_rejection_message_names_the_variable_and_the_requirement() -> None:
    with pytest.raises(ConfigError) as exc:
        load({ENV_OVERRIDE: "did:key:zNope"})
    message = str(exc.value)
    assert ENV_OVERRIDE in message
    assert "Ed25519" in message


# --- 5. public-only data ---------------------------------------------------
def test_the_module_contains_only_public_data(repo_root: Path) -> None:
    """Structural, not lexical.

    A first attempt grepped the source for words like "private key" and failed --
    because the module's docstring *warns* about them, which is a virtue. Prose
    that explains what an identifier is not is exactly what belongs here. What
    must not exist is machinery: file reads, key imports, or a secret-shaped
    assignment.
    """
    source = (repo_root / "config" / "public_identity.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"open", "eval", "exec", "compile", "input"}, called

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert imported == {"identity.did", "__future__"}, (
        f"the public identity module should import nothing else; got {imported}"
    )

    assigned = {
        target.id
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        if isinstance(target, ast.Name)
    }
    for name in assigned:
        assert not any(
            bad in name.lower()
            for bad in ("private", "secret", "passphrase", "seed", "mnemonic", "key_bytes")
        ), f"secret-shaped module attribute: {name}"

    # And the scanner -- the repository's own definition of "looks like a secret"
    # -- must find nothing in it.
    from tools.secret_scan import scan_text  # noqa: PLC0415

    assert scan_text(source, "config/public_identity.py") == []


def test_secret_scanner_does_not_flag_the_public_did() -> None:
    """A public artefact must not trip the alarm -- false alarms get ignored."""
    from tools.secret_scan import scan_text  # noqa: PLC0415

    assert scan_text(f"{ENV_OVERRIDE}={ROOT_AGENT_DID}", "config.env") == []
    assert scan_text(f'ROOT_AGENT_DID = "{ROOT_AGENT_DID}"', "x.py") == []


def test_only_one_canonical_did_in_production_source(repo_root: Path) -> None:
    """P1: one identity.

    Scoped to production source and documentation, not to tests. Test modules
    legitimately need *other* DIDs -- one to prove nonce scoping is per-key, one
    published spec vector to prove decoding, and the conformance fixture records
    one ephemeral key per attempt. Those are fixtures and evidence, not
    identities this project holds, and a rule that forbade them would be a rule
    nobody could keep.

    What must never happen is a second identity appearing in the code that runs.
    """
    import re  # noqa: PLC0415

    pattern = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{40,}")
    found: dict[str, list[str]] = {}

    for package in ("config", "identity", "technocore", "proof", "storage",
                    "flopoffice", "tools", "docs"):
        root = repo_root / package
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.suffix not in {".py", ".md", ".toml", ".yaml", ".yml"}:
                continue
            if "__pycache__" in path.parts:
                continue
            rel = path.relative_to(repo_root).as_posix()
            for match in pattern.findall(path.read_text(encoding="utf-8", errors="ignore")):
                found.setdefault(match, []).append(rel)

    # docs/ may cite the published W3C spec vector when explaining did:key.
    spec_vector = OTHER_VALID_DID
    identities = {did: files for did, files in found.items() if did != spec_vector}
    assert set(identities) <= {ROOT_AGENT_DID}, (
        f"a second identity appears in production source: "
        f"{ {d: f for d, f in identities.items() if d != ROOT_AGENT_DID} }"
    )
    assert ROOT_AGENT_DID in found, "the canonical DID should appear in config/"


def test_the_canonical_did_is_written_down_exactly_once(repo_root: Path) -> None:
    """One definition, so changing identity is one reviewable line."""
    import re  # noqa: PLC0415

    pattern = re.compile(re.escape(ROOT_AGENT_DID))
    definitions = []
    for package in ("config", "identity", "technocore", "proof", "storage",
                    "flopoffice", "tools"):
        root = repo_root / package
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            if pattern.search(path.read_text(encoding="utf-8")):
                definitions.append(path.relative_to(repo_root).as_posix())
    assert definitions == ["config/public_identity.py"], definitions


# --- 6/7/8. configuring an identity creates no signer ---------------------
def test_loading_settings_creates_no_signer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configuring a public identity must not touch a key, ever."""
    import identity.keystore as keystore  # noqa: PLC0415

    calls: list[str] = []
    for name in ("load_encrypted_pem", "generate_ephemeral", "production_signer"):
        monkeypatch.setattr(
            keystore, name,
            lambda *a, _n=name, **k: calls.append(_n),  # noqa: ARG005
        )

    settings = load({})
    assert settings.root_agent_did.did == ROOT_AGENT_DID
    assert calls == [], f"settings.load() reached key machinery: {calls}"


def test_settings_module_never_imports_key_machinery(repo_root: Path) -> None:
    source = (repo_root / "config" / "settings.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert "identity.keystore" not in imported
    assert "identity.capability" not in imported
    assert "identity.signer" not in imported


def test_production_signer_still_raises() -> None:
    from identity.keystore import KeyNotWiredError, production_signer  # noqa: PLC0415

    with pytest.raises(KeyNotWiredError):
        production_signer()


def test_root_agent_capability_signer_still_raises() -> None:
    from identity.capability import root_agent_capability_signer  # noqa: PLC0415
    from identity.keystore import KeyNotWiredError  # noqa: PLC0415

    with pytest.raises(KeyNotWiredError):
        root_agent_capability_signer()


def test_no_automatic_generation_or_rotation_exists(repo_root: Path) -> None:
    """P1: nothing may mint or rotate the project identity on its own."""
    import re  # noqa: PLC0415

    offenders = []
    for package in ("config", "identity", "technocore", "proof", "storage", "flopoffice"):
        for path in (repo_root / package).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if re.search(r"\bdef\s+(rotate|regenerate|new_did|mint_did)\w*", text):
                offenders.append(path.relative_to(repo_root).as_posix())
    assert not offenders, f"DID rotation/minting entry points exist: {offenders}"


# --- 9/10 are covered by tests/security; 11. CLI output --------------------
def test_doctor_shows_the_public_did_and_no_private_data(capsys) -> None:
    from flopoffice.__main__ import main  # noqa: PLC0415

    assert main(["doctor"]) == 0
    out = capsys.readouterr().out

    assert ROOT_AGENT.short in out
    assert ROOT_AGENT_DID not in out, "abbreviated by default"
    assert "(committed)" in out

    for forbidden in ("PRIVATE", "passphrase", "BEGIN", ".pem", ".jwk", "keystore path"):
        assert forbidden not in out
    assert "NOT WIRED" in out
    assert "not authorisation to sign" in out


def test_doctor_full_did_prints_the_complete_public_value(capsys) -> None:
    from flopoffice.__main__ import main  # noqa: PLC0415

    assert main(["doctor", "--full-did"]) == 0
    out = capsys.readouterr().out
    assert ROOT_AGENT_DID in out
    for forbidden in ("PRIVATE", "passphrase", "BEGIN"):
        assert forbidden not in out


def test_doctor_reports_an_environment_override(capsys, monkeypatch) -> None:
    monkeypatch.setenv(ENV_OVERRIDE, OTHER_VALID_DID)
    from flopoffice.__main__ import main  # noqa: PLC0415

    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "(environment)" in out


def test_doctor_fails_clearly_on_a_malformed_override(capsys, monkeypatch) -> None:
    monkeypatch.setenv(ENV_OVERRIDE, "did:key:zBroken")
    from flopoffice.__main__ import main  # noqa: PLC0415

    assert main(["doctor"]) == 3
    err = capsys.readouterr().err
    assert "CONFIG ERROR" in err
    assert ENV_OVERRIDE in err
