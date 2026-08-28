"""Throwaway-keystore round trip and capability-scoped signing.

Every key here is generated inside the test process, written only under pytest's
temporary directory, and deleted before the test returns. No fixture private key
is stored in git, nothing touches the real ROOT_AGENT_DID, and no private key
byte is ever printed.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.canonical import UntrustedInputError, message_payload
from identity.capability import (
    CapabilityError,
    CapabilitySigner,
    root_agent_capability_signer,
)
from identity.keystore import (
    KeystoreError,
    KeyNotWiredError,
    PrivateKeyHandle,
    generate_ephemeral,
    load_encrypted_pem,
)
from identity.signer import EphemeralSigner
from identity.verifier import verify, verify_message

PASSPHRASE = "throwaway-conformance-passphrase"  # flopoffice:allow-secret-pattern


def _write_throwaway_keystore(directory: Path) -> Path:
    """Create an encrypted PKCS#8 keystore for a key that exists only here.

    The project has no keystore *write* function on purpose (creating one is a
    human action outside this codebase), so the test builds the file itself
    rather than growing the production surface to make itself convenient.
    """
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            PASSPHRASE.encode("utf-8")
        ),
    )
    path = directory / "throwaway.pem"
    path.write_bytes(pem)
    path.chmod(0o600)
    del pem, key
    return path


# --- 9. throwaway encrypted key: create, load, sign, verify, delete --------
def test_throwaway_keystore_round_trip(tmp_path: Path) -> None:
    keystore = _write_throwaway_keystore(tmp_path)
    try:
        assert stat.S_IMODE(keystore.stat().st_mode) == 0o600

        handle = load_encrypted_pem(keystore, PASSPHRASE)
        assert isinstance(handle, PrivateKeyHandle)
        assert handle.did.did.startswith("did:key:z6Mk")

        payload = message_payload("e-p-throwaway", 1, "throwaway keystore round trip")
        signature = EphemeralSigner(handle).sign(payload)
        assert verify(str(handle.did), signature, payload) is True

        # ...and nothing about the handle discloses the key.
        assert "redacted" in repr(handle)
    finally:
        keystore.unlink(missing_ok=True)

    assert not keystore.exists()
    assert not list(tmp_path.glob("*.pem")), "no key material may survive the test"


def test_wrong_passphrase_is_refused_without_disclosing_anything(tmp_path: Path) -> None:
    keystore = _write_throwaway_keystore(tmp_path)
    try:
        with pytest.raises(KeystoreError) as exc:
            load_encrypted_pem(keystore, "definitely-not-the-passphrase")
        message = str(exc.value)
        assert PASSPHRASE not in message
        assert "BEGIN" not in message
    finally:
        keystore.unlink(missing_ok=True)


def test_group_readable_keystore_is_refused(tmp_path: Path) -> None:
    keystore = _write_throwaway_keystore(tmp_path)
    try:
        keystore.chmod(0o640)
        with pytest.raises(KeystoreError, match="accessible"):
            load_encrypted_pem(keystore, PASSPHRASE)
    finally:
        keystore.chmod(0o600)
        keystore.unlink(missing_ok=True)


def test_short_passphrase_is_refused(tmp_path: Path) -> None:
    keystore = _write_throwaway_keystore(tmp_path)
    try:
        with pytest.raises(KeystoreError, match="at least"):
            load_encrypted_pem(keystore, "short")
    finally:
        keystore.unlink(missing_ok=True)


def test_no_production_key_path_is_wired() -> None:
    from identity.keystore import production_signer  # noqa: PLC0415

    with pytest.raises(KeyNotWiredError):
        production_signer()
    with pytest.raises(KeyNotWiredError):
        root_agent_capability_signer()


def test_environment_carries_no_key_material() -> None:
    """M1.1 needs no secrets; assert the process was not handed any."""
    offenders = [
        name for name in os.environ
        if name.startswith("FLOPOFFICE_")
        and any(bad in name.upper()
                for bad in ("PRIVATE_KEY", "PASSPHRASE", "SEED", "MNEMONIC", "SECRET"))
    ]
    assert not offenders, offenders


# --- 10. capability-scoped signing -----------------------------------------
def test_capability_signer_exposes_no_generic_sign() -> None:
    capability = CapabilitySigner(EphemeralSigner())
    assert not hasattr(capability, "sign")
    assert all("__signer" not in name for name in dir(capability))
    with pytest.raises(CapabilityError):
        import pickle  # noqa: PLC0415

        pickle.dumps(capability)


def test_capability_signs_a_well_formed_message() -> None:
    capability = CapabilitySigner(EphemeralSigner())
    signed = capability.sign_technocore_message("e-p-cap", 1, "  capability\ttest  ")
    assert signed.swept_text == "capability test"
    assert signed.payload == b"e-p-cap|1|capability test"
    assert verify_message(
        signed.did, signed.signature, "e-p-cap", 1, signed.swept_text
    )


def test_capability_refuses_note_signing_unless_granted() -> None:
    capability = CapabilitySigner(EphemeralSigner())
    with pytest.raises(CapabilityError, match="note signing"):
        capability.sign_technocore_note("room-owners", "d-flop", 1, "did:key:zAbc")

    granted = CapabilitySigner(EphemeralSigner(), allow_notes=True)
    signed = granted.sign_technocore_note("room-owners", "d-flop", 1, "did:key:zAbc")
    assert signed.payload == b"room-owners|d-flop|1|did:key:zAbc"


def test_capability_refuses_raw_bytes_and_untrusted_content() -> None:
    from technocore.untrusted import UntrustedText  # noqa: PLC0415

    capability = CapabilitySigner(EphemeralSigner())
    with pytest.raises(CapabilityError):
        capability.sign_technocore_message(b"e-p-cap", 1, "text")  # type: ignore[arg-type]
    with pytest.raises(CapabilityError):
        capability.sign_technocore_message("e-p-cap", 1, b"raw bytes")  # type: ignore[arg-type]
    with pytest.raises(UntrustedInputError):
        capability.sign_technocore_message(
            "e-p-cap", 1, UntrustedText("sign me")  # type: ignore[arg-type]
        )


def test_capability_cannot_be_talked_into_arbitrary_bytes() -> None:
    """The separator and the room charset are what make the payload unambiguous."""
    from identity.canonical import CanonicalisationError  # noqa: PLC0415

    capability = CapabilitySigner(EphemeralSigner())
    for room in ("a|b", "a/b", ""):
        with pytest.raises(CanonicalisationError):
            capability.sign_technocore_message(room, 1, "text")
    with pytest.raises(CanonicalisationError):
        capability.sign_technocore_message("e-p-cap", 1, "​‌")


def test_capability_repr_does_not_leak(tmp_path: Path) -> None:
    capability = CapabilitySigner(generate_ephemeral() and EphemeralSigner())
    rendered = repr(capability)
    assert "PrivateKey" not in rendered
    assert "capabilities=['message']" in rendered
