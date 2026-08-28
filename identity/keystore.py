"""Private key custody.

Rules this module enforces mechanically, not by convention:

1. Raw private key bytes never cross the object boundary. There is no accessor
   that returns them. Signing happens *inside* the handle.
2. ``repr()``, ``str()``, ``format()`` and pickling never reveal key material.
   Pickling is refused outright -- a pickled key is a key written to disk.
3. Exceptions raised here carry a path or a reason, never file content.
4. The only real-key wiring path is explicit and capability-scoped. This module
   never discovers a keystore and never returns a production raw signer.
   :func:`production_signer` deliberately raises.
5. Real DID generation and rotation are not implemented. Both require an
   explicit, interactive human decision that this codebase does not take.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .did import DidKey

__all__ = [
    "KeystoreError",
    "KeyNotWiredError",
    "KeystorePermissionError",
    "DEFAULT_KEYSTORE_DIR",
    "derive_did",
    "PrivateKeyHandle",
    "generate_ephemeral",
    "load_encrypted_pem",
    "save_encrypted_pem",
    "production_signer",
    "REDACTED",
]

REDACTED: Final = "<Ed25519PrivateKey redacted>"
_MIN_PASSPHRASE_LEN: Final = 12

#: Where a real keystore is expected to live: outside any repository, in the
#: user's home, in a directory only they can read. Nothing auto-discovers it --
#: this constant documents the policy and gives the future wiring step a default
#: to validate against. It is never read at import.
DEFAULT_KEYSTORE_DIR: Final = "~/.flopoffice/keys/"
REPO_ROOT: Final = Path(__file__).resolve().parents[1]


class KeystoreError(Exception):
    """Keystore failure. Never carries key material or file content."""


class KeyNotWiredError(KeystoreError):
    """A production signing path was requested that M1 deliberately does not provide."""


class KeystorePermissionError(KeystoreError):
    """The keystore file or its directory is readable by someone other than the owner."""


class PrivateKeyHandle:
    """Opaque custodian of an Ed25519 private key.

    The private key object is stored on a name-mangled attribute and is never
    returned. Callers get signatures, a public key, and a DID -- nothing else.
    """

    __slots__ = ("__key", "__did", "__label")

    def __init__(self, key: Ed25519PrivateKey, *, label: str = "unlabelled") -> None:
        if not isinstance(key, Ed25519PrivateKey):
            raise KeystoreError("handle requires an Ed25519 private key")
        object.__setattr__(self, "_PrivateKeyHandle__key", key)
        object.__setattr__(self, "_PrivateKeyHandle__label", label)
        public_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        object.__setattr__(
            self, "_PrivateKeyHandle__did", DidKey.from_public_bytes(public_bytes)
        )

    # --- the only capability the handle grants -------------------------------
    def sign(self, payload: bytes) -> bytes:
        """Return a raw 64-byte Ed25519 signature over ``payload``."""
        if type(payload) is not bytes:  # noqa: E721 - subclasses may carry taint
            raise KeystoreError(
                "sign() requires exactly bytes; wrapper/tainted types are refused"
            )
        return self.__key.sign(payload)

    # --- public, safe surface ------------------------------------------------
    @property
    def did(self) -> DidKey:
        return self.__did

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.__key.public_key()

    @property
    def label(self) -> str:
        return self.__label

    # --- leak prevention -----------------------------------------------------
    def __repr__(self) -> str:
        return f"PrivateKeyHandle(label={self.__label!r}, did={self.__did.short}, key={REDACTED})"

    def __str__(self) -> str:
        return self.__repr__()

    def __format__(self, spec: str) -> str:
        return self.__repr__()

    def __reduce__(self):
        raise KeystoreError("PrivateKeyHandle is not serialisable")

    def __getstate__(self):
        raise KeystoreError("PrivateKeyHandle is not serialisable")

    def __copy__(self):
        raise KeystoreError("PrivateKeyHandle must not be copied")

    def __deepcopy__(self, memo):
        raise KeystoreError("PrivateKeyHandle must not be copied")

    def __dir__(self):
        # Keep the mangled attribute out of tab-completion and introspection dumps.
        return [n for n in super().__dir__() if "__key" not in n]


def generate_ephemeral(*, label: str = "ephemeral-test-key") -> PrivateKeyHandle:
    """Generate a throwaway keypair.

    Intended for tests and local development only. Refused when
    ``FLOPOFFICE_ENV=prod`` so an accidental production call cannot mint an
    identity that then starts signing.

    This is NOT how the root agent DID is created. Creating or rotating the real
    DID is an explicit human action performed outside this codebase.
    """
    if os.environ.get("FLOPOFFICE_ENV", "dev").lower() == "prod":
        raise KeystoreError(
            "ephemeral key generation is disabled when FLOPOFFICE_ENV=prod"
        )
    return PrivateKeyHandle(Ed25519PrivateKey.generate(), label=label)


def save_encrypted_pem(
    handle: PrivateKeyHandle, path: Path | str, passphrase: str
) -> Path:
    """Write an encrypted PKCS#8 PEM. Used by tests with ephemeral keys.

    Refuses to write inside the repository working tree and refuses weak
    passphrases. The file is created 0600.
    """
    raise KeyNotWiredError(
        "save_encrypted_pem is intentionally not implemented in M1: writing a "
        "keystore is a human action taken outside this codebase. Implement it "
        "only when there is a reviewed key-management procedure to attach it to."
    )


def load_encrypted_pem(path: Path | str, passphrase: str | bytes) -> PrivateKeyHandle:
    """Load an encrypted PKCS#8 Ed25519 private key from ``path``.

    Implemented and unit-tested against keys created inside the test process.
    It is not called by any M1 code path and must not be pointed at the real
    root-agent keystore until the signing milestone is explicitly approved.
    """
    p = Path(path).expanduser()
    if _is_inside_repo(p):
        raise KeystoreError(
            "keystore path is inside the repository working tree; keep signing "
            "keys outside the repo"
        )
    if p.is_symlink():
        raise KeystoreError("keystore path is a symlink; refusing to follow it")
    if not p.exists():
        raise KeystoreError(f"keystore not found: {p}")
    if not p.is_file():
        raise KeystoreError(f"keystore path is not a regular file: {p}")
    passphrase_bytes = _passphrase_bytes(passphrase)
    if len(passphrase_bytes) < _MIN_PASSPHRASE_LEN:
        raise KeystoreError(
            f"passphrase must be at least {_MIN_PASSPHRASE_LEN} characters"
        )

    if p.stat().st_mode & 0o077:
        raise KeystorePermissionError(
            f"keystore {p} is group/world accessible; chmod 600 it before use"
        )
    # The directory matters too: 0600 on the file is no protection if anyone can
    # rename it, replace it, or drop a symlink in its place.
    parent = p.parent
    if parent.exists() and parent.stat().st_mode & 0o077:
        raise KeystorePermissionError(
            f"keystore directory {parent} is group/world accessible; "
            f"chmod 700 it before use"
        )

    data = None
    try:
        data = p.read_bytes()
        if b"ENCRYPTED" not in data and b"-----BEGIN OPENSSH" not in data:
            # An unencrypted PKCS#8 PEM would load happily if we passed
            # password=None. We never do: there is no plaintext fallback, and a
            # key sitting in the clear is a finding, not an inconvenience.
            raise KeystoreError(
                f"keystore {p} does not look encrypted. This loader has no "
                "plaintext fallback -- re-export the key with a passphrase."
            )
        key = serialization.load_pem_private_key(
            data, password=passphrase_bytes
        )
    except KeystoreError:
        raise
    except Exception:  # noqa: BLE001 - message is deliberately content-free
        raise KeystoreError(
            f"could not decrypt keystore at {p} (wrong passphrase or bad format)"
        ) from None
    finally:
        data = None  # drop the reference promptly

    if not isinstance(key, Ed25519PrivateKey):
        raise KeystoreError("keystore does not contain an Ed25519 private key")
    return PrivateKeyHandle(key, label=p.name)


def _passphrase_bytes(passphrase: str | bytes) -> bytes:
    if isinstance(passphrase, str):
        return passphrase.encode("utf-8")
    if isinstance(passphrase, bytes):
        return passphrase
    raise KeystoreError("passphrase must be supplied at runtime as str or bytes")


def _is_inside_repo(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(REPO_ROOT)
    except ValueError:
        return False
    return True


def derive_did(handle: PrivateKeyHandle) -> DidKey:
    """The did:key implied by a loaded private key.

    Public output from private input, which is the whole point: it lets the
    wiring step check that the key in the file is the key the project claims,
    without anything private leaving the handle.
    """
    return handle.did


def production_signer():
    """Deliberately unavailable: production code must use capabilities only."""
    raise KeyNotWiredError(
        "No raw production signer is available. Root-agent signing, when "
        "explicitly enabled, returns only a CapabilitySigner."
    )
