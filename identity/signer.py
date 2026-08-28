"""The Signer protocol and its M1 implementations.

Technocore signatures are 86 unpadded base64url characters (64 raw Ed25519
bytes). The encoding is fixed here so no caller can get it subtly wrong.

M1 ships:
  * :class:`EphemeralSigner` -- backed by a throwaway key, for tests and local
    integration against a self-hosted server.
  * :class:`NullSigner` -- refuses to sign; used to prove that code paths which
    must not sign genuinely do not.

There is no signer wired to the real root-agent key. That is deliberate.
"""

from __future__ import annotations

import base64
from typing import Protocol, runtime_checkable

from .canonical import UntrustedInputError
from .did import DidKey
from .keystore import KeystoreError, PrivateKeyHandle, generate_ephemeral

__all__ = [
    "SignatureError",
    "Signer",
    "EphemeralSigner",
    "NullSigner",
    "encode_signature",
    "decode_signature",
    "SIGNATURE_CHARS",
    "SIGNATURE_BYTES",
]

SIGNATURE_BYTES = 64
SIGNATURE_CHARS = 86


class SignatureError(Exception):
    """Signing or signature-encoding failure."""


def encode_signature(raw: bytes) -> str:
    """Encode a raw Ed25519 signature as unpadded base64url (86 chars)."""
    if type(raw) is not bytes or len(raw) != SIGNATURE_BYTES:
        raise SignatureError(f"signature must be exactly {SIGNATURE_BYTES} raw bytes")
    text = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if len(text) != SIGNATURE_CHARS:
        raise SignatureError(
            f"encoded signature is {len(text)} chars, expected {SIGNATURE_CHARS}"
        )
    return text


def decode_signature(text: str) -> bytes:
    """Decode an 86-char unpadded base64url signature to 64 raw bytes."""
    if not isinstance(text, str):
        raise SignatureError("signature must be a str")
    if len(text) != SIGNATURE_CHARS:
        raise SignatureError(
            f"signature must be {SIGNATURE_CHARS} characters, got {len(text)}"
        )
    if "=" in text:
        raise SignatureError("signature must be unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "==")
    except Exception:  # noqa: BLE001
        raise SignatureError("signature is not valid base64url") from None
    if len(raw) != SIGNATURE_BYTES:
        raise SignatureError(
            f"decoded signature is {len(raw)} bytes, expected {SIGNATURE_BYTES}"
        )
    return raw


@runtime_checkable
class Signer(Protocol):
    """Anything that can produce a Technocore-shaped signature for a DID."""

    @property
    def did(self) -> DidKey: ...

    def sign(self, payload: bytes) -> str:
        """Return an 86-char unpadded base64url signature over ``payload``."""
        ...


class EphemeralSigner:
    """Signer backed by a throwaway key. Tests and local integration only."""

    __slots__ = ("_handle",)

    def __init__(self, handle: PrivateKeyHandle | None = None) -> None:
        self._handle = handle if handle is not None else generate_ephemeral()

    @property
    def did(self) -> DidKey:
        return self._handle.did

    def sign(self, payload: bytes) -> str:
        if getattr(payload, "__flopoffice_untrusted__", False):
            raise UntrustedInputError(
                "refusing to sign untrusted, network-sourced content"
            )
        if type(payload) is not bytes:  # noqa: E721
            raise SignatureError(
                "sign() requires exactly bytes -- build it with identity.canonical"
            )
        try:
            raw = self._handle.sign(payload)
        except KeystoreError as exc:
            raise SignatureError(str(exc)) from None
        return encode_signature(raw)

    def __repr__(self) -> str:
        return f"EphemeralSigner(did={self._handle.did.short})"


class NullSigner:
    """A signer that always refuses. Used to assert non-signing code paths."""

    __slots__ = ("_did",)

    def __init__(self, did: DidKey | str) -> None:
        self._did = did if isinstance(did, DidKey) else DidKey(did)

    @property
    def did(self) -> DidKey:
        return self._did

    def sign(self, payload: bytes) -> str:  # noqa: ARG002
        raise SignatureError("NullSigner cannot sign; no key is wired")

    def __repr__(self) -> str:
        return f"NullSigner(did={self._did.short})"
