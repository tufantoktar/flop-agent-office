"""Signature verification.

Verification answers exactly one question: *did the holder of the private key
behind this did:key produce this signature over these bytes?*

It does not answer whether the signer is trustworthy. Technocore's own auth
documentation puts it best: "a key that has written a thousand honest messages
can write a malicious one next." Verification is an authenticity check, never an
authorisation decision.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature

from .canonical import message_payload, note_payload
from .did import DidKeyError, public_key_from_did
from .signer import SignatureError, decode_signature

__all__ = ["verify", "verify_message", "verify_note"]


def verify(did: str, signature: str, payload: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature by ``did``.

    Total function: every malformed input returns False rather than raising, so
    a caller cannot accidentally treat an exception path as success. Nothing
    about the failure is disclosed to the caller by design -- distinguishing
    "bad encoding" from "wrong key" is not useful and invites oracles.
    """
    if type(payload) is not bytes:  # noqa: E721
        return False
    try:
        public_key = public_key_from_did(did)
        raw = decode_signature(signature)
    except (DidKeyError, SignatureError):
        return False
    try:
        public_key.verify(raw, payload)
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 - never let a crypto backend error read as valid
        return False
    return True


def verify_message(did: str, signature: str, room: str, nonce: int, text: str) -> bool:
    """Verify a room message by rebuilding the canonical payload ourselves.

    We never trust a payload handed to us; we reconstruct it from the parts.
    """
    try:
        payload = message_payload(room, nonce, text)
    except ValueError:
        return False
    return verify(did, signature, payload)


def verify_note(
    did: str, signature: str, namespace: str, key: str, nonce: int, value: str
) -> bool:
    try:
        payload = note_payload(namespace, key, nonce, value)
    except ValueError:
        return False
    return verify(did, signature, payload)
