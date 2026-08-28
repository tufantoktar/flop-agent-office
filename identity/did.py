"""did:key encoding/decoding for Ed25519, per the Technocore requirement.

Technocore accepts Ed25519 keys only, expressed as
``did:key:z<base58btc(multicodec)>`` where the multicodec prefix for
``ed25519-pub`` is 0xED 0x01 followed by the 32-byte raw public key.

This module resolves nothing over the network. A did:key is self-describing:
the public key is *inside* the identifier, so resolution is pure decoding. That
is a security property worth keeping -- no DID document fetch means no fetch to
poison.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "DidKeyError",
    "ED25519_MULTICODEC",
    "encode_did_key",
    "decode_did_key",
    "public_key_from_did",
    "is_valid_did_key",
    "DidKey",
]

ED25519_MULTICODEC = b"\xed\x01"
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

DID_PREFIX = "did:key:"
MULTIBASE_BASE58BTC = "z"
ED25519_PUBLIC_KEY_LENGTH = 32


class DidKeyError(ValueError):
    """Raised when a did:key string is malformed or not Ed25519.

    Carries only structural information -- never key material.
    """


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_B58_ALPHABET[rem])
    # Leading zero bytes map to leading '1's.
    for byte in data:
        if byte != 0:
            break
        out.append(_B58_ALPHABET[0])
    return out[::-1].decode("ascii")


def _b58decode(text: str) -> bytes:
    if not text:
        raise DidKeyError("empty base58btc payload")
    n = 0
    for char in text.encode("ascii", errors="strict"):
        try:
            n = n * 58 + _B58_INDEX[char]
        except KeyError:
            raise DidKeyError("invalid base58btc character in did:key") from None
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading = 0
    for char in text:
        if char != "1":
            break
        leading += 1
    return b"\x00" * leading + body


def encode_did_key(public_key_bytes: bytes) -> str:
    """Encode a raw 32-byte Ed25519 public key as a did:key string."""
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise DidKeyError("public key must be bytes")
    if len(public_key_bytes) != ED25519_PUBLIC_KEY_LENGTH:
        raise DidKeyError(
            f"Ed25519 public key must be {ED25519_PUBLIC_KEY_LENGTH} bytes, "
            f"got {len(public_key_bytes)}"
        )
    payload = ED25519_MULTICODEC + bytes(public_key_bytes)
    return f"{DID_PREFIX}{MULTIBASE_BASE58BTC}{_b58encode(payload)}"


def decode_did_key(did: str) -> bytes:
    """Return the raw 32-byte Ed25519 public key inside ``did``.

    Raises DidKeyError for anything that is not a well-formed Ed25519 did:key.
    """
    if not isinstance(did, str):
        raise DidKeyError("did must be a str")
    if not did.startswith(DID_PREFIX):
        raise DidKeyError("did must start with 'did:key:'")
    body = did[len(DID_PREFIX):]
    if not body.startswith(MULTIBASE_BASE58BTC):
        raise DidKeyError("did:key must use multibase base58btc ('z') encoding")
    decoded = _b58decode(body[1:])
    if not decoded.startswith(ED25519_MULTICODEC):
        raise DidKeyError("did:key is not an ed25519-pub key (multicodec 0xED01)")
    key = decoded[len(ED25519_MULTICODEC):]
    if len(key) != ED25519_PUBLIC_KEY_LENGTH:
        raise DidKeyError(
            f"decoded key is {len(key)} bytes, expected {ED25519_PUBLIC_KEY_LENGTH}"
        )
    return key


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """Return a usable Ed25519PublicKey object for ``did``."""
    return Ed25519PublicKey.from_public_bytes(decode_did_key(did))


def is_valid_did_key(did: str) -> bool:
    try:
        decode_did_key(did)
    except DidKeyError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class DidKey:
    """A validated public identity. Contains no private material by design."""

    did: str

    def __post_init__(self) -> None:
        decode_did_key(self.did)  # raises DidKeyError if malformed

    @classmethod
    def from_public_bytes(cls, public_key_bytes: bytes) -> "DidKey":
        return cls(encode_did_key(public_key_bytes))

    @property
    def public_key_bytes(self) -> bytes:
        return decode_did_key(self.did)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return public_key_from_did(self.did)

    @property
    def short(self) -> str:
        """Technocore-style abbreviation, e.g. 'z6Mk...2doK'."""
        body = self.did[len(DID_PREFIX):]
        return f"{body[:4]}...{body[-4:]}" if len(body) > 12 else body

    def __str__(self) -> str:
        return self.did
