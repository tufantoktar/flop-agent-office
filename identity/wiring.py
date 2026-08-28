"""The one designed path from a keystore file to a signing capability.

    ROOT_AGENT_DID  (config/public_identity.py, committed, public)
         |
    keystore path   (local config; never auto-discovered)
         |
    load_encrypted_pem(path, passphrase)      -> PrivateKeyHandle (opaque)
         |
    assert_key_matches_did(handle, expected)  -> fail closed on mismatch
         |
    EphemeralSigner(handle)                   -> raw Signer, never returned
         |
    CapabilitySigner(signer)                  -> the only thing a caller gets
         |
    sign_technocore_message / sign_technocore_note

Two properties make this worth writing down as code rather than prose.

**The raw signer never escapes.** :func:`build_capability_signer` constructs it
and immediately wraps it; the wrapper is what is returned, and the wrapper holds
the signer in a closure rather than an attribute. Nothing in this module hands a
`sign(bytes)` oracle to a caller.

**It is closed by default.** The function refuses unless the caller passes
``reviewed=True`` -- a keyword that exists to make wiring a deliberate, greppable
act rather than something that happens because a config value was set. In M1.3
the only callers that pass it are tests using throwaway keys.
:func:`root_agent_capability_signer` does not pass it and never will until that
is a reviewed change.

Nothing here reads a path on its own. There is no auto-discovery from the
repository, the working directory, ``~/Downloads``, ``~/.flopoffice`` or the
environment: every input arrives as an argument.
"""

from __future__ import annotations

from pathlib import Path

from identity.capability import CapabilitySigner
from identity.did import DidKey
from identity.keystore import (
    KeyNotWiredError,
    KeystoreError,
    PrivateKeyHandle,
    load_encrypted_pem,
)
from identity.signer import EphemeralSigner

__all__ = [
    "DidMismatchError",
    "assert_key_matches_did",
    "build_capability_signer",
    "REVIEW_GATE_MESSAGE",
]

REVIEW_GATE_MESSAGE = (
    "signer wiring is gated: pass reviewed=True only from a change that has been "
    "reviewed for it. The root agent's key is not wired in this milestone."
)


class DidMismatchError(KeystoreError):
    """The loaded key does not correspond to the DID we expected.

    This is a fail-closed condition, never a warning. A key that is not the
    project's identity must not sign as the project's identity -- whether the
    cause is the wrong file, a rotated key, a stale config, or an attacker who
    swapped the keystore.
    """


def assert_key_matches_did(handle: PrivateKeyHandle, expected: DidKey | str) -> DidKey:
    """Check that ``handle``'s public key derives exactly ``expected``.

    Compares the 32 raw public-key bytes, not the strings: two encodings of the
    same key must compare equal, and two different keys must not compare equal
    because their text happens to look alike.

    Raises :class:`DidMismatchError` on any disagreement. The error names both
    DIDs -- they are public -- and nothing private appears in it or anywhere on
    this path.
    """
    want = expected if isinstance(expected, DidKey) else DidKey(str(expected))
    got = handle.did

    if got.public_key_bytes != want.public_key_bytes:
        raise DidMismatchError(
            "keystore does not hold the expected identity: the key derives "
            f"{got.did}, but the configured ROOT_AGENT_DID is {want.did}. "
            "Refusing to sign. Check which keystore the path points at; do not "
            "change the configured DID to match a key."
        )
    if got.did != want.did:  # pragma: no cover - unreachable while encoding is canonical
        raise DidMismatchError(
            "keystore key matches byte-for-byte but its did:key encoding differs "
            f"({got.did} vs {want.did}); refusing to sign on an ambiguous encoding"
        )
    return got


def build_capability_signer(
    keystore_path: Path | str,
    passphrase: str,
    expected_did: DidKey | str,
    *,
    allow_notes: bool = False,
    reviewed: bool = False,
) -> CapabilitySigner:
    """Load a keystore and return a capability-scoped signer for it.

    Order matters and is the point of the function: load, then **verify identity,
    then** construct anything that can sign. A mismatch raises before a signer
    exists, so there is no window in which the wrong key is holdable.

    ``reviewed`` must be True. See :data:`REVIEW_GATE_MESSAGE`.
    """
    if not reviewed:
        raise KeyNotWiredError(REVIEW_GATE_MESSAGE)

    handle = load_encrypted_pem(keystore_path, passphrase)
    assert_key_matches_did(handle, expected_did)

    # The raw signer is constructed here and wrapped in the same expression it is
    # created in; no name in this scope outlives the call holding it.
    return CapabilitySigner(EphemeralSigner(handle), allow_notes=allow_notes)


# NOTE: the public gate stays where it already was --
# identity.capability.root_agent_capability_signer -- so there is one name for it
# and existing tests and docs keep pointing at the same thing. When it is opened
# it must call build_capability_signer() above, so the DID check and the
# capability wrapper cannot be bypassed.
