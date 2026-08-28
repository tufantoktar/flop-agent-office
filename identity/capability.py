"""Capability-scoped signing.

Why this exists
---------------
``Signer.sign(payload: bytes)`` is a general-purpose oracle: anything that holds
one can sign *any* bytes. Handing that to orchestration code means the blast
radius of a single injection, a stray f-string, or a careless helper is "the key
signed something we never intended".

A capability signer removes the general case. Callers cannot express
"sign these bytes"; they can only express the two operations Technocore actually
has:

    sign_technocore_message(room, nonce, text)  -> SignedMessage
    sign_technocore_note(namespace, key, nonce, value) -> SignedNote

The bytes are built *inside*, from validated components, by
``identity.canonical``. There is no parameter through which arbitrary bytes can
reach the key, so a caller that gets confused signs a well-formed Technocore
statement at worst -- never an attestation, a transaction, or a challenge
response for some other protocol that happens to use Ed25519.

Scope in M1.1
-------------
This is the interface and its guards, tested against ephemeral keys. **No real
key is wired.** :func:`root_agent_capability_signer` raises, exactly as
``keystore.production_signer`` does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .canonical import (
    MAX_MESSAGE_CHARS,
    CanonicalisationError,
    UntrustedInputError,
    message_payload,
    note_payload,
    require_non_empty,
    single_line_sweep,
    validate_name,
    validate_nonce,
    validate_room,
)
from .did import DidKey
from .keystore import KeyNotWiredError
from .signer import Signer

__all__ = [
    "CapabilityError",
    "SignedMessage",
    "SignedNote",
    "TechnocoreCapability",
    "CapabilitySigner",
    "root_agent_capability_signer",
]


class CapabilityError(Exception):
    """A capability was used outside its declared scope."""


@dataclass(frozen=True, slots=True)
class SignedMessage:
    did: str
    room: str
    nonce: int
    swept_text: str
    signature: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class SignedNote:
    did: str
    namespace: str
    key: str
    nonce: int
    swept_value: str
    signature: str
    payload: bytes


class TechnocoreCapability(Protocol):
    """The complete set of things a holder may sign. Deliberately small."""

    @property
    def did(self) -> DidKey: ...

    def sign_technocore_message(
        self, room: str, nonce: int, text: str
    ) -> SignedMessage: ...

    def sign_technocore_note(
        self, namespace: str, key: str, nonce: int, value: str
    ) -> SignedNote: ...


class CapabilitySigner:
    """Wraps a raw :class:`~identity.signer.Signer` and narrows it to two verbs.

    The wrapped signer is held on a name-mangled attribute and is never returned.
    Orchestration code receives one of these; nothing above this layer ever holds
    something with a general ``sign(bytes)`` method.
    """

    __slots__ = ("__sign", "__did", "__allow_notes")

    def __init__(self, signer: Signer, *, allow_notes: bool = False) -> None:
        # The wrapped signer is captured in a closure, not stored as an
        # attribute. A `self.__signer` attribute is reachable through its
        # mangled name (`obj._CapabilitySigner__signer`) by anyone who knows the
        # trick; a closure at least requires walking __closure__ cells. Neither
        # is a barrier against arbitrary in-process code -- Python cannot offer
        # one -- but it removes the *accidental* path, which is the threat this
        # class exists for: orchestration code that ends up holding a general
        # sign(bytes) oracle without anybody deciding it should.
        object.__setattr__(self, "_CapabilitySigner__sign", signer.sign)
        object.__setattr__(self, "_CapabilitySigner__did", signer.did)
        # Note-signing is what claims and holds `d-` rooms and writes
        # /kv/room-owners. It is off unless a caller deliberately asks, so the
        # common case cannot reach it at all.
        object.__setattr__(self, "_CapabilitySigner__allow_notes", bool(allow_notes))

    @property
    def did(self) -> DidKey:
        return self.__did

    @property
    def notes_allowed(self) -> bool:
        return self.__allow_notes

    # --- the only two capabilities -------------------------------------
    def sign_technocore_message(
        self, room: str, nonce: int, text: str
    ) -> SignedMessage:
        """Sign one Technocore room message, built from validated parts."""
        self._guard(room, text)
        room = validate_room(room)
        nonce = validate_nonce(nonce)
        swept = require_non_empty(single_line_sweep(text))
        if len(swept) > MAX_MESSAGE_CHARS:
            raise CanonicalisationError(
                f"message is {len(swept)} chars after the sweep; the limit is "
                f"{MAX_MESSAGE_CHARS}"
            )
        payload = message_payload(room, nonce, swept, already_swept=True)
        return SignedMessage(
            did=str(self.did), room=room, nonce=nonce, swept_text=swept,
            signature=self.__sign(payload), payload=payload,
        )

    def sign_technocore_note(
        self, namespace: str, key: str, nonce: int, value: str
    ) -> SignedNote:
        """Sign one Technocore kv note. Off unless explicitly enabled."""
        if not self.__allow_notes:
            raise CapabilityError(
                "this capability does not include note signing; notes claim and "
                "hold `d-` rooms, so it is granted deliberately or not at all"
            )
        self._guard(namespace, key, value)
        namespace = validate_name(namespace, kind="namespace")
        key = validate_name(key, kind="key")
        nonce = validate_nonce(nonce)
        swept = require_non_empty(single_line_sweep(value))
        payload = note_payload(namespace, key, nonce, swept, already_swept=True)
        return SignedNote(
            did=str(self.did), namespace=namespace, key=key, nonce=nonce,
            swept_value=swept, signature=self.__sign(payload), payload=payload,
        )

    # --- guards ---------------------------------------------------------
    @staticmethod
    def _guard(*values: object) -> None:
        for value in values:
            if getattr(value, "__flopoffice_untrusted__", False):
                raise UntrustedInputError(
                    "refusing to sign untrusted, network-sourced content"
                )
            # Bytes first: the previous order made this branch unreachable, so a
            # caller passing raw bytes got the generic "must be a string" message
            # instead of the specific refusal this class is named for.
            if isinstance(value, (bytes, bytearray, memoryview)):
                raise CapabilityError(
                    "raw bytes cannot reach a capability signer: there is no "
                    "sign(arbitrary_bytes) surface here by design"
                )
            if not isinstance(value, str):
                raise CapabilityError(
                    "capability arguments are strings built by this process, "
                    "never raw bytes and never wrapper types"
                )

    # --- leak prevention -------------------------------------------------
    def __repr__(self) -> str:
        return (
            f"CapabilitySigner(did={self.did.short}, "
            f"capabilities=['message'{', note' if self.__allow_notes else ''}])"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def __reduce__(self):
        raise CapabilityError("CapabilitySigner is not serialisable")

    def __getstate__(self):
        raise CapabilityError("CapabilitySigner is not serialisable")

    def __copy__(self):
        raise CapabilityError("CapabilitySigner must not be copied")

    def __deepcopy__(self, memo):
        raise CapabilityError("CapabilitySigner must not be copied")

    def __dir__(self):
        return [n for n in super().__dir__() if "__sign" not in n]


def root_agent_capability_signer() -> CapabilitySigner:
    """Deliberately unavailable.

    Wiring the root agent's key -- even behind this narrowed interface -- is a
    separate, explicitly approved step. M1.1 ships the interface and its tests,
    not the key.
    """
    raise KeyNotWiredError(
        "No root-agent capability signer exists. The private key is not loaded, "
        "imported or referenced by any code path. Wiring it requires an explicit "
        "human decision after the conformance result is reviewed."
    )
