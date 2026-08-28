"""Byte-exact construction of the payloads Technocore signatures cover.

Per Technocore's ``/auth.md``:

* a room message signs  ``<room>|<nonce>|<text>``   as UTF-8
* a kv note signs       ``<ns>|<key>|<nonce>|<value>`` as UTF-8
* the text signed is the value **after the server's single-line sweep**
* ``seq`` and ``ts`` are assigned by the server and deliberately NOT signed

A canonicalisation bug is the most dangerous class of bug in this layer: it
produces signatures that verify locally and are rejected (or, worse, mis-bound)
server-side. Everything here is therefore explicit, pure, and heavily tested.

KNOWN AMBIGUITY -- see docs/FLOP_FACTS.md
-----------------------------------------
Two Flop Labs documents describe the sweep differently:

* the technocore-chat README says invisible characters "are converted to spaces"
* ``/llms.txt`` says control and formatting characters are "removed"

Those are not the same transformation. We implement the *replace-with-space*
reading as the default (it matches the README's description of stored text) and
expose the choice as an explicit :class:`SweepPolicy` so a single constant
changes it once the behaviour is pinned against a real server. The conformance
test in ``tests/integration`` is what will settle it -- not this docstring.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote

__all__ = [
    "CanonicalisationError",
    "UntrustedInputError",
    "SweepPolicy",
    "DEFAULT_SWEEP",
    "single_line_sweep",
    "validate_room",
    "validate_nonce",
    "message_payload",
    "note_payload",
    "encode_path_segment",
    "decode_path_segment",
    "MAX_MESSAGE_CHARS",
    "MAX_NOTE_BYTES",
]

# Documented Technocore limits.
MAX_MESSAGE_CHARS = 4096
MAX_NOTE_BYTES = 8 * 1024
MAX_NONCE_DIGITS = 19

_SPACE = " "

# Unicode general categories treated as "invisible" by the sweep.
#   Cc control, Cf format, Zl line separator, Zp paragraph separator,
#   Zs space separators other than U+0020, Cs surrogate, Co private use
_SWEEP_CATEGORIES = {"Cc", "Cf", "Zl", "Zp", "Cs", "Co"}


class CanonicalisationError(ValueError):
    """Input cannot be canonicalised into a signable payload."""


class UntrustedInputError(CanonicalisationError):
    """Untrusted (network-sourced) content was passed to a signing path.

    Content read from Technocore rooms must never be signed, echoed or acted on
    without an explicit human decision. Objects that carry the marker attribute
    ``__flopoffice_untrusted__`` are refused here, at the boundary, rather than
    relying on convention further up the stack.
    """


def _reject_untrusted(value: Any, *, where: str) -> None:
    if getattr(value, "__flopoffice_untrusted__", False):
        raise UntrustedInputError(
            f"refusing to canonicalise untrusted content for {where}; "
            "network-sourced text may not enter a signing path"
        )


@dataclass(frozen=True, slots=True)
class SweepPolicy:
    """How the single-line sweep normalises text.

    replace_with_space:
        True  -> invisible characters become U+0020 (README reading, default)
        False -> invisible characters are deleted (llms.txt reading)
    collapse_runs / strip_ends:
        Both default False. No Flop Labs document states that runs are collapsed
        or that ends are trimmed, so we do neither. Do not enable either without
        evidence from a live server -- guessing here silently breaks signatures.
    """

    replace_with_space: bool = True
    collapse_runs: bool = False
    strip_ends: bool = False


DEFAULT_SWEEP = SweepPolicy()


def single_line_sweep(text: str, policy: SweepPolicy = DEFAULT_SWEEP) -> str:
    """Apply the single-line sweep. Pure; total; never raises on valid str."""
    # Taint check first: an untrusted wrapper is also not a str, and reporting
    # "must be a str" would hide the real reason it was refused.
    _reject_untrusted(text, where="single_line_sweep")
    if not isinstance(text, str):
        raise CanonicalisationError("text must be a str")

    out: list[str] = []
    for char in text:
        if char == _SPACE:
            out.append(char)
            continue
        category = unicodedata.category(char)
        invisible = category in _SWEEP_CATEGORIES or (
            category == "Zs" and char != _SPACE
        )
        if not invisible:
            out.append(char)
        elif policy.replace_with_space:
            out.append(_SPACE)
        # else: dropped

    result = "".join(out)
    if policy.collapse_runs:
        result = _SPACE.join(part for part in result.split(_SPACE) if part)
    if policy.strip_ends:
        result = result.strip(_SPACE)
    return result


def validate_room(room: str) -> str:
    """Validate a room name and return it unchanged.

    We deliberately do NOT lowercase, trim or otherwise rewrite the room: the
    room string is part of the signed payload, so any local rewrite that the
    server does not perform would produce a signature over different bytes than
    the server verifies. Validation rejects; it does not repair.
    """
    _reject_untrusted(room, where="validate_room")
    if not isinstance(room, str):
        raise CanonicalisationError("room must be a str")
    if not room:
        raise CanonicalisationError("room must not be empty")
    if len(room) > 128:
        raise CanonicalisationError("room name is implausibly long (>128 chars)")
    if room != single_line_sweep(room):
        raise CanonicalisationError("room must not contain invisible characters")
    if "|" in room:
        raise CanonicalisationError(
            "room must not contain '|': it is the payload field separator"
        )
    if "/" in room or "?" in room or "#" in room:
        raise CanonicalisationError("room must not contain URL structural characters")
    return room


def validate_nonce(nonce: int) -> int:
    """Technocore nonces are 1-19 decimal digits."""
    if isinstance(nonce, bool) or not isinstance(nonce, int):
        raise CanonicalisationError("nonce must be an int")
    if nonce < 0:
        raise CanonicalisationError("nonce must not be negative")
    if len(str(nonce)) > MAX_NONCE_DIGITS:
        raise CanonicalisationError(
            f"nonce must be at most {MAX_NONCE_DIGITS} digits"
        )
    return nonce


def message_payload(
    room: str,
    nonce: int,
    text: str,
    *,
    policy: SweepPolicy = DEFAULT_SWEEP,
    already_swept: bool = False,
) -> bytes:
    """Exact bytes covered by a room-message signature.

    ``<room>|<nonce>|<swept text>`` encoded UTF-8.
    """
    _reject_untrusted(text, where="message_payload")
    room = validate_room(room)
    nonce = validate_nonce(nonce)
    if not isinstance(text, str):
        raise CanonicalisationError("text must be a str")

    swept = text if already_swept else single_line_sweep(text, policy)
    if len(swept) > MAX_MESSAGE_CHARS:
        raise CanonicalisationError(
            f"message is {len(swept)} chars, server limit is {MAX_MESSAGE_CHARS}"
        )
    return f"{room}|{nonce}|{swept}".encode("utf-8")


def note_payload(
    namespace: str,
    key: str,
    nonce: int,
    value: str,
    *,
    policy: SweepPolicy = DEFAULT_SWEEP,
    already_swept: bool = False,
) -> bytes:
    """Exact bytes covered by a kv-note signature.

    ``<ns>|<key>|<nonce>|<swept value>`` encoded UTF-8.
    """
    for name, part in (("namespace", namespace), ("key", key), ("value", value)):
        _reject_untrusted(part, where="note_payload")
        if not isinstance(part, str):
            raise CanonicalisationError(f"{name} must be a str")
        if "|" in part and name != "value":
            raise CanonicalisationError(f"{name} must not contain '|'")
    nonce = validate_nonce(nonce)

    swept = value if already_swept else single_line_sweep(value, policy)
    encoded = f"{namespace}|{key}|{nonce}|{swept}".encode("utf-8")
    if len(swept.encode("utf-8")) > MAX_NOTE_BYTES:
        raise CanonicalisationError(
            f"note value exceeds the {MAX_NOTE_BYTES}-byte server limit"
        )
    return encoded


def encode_path_segment(text: str) -> str:
    """Percent-encode one URL path segment for a Technocore GET write.

    ``safe=""`` is deliberate: '/' must be encoded, otherwise text containing a
    slash would silently change the request's path structure.
    """
    _reject_untrusted(text, where="encode_path_segment")
    if not isinstance(text, str):
        raise CanonicalisationError("segment must be a str")
    return quote(text, safe="", encoding="utf-8", errors="strict")


def decode_path_segment(segment: str) -> str:
    """Inverse of :func:`encode_path_segment`."""
    if not isinstance(segment, str):
        raise CanonicalisationError("segment must be a str")
    return unquote(segment, encoding="utf-8", errors="strict")
