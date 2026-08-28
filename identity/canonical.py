"""Byte-exact construction of the payloads Technocore signatures cover.

Per Technocore's ``/auth.md``:

* a room message signs  ``<room>|<nonce>|<text>``   as UTF-8
* a kv note signs       ``<ns>|<key>|<nonce>|<value>`` as UTF-8
* the text signed is the value **after the server's single-line sweep**
* ``seq`` and ``ts`` are assigned by the server and deliberately NOT signed

A canonicalisation bug is the most dangerous class of bug in this layer: it
produces signatures that verify locally and are rejected (or, worse, mis-bound)
server-side. Everything here is therefore explicit, pure, and heavily tested.

PINNED AGAINST THE OFFICIAL IMPLEMENTATION
------------------------------------------
The two Flop Labs documents describe the sweep differently (README: invisible
characters "converted to spaces"; llms.txt: "removed"). M1.1 settled it against
technocore-chat v0.10.0 (commit 9c7df0e) running locally -- see
docs/TECHNOCORE_CONFORMANCE.md for the matrix and the reproduction command.

Observed behaviour, which this module now reproduces exactly:

* every character whose Unicode general category is Cc, Cf, Cs, Co, Zl or Zp is
  replaced with U+0020 -- the README reading is correct, "removed" is not;
* category **Zs is NOT swept**. U+00A0, U+2003, U+1680, U+2007 and U+3000 all
  survive interior positions unchanged. M1 wrongly swept them;
* the result is then **trimmed** with Python ``str.strip()`` semantics, which do
  remove Zs (and every other ``str.isspace()`` character) at the ends. M1 did not
  trim at all;
* runs are **not** collapsed: "AA \t\t BB" stores as "AA" + four spaces + "BB";
* text that is empty after the sweep is refused by the server (HTTP 400), so it is
  refused here too rather than sent.

The server verifies the signature over ``clean_text(received_text)``. Our client
therefore sweeps once, signs the swept form, and transmits that same swept form --
which is a fixed point of the server's sweep, so its re-sweep is a no-op.
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
    "require_non_empty",
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

# Unicode general categories the official implementation replaces with a space.
# This is technocore-chat's own INVISIBLE_CATEGORIES tuple, verified empirically:
#   Cc control      Cf format       Cs surrogate
#   Co private use  Zl line sep     Zp paragraph sep
#
# Zs (U+00A0, U+2003, U+1680, U+2007, U+3000, ...) is deliberately ABSENT: the
# server keeps those characters in interior positions. M1 swept them and would
# have produced signatures the server rejects.
_SWEEP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


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
    """The sweep's parameters, pinned to observed official behaviour.

    This is NOT a runtime switch. Production signing always uses
    :data:`DEFAULT_SWEEP`; there is exactly one deterministic signing behaviour.
    The non-default combination exists so the conformance suite can demonstrate
    that the rejected reading really is rejected by the official server -- it is
    evidence, not a configuration option.

    replace_with_space:
        True  -> invisible characters become U+0020. CONFIRMED against v0.10.0.
        False -> invisible characters are deleted. DISPROVEN: 15 of 15
                 discriminating cases were rejected 403 under this reading.
    trim_ends:
        True  -> Python ``str.strip()`` after sweeping. CONFIRMED.
    collapse_runs:
        False -> runs of spaces are preserved. CONFIRMED.
    """

    replace_with_space: bool = True
    trim_ends: bool = True
    collapse_runs: bool = False


DEFAULT_SWEEP = SweepPolicy()


def single_line_sweep(text: str, policy: SweepPolicy = None) -> str:  # type: ignore[assignment]
    """Reproduce technocore-chat's ``store.clean_text`` sweep, minus its length check.

    Sweep, then trim. Pure and total for any ``str``; raises only when the result
    is empty, which the official server also refuses.
    """
    if policy is None:
        policy = DEFAULT_SWEEP
    # Taint check first: an untrusted wrapper is also not a str, and reporting
    # "must be a str" would hide the real reason it was refused.
    _reject_untrusted(text, where="single_line_sweep")
    if not isinstance(text, str):
        raise CanonicalisationError("text must be a str")

    out: list[str] = []
    for char in text:
        if unicodedata.category(char) in _SWEEP_CATEGORIES:
            if policy.replace_with_space:
                out.append(_SPACE)
            # else: dropped (the disproven reading; conformance evidence only)
        else:
            out.append(char)

    result = "".join(out)
    if policy.collapse_runs:
        result = _SPACE.join(part for part in result.split(_SPACE) if part)
    if policy.trim_ends:
        # Python str.strip() semantics, matching the official implementation:
        # this DOES remove Zs characters at the ends even though the sweep above
        # leaves them alone in interior positions.
        result = result.strip()
    return result


def require_non_empty(swept: str) -> str:
    """Refuse text the server would reject as empty-after-sweep (its HTTP 400).

    Failing here costs a local exception; failing at the server costs a wasted
    nonce and a round trip.
    """
    if not swept:
        raise CanonicalisationError(
            "nothing visible survives the single-line sweep; the server refuses "
            "this with HTTP 400. Send at least one visible character."
        )
    return swept


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

    swept = require_non_empty(text if already_swept else single_line_sweep(text, policy))
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

    swept = require_non_empty(value if already_swept else single_line_sweep(value, policy))
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
