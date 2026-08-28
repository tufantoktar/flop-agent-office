"""Technocore signing-conformance matrix.

Drives a **locally running official technocore-chat instance** with messages signed
by our own client, and records what the official implementation accepted and stored.

The point is empirical: documentation about the single-line sweep is contradictory
(see docs/FLOP_FACTS.md), so the answer has to come from the implementation. Every
case is run under both candidate policies, and a policy is only "confirmed" where
the two produce different bytes and exactly one is accepted.

This module performs no I/O on import and is safe to import in unit tests. Nothing
here touches the public technocore.chat instance -- the runner refuses any host
that is not loopback.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from identity.canonical import SweepPolicy, single_line_sweep
from identity.signer import EphemeralSigner
from identity.verifier import verify_message

__all__ = [
    "CASES",
    "Case",
    "CaseResult",
    "POLICIES",
    "PolicyName",
    "run_matrix",
    "conclude",
]

PolicyName = Literal["REPLACE_WITH_SPACE", "REMOVE"]
TransmitMode = Literal["raw", "pre_swept"]

# Why two transmit modes
# ----------------------
# The official handler computes ``body = store.clean_text(received_text)`` and then
# verifies the signature over ``room|nonce|body``. So:
#
# * ``raw``       -- transmit the ORIGINAL text and sign our *prediction* of what the
#                    server's sweep will produce. This is the only mode that
#                    discriminates between the two policies: a wrong prediction is a
#                    403. It is the protocol's intended flow ("sign the text after the
#                    single-line sweep").
# * ``pre_swept`` -- transmit text we already swept and sign that. Accepted under EITHER
#                    policy whenever our output is a fixed point of the server's sweep,
#                    because the server's re-sweep is then a no-op. Our M1 client works
#                    this way, which is exactly why the first matrix run could not tell
#                    the policies apart. Kept as a separate check, never as evidence.

#: The two readings of the Flop Labs documentation, as executable policies.
POLICIES: dict[PolicyName, SweepPolicy] = {
    "REPLACE_WITH_SPACE": SweepPolicy(replace_with_space=True),
    "REMOVE": SweepPolicy(replace_with_space=False),
}


@dataclass(frozen=True, slots=True)
class Case:
    """One input to push through both policies."""

    case_id: str
    description: str
    text: str

    @property
    def discriminating(self) -> bool:
        """Can acceptance tell the two policies apart for this input?

        Computed, never declared: it is exactly "do the policies produce different
        bytes here". Declaring it by hand went stale the moment the sweep was
        corrected -- U+00A0 and U+3000 stopped discriminating once we (correctly)
        left Zs alone, and a hand-written flag would have quietly claimed evidence
        that no longer existed.
        """
        return (
            single_line_sweep(self.text, POLICIES["REPLACE_WITH_SPACE"])
            != single_line_sweep(self.text, POLICIES["REMOVE"])
        )

    @property
    def codepoints(self) -> list[str]:
        return [f"U+{ord(c):04X}" for c in self.text]


# --- the matrix ------------------------------------------------------------
# Every case carries enough length that the server's duplicate filter is not the
# thing under test, and unique wording so cases cannot collide with each other.
CASES: tuple[Case, ...] = (
    Case("ascii", "ordinary ASCII, no invisible characters",
         "flopoffice conformance ordinary ascii case"),
    Case("newline", "LF between words", "flopoffice conformance\nnewline case"),
    Case("carriage_return", "CR between words", "flopoffice conformance\rcarriage case"),
    Case("crlf", "CRLF pair", "flopoffice conformance\r\ncrlf pair case"),
    Case("tab", "horizontal tab", "flopoffice conformance\ttab case"),
    Case("repeated_whitespace", "runs of spaces and tabs",
         "flopoffice   conformance \t\t repeated whitespace case"),
    Case("zero_width_space", "U+200B ZERO WIDTH SPACE (Cf)",
         "flopoffice conformance​zero width space case"),
    Case("zero_width_joiner", "U+200D ZWJ (Cf)",
         "flopoffice conformance‍zero width joiner case"),
    Case("zero_width_non_joiner", "U+200C ZWNJ (Cf)",
         "flopoffice conformance‌zero width non joiner case"),
    Case("bidi_override", "U+202E RIGHT-TO-LEFT OVERRIDE (Cf) - Trojan Source vector",
         "flopoffice conformance‮bidi override case"),
    Case("bidi_isolate", "U+2066/U+2069 isolates (Cf)",
         "flopoffice conformance⁦isolated⁩ bidi isolate case"),
    Case("unicode_tag", "U+E0041 Unicode tag character (Cf) - invisible ASCII smuggling",
         "flopoffice conformance\U000e0041unicode tag case"),
    Case("line_separator", "U+2028 LINE SEPARATOR (Zl)",
         "flopoffice conformance line separator case"),
    Case("paragraph_separator", "U+2029 PARAGRAPH SEPARATOR (Zp)",
         "flopoffice conformance paragraph separator case"),
    Case("nul_control", "U+0000 NUL (Cc)",
         "flopoffice conformance\x00nul control case"),
    Case("c1_control", "U+0085 NEL (Cc)",
         "flopoffice conformance\x85c1 control case"),
    Case("nbsp", "U+00A0 NO-BREAK SPACE (Zs, NOT Cf/Cc)",
         "flopoffice conformance nbsp separator case"),
    Case("ideographic_space", "U+3000 IDEOGRAPHIC SPACE (Zs)",
         "flopoffice conformance　ideographic space case"),
    Case("combining_marks", "combining acute + cedilla",
         "flopoffice conformance combining áç marks case"),
    Case("emoji", "astral-plane emoji",
         "flopoffice conformance \U0001f680\U0001f9ee emoji case"),
    Case("emoji_zwj_sequence", "ZWJ family sequence - flattens if ZWJ is swept",
         "flopoffice conformance \U0001f468‍\U0001f469‍\U0001f467 zwj emoji case"),
    Case("mixed_unicode_control", "CJK + emoji + tab + zero width together",
         "flopoffice 漢字\tconformance​ \U0001f680 mixed case"),
    Case("leading_whitespace", "leading spaces",
         "   flopoffice conformance leading whitespace case"),
    Case("trailing_whitespace", "trailing spaces",
         "flopoffice conformance trailing whitespace case   "),
    Case("leading_trailing_newline", "leading and trailing LF",
         "\nflopoffice conformance surrounding newline case\n"),
    Case("only_invisible", "nothing visible survives any sweep",
         "​‌‍ "),
)


@dataclass
class Attempt:
    """One (case, policy) write attempt against the official server."""

    policy: PolicyName
    transmitted_text: str            # (B) what our client sends
    canonical_bytes_hex: str         # (C) exact bytes our client signs
    canonical_string: str
    transmit_mode: TransmitMode
    accepted: bool                   # (E)
    http_status: int
    server_error: str | None = None
    stored_text: str | None = None   # (G) what the server stored, read back
    server_transformed: bool | None = None   # (F)
    stored_codepoints: list[str] = field(default_factory=list)
    signature_verifies_over_stored: bool | None = None   # (D)


@dataclass
class CaseResult:
    case_id: str
    description: str
    original_text: str               # (A)
    original_codepoints: list[str]
    discriminating: bool
    attempts: list[Attempt] = field(default_factory=list)

    def attempts_in(self, mode: TransmitMode) -> list[Attempt]:
        return [a for a in self.attempts if a.transmit_mode == mode]

    @property
    def accepted_policies(self) -> list[PolicyName]:
        """Policies accepted in RAW mode -- the only mode that can discriminate."""
        return [a.policy for a in self.attempts_in("raw") if a.accepted]

    @property
    def verdict(self) -> str:
        accepted = self.accepted_policies
        if not self.discriminating:
            return "NON_DISCRIMINATING" if accepted else "REJECTED_BY_SERVER"
        if len(accepted) == 1:
            return f"CONFIRMS_{accepted[0]}"
        if not accepted:
            return "BOTH_REJECTED"
        return "AMBIGUOUS_BOTH_ACCEPTED"


def _require_loopback(base_url: str) -> None:
    host = (urlparse(base_url).hostname or "").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError(
            f"conformance runs against a LOCAL official instance only; got host {host!r}. "
            "Never run this against technocore.chat."
        )


def _sweep(text: str, policy: PolicyName) -> str:
    return single_line_sweep(text, POLICIES[policy])


def run_matrix(
    base_url: str,
    *,
    room_prefix: str = "e-p-flopconf",
    cases: tuple[Case, ...] = CASES,
    transmit_modes: tuple[TransmitMode, ...] = ("raw", "pre_swept"),
    client: httpx.Client | None = None,
) -> list[CaseResult]:
    """Run every case under every policy and transmit mode against a LOCAL official instance.

    Each attempt gets its own ephemeral key and its own room, so nonce ordering, the
    duplicate filter and per-key state cannot make one attempt depend on another.
    """
    _require_loopback(base_url)
    owns = client is None
    http = client or httpx.Client(timeout=15.0, follow_redirects=False)
    results: list[CaseResult] = []

    try:
        for index, case in enumerate(cases):
            result = CaseResult(
                case_id=case.case_id,
                description=case.description,
                original_text=case.text,
                original_codepoints=case.codepoints,
                discriminating=case.discriminating,
            )
            for mode in transmit_modes:
                for policy in POLICIES:
                    result.attempts.append(
                        _attempt(http, base_url, room_prefix, index, case, policy, mode)
                    )
            results.append(result)
    finally:
        if owns:
            http.close()
    return results


def _attempt(
    http: httpx.Client,
    base_url: str,
    room_prefix: str,
    index: int,  # noqa: ARG001 - kept for result ordering/debugging
    case: Case,
    policy: PolicyName,
    mode: TransmitMode,
) -> Attempt:
    from identity.canonical import encode_path_segment, message_payload  # noqa: PLC0415

    # One room for the whole matrix, not one per attempt. Every attempt uses a
    # fresh ephemeral key and Technocore scopes nonces per (did, room), so nonce 1
    # is always valid here -- and a 26x2x2 matrix stops burning 104 rooms out of
    # the server's per-IP daily room budget, which is what made re-runs fail.
    room = room_prefix
    signer = EphemeralSigner()

    predicted = _sweep(case.text, policy)          # what we believe the server will store
    transmitted = case.text if mode == "raw" else predicted

    try:
        payload = message_payload(room, 1, predicted, already_swept=True)
    except Exception as exc:  # noqa: BLE001 - a local refusal is itself a result
        return Attempt(
            policy=policy, transmit_mode=mode, transmitted_text=transmitted,
            canonical_bytes_hex="", canonical_string="", accepted=False,
            http_status=0, server_error=f"client refused before sending: {exc}",
        )

    signature = signer.sign(payload)
    path = (
        f"/r/{encode_path_segment(room)}/say-signed/"
        f"{encode_path_segment(str(signer.did))}/"
        f"{encode_path_segment(signature)}/1/"
        f"{encode_path_segment(transmitted)}"
    )
    try:
        response = http.get(base_url + path, params={"format": "json"})
        status, body = response.status_code, response.text
    except httpx.HTTPError as exc:
        return Attempt(
            policy=policy, transmit_mode=mode, transmitted_text=transmitted,
            canonical_bytes_hex=payload.hex(),
            canonical_string=payload.decode("utf-8"),
            accepted=False, http_status=-1,
            server_error=f"transport refused the request: {type(exc).__name__}",
        )

    accepted = status == 200
    attempt = Attempt(
        policy=policy, transmit_mode=mode, transmitted_text=transmitted,
        canonical_bytes_hex=payload.hex(),
        canonical_string=payload.decode("utf-8"),
        accepted=accepted, http_status=status,
    )
    if not accepted:
        attempt.server_error = body[:400]
        return attempt

    stored = _read_back(http, base_url, room, want_did=str(signer.did))
    attempt.stored_text = stored
    if stored is not None:
        attempt.stored_codepoints = [f"U+{ord(c):04X}" for c in stored]
        attempt.server_transformed = stored != transmitted
        attempt.signature_verifies_over_stored = verify_message(
            str(signer.did), signature, room, 1, stored
        )
    return attempt


def _read_back(
    http: httpx.Client, base_url: str, room: str, *, want_did: str | None = None
) -> str | None:
    response = http.get(f"{base_url}/r/{room}", params={"format": "json"})
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if not messages:
        return None
    if want_did is not None:
        # v0.10.0 returns the author under `from`; pick OUR record out of a shared
        # room rather than assuming the last message is ours.
        mine = [m for m in messages
                if (m.get("from") or m.get("did")) == want_did]
        if mine:
            return str(mine[-1].get("text", ""))
        return None
    return str(messages[-1].get("text", ""))


def conclude(results: list[CaseResult]) -> dict[str, Any]:
    """Reduce the matrix to a decision. Fails closed on any contradiction."""
    confirming: dict[str, list[str]] = {name: [] for name in POLICIES}
    ambiguous: list[str] = []
    both_rejected: list[str] = []
    non_discriminating: list[str] = []

    for result in results:
        verdict = result.verdict
        if verdict.startswith("CONFIRMS_"):
            confirming[verdict.removeprefix("CONFIRMS_")].append(result.case_id)
        elif verdict == "AMBIGUOUS_BOTH_ACCEPTED":
            ambiguous.append(result.case_id)
        elif verdict == "BOTH_REJECTED":
            both_rejected.append(result.case_id)
        else:
            non_discriminating.append(result.case_id)

    winners = [name for name, ids in confirming.items() if ids]
    if len(winners) == 1 and not ambiguous:
        decision = winners[0]
        status = "PINNED"
    elif not winners:
        decision = None
        status = "UNRESOLVED_NO_DISCRIMINATING_EVIDENCE"
    else:
        decision = None
        status = "FAIL_CLOSED_CONTRADICTORY_EVIDENCE"

    return {
        "status": status,
        "decision": decision,
        "confirming_cases": confirming,
        "ambiguous_cases": ambiguous,
        "both_rejected_cases": both_rejected,
        "non_discriminating_cases": non_discriminating,
    }


def to_json(results: list[CaseResult], meta: dict[str, Any]) -> str:
    return json.dumps(
        {
            "meta": meta,
            "conclusion": conclude(results),
            "cases": [asdict(r) for r in results],
        },
        indent=2,
        ensure_ascii=False,
        sort_keys=False,
    )


def describe(text: str) -> str:
    """Human-readable codepoint dump, for report tables."""
    return " ".join(
        f"U+{ord(c):04X}({unicodedata.category(c)})" for c in text
    )
