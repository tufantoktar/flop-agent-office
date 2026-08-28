"""Conformance against the OFFICIAL technocore-chat implementation.

These tests are skipped unless ``TECHNOCORE_OFFICIAL_URL`` points at a locally
running official instance. CI never depends on them and never contacts a public
server; the runner refuses any host that is not loopback.

Reproduce (see docs/TECHNOCORE_CONFORMANCE.md for the pinned commit)::

    git clone https://github.com/flop-labs/technocore-chat
    cd technocore-chat && git checkout 9c7df0e
    python3.12 -m venv .venv && .venv/bin/pip install \\
        'starlette==1.6.0' 'uvicorn[standard]==0.52.2' 'pynacl==1.6.2' \\
        'orjson==3.12.0' 'cryptography==50.0.0'
    CHAT_ROOT=/tmp/tcdata CHAT_RATE_WRITE=6000 CHAT_RATE_READ=6000 \\
    CHAT_RATE_ROOMS_PER_DAY=500 CHAT_DUPE_FILTER_SECONDS=0 \\
        .venv/bin/python -m uvicorn --app-dir src app:app --host 127.0.0.1 --port 8099

    TECHNOCORE_OFFICIAL_URL=http://127.0.0.1:8099 python -m pytest tests/integration/test_technocore_conformance.py -v

The rate and duplicate-filter knobs are raised only so that the matrix is not
throttled. They do not affect canonicalisation, which is what is under test.
"""

from __future__ import annotations

import os
import uuid
from urllib.parse import quote

import httpx
import pytest

from identity.canonical import (
    SweepPolicy,
    message_payload,
    require_non_empty,
    single_line_sweep,
)
from identity.nonce import NonceStore
from identity.signer import EphemeralSigner
from identity.verifier import verify_message

from .conformance import CASES, POLICIES, conclude, run_matrix

pytestmark = [pytest.mark.integration, pytest.mark.conformance]

OFFICIAL_URL = os.environ.get("TECHNOCORE_OFFICIAL_URL", "").strip()

#: Rooms and per-key nonces persist in the server's data directory, so a fixed
#: room name makes the suite pass once and fail on every re-run. Every room this
#: module touches carries a per-run suffix; the conformance suite has to be
#: re-runnable against a long-lived local instance to be worth anything.
RUN = uuid.uuid4().hex[:8]


def room(name: str) -> str:
    """An ephemeral, unlisted, per-run room."""
    return f"e-p-conf-{name}-{RUN}"


pytest_skip_reason = (
    "set TECHNOCORE_OFFICIAL_URL to a LOCAL official technocore-chat instance "
    "(see this module's docstring)"
)


@pytest.fixture(scope="module")
def official() -> str:
    if not OFFICIAL_URL:
        pytest.skip(pytest_skip_reason)
    try:
        response = httpx.get(f"{OFFICIAL_URL}/healthz", timeout=5.0)
    except httpx.HTTPError:
        pytest.skip(f"no official instance reachable at {OFFICIAL_URL}")
    if response.status_code != 200:
        pytest.skip(f"official instance at {OFFICIAL_URL} is not healthy")
    return OFFICIAL_URL


@pytest.fixture(scope="module")
def http() -> httpx.Client:
    with httpx.Client(timeout=15.0, follow_redirects=False) as client:
        yield client


def _post_signed(http: httpx.Client, base: str, room_name: str, nonce: int,
                 raw_text: str, signed_over: str, signer: EphemeralSigner):
    """POST lane: carries raw control characters a GET path cannot."""
    signature = signer.sign(
        message_payload(room_name, nonce, signed_over, already_swept=True)
    )
    response = http.post(
        f"{base}/r/{room_name}",
        json={"did": str(signer.did), "sig": signature, "nonce": str(nonce),
              "text": raw_text},
    )
    return response, signature


def _stored(http: httpx.Client, base: str, room_name: str) -> str | None:
    response = http.get(f"{base}/r/{room_name}", params={"format": "json"})
    if response.status_code != 200:
        return None
    messages = response.json().get("messages") or []
    return str(messages[-1]["text"]) if messages else None


# --- 1-9: the per-class cases ---------------------------------------------
@pytest.mark.parametrize(
    "label",
    [
        "ascii", "newline", "tab", "nul_control", "c1_control",
        "zero_width_space", "zero_width_joiner", "bidi_override", "unicode_tag",
        "line_separator", "paragraph_separator", "nbsp", "ideographic_space",
        "combining_marks", "emoji", "emoji_zwj_sequence",
        "leading_whitespace", "trailing_whitespace", "leading_trailing_newline",
        "mixed_unicode_control",
    ],
)
def test_our_prediction_matches_the_official_server(
    official: str, http: httpx.Client, label: str
) -> None:
    """Our sweep must predict exactly what the official server stores.

    Uses the POST lane so raw LF can be transmitted -- the GET write path answers
    404 for a percent-encoded LF, which is a transport limit, not a signing one.
    """
    case = next(c for c in CASES if c.case_id == label)
    room_name = room(label.replace("_", "-"))
    signer = EphemeralSigner()
    predicted = single_line_sweep(case.text)

    response, signature = _post_signed(http, official, room_name, 1, case.text, predicted, signer)

    assert response.status_code == 200, (
        f"official server refused our prediction for {label}: "
        f"HTTP {response.status_code} {response.text[:200]}"
    )
    stored = _stored(http, official, room_name)
    assert stored == predicted, (
        f"{label}: server stored {stored!r}, we predicted {predicted!r}"
    )
    assert verify_message(str(signer.did), signature, room_name, 1, stored)


# --- 10: the disproven policy is genuinely rejected ------------------------
@pytest.mark.parametrize(
    "label", ["newline", "tab", "zero_width_space", "bidi_override", "line_separator"]
)
def test_remove_policy_is_rejected_by_the_official_server(
    official: str, http: httpx.Client, label: str
) -> None:
    """The 'removed' reading of the docs is not what the implementation does."""
    case = next(c for c in CASES if c.case_id == label)
    room_name = room(f"rem-{label.replace(chr(95), chr(45))}")
    signer = EphemeralSigner()
    wrong = single_line_sweep(case.text, POLICIES["REMOVE"])

    response, _ = _post_signed(http, official, room_name, 1, case.text, wrong, signer)
    assert response.status_code == 403, (
        f"{label}: REMOVE should be rejected, got HTTP {response.status_code}"
    )


def test_untrimmed_prediction_is_rejected(official: str, http: httpx.Client) -> None:
    """M1's no-trim behaviour would have been refused for every padded message."""
    room_name = room("untrimmed")
    signer = EphemeralSigner()
    untrimmed = single_line_sweep(
        "   flopoffice untrimmed case   ", SweepPolicy(trim_ends=False)
    )
    assert untrimmed != untrimmed.strip()
    response, _ = _post_signed(
        http, official, room_name, 1, "   flopoffice untrimmed case   ", untrimmed, signer
    )
    assert response.status_code == 403


def test_sweeping_zs_would_be_rejected(official: str, http: httpx.Client) -> None:
    """M1 swept Zs; the official server keeps it. Prove the divergence is real."""
    raw = "flopoffice zs conformance case"
    room_name = room("zs")
    signer = EphemeralSigner()
    m1_style = raw.replace(" ", " ")           # what M1 would have signed
    assert m1_style != single_line_sweep(raw)
    response, _ = _post_signed(http, official, room_name, 1, raw, m1_style, signer)
    assert response.status_code == 403


# --- 11/12: the pinned policy is accepted, byte-for-byte ------------------
def test_pinned_policy_transmits_exactly_what_is_verified(
    official: str, http: httpx.Client
) -> None:
    """Our client signs the swept text and sends that same text."""
    from technocore.client import build_signed_message  # noqa: PLC0415

    room_name = room("exact")
    signer = EphemeralSigner()
    raw = "  flopoffice\texact​ bytes case  "
    write = build_signed_message(signer, room_name, 1, raw)

    assert write.swept_text == single_line_sweep(raw)
    assert write.payload == f"{room_name}|1|{write.swept_text}".encode("utf-8")

    response = http.get(
        f"{official}/r/{room_name}/say-signed/{quote(str(signer.did), safe='')}/"
        f"{quote(write.signature, safe='')}/1/{quote(write.swept_text, safe='')}",
        params={"format": "json"},
    )
    assert response.status_code == 200, response.text[:300]
    assert _stored(http, official, room_name) == write.swept_text


# --- 13: seq and ts are not covered by the signature ----------------------
def test_seq_and_ts_are_excluded_from_the_signed_bytes(
    official: str, http: httpx.Client
) -> None:
    room_name = room("seqts")
    signer = EphemeralSigner()
    text = "flopoffice seq and ts exclusion case"

    signatures = {}
    for nonce in (1, 2):
        response, signature = _post_signed(http, official, room_name, nonce, text, text, signer)
        assert response.status_code == 200, response.text[:200]
        signatures[nonce] = signature

    messages = http.get(f"{official}/r/{room_name}", params={"format": "json"}).json()["messages"]
    assert len(messages) == 2
    first, second = messages[-2], messages[-1]
    assert first["seq"] != second["seq"], "server must assign distinct seq values"
    assert first["ts"] != second["ts"] or first["seq"] != second["seq"]

    # The signature verifies over room|nonce|text alone -- whatever seq and ts the
    # server chose. If either were covered, these checks could not both hold.
    for message in (first, second):
        assert verify_message(
            str(signer.did), signatures[int(message["nonce"])], room_name,
            int(message["nonce"]), message["text"]
        )
    # Structural proof: the payload is exactly room|nonce|text and nothing else,
    # so there is no field in which a seq or ts could be hiding. (A substring test
    # on seq alone would be meaningless -- seq 1 and nonce 1 print the same.)
    payload = message_payload(room_name, 1, text)
    assert payload == f"{room_name}|1|{text}".encode("utf-8")
    assert payload.count(b"|") == 2
    assert str(first["ts"]).encode() not in payload
    assert str(second["ts"]).encode() not in payload

    # And the server does not hand signatures back at all, so a reader cannot
    # re-verify authorship from a room read -- only the writer can.
    assert "sig" not in first and "sig" not in second
    assert first["from"] == str(signer.did)


# --- 14: nonce semantics unchanged ----------------------------------------
def test_nonce_must_strictly_increase_per_key_per_room(
    official: str, http: httpx.Client
) -> None:
    room_name = room("nonce")
    signer = EphemeralSigner()

    assert _post_signed(http, official, room_name, 5, "flopoffice nonce five case",
                        "flopoffice nonce five case", signer)[0].status_code == 200
    # v0.10.0 answers 400 for a non-increasing nonce. Our fake double answered
    # 409 during M1 and the M1 test believed it -- one reason a double is never
    # evidence about someone else's implementation.
    for stale in (4, 5):
        response, _ = _post_signed(
            http, official, room_name, stale, f"flopoffice nonce {stale} retry case",
            f"flopoffice nonce {stale} retry case", signer,
        )
        assert response.status_code == 400, f"nonce {stale} should be refused"
    assert _post_signed(http, official, room_name, 6, "flopoffice nonce six case",
                        "flopoffice nonce six case", signer)[0].status_code == 200


def test_nonce_scope_is_per_room_on_the_official_server(
    official: str, http: httpx.Client
) -> None:
    """Our NonceStore scopes per (did, room_name). Confirm the server agrees."""
    signer = EphemeralSigner()
    text = "flopoffice per room nonce scope case"
    for room_name in (room("scope-a"), room("scope-b")):
        response, _ = _post_signed(http, official, room_name, 1, text, text, signer)
        assert response.status_code == 200, (
            f"nonce 1 must be usable in {room_name}: {response.text[:200]}"
        )


def test_our_nonce_store_agrees_with_the_official_server(
    official: str, http: httpx.Client, conn
) -> None:
    room_name = room("store")
    signer = EphemeralSigner()
    nonces = NonceStore(conn)
    for _ in range(3):
        nonce = nonces.reserve(str(signer.did), room_name).nonce
        text = f"flopoffice nonce store case number {nonce}"
        response, _ = _post_signed(http, official, room_name, nonce, text, text, signer)
        assert response.status_code == 200, response.text[:200]


# --- 15: invalid signatures are rejected ----------------------------------
def test_invalid_signature_is_rejected_by_the_official_server(
    official: str, http: httpx.Client
) -> None:
    room_name = room("badsig")
    signer, other = EphemeralSigner(), EphemeralSigner()
    text = "flopoffice invalid signature case"

    # signed by a different key
    signature = other.sign(message_payload(room_name, 1, text, already_swept=True))
    response = http.post(
        f"{official}/r/{room_name}",
        json={"did": str(signer.did), "sig": signature, "nonce": "1", "text": text},
    )
    assert response.status_code == 403

    # signed over different text
    signature = signer.sign(message_payload(room_name, 2, text + "!", already_swept=True))
    response = http.post(
        f"{official}/r/{room_name}",
        json={"did": str(signer.did), "sig": signature, "nonce": "2", "text": text},
    )
    assert response.status_code == 403


def test_empty_after_sweep_is_refused_by_both_sides(
    official: str, http: httpx.Client
) -> None:
    """We refuse locally; confirm the server would have refused too."""
    from identity.canonical import CanonicalisationError  # noqa: PLC0415

    raw = "​‌‍"
    with pytest.raises(CanonicalisationError):
        require_non_empty(single_line_sweep(raw))

    signer = EphemeralSigner()
    response = http.post(
        f"{official}/r/{room(chr(101)+chr(109)+chr(112)+chr(116)+chr(121))}",
        json={"did": str(signer.did), "sig": "A" * 86, "nonce": "1", "text": raw},
    )
    assert response.status_code == 400


# --- the matrix as a whole -------------------------------------------------
def test_full_matrix_pins_replace_with_space(official: str) -> None:
    """The headline result, re-derived on every conformance run."""
    results = run_matrix(official, room_prefix=f"e-p-matrix-{RUN}")
    conclusion = conclude(results)
    assert conclusion["status"] == "PINNED", conclusion
    assert conclusion["decision"] == "REPLACE_WITH_SPACE", conclusion
    assert not conclusion["ambiguous_cases"], conclusion["ambiguous_cases"]
    assert len(conclusion["confirming_cases"]["REPLACE_WITH_SPACE"]) >= 10
    assert not conclusion["confirming_cases"]["REMOVE"]
