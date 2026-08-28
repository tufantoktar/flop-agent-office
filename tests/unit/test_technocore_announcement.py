"""M1.6 first-message preparation: signed locally, never published."""

from __future__ import annotations

import json
import sqlite3

import httpx
import pytest

from identity.capability import CapabilitySigner
from identity.canonical import message_payload, single_line_sweep
from identity.nonce import NonceStore, scope_for_room
from identity.signer import EphemeralSigner
from identity.verifier import verify_message
from proof.verify import Status, verify_chain
from technocore.announcement import (
    CANONICALIZATION_PROFILE,
    FIRST_ANNOUNCEMENT_ROOM,
    FIRST_ANNOUNCEMENT_SHA256,
    FIRST_ANNOUNCEMENT_TEXT,
    NOT_SENT,
    PUBLISHED,
    AnnouncementPreparationError,
    build_local_announcement_proof,
    prepare_first_announcement,
    publish_first_announcement_once,
    reserve_announcement_nonce,
    verify_announcement_proof,
)
from technocore.client import (
    OneTimePublicWriteGate,
    PUBLIC_HOSTS,
    PublicWriteRefused,
    TechnocoreClient,
    TechnocoreError,
    build_signed_message,
)


def _capability(signer) -> CapabilitySigner:
    return CapabilitySigner(signer)


def _meta(conn, activity_id: str) -> dict:
    row = conn.execute(
        "SELECT meta_json FROM activities WHERE activity_id = ?", (activity_id,)
    ).fetchone()
    return json.loads(row["meta_json"])


def test_first_announcement_text_is_deterministic() -> None:
    assert FIRST_ANNOUNCEMENT_ROOM == "lobby"
    assert FIRST_ANNOUNCEMENT_TEXT == (
        "FlopOffice is a DID-authenticated multi-agent workspace for signed "
        "coordination, append-only proof logging, and capability-scoped agent "
        "actions. Current milestone: Technocore signing conformance is pinned, "
        "the root DID is configured, and signer wiring is fail-closed. Public "
        "testnet integrations will be added only when official FLOP interfaces "
        "are available."
    )
    forbidden = (
        "airdrop",
        "farming",
        "eligible",
        "onchain",
        "wallet",
        "endorsed",
    )
    lowered = FIRST_ANNOUNCEMENT_TEXT.lower()
    assert not any(term in lowered for term in forbidden)


def test_canonicalization_matches_the_pinned_m11_payload(signer) -> None:
    proof = build_local_announcement_proof(_capability(signer), nonce=1)
    assert proof.canonical_text == single_line_sweep(FIRST_ANNOUNCEMENT_TEXT)
    assert proof.canonical_text == FIRST_ANNOUNCEMENT_TEXT
    assert proof.canonicalization_profile == CANONICALIZATION_PROFILE
    assert proof.payload_hash == _sha256_bytes(
        message_payload(FIRST_ANNOUNCEMENT_ROOM, 1, proof.canonical_text)
    )


def test_nonce_is_required_before_signing(signer) -> None:
    with pytest.raises(TypeError):
        build_local_announcement_proof(_capability(signer))  # type: ignore[call-arg]


def test_non_increasing_explicit_nonce_is_rejected(conn, signer) -> None:
    nonces = NonceStore(conn)
    did = str(signer.did)
    assert reserve_announcement_nonce(nonces, did, nonce=3) == 3
    with pytest.raises(AnnouncementPreparationError, match="greater"):
        reserve_announcement_nonce(nonces, did, nonce=3)
    assert nonces.current(did, scope_for_room(FIRST_ANNOUNCEMENT_ROOM)) == 3


def test_capability_signer_is_required(signer) -> None:
    with pytest.raises(AnnouncementPreparationError, match="CapabilitySigner"):
        build_local_announcement_proof(signer, nonce=1)  # type: ignore[arg-type]


def test_raw_signer_cannot_be_used(signer) -> None:
    assert hasattr(signer, "sign")
    with pytest.raises(AnnouncementPreparationError, match="raw signers"):
        build_local_announcement_proof(signer, nonce=1)  # type: ignore[arg-type]


def test_local_signature_verifies(signer) -> None:
    proof = build_local_announcement_proof(_capability(signer), nonce=1)
    assert proof.verified is True
    assert verify_announcement_proof(proof) is True
    assert verify_message(
        proof.did, proof.signature, proof.room, proof.nonce, proof.canonical_text
    )


def test_wrong_did_verification_fails(signer) -> None:
    proof = build_local_announcement_proof(_capability(signer), nonce=1)
    other = EphemeralSigner()
    assert verify_announcement_proof(proof, did=str(other.did)) is False


def test_prepare_records_four_append_only_events(conn, ledger, signer) -> None:
    preparation = prepare_first_announcement(
        _capability(signer), ledger, NonceStore(conn)
    )
    records = preparation.records
    rows = conn.execute(
        "SELECT activity_type, ref_activity_id, tc_room, tc_nonce, signature "
        "FROM activities ORDER BY chain_index"
    ).fetchall()

    assert [row["activity_type"] for row in rows] == [
        "technocore_message_prepare_intent",
        "technocore_message_signed_local",
        "technocore_message_verified_local",
        "technocore_message_publish_blocked",
    ]
    assert rows[0]["ref_activity_id"] is None
    assert rows[1]["ref_activity_id"] == records.prepare_intent.activity_id
    assert rows[2]["ref_activity_id"] == records.signed_local.activity_id
    assert rows[3]["ref_activity_id"] == records.verified_local.activity_id
    assert {row["tc_room"] for row in rows} == {FIRST_ANNOUNCEMENT_ROOM}
    assert {row["tc_nonce"] for row in rows} == {preparation.proof.nonce}
    assert rows[0]["signature"] is None
    assert rows[1]["signature"] == preparation.proof.signature
    assert rows[2]["signature"] == preparation.proof.signature
    assert verify_chain(conn).status is Status.VALID


def test_ledger_proof_keeps_publish_status_not_sent(conn, ledger, signer) -> None:
    preparation = prepare_first_announcement(
        _capability(signer), ledger, NonceStore(conn)
    )
    assert preparation.proof.technocore_status == NOT_SENT
    for record in (
        preparation.records.prepare_intent,
        preparation.records.signed_local,
        preparation.records.verified_local,
        preparation.records.publish_blocked,
    ):
        meta = _meta(conn, record.activity_id)
        assert meta["publish_status"] == NOT_SENT
        assert meta["reason"] == "awaiting_explicit_user_approval"
        assert "passphrase" not in json.dumps(meta).lower()
        assert "keystore" not in json.dumps(meta).lower()


def test_signed_record_contains_independent_public_authorship_material(
    conn, ledger, signer
) -> None:
    preparation = prepare_first_announcement(
        _capability(signer), ledger, NonceStore(conn)
    )
    meta = _meta(conn, preparation.records.signed_local.activity_id)
    assert meta["canonical_text"] == preparation.proof.canonical_text
    assert meta["signing_algorithm"] == "Ed25519"
    assert meta["canonicalization_profile"] == CANONICALIZATION_PROFILE
    assert verify_announcement_proof(preparation.proof)


def test_ledger_remains_append_only(conn, ledger, signer) -> None:
    preparation = prepare_first_announcement(
        _capability(signer), ledger, NonceStore(conn)
    )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(
            "UPDATE activities SET activity_type = 'note' WHERE activity_id = ?",
            (preparation.records.prepare_intent.activity_id,),
        )


def test_no_technocore_http_write_occurs(monkeypatch, conn, ledger, signer) -> None:
    called = False

    def fail_send(*args, **kwargs):  # noqa: ANN002, ANN003, ARG001
        nonlocal called
        called = True
        pytest.fail("M1.6 preparation must not call send_signed_message")

    monkeypatch.setattr(TechnocoreClient, "send_signed_message", fail_send)
    prepare_first_announcement(_capability(signer), ledger, NonceStore(conn))
    assert called is False


def test_public_write_guard_remains_active(monkeypatch, signer) -> None:
    assert PUBLIC_HOSTS == frozenset(
        {"technocore.chat", "www.technocore.chat", "api.technocore.chat"}
    )
    monkeypatch.setenv("FLOPOFFICE_ALLOW_LOCAL_WRITE", "1")
    transport = httpx.MockTransport(
        lambda request: pytest.fail(f"a request reached the network: {request.url}")
    )
    with TechnocoreClient(
        "https://technocore.chat", client=httpx.Client(transport=transport)
    ) as client:
        with pytest.raises(PublicWriteRefused, match="blocked in M1"):
            client.send_signed_message(
                # Existing client tests cover this raw-signer construction path;
                # here it is only a throwaway payload for the host guard.
                build_signed_message(signer, FIRST_ANNOUNCEMENT_ROOM, 1, "not sent")
            )


def test_preparation_prints_no_private_or_path_material(capsys, conn, ledger, signer) -> None:
    preparation = prepare_first_announcement(
        _capability(signer), ledger, NonceStore(conn)
    )
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert combined == ""
    assert not hasattr(preparation.proof, "sign")
    for forbidden in ("passphrase", "PRIVATE KEY", "BEGIN", ".pem", "/keys/"):
        assert forbidden not in combined


def test_settings_and_doctor_still_do_not_load_signer(monkeypatch, capsys) -> None:
    import identity.capability as capability_module  # noqa: PLC0415
    import identity.keystore as keystore_module  # noqa: PLC0415
    import identity.wiring as wiring_module  # noqa: PLC0415
    from config.settings import load  # noqa: PLC0415
    from flopoffice.__main__ import main  # noqa: PLC0415

    touched: list[str] = []
    for module, name in (
        (keystore_module, "load_encrypted_pem"),
        (capability_module, "root_agent_capability_signer"),
        (wiring_module, "build_capability_signer"),
    ):
        monkeypatch.setattr(
            module,
            name,
            lambda *a, _n=name, **k: touched.append(_n),  # noqa: ARG005
        )

    load()
    assert main(["doctor"]) == 0
    assert touched == []
    assert "key never loaded by doctor" in capsys.readouterr().out


def test_publish_requires_confirmation(conn, ledger, signer) -> None:
    client = _mock_public_client(lambda request: {"ok": True, "seq": 1})
    with pytest.raises(AnnouncementPreparationError, match="confirmation"):
        publish_first_announcement_once(
            _capability(signer),
            ledger,
            NonceStore(conn),
            client,
            room=FIRST_ANNOUNCEMENT_ROOM,
            message_sha256=FIRST_ANNOUNCEMENT_SHA256,
        )


def test_publish_blocks_wrong_message_hash(conn, ledger, signer) -> None:
    client = _mock_public_client(lambda request: {"ok": True, "seq": 1})
    with pytest.raises(AnnouncementPreparationError, match="SHA-256"):
        publish_first_announcement_once(
            _capability(signer),
            ledger,
            NonceStore(conn),
            client,
            room=FIRST_ANNOUNCEMENT_ROOM,
            message_sha256="0" * 64,
            confirm_public_technocore_publish=True,
        )


def test_publish_blocks_wrong_room(conn, ledger, signer) -> None:
    client = _mock_public_client(lambda request: {"ok": True, "seq": 1})
    with pytest.raises(AnnouncementPreparationError, match="room"):
        publish_first_announcement_once(
            _capability(signer),
            ledger,
            NonceStore(conn),
            client,
            room="e-p-flopoffice-test",
            message_sha256=FIRST_ANNOUNCEMENT_SHA256,
            confirm_public_technocore_publish=True,
        )


def test_publish_blocks_local_verification_failure(monkeypatch, conn, ledger, signer) -> None:
    import technocore.announcement as announcement  # noqa: PLC0415

    monkeypatch.setattr(announcement, "verify_announcement_proof", lambda proof: False)
    client = _mock_public_client(lambda request: {"ok": True, "seq": 1})
    with pytest.raises(AnnouncementPreparationError, match="verification"):
        publish_first_announcement_once(
            _capability(signer),
            ledger,
            NonceStore(conn),
            client,
            room=FIRST_ANNOUNCEMENT_ROOM,
            message_sha256=FIRST_ANNOUNCEMENT_SHA256,
            confirm_public_technocore_publish=True,
        )


def test_publish_records_pre_send_and_result_events(conn, ledger, signer) -> None:
    seen_paths: list[str] = []
    client = _mock_public_client(
        lambda request: seen_paths.append(request.url.path) or {"ok": True, "seq": 42}
    )
    result = publish_first_announcement_once(
        _capability(signer),
        ledger,
        NonceStore(conn),
        client,
        room=FIRST_ANNOUNCEMENT_ROOM,
        message_sha256=FIRST_ANNOUNCEMENT_SHA256,
        confirm_public_technocore_publish=True,
    )
    rows = conn.execute(
        "SELECT activity_type, tc_nonce, tc_seq FROM activities ORDER BY chain_index"
    ).fetchall()
    assert [row["activity_type"] for row in rows] == [
        "technocore_message_prepare_intent",
        "technocore_message_signed_local",
        "technocore_message_verified_local",
        "technocore_message_publish_blocked",
        "technocore_message_publish_result",
    ]
    assert len(seen_paths) == 1
    assert result.server_seq == 42
    assert rows[-1]["tc_seq"] == 42
    assert {row["tc_nonce"] for row in rows} == {result.preparation.proof.nonce}
    meta = _meta(conn, result.publish_record.activity_id)
    assert meta["publish_status"] == PUBLISHED
    assert meta["sent_once"] is True
    assert verify_chain(conn).status is Status.VALID


def test_publish_reserves_one_nonce_only(conn, ledger, signer) -> None:
    nonces = NonceStore(conn)
    client = _mock_public_client(lambda request: {"ok": True, "seq": 1})
    result = publish_first_announcement_once(
        _capability(signer),
        ledger,
        nonces,
        client,
        room=FIRST_ANNOUNCEMENT_ROOM,
        message_sha256=FIRST_ANNOUNCEMENT_SHA256,
        confirm_public_technocore_publish=True,
    )
    assert nonces.current(str(signer.did), scope_for_room(FIRST_ANNOUNCEMENT_ROOM)) == (
        result.preparation.proof.nonce
    )


def test_one_time_gate_allows_one_send_and_then_closes(signer) -> None:
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return {"ok": True, "seq": calls}

    client = _mock_public_client(handler)
    write = build_signed_message(signer, FIRST_ANNOUNCEMENT_ROOM, 7, FIRST_ANNOUNCEMENT_TEXT)
    gate = OneTimePublicWriteGate(
        host="technocore.chat",
        room=FIRST_ANNOUNCEMENT_ROOM,
        message_sha256=FIRST_ANNOUNCEMENT_SHA256,
        nonce=7,
        confirm_public_technocore_publish=True,
    )
    assert client.send_signed_message(write, public_gate=gate)["seq"] == 1
    assert gate.used is True
    assert gate.closed is True
    with pytest.raises(PublicWriteRefused, match="closed"):
        client.send_signed_message(write, public_gate=gate)
    assert calls == 1


def test_gate_closes_after_send_exception(signer) -> None:
    def handler(request):  # noqa: ARG001
        raise httpx.ConnectError("boom")

    client = _mock_public_client(handler)
    write = build_signed_message(signer, FIRST_ANNOUNCEMENT_ROOM, 8, FIRST_ANNOUNCEMENT_TEXT)
    gate = OneTimePublicWriteGate(
        host="technocore.chat",
        room=FIRST_ANNOUNCEMENT_ROOM,
        message_sha256=FIRST_ANNOUNCEMENT_SHA256,
        nonce=8,
        confirm_public_technocore_publish=True,
    )
    with pytest.raises(TechnocoreError):
        client.send_signed_message(write, public_gate=gate)
    assert gate.used is True
    assert gate.closed is True


def test_public_writes_still_blocked_outside_gate(signer) -> None:
    client = _mock_public_client(lambda request: pytest.fail("request reached transport"))
    with pytest.raises(PublicWriteRefused, match="blocked in M1"):
        client.send_signed_message(
            build_signed_message(signer, FIRST_ANNOUNCEMENT_ROOM, 1, "blocked")
        )


def test_gate_scope_rejects_room_hash_and_nonce_mismatch(signer) -> None:
    write = build_signed_message(signer, FIRST_ANNOUNCEMENT_ROOM, 9, FIRST_ANNOUNCEMENT_TEXT)
    client = _mock_public_client(lambda request: pytest.fail("request reached transport"))

    bad_room = OneTimePublicWriteGate(
        host="technocore.chat",
        room="e-p-flopoffice-test",
        message_sha256=FIRST_ANNOUNCEMENT_SHA256,
        nonce=9,
        confirm_public_technocore_publish=True,
    )
    with pytest.raises(PublicWriteRefused, match="room mismatch"):
        client.send_signed_message(write, public_gate=bad_room)

    bad_hash = OneTimePublicWriteGate(
        host="technocore.chat",
        room=FIRST_ANNOUNCEMENT_ROOM,
        message_sha256="0" * 64,
        nonce=9,
        confirm_public_technocore_publish=True,
    )
    with pytest.raises(PublicWriteRefused, match="message mismatch"):
        client.send_signed_message(write, public_gate=bad_hash)

    bad_nonce = OneTimePublicWriteGate(
        host="technocore.chat",
        room=FIRST_ANNOUNCEMENT_ROOM,
        message_sha256=FIRST_ANNOUNCEMENT_SHA256,
        nonce=10,
        confirm_public_technocore_publish=True,
    )
    with pytest.raises(PublicWriteRefused, match="nonce mismatch"):
        client.send_signed_message(write, public_gate=bad_nonce)


def test_unexpected_publish_response_is_recorded_and_stops(conn, ledger, signer) -> None:
    client = _mock_public_client(lambda request: {"ok": True})
    with pytest.raises(AnnouncementPreparationError, match="unexpected"):
        publish_first_announcement_once(
            _capability(signer),
            ledger,
            NonceStore(conn),
            client,
            room=FIRST_ANNOUNCEMENT_ROOM,
            message_sha256=FIRST_ANNOUNCEMENT_SHA256,
            confirm_public_technocore_publish=True,
        )
    row = conn.execute(
        "SELECT activity_type, meta_json FROM activities ORDER BY chain_index DESC LIMIT 1"
    ).fetchone()
    assert row["activity_type"] == "technocore_message_publish_result"
    assert json.loads(row["meta_json"])["publish_status"] == "UNEXPECTED_RESPONSE"


def test_http_ambiguity_is_recorded_without_retry(conn, ledger, signer) -> None:
    calls = 0

    def handler(request):  # noqa: ARG001
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("unclear")

    client = _mock_public_client(handler)
    with pytest.raises(AnnouncementPreparationError, match="no retry"):
        publish_first_announcement_once(
            _capability(signer),
            ledger,
            NonceStore(conn),
            client,
            room=FIRST_ANNOUNCEMENT_ROOM,
            message_sha256=FIRST_ANNOUNCEMENT_SHA256,
            confirm_public_technocore_publish=True,
        )
    assert calls == 1
    row = conn.execute(
        "SELECT activity_type, meta_json FROM activities ORDER BY chain_index DESC LIMIT 1"
    ).fetchone()
    assert row["activity_type"] == "technocore_message_publish_result"
    assert json.loads(row["meta_json"])["publish_status"] == "AMBIGUOUS_OR_FAILED"


def _sha256_bytes(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()


def _mock_public_client(handler):
    def transport_handler(request):
        response = handler(request)
        return httpx.Response(200, json=response)

    return TechnocoreClient(
        "https://technocore.chat",
        client=httpx.Client(transport=httpx.MockTransport(transport_handler)),
    )
