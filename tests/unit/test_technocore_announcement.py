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
    FIRST_ANNOUNCEMENT_TEXT,
    NOT_SENT,
    AnnouncementPreparationError,
    build_local_announcement_proof,
    prepare_first_announcement,
    reserve_announcement_nonce,
    verify_announcement_proof,
)
from technocore.client import (
    PUBLIC_HOSTS,
    PublicWriteRefused,
    TechnocoreClient,
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


def _sha256_bytes(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()
