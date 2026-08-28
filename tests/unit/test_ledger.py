"""Proof ledger: append-only enforcement, hash chaining, tamper detection.

Covers required tests 10-16.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from proof.hashchain import CHAINED_FIELDS, GENESIS_PREV_HASH, compute_entry_hash
from proof.ledger import Activity, Ledger, LedgerError, SecretMaterialRefused
from proof.verify import BreakKind, Status, verify_chain
from storage.db import connect

DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


def make(n: int = 3, ledger: Ledger | None = None, **kwargs):
    assert ledger is not None
    return [
        ledger.append(
            Activity(agent_did=DID, activity_type="note", meta={"i": i}, **kwargs)
        )
        for i in range(n)
    ]


# --- 10. append-only write -------------------------------------------------
def test_append_assigns_chain_position_and_hash(ledger: Ledger) -> None:
    first = ledger.append(Activity(agent_did=DID, activity_type="ledger.genesis"))
    assert first.chain_index == 0
    assert first.prev_hash == GENESIS_PREV_HASH
    assert len(first.entry_hash) == 64

    second = ledger.append(Activity(agent_did=DID, activity_type="note"))
    assert second.chain_index == 1
    assert second.prev_hash == first.entry_hash


def test_append_persists_all_declared_fields(ledger: Ledger, conn) -> None:
    record = ledger.append(
        Activity(
            agent_did=DID,
            activity_type="technocore.write.result",
            task_id="task-1",
            tc_room="lobby",
            tc_seq=42,
            tc_nonce=7,
            signed_payload_hash="a" * 64,
            signature="s" * 86,
            result_hash="b" * 64,
            provider_id="local",
            model="none",
            cost_amount="1.5",
            cost_unit="FLOP_TEST",
        )
    )
    row = conn.execute(
        "SELECT * FROM activities WHERE activity_id = ?", (record.activity_id,)
    ).fetchone()
    assert row["tc_seq"] == 42
    assert row["cost_unit"] == "FLOP_TEST"
    assert row["cost_amount"] == "1.5"


def test_cost_requires_an_explicit_unit(ledger: Ledger) -> None:
    with pytest.raises(LedgerError, match="cost_unit"):
        ledger.append(
            Activity(agent_did=DID, activity_type="note", cost_amount="1.0")
        )
    with pytest.raises(LedgerError, match="decimal"):
        ledger.append(
            Activity(
                agent_did=DID, activity_type="note",
                cost_amount=1.0, cost_unit="USD",  # type: ignore[arg-type]
            )
        )


def test_unknown_activity_type_refused(ledger: Ledger) -> None:
    with pytest.raises(LedgerError, match="activity_type"):
        ledger.append(Activity(agent_did=DID, activity_type="wallet.transfer"))


def test_dangling_reference_refused(ledger: Ledger) -> None:
    with pytest.raises(LedgerError, match="ref_activity_id"):
        ledger.append(
            Activity(agent_did=DID, activity_type="note", ref_activity_id="nope")
        )


# --- 11/12. UPDATE and DELETE are rejected --------------------------------
def test_update_is_rejected_by_the_database(ledger: Ledger, conn) -> None:
    record = ledger.append(Activity(agent_did=DID, activity_type="note"))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(
            "UPDATE activities SET tc_seq = 999 WHERE activity_id = ?",
            (record.activity_id,),
        )
    row = conn.execute(
        "SELECT tc_seq FROM activities WHERE activity_id = ?", (record.activity_id,)
    ).fetchone()
    assert row["tc_seq"] is None


def test_delete_is_rejected_by_the_database(ledger: Ledger, conn) -> None:
    record = ledger.append(Activity(agent_did=DID, activity_type="note"))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(
            "DELETE FROM activities WHERE activity_id = ?", (record.activity_id,)
        )
    assert ledger.count() == 1


def test_corrections_are_compensating_rows(ledger: Ledger) -> None:
    """The only sanctioned way to revise a fact."""
    original = ledger.append(
        Activity(agent_did=DID, activity_type="technocore.write.intent",
                 tc_room="lobby", tc_nonce=1)
    )
    correction = ledger.append(
        Activity(
            agent_did=DID,
            activity_type="technocore.write.result",
            ref_activity_id=original.activity_id,
            tc_room="lobby",
            tc_nonce=1,
            tc_seq=1234,
        )
    )
    assert correction.chain_index == original.chain_index + 1
    assert ledger.by_id(correction.activity_id)["ref_activity_id"] == original.activity_id


# --- 13. intact chain verifies --------------------------------------------
def test_intact_chain_verifies(ledger: Ledger, conn) -> None:
    make(5, ledger=ledger)
    result = verify_chain(conn)
    assert result.status is Status.VALID
    assert result.records_checked == 5
    assert result.ok


def test_empty_ledger_is_valid(conn) -> None:
    result = verify_chain(conn)
    assert result.status is Status.EMPTY
    assert result.ok


# --- 14/15. tampering is detected and located ------------------------------
def _tamper(db_path: Path, sql: str, params: tuple = ()) -> None:
    """Edit the file behind the ledger's back, with the triggers dropped.

    This simulates an attacker with file access -- exactly the case the hash
    chain exists to make evident.
    """
    raw = sqlite3.connect(db_path)
    raw.execute("DROP TRIGGER IF EXISTS activities_no_update")
    raw.execute("DROP TRIGGER IF EXISTS activities_no_delete")
    raw.execute(sql, params)
    raw.commit()
    raw.close()


def test_tampered_row_is_detected_and_located(db_path: Path) -> None:
    conn = connect(db_path)
    ledger = Ledger(conn)
    records = make(5, ledger=ledger)
    conn.close()

    _tamper(
        db_path,
        "UPDATE activities SET tc_seq = 999 WHERE activity_id = ?",
        (records[2].activity_id,),
    )

    conn = connect(db_path, read_only=True)
    result = verify_chain(conn)
    conn.close()

    assert result.status is Status.BROKEN
    assert not result.ok
    assert result.first_break is not None
    assert result.first_break.chain_index == 2
    assert result.first_break.activity_id == records[2].activity_id
    assert result.first_break.kind is BreakKind.HASH_MISMATCH
    assert result.records_checked == 2


def test_first_break_is_reported_when_several_rows_are_edited(db_path: Path) -> None:
    conn = connect(db_path)
    ledger = Ledger(conn)
    records = make(6, ledger=ledger)
    conn.close()

    for index in (4, 1, 3):  # out of order on purpose
        _tamper(
            db_path,
            "UPDATE activities SET agent_did = 'did:key:zEvil' WHERE activity_id = ?",
            (records[index].activity_id,),
        )

    conn = connect(db_path, read_only=True)
    result = verify_chain(conn)
    conn.close()

    assert result.status is Status.BROKEN
    assert result.first_break.chain_index == 1, "must report the EARLIEST break"


def test_deleted_row_is_detected(db_path: Path) -> None:
    conn = connect(db_path)
    ledger = Ledger(conn)
    records = make(4, ledger=ledger)
    conn.close()

    _tamper(db_path, "DELETE FROM activities WHERE activity_id = ?",
            (records[2].activity_id,))

    conn = connect(db_path, read_only=True)
    result = verify_chain(conn)
    conn.close()
    assert result.status is Status.BROKEN
    assert result.first_break.kind is BreakKind.INDEX_GAP
    assert result.first_break.chain_index == 3


def test_rehashed_row_still_breaks_the_link(db_path: Path) -> None:
    """An attacker who recomputes one row's hash still breaks the next link."""
    conn = connect(db_path)
    ledger = Ledger(conn)
    records = make(4, ledger=ledger)
    row = dict(conn.execute(
        "SELECT * FROM activities WHERE activity_id = ?", (records[1].activity_id,)
    ).fetchone())
    conn.close()

    row["agent_did"] = "did:key:zEvil"
    forged = compute_entry_hash({k: row[k] for k in CHAINED_FIELDS})
    _tamper(
        db_path,
        "UPDATE activities SET agent_did = ?, entry_hash = ? WHERE activity_id = ?",
        ("did:key:zEvil", forged, records[1].activity_id),
    )

    conn = connect(db_path, read_only=True)
    result = verify_chain(conn)
    conn.close()
    assert result.status is Status.BROKEN
    assert result.first_break.kind is BreakKind.LINK_MISMATCH
    assert result.first_break.chain_index == 2


def test_genesis_prev_hash_is_checked(db_path: Path) -> None:
    conn = connect(db_path)
    make(2, ledger=Ledger(conn))
    conn.close()
    _tamper(db_path, "UPDATE activities SET prev_hash = ? WHERE chain_index = 0",
            ("f" * 64,))
    conn = connect(db_path, read_only=True)
    result = verify_chain(conn)
    conn.close()
    assert result.first_break.kind is BreakKind.BAD_GENESIS


# --- 16. no secret-shaped columns, and secrets are refused at write --------
SECRET_COLUMN_WORDS = (
    "private", "secret", "passphrase", "password", "seed", "mnemonic",
    "apikey", "api_key", "token", "credential", "wallet", "prompt_body",
)


def test_schema_has_no_secret_shaped_columns(conn) -> None:
    tables = [
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    ]
    offenders = []
    for table in tables:
        for column in conn.execute(f"PRAGMA table_info({table})").fetchall():
            name = column["name"].lower()
            if any(word in name for word in SECRET_COLUMN_WORDS):
                offenders.append(f"{table}.{column['name']}")
    assert not offenders, f"secret-shaped columns present: {offenders}"


def test_ledger_refuses_values_matching_secret_patterns(ledger: Ledger) -> None:
    fake_key_block = (
        "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END " + "PRIVATE KEY-----"
    )
    with pytest.raises(SecretMaterialRefused):
        ledger.append(
            Activity(agent_did=DID, activity_type="note",
                     meta={"oops": fake_key_block})
        )
    with pytest.raises(SecretMaterialRefused):
        ledger.append(
            Activity(agent_did=DID, activity_type="note", task_id="sk-" + "a" * 32)
        )
    assert ledger.count() == 0, "nothing may be written when a secret is detected"


def test_refusal_message_does_not_echo_the_secret(ledger: Ledger) -> None:
    marker = "sk-" + "z" * 40
    with pytest.raises(SecretMaterialRefused) as exc:
        ledger.append(Activity(agent_did=DID, activity_type="note", task_id=marker))
    assert marker not in str(exc.value)


def test_hash_covers_every_declared_field(ledger: Ledger, conn) -> None:
    """Sanity: no chained field may be omitted from the digest."""
    record = ledger.append(
        Activity(agent_did=DID, activity_type="note", tc_room="lobby", tc_nonce=1)
    )
    row = dict(conn.execute(
        "SELECT * FROM activities WHERE activity_id = ?", (record.activity_id,)
    ).fetchone())
    baseline = compute_entry_hash({k: row[k] for k in CHAINED_FIELDS})
    assert baseline == record.entry_hash
    for field in CHAINED_FIELDS:
        mutated = dict(row)
        mutated[field] = "MUTATED" if not isinstance(row[field], int) else 987654
        assert compute_entry_hash({k: mutated[k] for k in CHAINED_FIELDS}) != baseline, (
            f"field {field} is not covered by entry_hash"
        )
