"""Nonce monotonicity, scoping and concurrency safety (required tests 8-9)."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from identity.nonce import NonceError, NonceStore, scope_for_kv, scope_for_room
from storage.db import connect

DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


# --- 8. monotonicity -------------------------------------------------------
def test_nonces_start_at_one_and_increase(nonces: NonceStore) -> None:
    assert nonces.current(DID, "lobby") == 0
    values = [nonces.reserve(DID, "lobby").nonce for _ in range(5)]
    assert values == [1, 2, 3, 4, 5]
    assert nonces.current(DID, "lobby") == 5


def test_nonce_scope_is_per_room(nonces: NonceStore) -> None:
    """Technocore compares against the last nonce that key used *in that room*."""
    assert nonces.reserve(DID, scope_for_room("lobby")).nonce == 1
    assert nonces.reserve(DID, scope_for_room("mb-private")).nonce == 1
    assert nonces.reserve(DID, scope_for_room("lobby")).nonce == 2


def test_nonce_scope_is_per_did(nonces: NonceStore) -> None:
    other = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"
    assert nonces.reserve(DID, "lobby").nonce == 1
    assert nonces.reserve(other, "lobby").nonce == 1


def test_kv_scope_cannot_collide_with_a_room(nonces: NonceStore) -> None:
    assert scope_for_kv("room-owners") == "kv:room-owners"
    nonces.reserve(DID, scope_for_room("room-owners"))
    assert nonces.reserve(DID, scope_for_kv("room-owners")).nonce == 1


def test_observe_raises_the_floor_but_never_lowers_it(nonces: NonceStore) -> None:
    """The /kv/room-nonce/<room> counter is shared across signers."""
    nonces.reserve(DID, "d-flop")           # local -> 1
    nonces.observe(DID, "d-flop", 500)      # someone else used 500
    assert nonces.reserve(DID, "d-flop").nonce == 501
    nonces.observe(DID, "d-flop", 12)       # a stale report must not regress us
    assert nonces.current(DID, "d-flop") == 501
    assert nonces.reserve(DID, "d-flop").nonce == 502


def test_reserve_honours_an_explicit_floor(nonces: NonceStore) -> None:
    nonces.reserve(DID, "d-flop")
    assert nonces.reserve(DID, "d-flop", floor=99).nonce == 100


def test_nonce_survives_reconnect(db_path: Path) -> None:
    first = connect(db_path)
    try:
        NonceStore(first).reserve(DID, "lobby")
        NonceStore(first).reserve(DID, "lobby")
    finally:
        first.close()

    second = connect(db_path)
    try:
        assert NonceStore(second).reserve(DID, "lobby").nonce == 3
    finally:
        second.close()


def test_nonce_space_exhaustion_is_reported(conn: sqlite3.Connection) -> None:
    """At the storage ceiling we refuse rather than wrap or silently truncate."""
    from storage.db import MAX_STORABLE_NONCE  # noqa: PLC0415

    store = NonceStore(conn)
    conn.execute(
        "INSERT INTO nonces(agent_did, scope, last_nonce, updated_at) "
        "VALUES (?, ?, ?, datetime('now'))",
        (DID, "lobby", MAX_STORABLE_NONCE),
    )
    with pytest.raises(NonceError, match="exhausted"):
        store.reserve(DID, "lobby")
    # The stored value must be unchanged after the refusal.
    assert store.current(DID, "lobby") == MAX_STORABLE_NONCE


def test_bad_arguments_rejected(nonces: NonceStore) -> None:
    with pytest.raises(NonceError):
        nonces.reserve("", "lobby")
    with pytest.raises(NonceError):
        nonces.reserve(DID, "")
    with pytest.raises(NonceError):
        nonces.reserve(DID, "lobby", floor=-1)


# --- 9. concurrency --------------------------------------------------------
def test_concurrent_reservations_never_duplicate(db_path: Path) -> None:
    """Threads with independent connections must not receive the same nonce."""
    threads_count = 8
    per_thread = 25
    issued: list[int] = []
    errors: list[BaseException] = []
    lock = threading.Lock()
    barrier = threading.Barrier(threads_count)

    def worker() -> None:
        conn = connect(db_path)
        store = NonceStore(conn)
        local: list[int] = []
        try:
            barrier.wait(timeout=10)
            for _ in range(per_thread):
                local.append(store.reserve(DID, "lobby").nonce)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)
        finally:
            conn.close()
        with lock:
            issued.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(threads_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not errors, f"worker failures: {errors[:3]}"
    expected = threads_count * per_thread
    assert len(issued) == expected
    assert len(set(issued)) == expected, "a nonce was issued twice"
    assert sorted(issued) == list(range(1, expected + 1)), "the sequence has gaps"


class _FlakyConnection:
    """Delegating proxy that fails the nonce INSERT exactly as a disk error would."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self.insert_attempts = 0

    def execute(self, sql: str, *args, **kwargs):
        if sql.startswith("INSERT INTO nonces"):
            self.insert_attempts += 1
            raise sqlite3.OperationalError("simulated disk failure")
        return self._conn.execute(sql, *args, **kwargs)


def test_no_automatic_retry_on_failure(conn: sqlite3.Connection) -> None:
    """A failed reservation surfaces; it is never silently retried.

    Retrying here is how a caller ends up signing two payloads with one nonce.
    """
    flaky = _FlakyConnection(conn)
    store = NonceStore(flaky)  # type: ignore[arg-type]

    with pytest.raises(sqlite3.OperationalError):
        store.reserve(DID, "lobby")

    assert flaky.insert_attempts == 1, "reservation must not be retried internally"
    # The transaction rolled back, so nothing was recorded.
    assert NonceStore(conn).current(DID, "lobby") == 0
