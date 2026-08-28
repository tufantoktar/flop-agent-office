"""SQLite connection management and schema migrations.

WAL is enabled so a reader (the verify CLI) never blocks a writer. Every write
path that must be atomic uses ``BEGIN IMMEDIATE`` -- SQLite's default deferred
transactions upgrade lazily and can fail mid-way under concurrency, which is
exactly the situation nonce issuance must survive.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

__all__ = ["connect", "immediate", "MIGRATIONS", "apply_migrations", "DEFAULT_LEDGER"]

DEFAULT_LEDGER = "flopoffice.sqlite"

GENESIS_PREV_HASH = "0" * 64

#: Largest integer SQLite can store. The effective nonce ceiling.
MAX_STORABLE_NONCE = 2**63 - 1

# NOTE: schema_migrations itself is created by apply_migrations() with
# IF NOT EXISTS before the transaction opens, so it is not repeated here.
_SCHEMA_V1_SQL = """
-- ------------------------------------------------------------------
-- activities: the append-only spine of the proof ledger.
-- Contains public artefacts and hashes only. No key material, no
-- passphrases, no API secrets, no raw prompt bodies.
-- ------------------------------------------------------------------
CREATE TABLE activities (
    activity_id         TEXT PRIMARY KEY,
    chain_index         INTEGER NOT NULL UNIQUE,
    agent_did           TEXT    NOT NULL,
    activity_type       TEXT    NOT NULL,
    task_id             TEXT,
    ref_activity_id     TEXT REFERENCES activities(activity_id),
    tc_room             TEXT,
    tc_seq              INTEGER,
    tc_nonce            INTEGER,
    signed_payload_hash TEXT,
    signature           TEXT,
    result_hash         TEXT,
    provider_id         TEXT,
    model               TEXT,
    cost_amount         TEXT,
    cost_unit           TEXT    NOT NULL DEFAULT 'NONE'
                        CHECK (cost_unit IN ('NONE', 'FLOP_TEST', 'USD')),
    occurred_at         TEXT    NOT NULL,
    recorded_at         TEXT    NOT NULL,
    meta_json           TEXT,
    prev_hash           TEXT    NOT NULL,
    entry_hash          TEXT    NOT NULL UNIQUE,
    CHECK (length(entry_hash) = 64),
    CHECK (length(prev_hash) = 64),
    CHECK (chain_index >= 0)
);

CREATE INDEX idx_activities_did       ON activities(agent_did);
CREATE INDEX idx_activities_type      ON activities(activity_type);
CREATE INDEX idx_activities_task      ON activities(task_id);
CREATE INDEX idx_activities_ref       ON activities(ref_activity_id);
CREATE INDEX idx_activities_room_seq  ON activities(tc_room, tc_seq);

-- Append-only enforcement. Corrections are compensating rows, never edits.
CREATE TRIGGER activities_no_update
BEFORE UPDATE ON activities
BEGIN
    SELECT RAISE(ABORT,
        'activities is append-only: record a compensating activity instead of updating');
END;

CREATE TRIGGER activities_no_delete
BEFORE DELETE ON activities
BEGIN
    SELECT RAISE(ABORT,
        'activities is append-only: rows may never be deleted');
END;

-- ------------------------------------------------------------------
-- nonces: durable monotonic counters, one row per (did, scope).
-- Scope is the Technocore room for messages, or 'kv:<namespace>' for notes.
-- ------------------------------------------------------------------
CREATE TABLE nonces (
    agent_did   TEXT NOT NULL,
    scope       TEXT NOT NULL,
    last_nonce  INTEGER NOT NULL CHECK (last_nonce >= 0),
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (agent_did, scope)
);

-- ------------------------------------------------------------------
-- seen_signatures: our own replay defence. Technocore's anti-replay only
-- holds while a message stays inside the newest ~1 MiB of the room ring,
-- so we keep an unbounded local record instead of relying on that window.
-- ------------------------------------------------------------------
CREATE TABLE seen_signatures (
    agent_did      TEXT NOT NULL,
    tc_room        TEXT NOT NULL,
    tc_nonce       INTEGER NOT NULL,
    signature      TEXT NOT NULL,
    payload_hash   TEXT NOT NULL,
    first_seen_at  TEXT NOT NULL,
    PRIMARY KEY (agent_did, tc_room, tc_nonce)
);

CREATE INDEX idx_seen_signature ON seen_signatures(signature);
"""

def _split_statements(script: str) -> list[str]:
    """Split a schema script into statements, keeping trigger bodies intact.

    SQLite triggers contain internal semicolons, so a naive split on ';' breaks
    them. We track BEGIN...END nesting instead.
    """
    statements: list[str] = []
    buffer: list[str] = []
    depth = 0
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        buffer.append(line)
        upper = stripped.upper()
        if upper.endswith("BEGIN"):
            depth += 1
        elif upper.startswith("END;"):
            depth -= 1
            if depth == 0:
                statements.append("\n".join(buffer))
                buffer = []
        elif depth == 0 and stripped.endswith(";"):
            statements.append("\n".join(buffer))
            buffer = []
    if buffer:
        statements.append("\n".join(buffer))
    return statements


MIGRATIONS: list[tuple[int, list[str]]] = [(1, _split_statements(_SCHEMA_V1_SQL))]


def connect(path: str | Path = DEFAULT_LEDGER, *, read_only: bool = False) -> sqlite3.Connection:
    """Open the ledger, applying pragmas and any pending migrations."""
    p = Path(path).expanduser()
    if read_only:
        if not p.exists():
            raise FileNotFoundError(f"ledger not found: {p}")
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(p, isolation_level=None)

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA busy_timeout = 5000")
        apply_migrations(conn)
    return conn


@contextmanager
def immediate(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a block inside a BEGIN IMMEDIATE transaction.

    IMMEDIATE takes the write lock up front, so two concurrent nonce reservations
    serialise rather than racing and both reading the same 'last' value.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def apply_migrations(conn: sqlite3.Connection) -> int:
    """Apply pending migrations. Safe under concurrent connections.

    The bookkeeping table is created with IF NOT EXISTS, then the version check
    and the migration itself run inside one BEGIN IMMEDIATE transaction. That
    write lock is what stops two processes opening the ledger at the same moment
    from both trying to create the schema.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    with immediate(conn) as tx:
        row = tx.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        current = row["v"] or 0
        for version, statements in MIGRATIONS:
            if version <= current:
                continue
            for statement in statements:
                tx.execute(statement)
            tx.execute(
                "INSERT INTO schema_migrations(version, applied_at) "
                "VALUES (?, datetime('now'))",
                (version,),
            )
            current = version
    return current
