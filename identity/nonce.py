"""Durable, monotonic nonce issuance.

Technocore semantics (from ``/auth.md``):

* for a room message, the nonce must **exceed the last nonce that key used in
  that room** -- so the counter is scoped to ``(did, room)``, not global;
* for ownership notes, the counter at ``/kv/room-nonce/<room>`` is **shared
  across all signers** of that room, so a purely local counter is not
  sufficient: the server's value must be folded in as a floor before issuing.

Failure modes this guards against:

reuse
    Two payloads signed with the same nonce. Prevented by issuing inside
    ``BEGIN IMMEDIATE`` and persisting before the caller sees the value.
regression
    Issuing a nonce below one the server already recorded. Prevented by
    :meth:`NonceStore.observe`, which raises the floor from server-reported
    values, and by ``reserve(floor=...)``.
concurrent duplicate issuance
    Two threads or processes reserving the same value. Prevented by the write
    lock IMMEDIATE takes before the read.

Deliberately absent: retries. A failed reservation is surfaced, not retried --
retrying a nonce reservation is how a caller ends up signing twice.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from storage.db import MAX_STORABLE_NONCE, immediate

from .canonical import MAX_NONCE_DIGITS, CanonicalisationError, validate_nonce

__all__ = ["NonceError", "NonceStore", "scope_for_room", "scope_for_kv"]


class NonceError(Exception):
    """Nonce could not be issued or would violate monotonicity."""


def scope_for_room(room: str) -> str:
    """Nonce scope for a room message: the room itself."""
    return room


def scope_for_kv(namespace: str) -> str:
    """Nonce scope for a kv note, namespaced so it cannot collide with a room."""
    return f"kv:{namespace}"


@dataclass(frozen=True, slots=True)
class Reservation:
    agent_did: str
    scope: str
    nonce: int


class NonceStore:
    """Durable per-(did, scope) counter backed by the ledger database."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # ------------------------------------------------------------------
    def current(self, agent_did: str, scope: str) -> int:
        row = self._conn.execute(
            "SELECT last_nonce FROM nonces WHERE agent_did = ? AND scope = ?",
            (agent_did, scope),
        ).fetchone()
        return int(row["last_nonce"]) if row else 0

    def reserve(self, agent_did: str, scope: str, *, floor: int = 0) -> Reservation:
        """Atomically issue the next nonce for ``(agent_did, scope)``.

        ``floor`` lets a caller fold in a value observed from the server (for
        the shared ``room-nonce`` counter). The issued nonce is always strictly
        greater than both the stored value and ``floor``.
        """
        if not agent_did or not isinstance(agent_did, str):
            raise NonceError("agent_did must be a non-empty str")
        if not scope or not isinstance(scope, str):
            raise NonceError("scope must be a non-empty str")
        if floor < 0:
            raise NonceError("floor must not be negative")

        with immediate(self._conn) as conn:
            row = conn.execute(
                "SELECT last_nonce FROM nonces WHERE agent_did = ? AND scope = ?",
                (agent_did, scope),
            ).fetchone()
            stored = int(row["last_nonce"]) if row else 0
            nxt = max(stored, floor) + 1
            if nxt > MAX_STORABLE_NONCE:
                raise NonceError(
                    f"nonce space exhausted for scope {scope!r}: "
                    f"{nxt} exceeds the storable maximum {MAX_STORABLE_NONCE}"
                )
            try:
                validate_nonce(nxt)
            except CanonicalisationError:
                raise NonceError(
                    f"nonce space exhausted for scope {scope!r} "
                    f"(>{MAX_NONCE_DIGITS} digits)"
                ) from None
            conn.execute(
                "INSERT INTO nonces(agent_did, scope, last_nonce, updated_at) "
                "VALUES (?, ?, ?, datetime('now')) "
                "ON CONFLICT(agent_did, scope) DO UPDATE SET "
                "  last_nonce = excluded.last_nonce, updated_at = excluded.updated_at",
                (agent_did, scope, nxt),
            )
        return Reservation(agent_did, scope, nxt)

    def observe(self, agent_did: str, scope: str, nonce: int) -> int:
        """Raise the local floor to a nonce observed elsewhere.

        Used when the server (or another signer sharing a counter) reports a
        nonce we did not issue. Never lowers the stored value.
        """
        validate_nonce(nonce)
        with immediate(self._conn) as conn:
            row = conn.execute(
                "SELECT last_nonce FROM nonces WHERE agent_did = ? AND scope = ?",
                (agent_did, scope),
            ).fetchone()
            stored = int(row["last_nonce"]) if row else 0
            if nonce <= stored:
                return stored
            conn.execute(
                "INSERT INTO nonces(agent_did, scope, last_nonce, updated_at) "
                "VALUES (?, ?, ?, datetime('now')) "
                "ON CONFLICT(agent_did, scope) DO UPDATE SET "
                "  last_nonce = excluded.last_nonce, updated_at = excluded.updated_at",
                (agent_did, scope, nonce),
            )
            return nonce
