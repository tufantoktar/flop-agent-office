"""Ledger chain verification.

Walks the chain from genesis and reports the first record that does not agree
with its predecessor or with its own recomputed hash.

Scope reminder: this is local, application-level tamper evidence. A VALID result
means the file is internally consistent with this code -- not that it was
externally attested.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import Enum

from .hashchain import GENESIS_PREV_HASH, CHAINED_FIELDS, compute_entry_hash

__all__ = ["Status", "Break", "VerifyResult", "verify_chain"]


class Status(str, Enum):
    VALID = "VALID"
    EMPTY = "EMPTY"
    BROKEN = "BROKEN"


class BreakKind(str, Enum):
    HASH_MISMATCH = "entry_hash does not match the record's contents"
    LINK_MISMATCH = "prev_hash does not match the previous record's entry_hash"
    INDEX_GAP = "chain_index is not contiguous (a record is missing)"
    BAD_GENESIS = "first record does not carry the genesis prev_hash"


@dataclass(frozen=True, slots=True)
class Break:
    chain_index: int
    activity_id: str | None
    kind: BreakKind
    expected: str | None = None
    found: str | None = None

    def render(self) -> str:
        lines = [
            f"  first break at chain_index {self.chain_index}",
            f"  activity_id: {self.activity_id or '<missing>'}",
            f"  reason:      {self.kind.value}",
        ]
        if self.expected is not None:
            lines.append(f"  expected:    {self.expected}")
        if self.found is not None:
            lines.append(f"  found:       {self.found}")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class VerifyResult:
    status: Status
    records_checked: int
    head_hash: str | None = None
    first_break: Break | None = None

    @property
    def ok(self) -> bool:
        return self.status in (Status.VALID, Status.EMPTY)


def verify_chain(conn: sqlite3.Connection) -> VerifyResult:
    """Verify every record in ``activities`` in chain order."""
    rows = conn.execute(
        "SELECT * FROM activities ORDER BY chain_index ASC"
    ).fetchall()

    if not rows:
        return VerifyResult(Status.EMPTY, 0)

    expected_prev = GENESIS_PREV_HASH
    checked = 0

    for position, row in enumerate(rows):
        index = int(row["chain_index"])

        if index != position:
            return VerifyResult(
                Status.BROKEN,
                checked,
                first_break=Break(
                    chain_index=index,
                    activity_id=row["activity_id"],
                    kind=BreakKind.INDEX_GAP,
                    expected=str(position),
                    found=str(index),
                ),
            )

        if row["prev_hash"] != expected_prev:
            kind = BreakKind.BAD_GENESIS if position == 0 else BreakKind.LINK_MISMATCH
            return VerifyResult(
                Status.BROKEN,
                checked,
                first_break=Break(
                    chain_index=index,
                    activity_id=row["activity_id"],
                    kind=kind,
                    expected=expected_prev,
                    found=row["prev_hash"],
                ),
            )

        recomputed = compute_entry_hash({name: row[name] for name in CHAINED_FIELDS})
        if recomputed != row["entry_hash"]:
            return VerifyResult(
                Status.BROKEN,
                checked,
                first_break=Break(
                    chain_index=index,
                    activity_id=row["activity_id"],
                    kind=BreakKind.HASH_MISMATCH,
                    expected=recomputed,
                    found=row["entry_hash"],
                ),
            )

        expected_prev = row["entry_hash"]
        checked += 1

    return VerifyResult(Status.VALID, checked, head_hash=expected_prev)
