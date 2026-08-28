"""Append-only activity ledger.

Every write goes through :meth:`Ledger.append`. There is no update path and no
delete path -- the database enforces that with triggers, and this module offers
no API that would try.

Correcting the record
---------------------
When a fact changes (a Technocore write returns its server ``seq`` after the
fact, an estimate settles to an actual cost), we do not edit the original row.
We append a linked row that refers to it via ``ref_activity_id``. The pair reads
as intent -> result. This is why the outbound write path records intent *before*
the network call: a crash mid-flight leaves an unresolved intent, which is true,
rather than a missing row, which is a lie.

What never goes in
------------------
Private keys, seed phrases, keystore passphrases, wallet secrets, API secrets,
payment credentials, and raw prompt bodies. Two mechanisms enforce this rather
than trusting the caller: the schema has no column for any of them, and every
string value is run through the repository's secret scanner before insertion.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from storage.db import immediate
from tools.secret_scan import scan_text

from .hashchain import GENESIS_PREV_HASH, compute_entry_hash

__all__ = ["LedgerError", "SecretMaterialRefused", "Activity", "Ledger", "utc_now"]

VALID_COST_UNITS = frozenset({"NONE", "FLOP_TEST", "USD"})

#: Activity types used in M1. Namespaced by subsystem.
ACTIVITY_TYPES = frozenset(
    {
        "ledger.genesis",
        "technocore.read",
        "technocore.write.intent",
        "technocore.write.result",
        "technocore.write.failed",
        "identity.nonce.reserved",
        "note",
    }
)


class LedgerError(Exception):
    """Ledger write refused."""


class SecretMaterialRefused(LedgerError):
    """A value that looks like secret material was offered to the ledger."""


def utc_now() -> str:
    """RFC 3339 UTC timestamp with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True, slots=True)
class Activity:
    """One ledger entry, before chaining fields are assigned."""

    agent_did: str
    activity_type: str
    occurred_at: str = field(default_factory=utc_now)
    task_id: str | None = None
    ref_activity_id: str | None = None
    tc_room: str | None = None
    tc_seq: int | None = None
    tc_nonce: int | None = None
    signed_payload_hash: str | None = None
    signature: str | None = None
    result_hash: str | None = None
    provider_id: str | None = None
    model: str | None = None
    cost_amount: str | None = None
    cost_unit: str = "NONE"
    meta: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class LedgerRecord:
    activity_id: str
    chain_index: int
    prev_hash: str
    entry_hash: str
    recorded_at: str


class Ledger:
    """Append-only writer over an open ledger connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # ------------------------------------------------------------------
    def append(self, activity: Activity) -> LedgerRecord:
        """Append one activity and return its chain position and hash."""
        self._validate(activity)

        meta_json = (
            json.dumps(activity.meta, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False)
            if activity.meta is not None
            else None
        )
        self._refuse_secrets(activity, meta_json)

        activity_id = str(uuid.uuid4())
        recorded_at = utc_now()

        with immediate(self._conn) as conn:
            head = conn.execute(
                "SELECT chain_index, entry_hash FROM activities "
                "ORDER BY chain_index DESC LIMIT 1"
            ).fetchone()
            chain_index = 0 if head is None else int(head["chain_index"]) + 1
            prev_hash = GENESIS_PREV_HASH if head is None else head["entry_hash"]

            if activity.ref_activity_id is not None:
                exists = conn.execute(
                    "SELECT 1 FROM activities WHERE activity_id = ?",
                    (activity.ref_activity_id,),
                ).fetchone()
                if not exists:
                    raise LedgerError(
                        f"ref_activity_id {activity.ref_activity_id} does not exist"
                    )

            row: dict[str, Any] = {
                "activity_id": activity_id,
                "chain_index": chain_index,
                "agent_did": activity.agent_did,
                "activity_type": activity.activity_type,
                "task_id": activity.task_id,
                "ref_activity_id": activity.ref_activity_id,
                "tc_room": activity.tc_room,
                "tc_seq": activity.tc_seq,
                "tc_nonce": activity.tc_nonce,
                "signed_payload_hash": activity.signed_payload_hash,
                "signature": activity.signature,
                "result_hash": activity.result_hash,
                "provider_id": activity.provider_id,
                "model": activity.model,
                "cost_amount": activity.cost_amount,
                "cost_unit": activity.cost_unit,
                "occurred_at": activity.occurred_at,
                "recorded_at": recorded_at,
                "meta_json": meta_json,
                "prev_hash": prev_hash,
            }
            row["entry_hash"] = compute_entry_hash(row)

            conn.execute(
                """
                INSERT INTO activities (
                    activity_id, chain_index, agent_did, activity_type, task_id,
                    ref_activity_id, tc_room, tc_seq, tc_nonce, signed_payload_hash,
                    signature, result_hash, provider_id, model, cost_amount,
                    cost_unit, occurred_at, recorded_at, meta_json, prev_hash,
                    entry_hash
                ) VALUES (
                    :activity_id, :chain_index, :agent_did, :activity_type, :task_id,
                    :ref_activity_id, :tc_room, :tc_seq, :tc_nonce, :signed_payload_hash,
                    :signature, :result_hash, :provider_id, :model, :cost_amount,
                    :cost_unit, :occurred_at, :recorded_at, :meta_json, :prev_hash,
                    :entry_hash
                )
                """,
                row,
            )

        return LedgerRecord(
            activity_id=activity_id,
            chain_index=chain_index,
            prev_hash=prev_hash,
            entry_hash=row["entry_hash"],
            recorded_at=recorded_at,
        )

    # ------------------------------------------------------------------
    def head(self) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM activities ORDER BY chain_index DESC LIMIT 1"
        ).fetchone()

    def count(self) -> int:
        return int(
            self._conn.execute("SELECT COUNT(*) AS n FROM activities").fetchone()["n"]
        )

    def by_id(self, activity_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM activities WHERE activity_id = ?", (activity_id,)
        ).fetchone()

    # ------------------------------------------------------------------
    @staticmethod
    def _validate(activity: Activity) -> None:
        if not activity.agent_did:
            raise LedgerError("agent_did is required")
        if activity.activity_type not in ACTIVITY_TYPES:
            raise LedgerError(
                f"unknown activity_type {activity.activity_type!r}; "
                f"add it to ACTIVITY_TYPES deliberately"
            )
        if activity.cost_unit not in VALID_COST_UNITS:
            raise LedgerError(
                f"cost_unit must be one of {sorted(VALID_COST_UNITS)}; "
                "an untyped amount is not acceptable"
            )
        if activity.cost_amount is not None and activity.cost_unit == "NONE":
            raise LedgerError("cost_amount requires an explicit cost_unit")
        if activity.cost_amount is not None and not isinstance(activity.cost_amount, str):
            raise LedgerError(
                "cost_amount must be a decimal *string*; floats lose money"
            )

    @staticmethod
    def _refuse_secrets(activity: Activity, meta_json: str | None) -> None:
        """Run every string value past the repository secret scanner."""
        parts = [v for v in asdict(activity).values() if isinstance(v, str)]
        if meta_json:
            parts.append(meta_json)
        findings = []
        for value in parts:
            findings.extend(scan_text(value, path="<ledger-write>"))
        if findings:
            rules = sorted({f.rule_id for f in findings})
            raise SecretMaterialRefused(
                "refusing to write ledger row: value matched secret pattern(s) "
                f"{rules}. The matched text is not shown. The ledger stores hashes "
                "and public artefacts only."
            )
