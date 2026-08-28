"""Outbound write recording: intent before the network, result after.

The ledger is append-only, so the server-assigned ``seq`` cannot be patched into
the row that recorded the attempt. Instead every write produces a linked pair:

    technocore.write.intent   -- what we signed, recorded BEFORE the request
    technocore.write.result   -- what the server returned, linked by ref_activity_id
    technocore.write.failed   -- linked the same way when the request did not land

A crash between the two leaves a dangling intent. That is the correct outcome:
"we signed this and do not know what happened to it" is a true statement, and it
is exactly the state a human should investigate. Silently omitting the row would
be a lie, and mutating it would break the chain.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from proof.ledger import Activity, Ledger

from .client import SignedWrite, TechnocoreClient, TechnocoreError

__all__ = ["OutboundResult", "record_intent", "send_and_record", "dangling_intents"]


@dataclass(frozen=True, slots=True)
class OutboundResult:
    intent_activity_id: str
    result_activity_id: str
    delivered: bool
    tc_seq: int | None
    detail: str | None = None


def record_intent(ledger: Ledger, write: SignedWrite, *, task_id: str | None = None) -> str:
    """Append the intent row. Call this before any network activity."""
    payload_hash = hashlib.sha256(write.payload).hexdigest()
    record = ledger.append(
        Activity(
            agent_did=write.did,
            activity_type="technocore.write.intent",
            task_id=task_id,
            tc_room=write.room,
            tc_nonce=write.nonce,
            signed_payload_hash=payload_hash,
            signature=write.signature,
            meta={"swept_len": len(write.swept_text)},
        )
    )
    return record.activity_id


def send_and_record(
    client: TechnocoreClient,
    ledger: Ledger,
    write: SignedWrite,
    *,
    task_id: str | None = None,
) -> OutboundResult:
    """Record intent, attempt the write, record the linked outcome.

    No retries. A failed write is recorded as failed and returned to the caller,
    who may decide -- with a fresh nonce -- whether to try again.
    """
    intent_id = record_intent(ledger, write, task_id=task_id)

    try:
        response = client.send_signed_message(write)
    except TechnocoreError as exc:
        failure = ledger.append(
            Activity(
                agent_did=write.did,
                activity_type="technocore.write.failed",
                task_id=task_id,
                ref_activity_id=intent_id,
                tc_room=write.room,
                tc_nonce=write.nonce,
                signature=write.signature,
                meta={"error": type(exc).__name__, "detail": str(exc)[:300]},
            )
        )
        return OutboundResult(intent_id, failure.activity_id, False, None, str(exc))

    seq = response.get("seq") if isinstance(response, dict) else None
    result = ledger.append(
        Activity(
            agent_did=write.did,
            activity_type="technocore.write.result",
            task_id=task_id,
            ref_activity_id=intent_id,
            tc_room=write.room,
            tc_seq=int(seq) if isinstance(seq, int) else None,
            tc_nonce=write.nonce,
            signature=write.signature,
            result_hash=hashlib.sha256(
                repr(sorted(response.items())).encode("utf-8")
            ).hexdigest()
            if isinstance(response, dict)
            else None,
        )
    )
    return OutboundResult(
        intent_id, result.activity_id, True, int(seq) if isinstance(seq, int) else None
    )


def dangling_intents(ledger: Ledger) -> list[str]:
    """Intent rows with no linked result or failure. Operator attention needed."""
    rows = ledger._conn.execute(  # noqa: SLF001 - read-only reporting query
        """
        SELECT i.activity_id
        FROM activities AS i
        WHERE i.activity_type = 'technocore.write.intent'
          AND NOT EXISTS (
              SELECT 1 FROM activities AS r
              WHERE r.ref_activity_id = i.activity_id
                AND r.activity_type IN ('technocore.write.result',
                                        'technocore.write.failed')
          )
        ORDER BY i.chain_index
        """
    ).fetchall()
    return [row["activity_id"] for row in rows]
