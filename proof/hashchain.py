"""Hash chaining over ledger rows.

What this is
------------
Local, application-level tamper *evidence*. Each row commits to its predecessor,
so editing or removing a row invalidates every hash after it and the break is
locatable.

What this is NOT
----------------
It is not a blockchain, not a proof of existence, and not external attestation.
Anyone with write access to the database file and this source can recompute a
consistent chain from scratch. It detects accidental corruption and casual
tampering; it does not defend against an attacker who controls the machine.

Publishing a chain head somewhere we do not control (a signed Technocore note,
for example) is what would add external timestamping. That is a later milestone
and is not implemented here.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

__all__ = ["GENESIS_PREV_HASH", "CHAINED_FIELDS", "canonical_bytes", "compute_entry_hash"]

GENESIS_PREV_HASH = "0" * 64

#: Fields covered by ``entry_hash``, in a fixed order. ``entry_hash`` itself is
#: excluded. Changing this list changes every hash: it is a schema-breaking
#: change and needs a migration, not an edit.
CHAINED_FIELDS: Sequence[str] = (
    "activity_id",
    "chain_index",
    "agent_did",
    "activity_type",
    "task_id",
    "ref_activity_id",
    "tc_room",
    "tc_seq",
    "tc_nonce",
    "signed_payload_hash",
    "signature",
    "result_hash",
    "provider_id",
    "model",
    "cost_amount",
    "cost_unit",
    "occurred_at",
    "recorded_at",
    "meta_json",
    "prev_hash",
)


def canonical_bytes(row: Mapping[str, Any]) -> bytes:
    """Deterministic serialisation of the chained fields.

    JSON with sorted keys, no insignificant whitespace, and ``ensure_ascii`` off
    so unicode is encoded once (as UTF-8) rather than escaped -- one encoding,
    one set of bytes, no ambiguity.
    """
    payload = {name: row.get(name) for name in CHAINED_FIELDS}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_entry_hash(row: Mapping[str, Any]) -> str:
    """SHA-256 hex digest over :func:`canonical_bytes`."""
    return hashlib.sha256(canonical_bytes(row)).hexdigest()
