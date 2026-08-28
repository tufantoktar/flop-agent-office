"""First public Technocore announcement preparation.

M1.6 prepares the first message, signs it locally, verifies it locally, and
records append-only proof. It does not publish and does not hold a raw signer.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from identity.canonical import message_payload, single_line_sweep, validate_nonce
from identity.capability import CapabilitySigner
from identity.nonce import NonceStore, scope_for_room
from identity.verifier import verify_message
from proof.ledger import Activity, Ledger, LedgerRecord

__all__ = [
    "CANONICALIZATION_PROFILE",
    "FIRST_ANNOUNCEMENT_ROOM",
    "FIRST_ANNOUNCEMENT_TEXT",
    "NOT_SENT",
    "AnnouncementPreparation",
    "AnnouncementProof",
    "AnnouncementProofRecords",
    "AnnouncementPreparationError",
    "build_local_announcement_proof",
    "prepare_first_announcement",
    "record_local_announcement_proof",
    "reserve_announcement_nonce",
    "verify_announcement_proof",
]


FIRST_ANNOUNCEMENT_ROOM: Final = "lobby"
FIRST_ANNOUNCEMENT_TEXT: Final = (
    "FlopOffice is a DID-authenticated multi-agent workspace for signed "
    "coordination, append-only proof logging, and capability-scoped agent "
    "actions. Current milestone: Technocore signing conformance is pinned, "
    "the root DID is configured, and signer wiring is fail-closed. Public "
    "testnet integrations will be added only when official FLOP interfaces "
    "are available."
)
CANONICALIZATION_PROFILE: Final = "technocore-chat-v0.10.0-single-line-sweep"
NOT_SENT: Final = "NOT_SENT"
AWAITING_APPROVAL: Final = "awaiting_explicit_user_approval"


class AnnouncementPreparationError(Exception):
    """Announcement preparation was refused before publication could exist."""


@dataclass(frozen=True, slots=True)
class AnnouncementProof:
    did: str
    room: str
    nonce: int
    original_text: str
    canonical_text: str
    original_text_hash: str
    canonical_text_hash: str
    payload_hash: str
    signature: str
    signing_algorithm: str
    canonicalization_profile: str
    technocore_status: str
    verified: bool


@dataclass(frozen=True, slots=True)
class AnnouncementProofRecords:
    prepare_intent: LedgerRecord
    signed_local: LedgerRecord
    verified_local: LedgerRecord
    publish_blocked: LedgerRecord


@dataclass(frozen=True, slots=True)
class AnnouncementPreparation:
    proof: AnnouncementProof
    records: AnnouncementProofRecords


def reserve_announcement_nonce(
    nonces: NonceStore,
    did: str,
    *,
    room: str = FIRST_ANNOUNCEMENT_ROOM,
    nonce: int | None = None,
) -> int:
    """Reserve a monotonic room nonce, or atomically claim an explicit one."""
    scope = scope_for_room(room)
    current = nonces.current(did, scope)
    if nonce is not None:
        chosen = validate_nonce(nonce)
        if chosen < 1:
            raise AnnouncementPreparationError("announcement nonce must be >= 1")
        if chosen <= current:
            raise AnnouncementPreparationError(
                "announcement nonce must be greater than the stored local nonce"
            )
        reserved = nonces.reserve(did, scope, floor=chosen - 1).nonce
        if reserved != chosen:
            raise AnnouncementPreparationError(
                "announcement nonce reservation raced; refusing to sign"
            )
        return reserved

    return nonces.reserve(did, scope).nonce


def build_local_announcement_proof(
    capability: CapabilitySigner,
    *,
    nonce: int,
    room: str = FIRST_ANNOUNCEMENT_ROOM,
    text: str = FIRST_ANNOUNCEMENT_TEXT,
) -> AnnouncementProof:
    """Sign and locally verify the deterministic first message.

    A :class:`CapabilitySigner` is required deliberately; a raw signer with
    ``sign(bytes)`` is not accepted on this preparation path.
    """
    if not isinstance(capability, CapabilitySigner):
        raise AnnouncementPreparationError(
            "CapabilitySigner required; raw signers are not accepted"
        )
    chosen = validate_nonce(nonce)
    if chosen < 1:
        raise AnnouncementPreparationError("announcement nonce must be >= 1")

    canonical = single_line_sweep(text)
    signed = capability.sign_technocore_message(room, chosen, text)
    if signed.swept_text != canonical:
        raise AnnouncementPreparationError("canonicalization mismatch")

    payload = message_payload(room, chosen, canonical, already_swept=True)
    verified = verify_message(signed.did, signed.signature, room, chosen, canonical)
    return AnnouncementProof(
        did=signed.did,
        room=signed.room,
        nonce=signed.nonce,
        original_text=text,
        canonical_text=canonical,
        original_text_hash=_sha256_text(text),
        canonical_text_hash=_sha256_text(canonical),
        payload_hash=hashlib.sha256(payload).hexdigest(),
        signature=signed.signature,
        signing_algorithm="Ed25519",
        canonicalization_profile=CANONICALIZATION_PROFILE,
        technocore_status=NOT_SENT,
        verified=verified,
    )


def verify_announcement_proof(proof: AnnouncementProof, *, did: str | None = None) -> bool:
    """Verify the retained local authorship proof without trusting a server."""
    return verify_message(
        did or proof.did,
        proof.signature,
        proof.room,
        proof.nonce,
        proof.canonical_text,
    )


def record_local_announcement_proof(
    ledger: Ledger,
    proof: AnnouncementProof,
    *,
    task_id: str = "m1.6-first-technocore-announcement",
) -> AnnouncementProofRecords:
    """Append the four local-proof events. Nothing is sent to Technocore."""
    if not proof.verified or not verify_announcement_proof(proof):
        raise AnnouncementPreparationError(
            "local signature verification must pass before proof is recorded"
        )

    common = {
        "canonicalization_profile": proof.canonicalization_profile,
        "canonical_text_hash": proof.canonical_text_hash,
        "original_text_hash": proof.original_text_hash,
        "payload_hash": proof.payload_hash,
        "publish_status": proof.technocore_status,
        "reason": AWAITING_APPROVAL,
        "signing_algorithm": proof.signing_algorithm,
    }
    prepare = ledger.append(
        Activity(
            agent_did=proof.did,
            activity_type="technocore_message_prepare_intent",
            task_id=task_id,
            tc_room=proof.room,
            tc_nonce=proof.nonce,
            signed_payload_hash=proof.payload_hash,
            meta={**common, "stage": "prepared"},
        )
    )
    signed = ledger.append(
        Activity(
            agent_did=proof.did,
            activity_type="technocore_message_signed_local",
            task_id=task_id,
            ref_activity_id=prepare.activity_id,
            tc_room=proof.room,
            tc_nonce=proof.nonce,
            signed_payload_hash=proof.payload_hash,
            signature=proof.signature,
            meta={**common, "canonical_text": proof.canonical_text, "stage": "signed"},
        )
    )
    verified = ledger.append(
        Activity(
            agent_did=proof.did,
            activity_type="technocore_message_verified_local",
            task_id=task_id,
            ref_activity_id=signed.activity_id,
            tc_room=proof.room,
            tc_nonce=proof.nonce,
            signed_payload_hash=proof.payload_hash,
            signature=proof.signature,
            meta={**common, "signature_verification": "PASS", "stage": "verified"},
        )
    )
    blocked = ledger.append(
        Activity(
            agent_did=proof.did,
            activity_type="technocore_message_publish_blocked",
            task_id=task_id,
            ref_activity_id=verified.activity_id,
            tc_room=proof.room,
            tc_nonce=proof.nonce,
            signed_payload_hash=proof.payload_hash,
            result_hash=proof.canonical_text_hash,
            meta={
                **common,
                "stage": "publish_blocked",
                "technocore_publish": "BLOCKED",
            },
        )
    )
    return AnnouncementProofRecords(prepare, signed, verified, blocked)


def prepare_first_announcement(
    capability: CapabilitySigner,
    ledger: Ledger,
    nonces: NonceStore,
    *,
    nonce: int | None = None,
    room: str = FIRST_ANNOUNCEMENT_ROOM,
    text: str = FIRST_ANNOUNCEMENT_TEXT,
) -> AnnouncementPreparation:
    """Reserve, sign, verify, and record the local first-message proof."""
    chosen = reserve_announcement_nonce(nonces, str(capability.did), room=room, nonce=nonce)
    proof = build_local_announcement_proof(capability, room=room, nonce=chosen, text=text)
    records = record_local_announcement_proof(ledger, proof)
    return AnnouncementPreparation(proof=proof, records=records)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
