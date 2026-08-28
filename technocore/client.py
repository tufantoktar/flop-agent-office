"""Technocore HTTP client.

M1 posture
----------
* **Reads** are fully implemented against any instance.
* **Writes** are implemented as *construction plus a guarded send*. Signed-write
  construction is pure and heavily tested. The send refuses unless the target is
  a loopback host AND ``FLOPOFFICE_ALLOW_LOCAL_WRITE=1``. Public technocore.chat
  is blocked by an explicit host denylist that no environment variable can
  unlock.
* Nothing here posts to the public server. Sending the first public message is a
  separate, explicitly approved human decision.

Everything returned by a read is wrapped in the untrusted types from
``technocore.untrusted``. This module is the only place in the codebase allowed
to construct them.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

import httpx

from identity.canonical import (
    encode_path_segment,
    message_payload,
    single_line_sweep,
    validate_room,
    validate_nonce,
)
from identity.signer import Signer
from identity.verifier import verify_message

from .ratelimit import Budget
from .untrusted import UntrustedMessage, UntrustedRoom, UntrustedText

__all__ = [
    "TechnocoreError",
    "PublicWriteRefused",
    "TechnocoreClient",
    "SignedWrite",
    "OneTimePublicWriteGate",
    "build_signed_message",
    "PUBLIC_HOSTS",
]

#: Hosts that must never receive a write from this codebase in M1.
#: This is a denylist, not a toggle: no environment variable unlocks it.
PUBLIC_HOSTS = frozenset(
    {"technocore.chat", "www.technocore.chat", "api.technocore.chat"}
)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0"})

WRITE_ENABLE_ENV = "FLOPOFFICE_ALLOW_LOCAL_WRITE"


class TechnocoreError(Exception):
    """Transport or protocol failure talking to Technocore."""


class PublicWriteRefused(TechnocoreError):
    """A write was attempted against a non-local host. Always refused in M1."""


@dataclass(slots=True)
class OneTimePublicWriteGate:
    """A scoped, one-use exception to the public host denylist.

    The denylist remains the default. This object is explicit, bound to one
    public host, room, canonical message hash and nonce, and it is consumed
    before the HTTP request is made. It cannot be reused for retries.
    """

    host: str
    room: str
    message_sha256: str
    nonce: int
    confirm_public_technocore_publish: bool = False
    _used: bool = field(default=False, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self.host = self.host.lower()
        self.room = validate_room(self.room)
        self.nonce = validate_nonce(self.nonce)
        if not self.confirm_public_technocore_publish:
            raise PublicWriteRefused("public Technocore publish gate lacks confirmation")
        if self.host not in PUBLIC_HOSTS:
            raise PublicWriteRefused(
                "one-time public publish gate is only valid for the public denylist"
            )
        if not _is_sha256(self.message_sha256):
            raise PublicWriteRefused("message_sha256 must be a 64-character hex digest")

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def used(self) -> bool:
        return self._used

    def consume(self, *, host: str, write: SignedWrite) -> None:
        if self._closed or self._used:
            raise PublicWriteRefused("one-time public publish gate is already closed")
        if host.lower() != self.host:
            self.close()
            raise PublicWriteRefused("one-time public publish gate host mismatch")
        if write.room != self.room:
            self.close()
            raise PublicWriteRefused("one-time public publish gate room mismatch")
        if write.nonce != self.nonce:
            self.close()
            raise PublicWriteRefused("one-time public publish gate nonce mismatch")
        actual_hash = hashlib.sha256(write.swept_text.encode("utf-8")).hexdigest()
        if actual_hash != self.message_sha256:
            self.close()
            raise PublicWriteRefused("one-time public publish gate message mismatch")
        self._used = True

    def close(self) -> None:
        self._closed = True


# ---------------------------------------------------------------------------
# Signed write construction -- pure, no network
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class SignedWrite:
    """A fully-formed signed write, not yet sent.

    ``payload`` holds the exact bytes the signature covers, so the ledger can
    record their hash *before* anything touches the network.
    """

    did: str
    room: str
    nonce: int
    text: str
    swept_text: str
    signature: str
    payload: bytes

    @property
    def path(self) -> str:
        """GET path for the say-signed endpoint."""
        return (
            f"/r/{encode_path_segment(self.room)}/say-signed/"
            f"{encode_path_segment(self.did)}/"
            f"{encode_path_segment(self.signature)}/"
            f"{self.nonce}/"
            f"{encode_path_segment(self.swept_text)}"
        )

    @property
    def json_body(self) -> dict[str, Any]:
        """Body for the POST alternative."""
        return {
            "did": self.did,
            "sig": self.signature,
            "nonce": self.nonce,
            "text": self.swept_text,
        }

    def verifies(self) -> bool:
        """Self-check: does our own signature verify against our own payload?"""
        return verify_message(
            self.did, self.signature, self.room, self.nonce, self.swept_text
        )


def build_signed_message(
    signer: Signer, room: str, nonce: int, text: str
) -> SignedWrite:
    """Construct a signed room message. Pure: performs no I/O.

    The text is swept once, here, and the swept form is what is both signed and
    transmitted -- signing pre-sweep text and sending post-sweep text is the
    canonicalisation bug this ordering exists to prevent.
    """
    room = validate_room(room)
    nonce = validate_nonce(nonce)
    swept = single_line_sweep(text)
    payload = message_payload(room, nonce, swept, already_swept=True)
    signature = signer.sign(payload)

    write = SignedWrite(
        did=str(signer.did),
        room=room,
        nonce=nonce,
        text=text,
        swept_text=swept,
        signature=signature,
        payload=payload,
    )
    if not write.verifies():
        # Refuse to emit a signature we cannot verify ourselves.
        raise TechnocoreError(
            "constructed signature failed local verification; "
            "canonicalisation and signer disagree"
        )
    return write


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class TechnocoreClient:
    """Read-first Technocore client with a hard write guard."""

    def __init__(
        self,
        base_url: str,
        *,
        budget: Budget | None = None,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
        discover_limits: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https"):
            raise TechnocoreError("base_url must be http(s)")
        self._host = (parsed.hostname or "").lower()
        self._budget = budget or Budget.conservative()
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=False)
        self._owns_client = client is None
        if discover_limits:
            self.discover_limits()

    # --- lifecycle -----------------------------------------------------
    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "TechnocoreClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- guards --------------------------------------------------------
    @property
    def is_public(self) -> bool:
        return self._host in PUBLIC_HOSTS

    @property
    def host(self) -> str:
        return self._host

    @property
    def is_loopback(self) -> bool:
        return self._host in LOOPBACK_HOSTS

    def _assert_write_allowed(
        self,
        write: SignedWrite,
        *,
        public_gate: OneTimePublicWriteGate | None = None,
    ) -> None:
        if public_gate is not None:
            if not self.is_public:
                public_gate.close()
                raise PublicWriteRefused(
                    "one-time public publish gate may only be used for public hosts"
                )
            public_gate.consume(host=self._host, write=write)
            return
        if self.is_public:
            raise PublicWriteRefused(
                f"writes to {self._host} are blocked in M1. Posting the first "
                "public signed message is a separate, explicitly approved step."
            )
        if not self.is_loopback:
            raise PublicWriteRefused(
                f"writes are only permitted against a loopback host; got {self._host!r}"
            )
        if os.environ.get(WRITE_ENABLE_ENV) != "1":
            raise PublicWriteRefused(
                f"set {WRITE_ENABLE_ENV}=1 to enable writes against a local instance"
            )

    # --- transport -----------------------------------------------------
    def _get(self, path: str, params: Mapping[str, Any] | None = None) -> httpx.Response:
        self._budget.reads.acquire()
        try:
            response = self._client.get(self.base_url + path, params=params)
        except httpx.HTTPError as exc:
            raise TechnocoreError(f"GET {path} failed: {type(exc).__name__}") from None
        if response.status_code == 429:
            raise TechnocoreError(
                f"server rate limit hit (429); Retry-After="
                f"{response.headers.get('Retry-After', 'unknown')}"
            )
        if response.status_code >= 400:
            raise TechnocoreError(f"GET {path} returned HTTP {response.status_code}")
        return response

    # --- discovery -----------------------------------------------------
    def discover_limits(self) -> Budget:
        """Read ``/.well-known/agent.json`` and size our buckets below it."""
        try:
            data = self._get("/.well-known/agent.json").json()
        except (TechnocoreError, json.JSONDecodeError, ValueError):
            self._budget = Budget.conservative()
            return self._budget
        limits = data.get("limits", {}) if isinstance(data, dict) else {}
        reads = int(limits.get("reads_per_minute_per_ip", 30) or 30)
        writes = int(limits.get("writes_per_minute_per_ip", 2) or 2)
        self._budget = Budget.from_advertised(reads, writes)
        return self._budget

    # --- reads ---------------------------------------------------------
    def read_room(
        self, room: str, *, since: int | None = None, limit: int | None = None
    ) -> tuple[UntrustedMessage, ...]:
        """Read a room. Every message comes back wrapped as untrusted data."""
        room = validate_room(room)
        params: dict[str, Any] = {"format": "json"}
        if since is not None:
            params["since"] = int(since)
        if limit is not None:
            params["limit"] = int(limit)
        response = self._get(f"/r/{encode_path_segment(room)}", params)
        payload = self._as_json(response)
        raw_messages = payload.get("messages", payload) if isinstance(payload, dict) else payload
        if not isinstance(raw_messages, list):
            raise TechnocoreError("unexpected room payload shape")
        return tuple(self._to_message(room, item) for item in raw_messages)

    def list_rooms(self) -> tuple[UntrustedRoom, ...]:
        """Enumerate rooms. Topics are user-written and are wrapped too."""
        response = self._get("/rooms", {"format": "json"})
        payload = self._as_json(response)
        raw = payload.get("rooms", payload) if isinstance(payload, dict) else payload
        if not isinstance(raw, list):
            raise TechnocoreError("unexpected /rooms payload shape")
        out = []
        for item in raw:
            if isinstance(item, str):
                out.append(UntrustedRoom(name=item))
                continue
            if not isinstance(item, dict):
                continue
            name = str(item.get("room") or item.get("name") or "")
            topic = item.get("topic")
            out.append(
                UntrustedRoom(
                    name=name,
                    topic=UntrustedText(str(topic)) if topic else None,
                    raw=item,
                )
            )
        return tuple(out)

    @staticmethod
    def _as_json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except (json.JSONDecodeError, ValueError):
            raise TechnocoreError("response was not valid JSON") from None

    @staticmethod
    def _to_message(room: str, item: Any) -> UntrustedMessage:
        """Wrap one room record.

        Field names measured against technocore-chat v0.10.0: a room read returns
        ``seq``, ``ts``, ``from`` (the DID), ``text`` and ``nonce``. It does NOT
        return ``sig``. ``did`` is accepted as an alias so a future or self-hosted
        variant that does return it still parses.
        """
        if not isinstance(item, dict):
            return UntrustedMessage(room=room, seq=None, ts=None,
                                    text=UntrustedText(str(item)))
        author = item.get("from") or item.get("did")
        signature = item.get("sig") or item.get("signature")
        nonce = item.get("nonce")
        text = str(item.get("text", ""))

        verified = False
        if author and signature and nonce is not None:
            # Re-verify ourselves. A server flag saying "verified" is the server's
            # claim; the signature is the evidence, and we check it.
            try:
                verified = verify_message(str(author), str(signature), room,
                                          int(nonce), text)
            except (ValueError, TypeError):
                verified = False

        return UntrustedMessage(
            room=room,
            seq=item.get("seq"),
            ts=item.get("ts"),
            text=UntrustedText(text),
            did=str(author) if author else None,
            nick=str(item["nick"]) if item.get("nick") else None,
            signature=str(signature) if signature else None,
            nonce=int(nonce) if isinstance(nonce, (int, str)) and str(nonce).isdigit() else None,
            verified=verified,
            signature_returned=bool(signature),
            raw=item,
        )

    # --- guarded write -------------------------------------------------
    def send_signed_message(
        self,
        write: SignedWrite,
        *,
        public_gate: OneTimePublicWriteGate | None = None,
    ) -> dict[str, Any]:
        """Send a prepared signed write. Local instances only.

        Callers must have recorded a ``technocore.write.intent`` ledger row
        before calling this, and must record a linked result row afterwards.
        """
        try:
            if not write.verifies():
                raise TechnocoreError(
                    "refusing to send a write that fails local verification"
                )
            self._assert_write_allowed(write, public_gate=public_gate)
            self._budget.writes.acquire()
            try:
                response = self._client.get(self.base_url + write.path)
            except httpx.HTTPError as exc:
                raise TechnocoreError(
                    f"signed write failed: {type(exc).__name__}"
                ) from None
            if response.status_code >= 400:
                raise TechnocoreError(
                    f"signed write rejected with HTTP {response.status_code}"
                )
            try:
                return response.json()
            except (json.JSONDecodeError, ValueError):
                return {"raw": response.text[:512]}
        finally:
            if public_gate is not None:
                public_gate.close()


def _is_sha256(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )
