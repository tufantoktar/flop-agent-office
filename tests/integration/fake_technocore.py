"""A local stand-in for Technocore, for integration tests.

Why a stand-in rather than the real container
---------------------------------------------
CI must not depend on the public server, and pulling the official image is not
always possible in a sandbox. This server implements the documented endpoints
and the documented signature rules so the round-trip has something real to
verify against.

It deliberately re-implements base58btc decoding and signature verification
*independently* of ``identity/``. If both sides shared our decoder, a bug in it
would make the round-trip test pass while the real server rejected every
message -- the exact failure the test exists to catch.

This is a test double, not a conformance oracle. When ``TECHNOCORE_BASE_URL``
points at a real self-hosted instance, the same tests run against that instead,
and that is what actually pins the single-line sweep behaviour.
"""

from __future__ import annotations

import json
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(text: str) -> bytes:
    """Independent base58btc decoder (table lookup, not shared with identity/)."""
    num = 0
    for char in text:
        index = _ALPHABET.find(char)
        if index < 0:
            raise ValueError("bad base58 character")
        num = num * 58 + index
    raw = bytearray()
    while num:
        num, rem = divmod(num, 256)
        raw.append(rem)
    pad = len(text) - len(text.lstrip("1"))
    return bytes(raw[::-1]).rjust(len(raw) + pad, b"\x00")


def _pubkey_from_did(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError("not a base58btc did:key")
    decoded = _b58decode(did[len("did:key:z"):])
    if decoded[:2] != b"\xed\x01":
        raise ValueError("not ed25519-pub")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def _b64url_decode(text: str) -> bytes:
    import base64

    if len(text) != 86:
        raise ValueError("signature must be 86 chars")
    return base64.urlsafe_b64decode(text + "==")


# technocore-chat v0.10.0 store.INVISIBLE_CATEGORIES, verified empirically in M1.1.
# Zs is deliberately absent -- the official sweep keeps NBSP and friends.
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")


def single_line_sweep(text: str) -> str:
    """Mirror of the official ``store.clean_text``: sweep to spaces, then strip."""
    return "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()


class FakeTechnocoreState:
    def __init__(self, *, writes_per_minute: int = 30, reads_per_minute: int = 120):
        self.rooms: dict[str, list[dict]] = {}
        self.next_seq = 1
        self.nonces: dict[tuple[str, str], int] = {}
        self.writes_per_minute = writes_per_minute
        self.reads_per_minute = reads_per_minute
        self._write_times: list[float] = []
        self.lock = threading.Lock()

    def rate_limited(self) -> bool:
        now = time.monotonic()
        self._write_times = [t for t in self._write_times if now - t < 60.0]
        if len(self._write_times) >= self.writes_per_minute:
            return True
        self._write_times.append(now)
        return False


class _Handler(BaseHTTPRequestHandler):
    state: FakeTechnocoreState

    def log_message(self, *args):  # silence test output
        return

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if code == 429:
            self.send_header("Retry-After", "2")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        parts = [unquote(p) for p in parsed.path.strip("/").split("/")]
        query = parse_qs(parsed.query)

        if parsed.path == "/.well-known/agent.json":
            self._send(200, {
                "service": "fake-technocore",
                "limits": {
                    "reads_per_minute_per_ip": self.state.reads_per_minute,
                    "writes_per_minute_per_ip": self.state.writes_per_minute,
                },
            })
            return

        if parsed.path == "/rooms":
            self._send(200, {"rooms": [
                {"room": name, "topic": f"topic for {name}"}
                for name in sorted(self.state.rooms)
            ]})
            return

        # /r/<room>/say-signed/<did>/<sig>/<nonce>/<text>
        if len(parts) >= 7 and parts[0] == "r" and parts[2] == "say-signed":
            self._say_signed(room=parts[1], did=parts[3], sig=parts[4],
                             nonce_text=parts[5], text="/".join(parts[6:]))
            return

        # /r/<room>
        if len(parts) == 2 and parts[0] == "r":
            room = parts[1]
            messages = list(self.state.rooms.get(room, []))
            since = query.get("since")
            if since:
                messages = [m for m in messages if m["seq"] > int(since[0])]
            limit = query.get("limit")
            if limit:
                messages = messages[-int(limit[0]):]
            self._send(200, {"room": room, "messages": messages,
                             "first_seq": messages[0]["seq"] if messages else None})
            return

        self._send(404, {"error": "not found"})

    def _say_signed(self, room: str, did: str, sig: str, nonce_text: str, text: str) -> None:
        with self.state.lock:
            if self.state.rate_limited():
                self._send(429, {"error": "rate limited", "retry_after": 2})
                return

            if not nonce_text.isdigit() or not 1 <= len(nonce_text) <= 19:
                self._send(400, {"error": "nonce must be 1-19 digits"})
                return
            nonce = int(nonce_text)

            swept = single_line_sweep(text)
            payload = f"{room}|{nonce}|{swept}".encode("utf-8")

            try:
                _pubkey_from_did(did).verify(_b64url_decode(sig), payload)
            except (InvalidSignature, ValueError):
                self._send(403, {"error": "bad signature"})
                return

            key = (did, room)
            last = self.state.nonces.get(key, 0)
            if nonce <= last:
                # v0.10.0 answers 400 here, not 409. Mirroring the real code
                # matters: the double taught us 409 and the test believed it.
                self._send(400, {"error": f"nonce {nonce} is not greater than {last}",
                                 "last_nonce": last})
                return
            self.state.nonces[key] = nonce

            seq = self.state.next_seq
            self.state.next_seq += 1
            # Mirrors v0.10.0's stored record exactly: `from`, and NO signature.
            self.state.rooms.setdefault(room, []).append({
                "seq": seq,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "from": did,
                "nonce": nonce,
                "text": swept,
            })
            self._send(200, {"ok": True, "seq": seq})


class FakeTechnocore:
    """Context manager running the stand-in on an ephemeral localhost port."""

    def __init__(self, **kwargs) -> None:
        self.state = FakeTechnocoreState(**kwargs)
        handler = type("BoundHandler", (_Handler,), {"state": self.state})
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "FakeTechnocore":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
