"""Shared fixtures.

Every key used anywhere in this suite is generated inside the test process and
discarded when it ends. No test reads, imports or references the real root-agent
key or DID, and no test contacts the public Technocore instance.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from identity.keystore import generate_ephemeral
from identity.nonce import NonceStore
from identity.signer import EphemeralSigner
from proof.ledger import Ledger
from storage.db import connect

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def ephemeral_key():
    return generate_ephemeral(label="pytest-ephemeral")


@pytest.fixture
def signer(ephemeral_key) -> EphemeralSigner:
    return EphemeralSigner(ephemeral_key)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "ledger.sqlite"


@pytest.fixture
def conn(db_path: Path):
    connection = connect(db_path)
    yield connection
    connection.close()


@pytest.fixture
def ledger(conn: sqlite3.Connection) -> Ledger:
    return Ledger(conn)


@pytest.fixture
def nonces(conn: sqlite3.Connection) -> NonceStore:
    return NonceStore(conn)


@pytest.fixture(autouse=True)
def block_non_loopback_network(monkeypatch: pytest.MonkeyPatch):
    """Fail any test that opens a socket to something other than loopback.

    This is belt-and-braces on top of the client's own host denylist: it makes
    "no test contacted technocore.chat" a property the suite enforces, not a
    claim in a comment.
    """
    import socket

    real_connect = socket.socket.connect
    allowed = {"127.0.0.1", "::1", "localhost"}

    def guarded(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) else address
        if isinstance(host, str) and host not in allowed:
            raise AssertionError(
                f"test attempted a non-loopback connection to {host!r}; "
                "the suite must never contact a public service"
            )
        return real_connect(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded)
    yield
