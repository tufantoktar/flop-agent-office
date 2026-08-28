"""The verify-ledger CLI and the M1 posture report."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import httpx
import pytest

from identity.capability import CapabilitySigner
from identity.signer import EphemeralSigner
from identity.wiring import DidMismatchError
from flopoffice.__main__ import main
from proof.ledger import Activity, Ledger
from storage.db import connect
from technocore.announcement import FIRST_ANNOUNCEMENT_SHA256
from technocore.client import TechnocoreClient

DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


def _seed(db_path: Path, n: int = 3) -> list[str]:
    conn = connect(db_path)
    ledger = Ledger(conn)
    ids = [
        ledger.append(Activity(agent_did=DID, activity_type="note", meta={"i": i})).activity_id
        for i in range(n)
    ]
    conn.close()
    return ids


def test_verify_ledger_reports_valid(db_path: Path, capsys) -> None:
    _seed(db_path)
    assert main(["verify-ledger", "--ledger", str(db_path)]) == 0
    out = capsys.readouterr().out
    assert "LEDGER: VALID" in out
    assert "3 record(s)" in out
    assert "Not a blockchain" in out, "the CLI must not overstate what it proves"


def test_verify_ledger_reports_empty(db_path: Path, capsys) -> None:
    connect(db_path).close()
    assert main(["verify-ledger", "--ledger", str(db_path)]) == 0
    assert "LEDGER: EMPTY" in capsys.readouterr().out


def test_verify_ledger_reports_broken_and_locates_it(db_path: Path, capsys) -> None:
    ids = _seed(db_path, 4)

    raw = sqlite3.connect(db_path)
    raw.execute("DROP TRIGGER IF EXISTS activities_no_update")
    raw.execute("UPDATE activities SET agent_did = 'did:key:zEvil' WHERE activity_id = ?",
                (ids[1],))
    raw.commit()
    raw.close()

    assert main(["verify-ledger", "--ledger", str(db_path)]) == 2
    out = capsys.readouterr().out
    assert "LEDGER: BROKEN" in out
    assert "first break at chain_index 1" in out
    assert ids[1] in out


def test_verify_ledger_missing_file(tmp_path: Path) -> None:
    assert main(["verify-ledger", "--ledger", str(tmp_path / "nope.sqlite")]) == 3


def test_ledger_status_flags_dangling_intents(db_path: Path, capsys) -> None:
    conn = connect(db_path)
    Ledger(conn).append(
        Activity(agent_did=DID, activity_type="technocore.write.intent",
                 tc_room="lobby", tc_nonce=1)
    )
    conn.close()
    assert main(["ledger-status", "--ledger", str(db_path)]) == 0
    out = capsys.readouterr().out
    assert "technocore.write.intent" in out
    assert "no recorded outcome" in out


def test_doctor_states_the_safety_posture(capsys, monkeypatch) -> None:
    monkeypatch.delenv("FLOPOFFICE_ROOT_AGENT_DID", raising=False)
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "root signer configured: no" in out
    assert "root signer enabled:    no" in out
    assert "capability signer:      NOT LOADED" in out
    assert "RAW SIGNER UNAVAILABLE" in out
    assert "WRITES BLOCKED" in out
    assert "FLOP / faucet / wallet code: NONE" in out


def test_doctor_refuses_secret_shaped_environment(monkeypatch, capsys) -> None:
    monkeypatch.setenv("FLOPOFFICE_PRIVATE_KEY", "anything")
    assert main(["doctor"]) == 3
    assert "refusing to start" in capsys.readouterr().err


def test_config_rejects_a_keystore_inside_the_repo(monkeypatch, repo_root: Path) -> None:
    from config.settings import ConfigError, load  # noqa: PLC0415

    import pytest  # noqa: PLC0415

    with pytest.raises(ConfigError, match="inside the repository"):
        load({"FLOPOFFICE_KEYSTORE": str(repo_root / "keys" / "root.pem")})


def test_config_rejects_repo_keystore_independent_of_cwd(
    monkeypatch, repo_root: Path, tmp_path: Path
) -> None:
    from config.settings import ConfigError, load  # noqa: PLC0415

    import pytest  # noqa: PLC0415

    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError, match="inside the repository"):
        load({"FLOPOFFICE_KEYSTORE": str(repo_root / "keys" / "root.pem")})


def test_config_rejects_an_invalid_did() -> None:
    from config.settings import ConfigError, load  # noqa: PLC0415

    with pytest.raises(ConfigError, match="did:key"):
        load({"FLOPOFFICE_ROOT_AGENT_DID": "did:key:zNotReal"})


def test_publish_announcement_requires_confirmation(capsys) -> None:
    assert main([
        "publish-technocore-announcement",
        "--base-url", "https://technocore.chat",
        "--room", "lobby",
        "--message-sha256", FIRST_ANNOUNCEMENT_SHA256,
    ]) == 3
    assert "confirmation" in capsys.readouterr().err


def test_publish_announcement_blocks_wrong_hash(capsys) -> None:
    assert main([
        "publish-technocore-announcement",
        "--base-url", "https://technocore.chat",
        "--room", "lobby",
        "--message-sha256", "0" * 64,
        "--confirm-public-technocore-publish",
    ]) == 3
    assert "SHA-256" in capsys.readouterr().err


def test_publish_announcement_blocks_wrong_room(capsys) -> None:
    assert main([
        "publish-technocore-announcement",
        "--base-url", "https://technocore.chat",
        "--room", "e-p-flopoffice-test",
        "--message-sha256", FIRST_ANNOUNCEMENT_SHA256,
        "--confirm-public-technocore-publish",
    ]) == 3
    assert "room" in capsys.readouterr().err


def test_publish_announcement_requires_configured_keystore(
    monkeypatch, capsys
) -> None:
    import flopoffice.__main__ as cli  # noqa: PLC0415

    monkeypatch.setattr(cli, "_repo_is_clean", lambda: True)
    monkeypatch.delenv("FLOPOFFICE_KEYSTORE", raising=False)
    assert main([
        "publish-technocore-announcement",
        "--base-url", "https://technocore.chat",
        "--room", "lobby",
        "--message-sha256", FIRST_ANNOUNCEMENT_SHA256,
        "--confirm-public-technocore-publish",
    ]) == 3
    captured = capsys.readouterr()
    assert "FLOPOFFICE_KEYSTORE" in captured.err
    assert ".pem" not in captured.out + captured.err


def test_publish_announcement_prompts_safely_and_prints_no_secrets(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    import flopoffice.__main__ as cli  # noqa: PLC0415
    import identity.capability as capability_module  # noqa: PLC0415

    hidden = "runtime input stays hidden"
    monkeypatch.setattr(cli, "_repo_is_clean", lambda: True)
    monkeypatch.setenv("FLOPOFFICE_KEYSTORE", str(tmp_path / "configured.pem"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: hidden)
    monkeypatch.setattr(
        capability_module,
        "root_agent_capability_signer",
        lambda passphrase, *, enable: CapabilitySigner(EphemeralSigner()),
    )

    class ClientFactory:
        def __init__(self, base_url: str) -> None:
            self._client = TechnocoreClient(
                base_url,
                client=httpx.Client(
                    transport=httpx.MockTransport(
                        lambda request: httpx.Response(200, json={"ok": True, "seq": 1})
                    )
                ),
            )

        def __enter__(self):
            return self._client

        def __exit__(self, *exc: object) -> None:
            self._client.close()

    monkeypatch.setattr(cli, "TechnocoreClient", ClientFactory)

    assert main([
        "publish-technocore-announcement",
        "--base-url", "https://technocore.chat",
        "--room", "lobby",
        "--message-sha256", FIRST_ANNOUNCEMENT_SHA256,
        "--ledger", str(tmp_path / "ledger.sqlite"),
        "--confirm-public-technocore-publish",
    ]) == 0
    combined = capsys.readouterr().out
    assert "Technocore publish: SENT" in combined
    assert hidden not in combined
    assert str(tmp_path) not in combined
    assert ".pem" not in combined


def test_publish_announcement_stops_on_did_mismatch(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    import flopoffice.__main__ as cli  # noqa: PLC0415
    import identity.capability as capability_module  # noqa: PLC0415

    hidden = "runtime input stays hidden"
    monkeypatch.setattr(cli, "_repo_is_clean", lambda: True)
    monkeypatch.setenv("FLOPOFFICE_KEYSTORE", str(tmp_path / "configured.pem"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: hidden)

    def mismatch(passphrase, *, enable):  # noqa: ANN001, ARG001
        raise DidMismatchError("public DIDs only, no private data")

    monkeypatch.setattr(capability_module, "root_agent_capability_signer", mismatch)

    assert main([
        "publish-technocore-announcement",
        "--base-url", "https://technocore.chat",
        "--room", "lobby",
        "--message-sha256", FIRST_ANNOUNCEMENT_SHA256,
        "--ledger", str(tmp_path / "ledger.sqlite"),
        "--confirm-public-technocore-publish",
    ]) == 3
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert hidden not in combined
    assert str(tmp_path) not in combined
    assert ".pem" not in combined
