"""``python -m flopoffice`` -- M1 command line.

Commands
--------
verify-ledger   walk the hash chain and report VALID / EMPTY / BROKEN
ledger-status   counts, head hash, and any dangling write intents
scan-secrets    run the repository secret scanner over the working tree
doctor          report configuration and the M1 safety posture
publish-technocore-announcement
                one-time public publish of the reviewed announcement

No command performs a network write, touches a wallet, calls a FLOP endpoint, or
loads a private key except the explicitly confirmed public announcement publish
command. `doctor` prints the root agent's PUBLIC DID; no command may print,
derive or imply private key material.
"""

from __future__ import annotations

import argparse
import getpass
import subprocess
import sys
from pathlib import Path

from config.settings import ConfigError, load
from identity.keystore import KeystoreError
from identity.nonce import NonceStore
from identity.wiring import DidMismatchError
from proof.ledger import Ledger
from proof.verify import Status, verify_chain
from storage.db import connect
from technocore.announcement import (
    FIRST_ANNOUNCEMENT_ROOM,
    FIRST_ANNOUNCEMENT_SHA256,
    AnnouncementPreparationError,
    publish_first_announcement_once,
)
from technocore.client import TechnocoreClient

EXIT_OK = 0
EXIT_BROKEN = 2
EXIT_ERROR = 3


def _cmd_verify_ledger(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    if not path.exists():
        print(f"ledger not found: {path}", file=sys.stderr)
        return EXIT_ERROR
    conn = connect(path, read_only=True)
    try:
        result = verify_chain(conn)
    finally:
        conn.close()

    if result.status is Status.EMPTY:
        print("LEDGER: EMPTY - no activities recorded yet")
        return EXIT_OK
    if result.status is Status.VALID:
        print(f"LEDGER: VALID - {result.records_checked} record(s) verified")
        print(f"  head entry_hash: {result.head_hash}")
        print(
            "  note: local, application-level tamper evidence only. "
            "Not a blockchain and not external attestation."
        )
        return EXIT_OK

    print(f"LEDGER: BROKEN - {result.records_checked} record(s) verified before the break")
    if result.first_break:
        print(result.first_break.render())
    return EXIT_BROKEN


def _cmd_ledger_status(args: argparse.Namespace) -> int:
    from technocore.outbound import dangling_intents

    path = Path(args.ledger)
    if not path.exists():
        print(f"ledger not found: {path}", file=sys.stderr)
        return EXIT_ERROR
    conn = connect(path, read_only=True)
    try:
        ledger = Ledger(conn)
        head = ledger.head()
        print(f"records:   {ledger.count()}")
        print(f"head hash: {head['entry_hash'] if head else '-'}")
        rows = conn.execute(
            "SELECT activity_type, COUNT(*) AS n FROM activities "
            "GROUP BY activity_type ORDER BY n DESC"
        ).fetchall()
        for row in rows:
            print(f"  {row['activity_type']:<28} {row['n']}")
        pending = dangling_intents(ledger)
        if pending:
            print(f"\nWARNING: {len(pending)} write intent(s) with no recorded outcome:")
            for activity_id in pending:
                print(f"  {activity_id}")
    finally:
        conn.close()
    return EXIT_OK


def _cmd_scan_secrets(args: argparse.Namespace) -> int:
    from tools.secret_scan import main as scan_main

    return scan_main(["--root", args.root, "--all"])


def _cmd_doctor(args: argparse.Namespace) -> int:
    try:
        settings = load()
    except ConfigError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    did = settings.root_agent_did
    # Abbreviated by default. The full DID is public data -- it embeds a public
    # key, not a secret -- but an abbreviation is what a status line wants, and
    # `--full-did` is there for when the whole value is the thing you need.
    shown = did.did if getattr(args, "full_did", False) else did.short

    print("flop-agent-office - posture")
    print(f"  env:                 {settings.env}")
    print(f"  ledger:              {settings.ledger_path}")
    print(f"  root agent DID:      {shown}  ({settings.root_agent_did_source})")
    capability_state = (
        "READY-BY-CONFIG" if settings.root_signer_configured else "NOT LOADED"
    )
    print(f"  root signer configured: {'yes' if settings.root_signer_configured else 'no'}")
    print(f"  root signer enabled:    {'yes' if settings.root_signer_enabled else 'no'}")
    print(f"  capability signer:      {capability_state} (key never loaded by doctor)")
    print(f"  technocore base url: {settings.technocore_base_url or '<unset>'}")
    print(f"  local writes:        {'enabled' if settings.allow_local_write else 'disabled'}")
    print()
    print("  root agent DID is PUBLIC identity only:")
    print("    not a wallet, not proof of trust, not proof of FLOP eligibility,")
    print("    not an on-chain identity, and not authorisation to sign.")
    print()
    print("  production signer:   RAW SIGNER UNAVAILABLE")
    print("  public technocore:   WRITES BLOCKED (host denylist)")
    print("  FLOP / faucet / wallet code: NONE")
    return EXIT_OK


def _cmd_publish_technocore_announcement(args: argparse.Namespace) -> int:
    if not args.confirm_public_technocore_publish:
        print("ERROR: exact public publish confirmation flag is required", file=sys.stderr)
        return EXIT_ERROR
    if args.room != FIRST_ANNOUNCEMENT_ROOM:
        print("ERROR: room does not match the reviewed announcement", file=sys.stderr)
        return EXIT_ERROR
    if args.message_sha256 != FIRST_ANNOUNCEMENT_SHA256:
        print("ERROR: message SHA-256 does not match the reviewed announcement",
              file=sys.stderr)
        return EXIT_ERROR
    if args.base_url.rstrip("/") != "https://technocore.chat":
        print("ERROR: base URL must be exactly https://technocore.chat", file=sys.stderr)
        return EXIT_ERROR
    if not _repo_is_clean():
        print("ERROR: repository has uncommitted changes; refusing to publish",
              file=sys.stderr)
        return EXIT_ERROR

    try:
        settings = load()
    except ConfigError:
        print("ERROR: public/path configuration is invalid", file=sys.stderr)
        return EXIT_ERROR
    if settings.keystore_path is None:
        print("ERROR: explicit FLOPOFFICE_KEYSTORE configuration is required",
              file=sys.stderr)
        return EXIT_ERROR

    passphrase = None
    conn = None
    try:
        from identity.capability import root_agent_capability_signer  # noqa: PLC0415

        passphrase = getpass.getpass("Root key passphrase: ")
        capability = root_agent_capability_signer(passphrase, enable=True)
        ledger_path = Path(args.ledger) if args.ledger else settings.ledger_path
        conn = connect(ledger_path)
        with TechnocoreClient(args.base_url) as client:
            result = publish_first_announcement_once(
                capability,
                Ledger(conn),
                NonceStore(conn),
                client,
                room=args.room,
                message_sha256=args.message_sha256,
                confirm_public_technocore_publish=True,
            )
    except (AnnouncementPreparationError, ConfigError, DidMismatchError, KeystoreError):
        print("ERROR: publish flow stopped fail-closed", file=sys.stderr)
        return EXIT_ERROR
    finally:
        passphrase = None
        if conn is not None:
            conn.close()

    print(f"root DID: {result.preparation.proof.did.removeprefix('did:key:')[:4]}..."
          f"{result.preparation.proof.did[-4:]}")
    print("message prepared: yes")
    print("canonicalization: PASS")
    print("signature verification: PASS")
    print("ledger proof: recorded")
    print("Technocore publish: SENT")
    print(f"server seq: {result.server_seq}")
    print("status: PUBLISHED")
    return EXIT_OK


def _repo_is_clean() -> bool:
    root = Path(__file__).resolve().parents[1]
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0 and result.stdout.strip() == ""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="flopoffice", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify-ledger", help="verify the ledger hash chain")
    verify.add_argument("--ledger", default="flopoffice.sqlite")
    verify.set_defaults(func=_cmd_verify_ledger)

    status = sub.add_parser("ledger-status", help="summarise ledger contents")
    status.add_argument("--ledger", default="flopoffice.sqlite")
    status.set_defaults(func=_cmd_ledger_status)

    scan = sub.add_parser("scan-secrets", help="scan the working tree for secrets")
    scan.add_argument("--root", default=".")
    scan.set_defaults(func=_cmd_scan_secrets)

    doctor = sub.add_parser("doctor", help="report configuration and safety posture")
    doctor.add_argument(
        "--full-did", action="store_true",
        help="print the complete public root agent DID instead of an abbreviation",
    )
    doctor.set_defaults(func=_cmd_doctor)

    publish = sub.add_parser(
        "publish-technocore-announcement",
        help="publish the reviewed first Technocore announcement exactly once",
    )
    publish.add_argument("--base-url", required=True)
    publish.add_argument("--room", required=True)
    publish.add_argument("--message-sha256", required=True)
    publish.add_argument("--ledger")
    publish.add_argument("--confirm-public-technocore-publish", action="store_true")
    publish.set_defaults(func=_cmd_publish_technocore_announcement)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
