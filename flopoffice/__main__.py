"""``python -m flopoffice`` -- M1 command line.

Commands
--------
verify-ledger   walk the hash chain and report VALID / EMPTY / BROKEN
ledger-status   counts, head hash, and any dangling write intents
scan-secrets    run the repository secret scanner over the working tree
doctor          report configuration and the M1 safety posture

No command performs a network write, touches a wallet, calls a FLOP endpoint, or
loads a private key. `doctor` prints the root agent's PUBLIC DID; there is no
command that can print, derive or imply private key material.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from config.settings import ConfigError, load
from proof.ledger import Ledger
from proof.verify import Status, verify_chain
from storage.db import connect

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
    print(f"  keystore configured: {'yes' if settings.keystore_path else 'no'} (never loaded)")
    print(f"  technocore base url: {settings.technocore_base_url or '<unset>'}")
    print(f"  local writes:        {'enabled' if settings.allow_local_write else 'disabled'}")
    print()
    print("  root agent DID is PUBLIC identity only:")
    print("    not a wallet, not proof of trust, not proof of FLOP eligibility,")
    print("    not an on-chain identity, and not authorisation to sign.")
    print()
    print("  production signer:   NOT WIRED (by design)")
    print("  capability signer:   NOT WIRED (by design)")
    print("  public technocore:   WRITES BLOCKED (host denylist)")
    print("  FLOP / faucet / wallet code: NONE")
    return EXIT_OK


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
