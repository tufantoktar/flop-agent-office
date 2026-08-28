# flop-agent-office

FlopOffice — milestone **M1, "Signed and accounted for"**.

An identity layer, an append-only proof ledger, and a read-only Technocore
client with a hard untrusted-data boundary. Nothing else. There is no wallet
code, no FLOP endpoint, no faucet client, no policy engine and no agent
orchestration in this repository yet, and no code path loads a real private key.

## What M1 contains

| Package | Role |
|---|---|
| `identity/` | `did:key` Ed25519 encode/decode, byte-exact Technocore canonicalisation, signature encoding, verification, durable monotonic nonces, opaque key custody |
| `storage/` | SQLite (WAL) connection management and transactional migrations |
| `proof/` | Append-only activity ledger, hash chaining, chain verification |
| `technocore/` | HTTP client (reads implemented, writes guarded to loopback), frozen untrusted types, client-side rate limiting |
| `config/` | Public configuration. Refuses to start if secret-shaped environment variables are present |
| `tools/` | Secret scanner and commit guards |
| `flopoffice/` | Command line |

## Safety posture

* **No production signer.** `identity.keystore.production_signer()` raises by
  design. The root agent's private key is not loaded, imported, or referenced.
* **No real DID generation or rotation.** Both are human actions taken outside
  this codebase. `generate_ephemeral()` exists for tests and refuses to run when
  `FLOPOFFICE_ENV=prod`.
* **Public Technocore writes are blocked** by a host denylist that no
  environment variable unlocks. Writes work only against a loopback host *and*
  only with `FLOPOFFICE_ALLOW_LOCAL_WRITE=1`.
* **Room content is data, never instructions.** Everything read from Technocore
  is wrapped in a frozen type that is not a `str`, never renders its content in
  `repr`/`str`/logs, and is refused by every signing and canonicalisation path.
  A boundary test enforces this statically as well as at runtime.
* **The ledger stores hashes and public artefacts only.** There is no column for
  a secret, and every string value is run past the repository secret scanner
  before insertion.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pre-commit install

cp .env.example .env          # paths and flags only -- never secrets

python -m pytest              # full suite
python -m flopoffice doctor   # report the safety posture
python tools/secret_scan.py --all
```

## The ledger CLI

```bash
python -m flopoffice verify-ledger --ledger flopoffice.sqlite
python -m flopoffice ledger-status --ledger flopoffice.sqlite
```

`verify-ledger` walks the hash chain from genesis and exits `0` for
`VALID`/`EMPTY`, `2` for `BROKEN` (printing the first broken record), and `3` on
error.

> **What the chain proves.** Local, application-level tamper evidence. It makes
> editing or deleting a record detectable and locatable. It is **not** a
> blockchain, not proof of existence, and not external attestation — anyone with
> write access to the file and this source can recompute a consistent chain.

## Integration tests

Technocore integration runs against **loopback only**. By default the suite
starts a stand-in server (`tests/integration/fake_technocore.py`) that
implements the documented endpoints and re-derives signature verification
independently of `identity/`, so a bug in our decoder cannot make the test pass
falsely.

To run the same assertions against the real implementation:

```bash
docker run -p 8080:8080 ghcr.io/flop-labs/technocore-chat   # see that repo for the current image
TECHNOCORE_BASE_URL=http://127.0.0.1:8080 python -m pytest tests/integration
```

That run is what actually pins the single-line sweep behaviour — see
`docs/FLOP_FACTS.md` §2.18 for the contradiction between the two Flop Labs
documents, and why we treat our reading as an assumption rather than a fact.

## Keys

Never commit key material. The keystore lives outside the repository
(`~/.flopoffice/keys/` by default) and is referenced by path through
`FLOPOFFICE_KEYSTORE`. `.gitignore`, a filename guard and a content scanner all
run before a commit; the scanner reports rule ids and line numbers and never
prints the matched text.

The public DID is a public artefact and is safe to commit. It is left unset in
this template so nobody's identity is baked into it.

## Status of FLOP claims

See [`docs/FLOP_FACTS.md`](docs/FLOP_FACTS.md). Every statement there is tagged
**OFFICIAL FACT**, **ASSUMPTION** or **PLACEHOLDER**, with sources. All FLOP
token allocations, dates and reward mechanics published so far are draft and
provisional. **An airdrop is not guaranteed**, and nothing in this repository
may state or imply otherwise.

## Licence

Apache-2.0.
