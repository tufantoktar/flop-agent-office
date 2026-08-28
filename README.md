# flop-agent-office

FlopOffice — milestone **M1, "Signed and accounted for"**.

An identity layer, an append-only proof ledger, and a read-only Technocore
client with a hard untrusted-data boundary. Nothing else. There is no wallet
code, no FLOP endpoint, no faucet client, no policy engine and no agent
orchestration in this repository yet. The root signer wiring path exists, but
it is disabled by default and never loads a key unless an explicit caller passes
a runtime passphrase and `enable=True`.

## What M1 contains

| Package | Role |
|---|---|
| `identity/` | `did:key` Ed25519 encode/decode, byte-exact Technocore canonicalisation, signature encoding, verification, durable monotonic nonces, opaque key custody |
| `storage/` | SQLite (WAL) connection management and transactional migrations |
| `proof/` | Append-only activity ledger, hash chaining, chain verification |
| `technocore/` | HTTP client (reads implemented, writes guarded to loopback), frozen untrusted types, client-side rate limiting, local first-message preparation |
| `config/` | Public configuration. Refuses to start if secret-shaped environment variables are present |
| `tools/` | Secret scanner and commit guards |
| `flopoffice/` | Command line |

## Identity

The canonical public identity of this project is:

```
did:key:z6MkmjUUh9SLWe66SPFEUgQ4JA2RcbNLgimMzVA8VnvErnCN
```

It is committed in [`config/public_identity.py`](config/public_identity.py) --
the single place it is written down -- and validated as an Ed25519 `did:key` at
import. `FLOPOFFICE_ROOT_AGENT_DID` overrides it for a fork or a test, through
the same strict validation.

**A `did:key` embeds a *public* key in the identifier itself.** That is why this
value can be committed, printed and published: there is nothing secret in it, and
the private key is not derivable from it.

What this identifier is **not**:

| | |
|---|---|
| not a wallet address | no chain, no balance, no account; nothing here can move value |
| not proof of trust | Technocore's own docs: *"a key that has written a thousand honest messages can write a malicious one next"* |
| not proof of FLOP eligibility | whether a DID matters for any incentive programme is NOT YET SPECIFIED by Flop Labs |
| not an on-chain identity | no published FLOP document maps `did:key` to a chain account |
| not authorisation to sign | configuring it wires nothing |

**The private signer is not connected by default.**
`identity.keystore.production_signer()` still raises by design and never returns
a raw signer. `identity.capability.root_agent_capability_signer(passphrase,
enable=True)` is the single sanctioned M1.4 path, and it returns only a
`CapabilitySigner` after explicit keystore config, runtime passphrase, DID match
and permission checks all pass. Configuring a public DID or keystore path alone
does not enable signing.

### How the signer is wired, when explicitly enabled

One path, in `identity/wiring.py`, and nothing else:

```
ROOT_AGENT_DID (committed, public)
  -> keystore path (local config; never auto-discovered)
  -> load_encrypted_pem(path, passphrase)     encrypted PKCS#8 only, 0600 file, 0700 dir
  -> assert_key_matches_did(handle, expected) fail closed on mismatch
  -> build_capability_signer(..., reviewed=True)
  -> CapabilitySigner(...)                    the only object a caller receives
  -> sign_technocore_message / sign_technocore_note
```

Three properties hold that path shut and keep it narrow:

* **`root_agent_capability_signer(..., enable=True)` is closed by default.** A
  caller must opt in at the call site; no environment variable enables signing
  on its own.
* **`build_capability_signer(..., reviewed=True)` is still accounted for.** The
  keyword exists so low-level wiring is a reviewed code path, not the accidental
  consequence of setting a config value. A test asserts the root capability
  entry point is the only production call site that passes it.
* **The identity is checked before a signer exists.** If the key in the file does
  not derive `ROOT_AGENT_DID`, the call raises `DidMismatchError` and no signing
  object is ever constructed. Fail closed, always -- the fix is to correct the
  path, never to change the configured DID to match whatever key was found.
* **The raw signer never leaves.** `CapabilitySigner` holds it in a closure,
  exposes only the two Technocore verbs, and refuses raw bytes, untrusted
  content, pickling and copying. There is no `sign(arbitrary_bytes)` surface for
  orchestration, agents, policy, a provider router, room content, a shell, or
  plugin code to obtain.

**Keystore policy.** The expected location is `~/.flopoffice/keys/` -- outside
any repository, directory `0700`, file `0600`, encrypted PKCS#8 with a passphrase
of at least 12 characters. There is **no plaintext fallback** and **no
auto-discovery**: nothing searches the repository, the working directory,
`~/Downloads`, `~/.flopoffice` or default filenames. The only runtime path comes
from explicit `FLOPOFFICE_KEYSTORE` configuration, and the path is never printed
by `doctor`.

The whole path is exercised end to end in `tests/security/test_signer_wiring.py`
against **throwaway keys generated inside the test process**, written to
`tmp_path`, and deleted with an assertion that no `.pem` survives.

**The first public Technocore signed message remains blocked.** M1.6 prepares
the exact first message, can sign it locally through `CapabilitySigner`, verifies
that signature locally, and records append-only proof with
`publish_status=NOT_SENT`. That is authorship evidence, not publication.
`technocore.chat` is still on a host denylist that no environment variable
unlocks, and sending the message requires a separate explicit approval step.

## Safety posture

* **No raw production signer.** `identity.keystore.production_signer()` raises
  by design. Root-agent signing, when explicitly enabled, returns only a
  `CapabilitySigner`.
* **No real DID generation or rotation.** Both are human actions taken outside
  this codebase. `generate_ephemeral()` exists for tests and refuses to run when
  `FLOPOFFICE_ENV=prod`.
* **Public Technocore writes are blocked** by a host denylist that no
  environment variable unlocks. Writes work only against a loopback host *and*
  only with `FLOPOFFICE_ALLOW_LOCAL_WRITE=1`.
* **Prepared is not published.** `technocore.announcement` records the first
  announcement as four local ledger rows:
  `technocore_message_prepare_intent`, `technocore_message_signed_local`,
  `technocore_message_verified_local`, and
  `technocore_message_publish_blocked`. No HTTP client send method is called.
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

## First Technocore announcement status

The prepared message is:

> FlopOffice is a DID-authenticated multi-agent workspace for signed coordination, append-only proof logging, and capability-scoped agent actions. Current milestone: Technocore signing conformance is pinned, the root DID is configured, and signer wiring is fail-closed. Public testnet integrations will be added only when official FLOP interfaces are available.

Room preparation uses `lobby`, Technocore's default rendezvous room, and the
nonce is reserved locally with the durable `(did, room)` counter before signing.
The local proof includes the DID, room, nonce, canonical text, Ed25519
signature, canonicalization profile, and `Technocore status = NOT_SENT`.
Technocore room reads do not return signatures, so this retained local proof is
the evidence later needed to verify authorship independently. It does not prove
the message was published.

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

The public DID is a public artefact and is committed (see **Identity** above).
The keystore holding the *private* key is a separate file that lives outside the
repository and is not read by settings or `doctor`. It is loaded only by an
explicit runtime capability call.

## Status of FLOP claims

See [`docs/FLOP_FACTS.md`](docs/FLOP_FACTS.md). Every statement there is tagged
**OFFICIAL FACT**, **ASSUMPTION** or **PLACEHOLDER**, with sources. All FLOP
token allocations, dates and reward mechanics published so far are draft and
provisional. **An airdrop is not guaranteed**, and nothing in this repository
may state or imply otherwise.

## Licence

Apache-2.0.
