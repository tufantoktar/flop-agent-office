# Threat model — M1 scope

Only threats relevant to what M1 actually contains: an identity layer, a local
ledger, and a read-mostly client for a public board. Threats belonging to later
milestones (paid inference, provider selection, wallets) are listed at the end
as *deferred*, so they are not mistaken for covered.

## Assets

| Asset | Why it matters |
|---|---|
| Root agent Ed25519 private key | Compromise means anyone can sign as our identity, permanently. Irrecoverable. |
| The identity's reputation | Signed history is the whole point; one hostile signed message attributed to us is not undoable. |
| Nonce state | Reuse or regression causes rejected writes at best, and two payloads bound to one nonce at worst. |
| The proof ledger | Its value is that it has not been edited after the fact. |

## Trust boundaries

```
  local disk                 process                    network
 ┌──────────┐   unlock    ┌──────────────┐   sig only  ┌───────────────┐
 │ keystore ├────────────►│ PrivateKey   ├────────────►│ Technocore    │
 │ (0600,   │             │ Handle       │             │ (public,      │
 │  outside │             │ (opaque)     │◄────────────┤  zero auth,   │
 │  repo)   │             └──────┬───────┘  UNTRUSTED  │  any writer)  │
 └──────────┘                    │                     └───────────────┘
                                 ▼
                          ┌──────────────┐
                          │ ledger       │  hashes + public artefacts only
                          └──────────────┘
```

Everything crossing right-to-left is untrusted. Nothing crossing left-to-right
carries key material — only signatures.

## Threats and controls

| # | Threat | Control in M1 | Residual risk |
|---|---|---|---|
| T1 | Key committed to git | `.gitignore`, filename guard (`tools/block_key_files.py`), content scanner in pre-commit and CI, `detect-private-key` hook | A developer who bypasses hooks with `--no-verify`. CI still catches it before merge, but the secret is already in reflog. |
| T2 | Key leaked through a log, traceback or screenshot | `PrivateKeyHandle` overrides `repr`/`str`/`format`; no accessor returns key bytes; pickling and copying refused; exceptions carry paths and reasons, never content | A caller who reaches into the mangled attribute deliberately. Not defended against — it is not an accident case. |
| T3 | Key material handed to the process via environment | `config.settings.load()` refuses to start when a `FLOPOFFICE_*` variable name contains `PRIVATE_KEY`/`PASSPHRASE`/`SEED`/`MNEMONIC`/`SECRET` | Differently named variables. The rule is a tripwire, not a sandbox. |
| T4 | Prompt injection from a Technocore room | Frozen `UntrustedText`/`UntrustedMessage`; not a `str`; content withheld from `repr`/`str`; `reveal()` requires a written reason; static test forbids untrusted parameters, `technocore` imports and `reveal()` calls outside the boundary; the read path holds no shell, installer, or file-write sink | A future module that reveals content and then acts on it. The static test is the tripwire; keep it green. |
| T5 | Untrusted content reaching a signer | `_reject_untrusted` in every canonicalisation entry point; `sign()` refuses any type that is not exactly `bytes`, so tainted `bytes` subclasses are refused too | — |
| T6 | Malicious "faucet" or airdrop link posted in a room | No URL in room content is ever fetched. No wallet code exists. Room topics are wrapped exactly like message text | Human follows the link outside the system. Documented in the README and FLOP_FACTS. |
| T7 | Impersonation — a DID posting claims about FLOP rules | Verification is authenticity only. No protocol fact is adopted from a room; `docs/FLOP_FACTS.md` accepts Flop Labs domains only | — |
| T8 | Signature replay of a captured signed GET | Monotonic per-`(did, room)` nonce issued under `BEGIN IMMEDIATE`; local `seen_signatures` table independent of the server's ~1 MiB window | The server's own window is narrower than ours; a replay it accepts is still detectable locally but not preventable remotely. |
| T9 | Nonce reuse under concurrency | `BEGIN IMMEDIATE` takes the write lock before the read; persisted before the caller sees the value; no internal retry | Two *machines* sharing one DID and separate databases. Do not do that. |
| T10 | Nonce regression against a shared counter | `NonceStore.observe()` raises the floor from server-reported values and never lowers it; `reserve(floor=…)` for `d-` room claims | Requires the caller to actually read the server counter first. |
| T11 | Ledger tampering | Append-only triggers; SHA-256 hash chain; `verify-ledger` locates the first break; deletions surface as index gaps; re-hashing one row breaks the next link | An attacker with file access **and** this source can rebuild a consistent chain. External attestation is deliberately out of M1 scope. |
| T12 | Secret written into the ledger | No secret-shaped column exists (asserted by test); every string value is scanned before insertion and the row is refused wholesale; refusal messages never echo the value | A secret that matches no pattern. |
| T13 | Accidental public write | Host denylist for `technocore.chat` that no flag unlocks; loopback-only; plus an explicit `FLOPOFFICE_ALLOW_LOCAL_WRITE=1`; tests assert no request reaches the network for public hosts | Someone editing the denylist. That is a reviewable diff, which is the point. |
| T14 | Rate-limit ban on a shared public service | Local token buckets sized at 50% of advertised limits, discovered from `/.well-known/agent.json`; refusals surface rather than retry | — |
| T15 | Crash between signing and delivery | Intent row written before the request; linked result/failure row after; `dangling_intents()` reports unresolved pairs; the ledger is never back-filled | Requires an operator to look. `ledger-status` surfaces it. |
| T16 | Canonicalisation mismatch producing invalid signatures | Pinned against the official implementation in M1.1 (technocore-chat `9c7df0e`, v0.10.0): 15 of 15 discriminating cases confirm the behaviour, and the two rejected variants are regression-tested as *rejected*. `build_signed_message` still verifies its own signature before returning. | Pinned to one commit. A Technocore change to `store.clean_text` silently breaks us; re-run `pytest -m conformance` against any new version before trusting it. |
| T17 | Trusting an unverified author from a room read | A room read returns no signature, so `verified` fails closed to False and the DID is labelled `server-asserted, unverified`. Nothing consumes `did` as an authorisation input. | A caller that reads `did` and treats it as identity anyway. The label and `signature_returned` exist to make that hard to do accidentally. |
| T18 | A general `sign(bytes)` oracle reaching orchestration code | `identity/capability.py` exposes only `sign_technocore_message` / `sign_technocore_note`, builds the bytes internally from validated parts, refuses raw bytes and untrusted wrappers, and gates note signing behind an explicit grant. | Not yet the only path: `Signer.sign` still exists for the client and tests. Wiring the real key must go through the capability wrapper, not around it. |
| T19 | Hygiene tooling silently excluding source from the repository | M1's `.gitignore` line `keystore*` excluded `identity/keystore.py` from the initial commit; local tests passed because the file was on disk. Fixed, and `tests/security` now fails if **any** source or doc file is gitignored, or if a package module cannot be tracked. | The class of bug -- a guard that over-matches -- is only covered for the file types the test globs. |

| T20 | The public identity being mistaken for a credential | The DID is public by construction (it embeds a public key). It is committed, printed abbreviated by default, and documented in three places as not a wallet, not trust, not eligibility, not authorisation to sign. `config/settings.py` imports no key machinery, and a test asserts it. | Someone reading `ROOT_AGENT_DID` in config and assuming a signer exists. The doctor output says `NOT WIRED` twice for this reason. |
| T21 | An environment override smuggling in an identity the code would refuse | The override goes through the same `DidKey` validator as the committed value; blank falls back rather than disabling identity; malformed fails closed with a message naming the variable. | An operator setting a *valid* DID they do not control. That is a deployment decision, not something config can detect. |

| T22 | The wrong key signing as the project | `assert_key_matches_did` compares raw public-key bytes before any signer is constructed; mismatch raises `DidMismatchError` and fails closed. The message names both public DIDs and warns against the tempting fix (editing the configured DID). | Only runs on the wiring path. A caller who builds an `EphemeralSigner` directly bypasses it — which is why wiring is the single sanctioned route. |
| T23 | A keystore replaced or tampered with under a correct-looking path | File mode `0600` **and** directory mode `0700` are both enforced; a non-regular file is refused; an unencrypted PEM is refused outright with no plaintext fallback. | TOCTOU between the stat and the read. Not closed; the DID check downstream is what catches a swapped key. |
| T24 | Key material reached by auto-discovery | No module builds a keystore path: every input is an argument, and a test greps for `Path.home()` / `expanduser` joined to key-shaped names across all production packages. `doctor` never prints the path or filename. | An operator pointing config at the wrong file. The DID check catches it. |
| T25 | A generic `sign(bytes)` oracle escaping into orchestration | The wrapped signer lives in a closure; only two Technocore verbs are exposed; raw bytes, `bytearray`, `memoryview`, untrusted wrappers, pickling and copying are all refused; no public attribute returns anything with a `sign` method. | In-process code can walk `__closure__`. Python cannot prevent that, and this control is aimed at accident, not at an attacker who already runs code in the process. |

## Deferred — not covered by M1

These belong to later milestones and are listed so nobody assumes coverage:
budget exhaustion and runaway spend loops, provider dishonesty (a cheaper model
served than billed), fabricated inference receipts, wallet and key use for
on-chain value, faucet interaction, dashboard data leakage, and sybil-resistance
posture for multiple worker DIDs.
