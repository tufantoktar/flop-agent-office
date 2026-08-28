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
| T16 | Canonicalisation mismatch producing invalid signatures | Sweep, room, nonce and payload construction are pure and directly tested; `build_signed_message` verifies its own signature before returning; the same swept text is signed and transmitted | **The known contradiction in FLOP_FACTS §2.18.** Unresolved until tested against a real instance. Treat any rejection as this first. |

## Deferred — not covered by M1

These belong to later milestones and are listed so nobody assumes coverage:
budget exhaustion and runaway spend loops, provider dishonesty (a cheaper model
served than billed), fabricated inference receipts, wallet and key use for
on-chain value, faucet interaction, dashboard data leakage, and sybil-resistance
posture for multiple worker DIDs.
