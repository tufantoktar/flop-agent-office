# FLOP_FACTS

**Last updated:** 2026-08-28 (M1.1 conformance)

Three categories, kept strictly apart:

| Category | Meaning |
|---|---|
| **OFFICIAL FACT** | Published by Flop Labs, by Arthur Hayes writing as Flop Labs, or by a Flop Labs–operated service. Still provisional where the source says so. |
| **ASSUMPTION** | Our reading where sources are incomplete or disagree. Must be re-checked against a live system before code depends on it. |
| **PLACEHOLDER** | Something we invented to keep building. Not a protocol feature. Must never be described as one. |

Rule for this file: an item never moves up a category without a source. Add the source when you move it. **NOT YET SPECIFIED** is an acceptable answer and is preferable to a guess.

---

## 1. Network and token

| # | Statement | Category | Source |
|---|---|---|---|
| 1.1 | Flop Labs is led by Arthur Hayes; announced 19 Aug 2026 in the Substack essay "The Book of Genesis". | OFFICIAL FACT | cryptohayes.substack.com/p/the-book-of-genesis |
| 1.2 | The essay describes itself as an advertisement, calls the design "unfinished", and invites feedback. **Every figure below is provisional.** | OFFICIAL FACT | same |
| 1.3 | Agents pay native `$FLOP` for inference; miners earn block rewards plus inference fees via **Proof of Useful Inference (PoUI)**. | OFFICIAL FACT | same |
| 1.4 | Pricing is denominated in floating-point operations per unit time, not per-model tokens. | OFFICIAL FACT | same |
| 1.5 | A job request names an amount of FLOPs, a timeframe, and a model. | OFFICIAL FACT | same |
| 1.6 | "Anyone with an internet-connected computer" can mine. No hardware floor, stake or collateral stated. | OFFICIAL FACT | same |
| 1.7 | ~20% of supply to testnet participants, released over ten years. No presale; the team was self-funded. | OFFICIAL FACT | same |
| 1.8 | **Q4 2026 is the stated AIRDROP timing.** It is *not* a testnet launch date. | OFFICIAL FACT | same; crypto.news, blockonomi |
| 1.9 | **Q1 2027 is the stated GENESIS BLOCK timing.** | OFFICIAL FACT | same |
| 1.10 | **The testnet start date is NOT YET SPECIFIED.** No official source gives one. | OFFICIAL FACT (absence) | — |
| 1.11 | Total supply, emission curve and vesting shape are NOT YET SPECIFIED. The 20% figure has no absolute meaning without them. | NOT YET SPECIFIED | — |
| 1.12 | Hayes has said allocation will be determined by testnet activity; that a faucet will run through technocore.chat; and that only agents holding DID keys can access it. This reaches us through press reporting of his statements, not a Flop Labs document — one confidence step below the essay. | OFFICIAL FACT (reported) | bloomingbit.io/feed/news/119078 |
| 1.13 | Faucet endpoint, quota, cadence and the DID proof format are NOT YET SPECIFIED. | NOT YET SPECIFIED | — |
| 1.14 | How PoUI verifies that the requested model ran and the output is valid, given non-determinism, is NOT YET SPECIFIED. | NOT YET SPECIFIED | — |
| 1.15 | Chain / L1, consensus, validator set, RPC endpoints, contract addresses, SDK: all NOT YET SPECIFIED. | NOT YET SPECIFIED | — |
| 1.16 | Agent registration — whether it exists at all — is NOT YET SPECIFIED. | NOT YET SPECIFIED | — |
| 1.17 | Reward formula, snapshot date and sybil rules are NOT YET SPECIFIED. | NOT YET SPECIFIED | — |
| 1.18 | No whitepaper, audit, block explorer or token contract has been published. | OFFICIAL FACT (absence) | crypto.news, blockonomi (as of 2026-08-28) |
| 1.19 | An airdrop is **not guaranteed**. Nothing in this repository may state or imply otherwise. | ASSUMPTION (prudential) | — |

## 2. Technocore

| # | Statement | Category | Source |
|---|---|---|---|
| 2.1 | **Technocore is a satellite service operated by Flop Labs. It is NOT the FLOP protocol.** Its own documentation says so verbatim. | OFFICIAL FACT | technocore.chat/humans |
| 2.2 | Source at `github.com/flop-labs/technocore-chat`, Apache-2.0, Python. Self-hostable via `docker run`. | OFFICIAL FACT | repo README |
| 2.3 | Ephemeral by design; persists no identity, keys, or protocol state. | OFFICIAL FACT | repo README |
| 2.4 | Writes are plain `GET`s. Endpoints: `/r/<room>`, `/r/<room>/say/<nick>/<text>`, `/r/<room>/say-signed/<did>/<sig>/<nonce>/<text>`, JSON `POST` equivalents, `/kv/<ns>/<key>[/set/<value>]` with `?if=` / `?if_absent=1` (409 on loss), `/rooms`, `/r/events`, `/llms.txt`, `/auth.md`, `/openapi.json`, `/config`, `/.well-known/agent.json`, `/healthz`. | OFFICIAL FACT | technocore.chat/llms.txt |
| 2.5 | **Ed25519 only.** `did:key:z6Mk…`, multibase base58btc, multicodec `ed25519-pub` (0xED 0x01). | OFFICIAL FACT | technocore.chat/auth.md |
| 2.6 | Signature is 86 base64url characters, unpadded (64 raw bytes). | OFFICIAL FACT | same |
| 2.7 | A room message signs `<room>\|<nonce>\|<text>` as UTF-8. A kv note signs `<ns>\|<key>\|<nonce>\|<value>`. | OFFICIAL FACT | same |
| 2.8 | The text signed is the value **after the single-line sweep**. `seq` and `ts` are server-assigned and deliberately **not** signed. | OFFICIAL FACT | same |
| 2.9 | Nonce is 1–19 digits and must exceed the last nonce that key used **in that room**. | OFFICIAL FACT | same |
| 2.10 | For ownership notes the counter at `/kv/room-nonce/<room>` is **shared across all signers** of that room. | OFFICIAL FACT | same |
| 2.11 | Replay protection is bounded: a captured signed URL is single-use only while the message stays within the newest ~1 MiB of the room ring. | OFFICIAL FACT | technocore.chat/llms.txt |
| 2.12 | Room classes compose by prefix: `p-` unlisted, `mb-` signed-writes-only (403 otherwise), `d-` ownable by first signer, `e-` ephemeral (15 min). `lobby` is the default rendezvous. | OFFICIAL FACT | same |
| 2.13 | Ring ≈10 MiB; rooms deleted after 7 days of inactivity; message ≤4096 chars; note ≤8 KiB. | OFFICIAL FACT | repo README, technocore.chat/humans |
| 2.14 | Rate limits are per-IP token buckets and vary by deployment (docs cite ~120 reads/min, 30 writes/min). Discoverable via `/.well-known/agent.json`, `/config`, the inline budget line, or the 429 body and `Retry-After`. | OFFICIAL FACT | technocore.chat/llms.txt |
| 2.15 | A signature proves key possession only — not identity, not trustworthiness: *"a key that has written a thousand honest messages can write a malicious one next."* | OFFICIAL FACT | technocore.chat/auth.md |
| 2.16 | Room **topics** are written by whoever created the room. A topic such as "Verified Technocore Hub — Airdrop" is a claim by a stranger, not a Flop Labs statement. | OFFICIAL FACT (by construction) | technocore.chat/rooms |
| 2.17 | Whether Technocore activity counts toward FLOP allocation **at all** is NOT YET SPECIFIED. | NOT YET SPECIFIED | — |

### 2.18 — The single-line sweep: RESOLVED by measurement

M1 recorded this as an open contradiction. M1.1 settled it against the official
implementation running locally (technocore-chat `9c7df0e`, v0.10.0). Full matrix
and reproduction: [`TECHNOCORE_CONFORMANCE.md`](TECHNOCORE_CONFORMANCE.md).

| # | Statement | Category | Source |
|---|---|---|---|
| 2.18.1 | Characters in Unicode categories `Cc`, `Cf`, `Cs`, `Co`, `Zl`, `Zp` are replaced with U+0020. | OFFICIAL OBSERVED BEHAVIOR | measured, v0.10.0; matches `src/store.py` `INVISIBLE_CATEGORIES` |
| 2.18.2 | Category **`Zs` is NOT swept**. U+00A0, U+1680, U+2003, U+2007, U+3000 survive interior positions. | OFFICIAL OBSERVED BEHAVIOR | measured |
| 2.18.3 | The result is then trimmed with `str.strip()`, which **does** remove `Zs` at the ends. | OFFICIAL OBSERVED BEHAVIOR | measured |
| 2.18.4 | Interior runs of spaces are **not** collapsed. | OFFICIAL OBSERVED BEHAVIOR | measured |
| 2.18.5 | Text empty after the sweep is refused with HTTP 400. | OFFICIAL OBSERVED BEHAVIOR | measured |
| 2.18.6 | The README's "converted to spaces" is accurate; `/llms.txt`'s "removed" is **not** an accurate description of the implementation. Neither document mentions the trim or the `Zs` exemption. | OFFICIAL OBSERVED BEHAVIOR vs DOCUMENTED BEHAVIOR | both documents, plus measurement |
| 2.18.7 | `Cs` and `Co` are in the official category tuple but are unreachable over UTF-8, so their handling is read from source, not measured. | UNRESOLVED (minor) | `src/store.py` |
| 2.18.8 | That this behaviour is stable across future Technocore versions. | LOCAL ASSUMPTION | pinned to `9c7df0e` only |

### 2.19 — Further measured behaviour (M1.1)

| # | Statement | Category |
|---|---|---|
| 2.19.1 | A room read returns `seq`, `ts`, `from`, `text`, `nonce` — and **no signature**. A reader therefore cannot re-verify authorship; `from` is the service's claim, not evidence. | OFFICIAL OBSERVED BEHAVIOR |
| 2.19.2 | A percent-encoded LF (`%0A`) in a GET write path answers `404 no route matched`. `%0D`, `%00`, `%09`, `%E2%80%A8` all pass. The same text succeeds over `POST /r/<room>`. | OFFICIAL OBSERVED BEHAVIOR |
| 2.19.3 | A non-increasing nonce answers **HTTP 400**, not 409. | OFFICIAL OBSERVED BEHAVIOR |
| 2.19.4 | v0.10.0 refuses cross-sender duplicate room texts with **422** inside a window (`dupe_filter_seconds`, `dupe_min_length`, `dupe_max_copies`). | OFFICIAL OBSERVED BEHAVIOR |
| 2.19.5 | The signature covers `<room>\|<nonce>\|<swept text>` and excludes `seq`/`ts` — confirmed by two messages differing only in server-assigned fields both verifying. | OFFICIAL OBSERVED BEHAVIOR |

**Scope guard.** Everything in 2.18 and 2.19 is a fact about one HTTP service at
one commit. Technocore is a satellite service, **not the FLOP protocol** (§2.1).
None of it says anything about FLOP consensus, tokenomics, the testnet or the faucet.

## 2.20 — What our ROOT_AGENT_DID does and does not mean

| # | Statement | Category |
|---|---|---|
| 2.20.1 | `did:key:z6MkmjUUh9SLWe66SPFEUgQ4JA2RcbNLgimMzVA8VnvErnCN` is this project's canonical public identity. | LOCAL FACT (our own configuration) |
| 2.20.2 | It is a valid Ed25519 `did:key`, and Technocore accepts Ed25519 `did:key` for signed writes. | OFFICIAL OBSERVED BEHAVIOR (§2.5) |
| 2.20.3 | A signature by this DID demonstrates possession of the matching private key at signing time. Nothing more. | OFFICIAL OBSERVED BEHAVIOR (§2.15) |
| 2.20.4 | Whether holding a DID affects any FLOP incentive allocation. | **NOT YET SPECIFIED** — the faucet gating in §1.12 is reported, not documented, and says nothing about allocation |
| 2.20.5 | Whether `did:key` is the identity method of the FLOP network itself, or only of Technocore. | **NOT YET SPECIFIED** (§1.16) |
| 2.20.6 | Any mapping from `did:key` to a chain account or wallet address. | **NOT YET SPECIFIED** — none published |
| 2.20.7 | That this DID is a wallet, an account, proof of trust, or proof of eligibility. | **FALSE.** It is none of those. |

Configuring this identity earns nothing, claims nothing, and authorises nothing.
It gives the project one name, one place that name is written down, and a
verifiable way to attach future work to it.

## 3. FlopOffice concepts that are NOT FLOP protocol features

Everything in this section is our own design. None of it appears in any Flop Labs material. Describing any of it as a FLOP feature would be wrong.

| # | Concept | Category |
|---|---|---|
| 3.1 | Spend limits (daily, per-task, per-call) | PLACEHOLDER — FlopOffice design |
| 3.2 | Agent budgets and treasury reserve-and-settle | PLACEHOLDER — FlopOffice design |
| 3.3 | Declarative spend conditions / policy engine | PLACEHOLDER — FlopOffice design |
| 3.4 | "Inference session" as a first-class object with an ID | PLACEHOLDER — FlopOffice design. Whether the protocol has any such concept is NOT YET SPECIFIED. |
| 3.5 | `APPROVAL_REQUIRED` and the human approval loop | PLACEHOLDER — FlopOffice design |
| 3.6 | Worker roles (Planner / Researcher / Developer / Reviewer) | PLACEHOLDER — FlopOffice design |
| 3.7 | The proof ledger, its hash chain, and `activity_type` values | PLACEHOLDER — FlopOffice design. **Local, application-level tamper evidence only** — not a blockchain, not external attestation. |
| 3.8 | Example figures "10 / 5 / 20 FLOP" | PLACEHOLDER — illustrative only. Real FLOP denomination is NOT YET SPECIFIED. |
| 3.9 | `cost_unit = FLOP_TEST` | PLACEHOLDER — our label for test-token amounts, so they can never be confused with real value. |

## 4. Things this repository must never assume

* That the airdrop will happen, or that any activity qualifies for it.
* That `did:key` is the network's identity method (it is Technocore's; §1.16 is open).
* That Technocore messages count for anything.
* That any FLOP endpoint, method name, chain, or address exists before it is documented.
* That a signed message is a trustworthy message (§2.15).
