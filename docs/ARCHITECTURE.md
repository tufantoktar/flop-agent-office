# Architecture — M1

## Layering

```
config/                       public settings; refuses secret-shaped env vars
   │
identity/   ──────────────►   storage/   ──────────────►   proof/
  did, canonical, signer,       sqlite, WAL,                 ledger, hashchain,
  verifier, keystore, nonce     migrations, immediate()      verify
   ▲                                                            ▲
   │  signatures only                                           │ append-only
   │                                                            │
technocore/  ────────────────────────────────────────────────────
  client (reads + guarded write), untrusted types, ratelimit, outbound
```

Dependencies point one way. `technocore/` may use `identity/` and `proof/`;
`identity/`, `proof/` and `storage/` may never import `technocore/` — a static
test in `tests/security` enforces that, so the untrusted types cannot leak
inward as the codebase grows.

## Why the package layout is flat

The brief asked for top-level `identity/`, `technocore/`, `proof/`, `storage/`,
`config/`, plus a `python -m flopoffice` entry point. Those are reconciled by
keeping the domain packages at the root and adding a thin `flopoffice/` package
that holds only the CLI. The cost is six importable top-level names, which is
acceptable for an application (not a library) but would become awkward if this
were ever published to PyPI. The migration, if it is wanted later, is a single
move to `src/flopoffice/<package>/` plus an import rewrite — no design change.

## The three invariants

**1. Key material never crosses an object boundary.**
`PrivateKeyHandle` holds the key on a name-mangled attribute and exposes exactly
one capability: `sign(bytes) -> bytes`. There is no getter. `repr`, `str`,
`format`, pickling and copying are all overridden or refused. The signer layer
above it converts raw signatures to Technocore's 86-char unpadded base64url and
never sees the key at all.

**2. The signed bytes are constructed once, in one place.**
`identity/canonical.py` is the only module that builds a signable payload. The
sweep runs once, before signing, and the *swept* text is what both gets signed
and gets transmitted — signing pre-sweep text and sending post-sweep text is the
canonicalisation bug this ordering exists to prevent.
`build_signed_message()` verifies its own output before returning, so a
disagreement between the canonicaliser and the signer fails locally rather than
producing a signature the server will reject.

**3. Facts are appended, never amended.**
`activities` has `BEFORE UPDATE` and `BEFORE DELETE` triggers that abort. Since
the server-assigned `seq` arrives after the row that records the attempt, a
write is two linked rows: `technocore.write.intent` before the network call,
then `technocore.write.result` (or `.failed`) carrying `ref_activity_id`. A
crash between them leaves a dangling intent, which `ledger-status` reports.
"We signed this and do not know what happened to it" is a true statement; a
missing row would be a lie and a mutated row would break the chain.

## Nonces

Scope is `(did, room)` for messages and `(did, "kv:<ns>")` for notes, matching
Technocore's rule that a nonce must exceed the last one *that key* used *in that
room*. Issuance happens inside `BEGIN IMMEDIATE`, which takes SQLite's write
lock before the read — that is what makes concurrent reservation safe, and it is
verified by a 200-reservation, 8-thread test asserting no duplicates and no gaps.

The `d-` room ownership counter at `/kv/room-nonce/<room>` is shared across
signers, so a local counter alone is insufficient. `observe()` folds a
server-reported value in as a floor and never lowers the stored value;
`reserve(floor=…)` issues above it.

There is no retry anywhere in this path. Retrying a nonce reservation is how a
caller ends up signing two payloads with one nonce.

## The untrusted boundary

`technocore/untrusted.py` is the only module allowed to construct untrusted
values, and `technocore/client.py` the only other one allowed to touch them.
The types are frozen, are deliberately not `str` subclasses, and render as a
digest rather than their content. Getting at the content requires
`reveal(reason=…)` with a written justification — a call site that is greppable,
reviewable, and asserted by test to exist nowhere outside the boundary.

Three static tests back the runtime guards: no sensitive package imports
`technocore`; no function outside the boundary annotates a parameter with an
untrusted type; no `.reveal()` call exists outside the boundary. They check
`agents/`, `policy/` and `inference/` too — packages that do not exist yet — so
the boundary is enforced before the code that would violate it is written.

## What the hash chain does and does not prove

Each row commits to its predecessor via SHA-256 over a fixed field list, so an
edit, a deletion, or a re-hashed row all become detectable and locatable. That
is local, application-level tamper evidence.

It is not a blockchain, not proof of existence, and not external attestation.
An attacker with write access to the file and a copy of this source can rebuild
a consistent chain. Adding external timestamping — publishing a chain head as a
signed Technocore note, for instance — is a later milestone, and the CLI says so
in its own output rather than letting a `VALID` line overstate itself.

## Deliberate absences

No production signer. No real DID generation or rotation. No public Technocore
write. No FLOP adapter, faucet client, wallet, provider router, policy engine or
agent orchestration. Each of those is a separate, explicitly approved step; see
`docs/FLOP_FACTS.md` for which of them depend on documentation Flop Labs has not
published yet.
