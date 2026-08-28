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

Since M1.1 the sweep is **pinned to measured official behaviour**, not to a
reading of the documentation: replace `Cc`/`Cf`/`Cs`/`Co`/`Zl`/`Zp` with U+0020,
then `str.strip()`; leave `Zs` alone inside; never collapse runs; refuse text that
sweeps to empty. `SweepPolicy` still exists, but it is **not a runtime switch** --
production signing always uses `DEFAULT_SWEEP`, and the disproven combination is
reachable only from the conformance suite, where its job is to demonstrate that
the official server rejects it. See `docs/TECHNOCORE_CONFORMANCE.md`.

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

## The public identity

`config/public_identity.py` holds `ROOT_AGENT_DID` and nothing else. It imports
only `identity.did`, reads no files, and constructs the `DidKey` at import so a
malformed edit fails immediately rather than at the first `load()`.

`config/settings.py` resolves the identity as: environment override if set and
non-blank, otherwise the committed value -- both through the same strict Ed25519
validator, so an environment variable can change *which* identity but never
*whether* it is checked. `Settings.root_agent_did` is therefore always present,
and `root_agent_did_source` records which of the two it came from.

Deliberately absent: any function that generates, derives or rotates a DID.
Changing the project's identity is a reviewed commit to one line, not a runtime
capability. A test asserts the canonical value appears in exactly one production
module, and that no second identity appears in production source at all.

Nothing on this path touches key material. `config/settings.py` does not import
`identity.keystore`, `identity.signer` or `identity.capability`, and a test
asserts that it never will.

## Capability-scoped signing

`identity/capability.py` narrows a `Signer` to exactly two verbs --
`sign_technocore_message` and `sign_technocore_note` -- and builds the signed
bytes internally from validated components. There is no parameter through which
arbitrary bytes reach the key, so orchestration code cannot be talked into
signing an attestation, a transaction, or a challenge for some other Ed25519
protocol. Note signing is off unless explicitly granted, because notes are what
claim and hold `d-` rooms.

The wrapped signer is held in a **closure**, not an attribute: a mangled
attribute is reachable by anyone who knows the mangling, and the threat here is
accidental escape rather than a determined attacker with in-process execution --
against whom Python offers no defence at all, and we do not pretend otherwise.
The wrapper refuses pickling, copying, raw bytes and untrusted content, and note
signing stays behind an explicit grant.

Note segments are validated against Technocore's own charset
(`^[a-z0-9][a-z0-9_-]{0,47}$`, measured in M1.1), so a note the server would
reject with 400 is refused here instead -- a wasted nonce is the cheapest thing
this check saves.

`root_agent_capability_signer()` still raises: the interface and its tests ship,
the key does not.

## The root signer path (designed, not wired)

`identity/wiring.py` is the single route from a keystore file to something that
can sign, and it is deliberately short:

```
load_encrypted_pem  ->  assert_key_matches_did  ->  CapabilitySigner
```

The ordering is the design. Identity is verified *before* any signing object is
constructed, so there is no window in which the wrong key is holdable. A
mismatch raises `DidMismatchError`, names both public DIDs, and says explicitly
not to change the configured DID to match the key -- because the tempting fix is
the wrong one.

`build_capability_signer` refuses unless called with `reviewed=True`. That gate
is not a config value on purpose: opening it is a diff someone signs off on, and
an AST-based test asserts no production module passes it today.

Loading enforces the keystore policy: encrypted PKCS#8 only (no plaintext
fallback), regular file, `0600` on the file **and** `0700` on its directory --
because `0600` protects nothing if a third party can replace the file. The
default location, `~/.flopoffice/keys/`, is a documented constant, never a search
path; a test asserts no module builds a keystore path for itself.

## What a read from Technocore can and cannot prove

A room read returns no signature (measured, v0.10.0), so `verified` on an
inbound message is **always False** and the DID is the service's claim about
authorship rather than something we checked. `signature_returned` records which
case applies and the author label says `server-asserted, unverified`. Only our
own outbound writes -- where we hold the signature -- can be verified. Failing
closed here is deliberate: a field called `verified` must never be set by
somebody else's say-so.

## Deliberate absences

No production signer. No real DID generation or rotation. No public Technocore
write. No FLOP adapter, faucet client, wallet, provider router, policy engine or
agent orchestration. Each of those is a separate, explicitly approved step; see
`docs/FLOP_FACTS.md` for which of them depend on documentation Flop Labs has not
published yet.
