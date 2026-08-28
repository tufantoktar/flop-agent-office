# Technocore signing conformance

**Result: PINNED — the sweep replaces invisibles with U+0020 and then trims.**

M1 recorded the single-line sweep as an ASSUMPTION because two Flop Labs documents
describe it differently. M1.1 settled it empirically against the official
implementation. Three divergences were found in our M1 code; all three would have
produced signatures the real server rejects.

---

## 1. What was tested

| | |
|---|---|
| Official repository | https://github.com/flop-labs/technocore-chat |
| Commit tested | `9c7df0e3616cf28d17e7c8ebeb0c05de6adf117c` |
| Version | `0.10.0` ("feat(limit): refuse cross-sender duplicate room writes") |
| Startup | local process, `python3.12 -m uvicorn --app-dir src app:app --host 127.0.0.1 --port 8099` |
| Server runtime | CPython 3.12.3 · starlette 1.6.0 · uvicorn 0.52.2 · pynacl 1.6.2 · orjson 3.12.0 |
| Client runtime | CPython 3.12.3, this repository's `identity/` and `technocore/` |
| Host | `127.0.0.1` only. **The public technocore.chat instance was never written to.** |
| Endpoints | `GET /r/<room>/say-signed/<did>/<sig>/<nonce>/<text>`, `POST /r/<room>`, `GET /r/<room>?format=json` |

Docker was not available in the environment, so the documented local Python
startup from the project's own README was used instead. Four environment knobs
were raised — `CHAT_RATE_WRITE=6000`, `CHAT_RATE_READ=6000`,
`CHAT_RATE_ROOMS_PER_DAY=500`, `CHAT_DUPE_FILTER_SECONDS=0` — so throughput and
the duplicate filter would not confound the matrix. **None of them touches
canonicalisation**, which is what is under test.

Machine-readable results: [`tests/fixtures/technocore_conformance_cases.json`](../tests/fixtures/technocore_conformance_cases.json).

## 2. Method

The official handler is:

```python
body = store.clean_text(p["text"])          # sweep first
signer = _signer(p["did"], p["sig"], nonce, f"{room}|{nonce}|{body}")
```

So the server verifies the signature over **its own swept form of what it
received**. That has a consequence which invalidated our first attempt:

> If the client pre-sweeps and signs what it sends, **both candidate policies are
> accepted**, because either output is already a fixed point of the server's sweep
> and the re-sweep is a no-op.

The first matrix run returned "both accepted" for 19 of 26 cases for exactly this
reason. The discriminating experiment is to **transmit the raw text and sign our
*prediction* of the server's sweep**: a wrong prediction is a 403. Both modes are
recorded in the fixture; only `raw` is treated as evidence.

## 3. Sweep matrix

Columns A–G from the request map as: A = input, B/C = our prediction (transmitted
and signed), D/G = what the server verified and stored, E = acceptance, F = server
transformation (always none where accepted, since acceptance requires agreement).

| case | input (escaped) | our prediction | server stored | RWS | REM | verdict |
|---|---|---|---|---|---|---|
| `ascii` | `flopoffice conformance ordinary ascii case` | `flopoffice conformance ordinary ascii case` | `flopoffice conformance ordinary ascii case` | 200 | 200 | both accepted (non-discriminating) |
| `newline` | `flopoffice conformance\u000Anewline case` | `flopoffice conformance newline case` | — | 404 | 404 | GET path cannot carry LF |
| `carriage_return` | `flopoffice conformance\u000Dcarriage case` | `flopoffice conformance carriage case` | `flopoffice conformance carriage case` | 200 | 403 | **confirms RWS** |
| `crlf` | `flopoffice conformance\u000D\u000Acrlf pair case` | `flopoffice conformance  crlf pair case` | — | 404 | 404 | GET path cannot carry LF |
| `tab` | `flopoffice conformance\u0009tab case` | `flopoffice conformance tab case` | `flopoffice conformance tab case` | 200 | 403 | **confirms RWS** |
| `repeated_whitespace` | `flopoffice   conformance \u0009\u0009 repeated whi` | `flopoffice   conformance    repeated white` | `flopoffice   conformance    repeated white` | 200 | 403 | **confirms RWS** |
| `zero_width_space` | `flopoffice conformance\u200Bzero width space case` | `flopoffice conformance zero width space ca` | `flopoffice conformance zero width space ca` | 200 | 403 | **confirms RWS** |
| `zero_width_joiner` | `flopoffice conformance\u200Dzero width joiner case` | `flopoffice conformance zero width joiner c` | `flopoffice conformance zero width joiner c` | 200 | 403 | **confirms RWS** |
| `zero_width_non_joiner` | `flopoffice conformance\u200Czero width non joiner ` | `flopoffice conformance zero width non join` | `flopoffice conformance zero width non join` | 200 | 403 | **confirms RWS** |
| `bidi_override` | `flopoffice conformance\u202Ebidi override case` | `flopoffice conformance bidi override case` | `flopoffice conformance bidi override case` | 200 | 403 | **confirms RWS** |
| `bidi_isolate` | `flopoffice conformance\u2066isolated\u2069 bidi is` | `flopoffice conformance isolated  bidi isol` | `flopoffice conformance isolated  bidi isol` | 200 | 403 | **confirms RWS** |
| `unicode_tag` | `flopoffice conformance\uE0041unicode tag case` | `flopoffice conformance unicode tag case` | `flopoffice conformance unicode tag case` | 200 | 403 | **confirms RWS** |
| `line_separator` | `flopoffice conformance\u2028line separator case` | `flopoffice conformance line separator case` | `flopoffice conformance line separator case` | 200 | 403 | **confirms RWS** |
| `paragraph_separator` | `flopoffice conformance\u2029paragraph separator ca` | `flopoffice conformance paragraph separator` | `flopoffice conformance paragraph separator` | 200 | 403 | **confirms RWS** |
| `nul_control` | `flopoffice conformance\u0000nul control case` | `flopoffice conformance nul control case` | `flopoffice conformance nul control case` | 200 | 403 | **confirms RWS** |
| `c1_control` | `flopoffice conformancec1 control case` | `flopoffice conformance c1 control case` | `flopoffice conformance c1 control case` | 200 | 403 | **confirms RWS** |
| `nbsp` | `flopoffice conformance\u00A0nbsp separator case` | `flopoffice conformance\u00A0nbsp separator` | `flopoffice conformance\u00A0nbsp separator` | 200 | 200 | both accepted (non-discriminating) |
| `ideographic_space` | `flopoffice conformance\u3000ideographic space case` | `flopoffice conformance\u3000ideographic sp` | `flopoffice conformance\u3000ideographic sp` | 200 | 200 | both accepted (non-discriminating) |
| `combining_marks` | `flopoffice conformance combining áç marks case` | `flopoffice conformance combining áç mark` | `flopoffice conformance combining áç mark` | 200 | 200 | both accepted (non-discriminating) |
| `emoji` | `flopoffice conformance 🚀🧮 emoji case` | `flopoffice conformance 🚀🧮 emoji case` | `flopoffice conformance 🚀🧮 emoji case` | 200 | 200 | both accepted (non-discriminating) |
| `emoji_zwj_sequence` | `flopoffice conformance 👨\u200D👩\u200D👧 zwj emoji c` | `flopoffice conformance 👨 👩 👧 zwj emoji cas` | `flopoffice conformance 👨 👩 👧 zwj emoji cas` | 200 | 403 | **confirms RWS** |
| `mixed_unicode_control` | `flopoffice 漢字\u0009conformance\u200B 🚀 mixed case` | `flopoffice 漢字 conformance  🚀 mixed case` | `flopoffice 漢字 conformance  🚀 mixed case` | 200 | 403 | **confirms RWS** |
| `leading_whitespace` | `   flopoffice conformance leading whitespace case` | `flopoffice conformance leading whitespace ` | `flopoffice conformance leading whitespace ` | 200 | 200 | both accepted (non-discriminating) |
| `trailing_whitespace` | `flopoffice conformance trailing whitespace case   ` | `flopoffice conformance trailing whitespace` | `flopoffice conformance trailing whitespace` | 200 | 200 | both accepted (non-discriminating) |
| `leading_trailing_newline` | `\u000Aflopoffice conformance surrounding newline c` | `flopoffice conformance surrounding newline` | — | 404 | 404 | GET path cannot carry LF |
| `only_invisible` | `\u200B\u200C\u200D\u2028` | `(refused locally)` | — | 0 | 0 | both refused (0) |


**15 of 15 discriminating cases confirm REPLACE_WITH_SPACE. Zero confirm REMOVE.**

`discriminating` is computed, not declared: it is "do the two policies produce
different bytes for this input". `nbsp`, `ideographic_space`,
`leading_trailing_newline` and the whitespace cases stopped discriminating once
the sweep was corrected, and a hand-maintained flag would have gone on claiming
evidence that no longer existed.

## 4. Category-by-category behaviour

Probed by writing `AA<char>BB` and reading back what was stored.

| Unicode category | Behaviour | Verified codepoints |
|---|---|---|
| `Cc` control | replaced with U+0020 | U+0000, U+0009, U+000D, U+001B, U+0085 |
| `Cf` format | replaced with U+0020 | U+00AD, U+200B, U+200C, U+200D, U+202E, U+2066, U+FEFF, U+E0041 |
| `Zl` line separator | replaced with U+0020 | U+2028 |
| `Zp` paragraph separator | replaced with U+0020 | U+2029 |
| **`Zs` space separator** | **kept unchanged** | U+00A0, U+1680, U+2003, U+2007, U+3000 |
| `Mn` combining mark | kept unchanged | U+0301 |
| everything else | kept unchanged | — |

This matches the official `store.INVISIBLE_CATEGORIES = ("Cc","Cf","Cs","Co","Zl","Zp")`.
`Cs` and `Co` are in the tuple but are not reachable through a UTF-8 request, so
they are taken from source, not measurement — recorded here as such.

Then: **`str.strip()`**. The trim uses Python semantics, which *do* remove `Zs`
characters at the ends even though the sweep leaves them alone inside:

| input | stored |
|---|---|
| `"   AA BB"` | `"AA BB"` |
| `"AA BB   "` | `"AA BB"` |
| `"\u00A0AA BB"` | `"AA BB"` |
| `"\u3000AA BB"` | `"AA BB"` |
| `"AA \t\t BB"` | `"AA    BB"` (runs **not** collapsed) |
| `"AA\u00A0\u00A0BB"` | `"AA\u00A0\u00A0BB"` (interior Zs preserved) |
| `"\u200B\u200C"` | HTTP 400 — nothing visible survives |

## 5. Canonicalisation conclusion

**OFFICIAL OBSERVED BEHAVIOR** (v0.10.0, measured):

1. Replace every character in categories `Cc`, `Cf`, `Cs`, `Co`, `Zl`, `Zp` with U+0020.
2. Apply `str.strip()` to the result.
3. Do **not** collapse interior runs.
4. Do **not** touch `Zs`, `Mn`, or anything else in interior positions.
5. Refuse with HTTP 400 if nothing survives; refuse if the result exceeds 4096 characters.
6. The signature covers `<room>|<nonce>|<swept text>`, UTF-8. `seq` and `ts` are excluded.

**DOCUMENTED BEHAVIOR:** the README's "converted to spaces" is correct.
`/llms.txt`'s "removed" is **wrong** as a description of the implementation, and
neither document mentions the trim or the `Zs` exemption at all.

**LOCAL ASSUMPTION** (unchanged by this work): that this behaviour is stable
across Technocore versions. It is pinned to `9c7df0e` / v0.10.0 and nothing more.

**UNRESOLVED:** `Cs` and `Co` handling is read from source rather than measured.
Everything else in the matrix is settled.

## 6. Three divergences found in M1

| # | M1 behaviour | Official behaviour | Consequence had it shipped |
|---|---|---|---|
| 1 | swept `Zs` (NBSP, U+3000, …) to a space | keeps `Zs` | every message containing a non-breaking space would have been rejected 403 |
| 2 | never trimmed (`strip_ends=False`, with a test asserting it) | trims both ends | every message with leading or trailing whitespace would have been rejected 403 |
| 3 | replace-with-space | replace-with-space | correct — the one thing M1 guessed right |

Divergences 1 and 2 are now regression-tested in
`tests/integration/test_technocore_conformance.py`
(`test_sweeping_zs_would_be_rejected`, `test_untrimmed_prediction_is_rejected`),
which assert that the *old* behaviour really is refused.

## 7. Other interoperability findings

These were not the object of the exercise but are load-bearing, so they are
recorded rather than left in a commit message.

**A room read returns no signature.** `GET /r/<room>?format=json` returns
`seq`, `ts`, `from`, `text`, `nonce` — and **no `sig`**. Our M1 client looked for
`did`/`sig`, so against the real server it would have found neither: no message
would ever have been marked verified, silently. Two corrections followed:
`from` is now read as the author field, and `verified` now fails closed —
a DID on the read path is *the server's claim about authorship*, not evidence we
checked. `UntrustedMessage.signature_returned` records which case applies, and
the author label reads `server-asserted, unverified`.

This also shapes M1.6. The first public announcement can be prepared, signed,
and verified locally, but a future room read will not give the signature back.
The retained local proof therefore stores the canonical text, signature,
algorithm, canonicalization profile, room and nonce with `Technocore status =
NOT_SENT`. That record can prove authorship of the prepared payload; it cannot
prove publication.

**A percent-encoded LF cannot traverse the GET write lane.** `%0A` in a path
segment answers `404 no route matched`. `%0D`, `%00`, `%09` and `%E2%80%A8` all
pass. The same message succeeds over `POST /r/<room>` and stores with the LF as a
space — which is itself an independent confirmation of the sweep. Practical rule:
sweep before transmitting on the GET lane, or use POST.

**A non-increasing nonce answers 400, not 409.** Our M1 test double answered 409
and the M1 test believed it. The double now mirrors 400 and the real response
shape. This is the clearest argument against treating a self-written double as
evidence about somebody else's implementation.

**A duplicate-text filter exists** (v0.10.0, `422`): a room refuses further
copies of a normalised text within `dupe_filter_seconds`, above
`dupe_min_length` characters, past `dupe_max_copies`. Disabled during the matrix
so it could not be mistaken for a signing failure. Any future write path must
treat 422 as "this text already landed", not as a signature problem.

## 8. Reproducing

```bash
git clone https://github.com/flop-labs/technocore-chat
cd technocore-chat && git checkout 9c7df0e
python3.12 -m venv .venv && .venv/bin/pip install \
    'starlette==1.6.0' 'uvicorn[standard]==0.52.2' 'pynacl==1.6.2' \
    'orjson==3.12.0' 'cryptography==50.0.0'
CHAT_ROOT=/tmp/tcdata CHAT_RATE_WRITE=6000 CHAT_RATE_READ=6000 \
CHAT_RATE_ROOMS_PER_DAY=500 CHAT_DUPE_FILTER_SECONDS=0 \
    .venv/bin/python -m uvicorn --app-dir src app:app --host 127.0.0.1 --port 8099

# in this repository
TECHNOCORE_OFFICIAL_URL=http://127.0.0.1:8099 python -m pytest -m conformance -v
```

Without `TECHNOCORE_OFFICIAL_URL` the conformance tests skip, so CI never depends
on an external service. The runner refuses any host that is not loopback.

## 9. Scope reminder

Technocore is a **satellite service operated by Flop Labs, not the FLOP protocol**
— its own documentation says so. Nothing measured here is a statement about FLOP
consensus, tokenomics, the testnet, or the faucet. It is a fact about one HTTP
service at one commit.
