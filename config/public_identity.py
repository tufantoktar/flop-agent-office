"""The canonical public identity of this FlopOffice instance.

This module holds exactly one value and validates it at import. It is the single
place the root agent's DID is written down, so "which identity is this?" has one
answer that a reader can grep for and a test can assert is unique.

Everything here is **public data**. A ``did:key`` embeds a *public* key in the
identifier itself, which is why it can be committed, printed, and published
without disclosing anything. Nothing in this module touches, derives, implies or
requires private key material, and no code path reachable from here creates a
signer.

What ROOT_AGENT_DID is
----------------------
* a public identity **identifier**, in the ``did:key`` method, Ed25519 only;
* the name Technocore knows us by when we sign a write -- and the only thing a
  Technocore signature demonstrates is possession of the matching private key at
  the moment of signing.

What ROOT_AGENT_DID is **not**
------------------------------
* **not a wallet address.** No chain, no balance, no account. Nothing in this
  repository can receive or send value.
* **not proof of trust.** Technocore's own auth documentation is blunt about it:
  "a key that has written a thousand honest messages can write a malicious one
  next." A DID says who, never whether to believe them.
* **not proof of FLOP eligibility.** Whether holding a DID matters for any
  incentive programme is NOT YET SPECIFIED by Flop Labs. Configuring this value
  earns nothing and claims nothing.
* **not an on-chain identity.** No published FLOP document maps ``did:key`` to a
  chain account. If one ever does, that mapping is a separate, documented step.
* **not a private key, and not a means of finding one.** The public key is
  recoverable from this string by design; the private key is not, and never will
  be, by any amount of computation available to anyone.
* **not authorisation to sign.** Configuring a public identity does not wire a
  signer. See ``identity.keystore.production_signer`` and
  ``identity.capability.root_agent_capability_signer``, both of which still
  refuse.

Changing this value is changing who the project is. It is a reviewed commit, not
a runtime decision -- which is why there is no code here that generates, derives
or rotates a DID.
"""

from __future__ import annotations

from identity.did import DidKey

__all__ = ["ROOT_AGENT_DID", "ROOT_AGENT", "ENV_OVERRIDE"]

#: The committed public identity. Public by construction; safe to commit.
ROOT_AGENT_DID = "did:key:z6MkmjUUh9SLWe66SPFEUgQ4JA2RcbNLgimMzVA8VnvErnCN"

#: Environment variable that overrides the value above. The override is parsed by
#: the same strict validator -- it changes *which* DID, never *whether* it is
#: checked.
ENV_OVERRIDE = "FLOPOFFICE_ROOT_AGENT_DID"

#: Validated at import: a malformed or non-Ed25519 value fails immediately and
#: loudly, rather than at whatever later moment something first calls load().
ROOT_AGENT: DidKey = DidKey(ROOT_AGENT_DID)
