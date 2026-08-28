"""Configuration.

Public values only. This module reads paths, flags and the *public* DID. It
never reads, holds or logs a passphrase, private key, seed phrase or API secret,
and there is no setting that would make it do so.

The root agent DID is a public artefact and is committed, in exactly one place:
``config/public_identity.py``. ``FLOPOFFICE_ROOT_AGENT_DID`` overrides it for a
fork or a test, and the override goes through the same strict Ed25519 ``did:key``
validation -- it changes which identity, never whether it is checked.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from config.public_identity import ENV_OVERRIDE, ROOT_AGENT
from identity.did import DidKey, DidKeyError

__all__ = ["Settings", "ConfigError", "load", "DidSource"]

DidSource = Literal["committed", "environment"]

FORBIDDEN_ENV_SUBSTRINGS = ("PRIVATE_KEY", "PASSPHRASE", "SEED", "MNEMONIC", "SECRET")


class ConfigError(Exception):
    """Configuration is missing or unusable."""


@dataclass(frozen=True, slots=True)
class Settings:
    env: str
    ledger_path: Path
    #: Always present: the committed identity, or a validated override.
    root_agent_did: DidKey
    root_agent_did_source: DidSource
    keystore_path: Path | None
    technocore_base_url: str | None
    allow_local_write: bool

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"


def _reject_secret_env() -> None:
    """Fail loudly if the process was handed secret-shaped environment variables.

    M1 needs none of them. Their presence means either a misconfiguration or an
    attempt to feed key material into a codebase that must not accept it.
    """
    offenders = [
        name
        for name in os.environ
        if name.startswith("FLOPOFFICE_")
        and any(bad in name.upper() for bad in FORBIDDEN_ENV_SUBSTRINGS)
    ]
    if offenders:
        raise ConfigError(
            "refusing to start: secret-shaped environment variables present "
            f"({', '.join(sorted(offenders))}). M1 requires no secrets. "
            "Unset them; use an encrypted keystore file when signing is enabled."
        )


def load(environ: dict[str, str] | None = None) -> Settings:
    env_map = os.environ if environ is None else environ
    if environ is None:
        _reject_secret_env()

    override = (env_map.get(ENV_OVERRIDE) or "").strip()
    if override:
        try:
            root_did, did_source = DidKey(override), "environment"
        except DidKeyError as exc:
            # The override is validated exactly as strictly as the committed
            # value. An environment variable may not smuggle in a DID the code
            # would refuse if it were written down.
            raise ConfigError(
                f"{ENV_OVERRIDE} is not a valid Ed25519 did:key: {exc}"
            ) from None
    else:
        root_did, did_source = ROOT_AGENT, "committed"

    keystore = env_map.get("FLOPOFFICE_KEYSTORE")
    keystore_path = Path(keystore).expanduser() if keystore else None
    if keystore_path is not None:
        try:
            keystore_path.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            pass  # outside the repo: correct
        else:
            raise ConfigError(
                "FLOPOFFICE_KEYSTORE points inside the repository working tree. "
                "Keystores must live outside it (default ~/.flopoffice/keys/)."
            )

    return Settings(
        env=(env_map.get("FLOPOFFICE_ENV") or "dev").lower(),
        ledger_path=Path(env_map.get("FLOPOFFICE_LEDGER") or "flopoffice.sqlite"),
        root_agent_did=root_did,
        root_agent_did_source=did_source,
        keystore_path=keystore_path,
        technocore_base_url=(env_map.get("TECHNOCORE_BASE_URL") or "").strip() or None,
        allow_local_write=env_map.get("FLOPOFFICE_ALLOW_LOCAL_WRITE") == "1",
    )
