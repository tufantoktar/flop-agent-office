"""Configuration.

Public values only. This module reads paths, flags and the *public* DID. It
never reads, holds or logs a passphrase, private key, seed phrase or API secret,
and there is no setting that would make it do so.

The root agent DID is a public artefact and is safe to commit -- but it is left
unset by default so that nobody's identity is baked into a template repository.
Set ``FLOPOFFICE_ROOT_AGENT_DID`` or write ``config/agent.yaml`` locally.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from identity.did import DidKey, DidKeyError

__all__ = ["Settings", "ConfigError", "load"]

FORBIDDEN_ENV_SUBSTRINGS = ("PRIVATE_KEY", "PASSPHRASE", "SEED", "MNEMONIC", "SECRET")


class ConfigError(Exception):
    """Configuration is missing or unusable."""


@dataclass(frozen=True, slots=True)
class Settings:
    env: str
    ledger_path: Path
    root_agent_did: DidKey | None
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

    did_text = (env_map.get("FLOPOFFICE_ROOT_AGENT_DID") or "").strip()
    root_did: DidKey | None = None
    if did_text:
        try:
            root_did = DidKey(did_text)
        except DidKeyError as exc:
            raise ConfigError(f"FLOPOFFICE_ROOT_AGENT_DID is not a valid Ed25519 did:key: {exc}") from None

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
        keystore_path=keystore_path,
        technocore_base_url=(env_map.get("TECHNOCORE_BASE_URL") or "").strip() or None,
        allow_local_write=env_map.get("FLOPOFFICE_ALLOW_LOCAL_WRITE") == "1",
    )
