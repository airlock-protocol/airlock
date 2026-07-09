"""Passport self-registration against an Airlock registry.

Reuses the repo's existing registration flow: the profile is built with
:func:`airlock.sdk.simple.ensure_registered_profile` (the same helper the
SDK verification client uses) and submitted to the gateway's existing
``POST /register`` endpoint. That endpoint requires no proof-of-work or
handshake (PoW protects ``/handshake`` only), so registration is a single
idempotent upsert.

Key persistence uses the repo's seed-file convention (64 hex chars,
Ed25519 seed) with ``chmod 600`` on POSIX; Windows gets a plain write.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx

from airlock.crypto.keys import KeyPair
from airlock.passport.base import WELL_KNOWN_DIRECTORY_PATH
from airlock.schemas.passport import PassportRegistrationResult
from airlock.sdk.simple import ensure_registered_profile

logger = logging.getLogger(__name__)

DEFAULT_KEY_PATH = Path.home() / ".airlock" / "passport.key"


def load_or_create_passport_key(path: Path) -> tuple[KeyPair, bool]:
    """Load an Ed25519 seed file, creating one when absent.

    Returns ``(keypair, created)`` where ``created`` is True when a new
    key was generated. Never logs the seed.
    """
    if path.exists():
        text = path.read_text(encoding="utf-8").strip()
        if len(text) != 64:
            raise ValueError(
                f"Invalid passport key file {path}: expected 64 hex chars, got {len(text)}"
            )
        return KeyPair.from_seed(bytes.fromhex(text)), False

    path.parent.mkdir(parents=True, exist_ok=True)
    keypair = KeyPair.generate()
    path.write_text(keypair.signing_key.encode().hex(), encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)
    logger.info("Generated new passport key (did=%s)", keypair.did)
    return keypair, True


def directory_url_for_registry(registry_url: str) -> str:
    """The well-known key directory URL served by a registry."""
    return registry_url.rstrip("/") + WELL_KNOWN_DIRECTORY_PATH


async def register_passport(
    keypair: KeyPair,
    registry_url: str,
    *,
    display_name: str = "Airlock Passport Agent",
    endpoint_url: str = "https://localhost",
    timeout: float = 15.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> PassportRegistrationResult:
    """Register a passport key with an Airlock registry.

    Idempotent: ``POST /register`` upserts, so re-running with the same
    key succeeds and leaves the registration unchanged. ``transport`` is
    an injection point for in-process tests.
    """
    base = registry_url.rstrip("/")
    profile = ensure_registered_profile(
        keypair,
        display_name=display_name,
        endpoint_url=endpoint_url,
        capabilities=[
            ("web-bot-auth", "0.1.0", "RFC 9421 web-bot-auth request signing (passport)")
        ],
    )
    async with httpx.AsyncClient(
        base_url=base, timeout=httpx.Timeout(timeout), transport=transport
    ) as client:
        response = await client.post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Registration rejected by {base} (HTTP {response.status_code}): {response.text}"
        )
    payload = response.json()
    return PassportRegistrationResult(
        registered=bool(payload.get("registered", False)),
        did=str(payload.get("did", keypair.did)),
        registry_url=base,
        directory_url=directory_url_for_registry(base),
    )
