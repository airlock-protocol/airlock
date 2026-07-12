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
from airlock.crypto.signing import sign_model
from airlock.passport.base import WELL_KNOWN_DIRECTORY_PATH
from airlock.schemas.envelope import create_envelope
from airlock.schemas.passport import (
    PassportRegistrationResult,
    PassportStatus,
    SignedAssertion,
)
from airlock.schemas.requests import HeartbeatRequest
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
    assertion: SignedAssertion | None = None,
) -> PassportRegistrationResult:
    """Register a passport key with an Airlock registry.

    Idempotent: ``POST /register`` upserts, so re-running with the same
    key succeeds and leaves the registration unchanged. ``transport`` is
    an injection point for in-process tests. ``assertion`` attaches a
    tenant-signed directory assertion (possession proof) to the profile;
    the registry publishes it in its well-known assertions document.
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
    if assertion is not None:
        profile = profile.model_copy(update={"passport_assertion": assertion})
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


async def fetch_passport_status(
    registry_url: str,
    did: str,
    *,
    timeout: float = 15.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> PassportStatus | None:
    """Fetch ``GET /passport/{did}/status`` from a registry.

    Returns ``None`` when the registry does not expose passport status
    (feature disabled, older registry) instead of raising, so callers can
    treat tenant-directory discovery as best-effort.
    """
    base = registry_url.rstrip("/")
    try:
        async with httpx.AsyncClient(
            base_url=base, timeout=httpx.Timeout(timeout), transport=transport
        ) as client:
            response = await client.get(f"/passport/{did}/status")
    except httpx.HTTPError as exc:
        logger.debug("Passport status fetch failed for %s: %s", base, exc)
        return None
    if response.status_code != 200:
        return None
    try:
        return PassportStatus.model_validate(response.json())
    except ValueError:
        return None


async def upload_assertion(
    keypair: KeyPair,
    registry_url: str,
    assertion: SignedAssertion,
    *,
    endpoint_url: str = "https://localhost",
    timeout: float = 15.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Refresh the stored directory assertion via the heartbeat flow.

    Sends a signed ``POST /heartbeat`` carrying the fresh assertion. The
    agent must already be registered. Raises ``RuntimeError`` when the
    registry rejects the upload.
    """
    base = registry_url.rstrip("/")
    body = HeartbeatRequest(
        agent_did=keypair.did,
        endpoint_url=endpoint_url,  # type: ignore[arg-type]  # validated by Pydantic
        envelope=create_envelope(sender_did=keypair.did),
        signature=None,
        passport_assertion=assertion,
    )
    body.signature = sign_model(body, keypair.signing_key)
    async with httpx.AsyncClient(
        base_url=base, timeout=httpx.Timeout(timeout), transport=transport
    ) as client:
        response = await client.post(
            "/heartbeat",
            content=body.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Assertion upload rejected by {base} (HTTP {response.status_code}): {response.text}"
        )
