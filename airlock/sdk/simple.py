"""Low-friction SDK entrypoints: env-based gateway URL, auto key file, `protect` decorator."""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Coroutine
from functools import lru_cache
from pathlib import Path
from typing import Any, TypeVar

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_model
from airlock.crypto.vc import issue_credential
from airlock.schemas.envelope import create_envelope
from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest
from airlock.schemas.identity import AgentProfile
from airlock.sdk.middleware import AirlockMiddleware

F = TypeVar("F", bound=Callable[..., Coroutine[Any, Any, Any]])


def gateway_url_from_env() -> str:
    return (
        os.environ.get("AIRLOCK_GATEWAY_URL")
        or os.environ.get("AIRLOCK_DEFAULT_GATEWAY_URL")
        or "http://127.0.0.1:8000"
    )


def load_or_create_agent_keypair() -> KeyPair:
    """Load Ed25519 agent key from env seed or `.airlock/agent_seed.hex` (auto-created)."""
    hex_seed = (os.environ.get("AIRLOCK_AGENT_SEED_HEX") or "").strip()
    if len(hex_seed) == 64:
        return KeyPair.from_seed(bytes.fromhex(hex_seed))

    key_path = Path(os.environ.get("AIRLOCK_AGENT_KEY_PATH", ".airlock/agent_seed.hex"))
    if key_path.exists():
        h = key_path.read_text(encoding="utf-8").strip()
        if len(h) == 64:
            return KeyPair.from_seed(bytes.fromhex(h))
        raise ValueError(f"Invalid key file {key_path}: expected 64 hex chars")

    key_path.parent.mkdir(parents=True, exist_ok=True)
    kp = KeyPair.generate()
    key_path.write_text(kp.signing_key.encode().hex(), encoding="utf-8")
    return kp


@lru_cache(maxsize=1)
def default_middleware() -> AirlockMiddleware:
    """Singleton AirlockMiddleware from environment (gateway URL + agent key)."""
    return AirlockMiddleware(gateway_url_from_env(), load_or_create_agent_keypair())


def protect(func: F) -> F:
    """Decorator equivalent to ``default_middleware().protect`` — one line at call site."""
    return default_middleware().protect(func)


def build_signed_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    *,
    action: str = "connect",
    description: str = "Airlock handshake",
    claims: dict[str, Any] | None = None,
    session_id: str | None = None,
    credential_type: str = "AgentAuthorization",
) -> HandshakeRequest:
    """Construct a signed :class:`HandshakeRequest` without touching envelope types."""
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type=credential_type,
        claims=claims or {"role": "agent"},
    )
    envelope = create_envelope(sender_did=agent_kp.did)
    req = HandshakeRequest(
        envelope=envelope,
        session_id=session_id or str(uuid.uuid4()),
        initiator=agent_kp.to_agent_did(),
        intent=HandshakeIntent(
            action=action,
            description=description,
            target_did=target_did,
        ),
        credential=vc,
        signature=None,
    )
    req.signature = sign_model(req, agent_kp.signing_key)
    return req


def ensure_registered_profile(
    agent_kp: KeyPair,
    *,
    display_name: str = "Airlock Agent",
    endpoint_url: str = "http://localhost",
    capabilities: list[tuple[str, str, str]] | None = None,
) -> AgentProfile:
    """Build a minimal :class:`AgentProfile` for ``POST /register``."""
    from datetime import UTC, datetime  # noqa: PLC0415

    from airlock.schemas.identity import AgentCapability  # noqa: PLC0415

    caps = [
        AgentCapability(name=n, version=v, description=d)
        for n, v, d in (capabilities or [("default", "1.0", "Autoregistered agent")])
    ]

    return AgentProfile(
        did=agent_kp.to_agent_did(),
        display_name=display_name,
        capabilities=caps,
        endpoint_url=endpoint_url,
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )
