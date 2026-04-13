from __future__ import annotations

"""Generate EdDSA (Ed25519) JWT access tokens for the Airlock OAuth server."""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.signing import SigningKey

logger = logging.getLogger(__name__)


def _nacl_to_cryptography(signing_key: SigningKey) -> Ed25519PrivateKey:
    """Convert a PyNaCl ``SigningKey`` to a ``cryptography`` Ed25519 private key.

    PyJWT's EdDSA support requires keys from the ``cryptography`` library.
    """
    return Ed25519PrivateKey.from_private_bytes(signing_key.encode())


def generate_access_token(
    *,
    subject_did: str,
    client_id: str,
    scope: str,
    signing_key: SigningKey,
    issuer_did: str,
    ttl_seconds: int,
    trust_score: float | None = None,
    trust_tier: int | None = None,
    delegation_chain: list[str] | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Mint an EdDSA JWT access token with Airlock trust claims.

    Standard claims: sub, iss, aud, iat, exp, scope, client_id, jti.
    Custom claims: ``airlock:trust_score``, ``airlock:trust_tier``.
    Delegation claims: ``act`` (nested actor chain per RFC 8693).
    """
    now = datetime.now(UTC)
    exp = now + timedelta(seconds=ttl_seconds)
    jti = str(uuid.uuid4())

    payload: dict[str, Any] = {
        "sub": subject_did,
        "iss": issuer_did,
        "aud": "airlock-agent",
        "iat": now,
        "exp": exp,
        "scope": scope,
        "client_id": client_id,
        "jti": jti,
    }

    if trust_score is not None:
        payload["airlock:trust_score"] = trust_score
    if trust_tier is not None:
        payload["airlock:trust_tier"] = trust_tier
    if delegation_chain:
        # Build nested act claims per RFC 8693
        act: dict[str, Any] | None = None
        for actor_did in reversed(delegation_chain):
            if act is None:
                act = {"sub": actor_did}
            else:
                act = {"sub": actor_did, "act": act}
        if act is not None:
            payload["act"] = act
    if extra_claims:
        payload.update(extra_claims)

    crypto_key = _nacl_to_cryptography(signing_key)
    return jwt.encode(payload, crypto_key, algorithm="EdDSA")
