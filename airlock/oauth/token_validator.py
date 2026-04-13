from __future__ import annotations

"""Validate EdDSA JWT access tokens issued by the Airlock OAuth server."""

import logging
from collections.abc import Callable
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from nacl.signing import VerifyKey

logger = logging.getLogger(__name__)


class OAuthTokenError(Exception):
    """Raised when an OAuth access token fails validation."""


def _nacl_to_cryptography_pub(verify_key: VerifyKey) -> Ed25519PublicKey:
    """Convert a PyNaCl ``VerifyKey`` to a ``cryptography`` Ed25519 public key."""
    return Ed25519PublicKey.from_public_bytes(bytes(verify_key))


def validate_access_token(
    token: str,
    verify_key: VerifyKey,
    *,
    audience: str = "airlock-agent",
    revocation_check: Callable[[str], bool] | None = None,
    max_delegation_depth: int = 5,
) -> dict[str, Any]:
    """Decode and verify an Airlock OAuth access token.

    Parameters
    ----------
    token:
        Encoded EdDSA JWT.
    verify_key:
        The gateway's Ed25519 public key (PyNaCl ``VerifyKey``).
    audience:
        Expected ``aud`` claim.
    revocation_check:
        Optional callable ``(jti) -> bool``.  Returns True when revoked.
    max_delegation_depth:
        Maximum allowed depth of nested ``act`` claims.

    Raises
    ------
    OAuthTokenError
        On any validation failure (expired, bad signature, revoked, etc.).
    """
    crypto_pub = _nacl_to_cryptography_pub(verify_key)
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            crypto_pub,
            algorithms=["EdDSA"],
            audience=audience,
            options={"require": ["exp", "iat", "sub", "iss", "scope", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise OAuthTokenError(f"Token validation failed: {exc}") from exc

    jti: str = payload.get("jti", "")
    if revocation_check is not None and revocation_check(jti):
        raise OAuthTokenError(f"Token has been revoked (jti={jti})")

    # Check delegation depth
    depth = 0
    act = payload.get("act")
    while isinstance(act, dict):
        depth += 1
        if depth > max_delegation_depth:
            raise OAuthTokenError(
                f"Delegation chain exceeds maximum depth ({max_delegation_depth})"
            )
        act = act.get("act")

    return payload
