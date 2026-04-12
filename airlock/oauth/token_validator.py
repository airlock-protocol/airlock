from __future__ import annotations

"""Validate EdDSA-signed JWT access tokens."""

import logging
from typing import Any

import jwt
from nacl.signing import VerifyKey

from airlock.oauth.token_generator import _ed25519_public_key_pem

logger = logging.getLogger(__name__)

MAX_DELEGATION_DEPTH = 20


class TokenValidationError(Exception):
    """Raised when an access token fails validation."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def validate_access_token(
    token: str,
    *,
    verify_key: VerifyKey,
    expected_issuer: str | None = None,
    expected_audience: str = "airlock-gateway",
    max_delegation_depth: int = 5,
) -> dict[str, Any]:
    """Validate an EdDSA-signed JWT access token.

    Parameters
    ----------
    token:
        The encoded JWT string.
    verify_key:
        The gateway's Ed25519 public key for signature verification.
    expected_issuer:
        If set, the ``iss`` claim must match.
    expected_audience:
        Expected ``aud`` claim (default: ``"airlock-gateway"``).
    max_delegation_depth:
        Maximum allowed delegation chain depth.

    Returns
    -------
    The decoded JWT payload as a dict.

    Raises
    ------
    TokenValidationError
        On any validation failure.
    """
    pem = _ed25519_public_key_pem(bytes(verify_key))

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            pem,
            algorithms=["EdDSA"],
            audience=expected_audience,
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise TokenValidationError("Token has expired")
    except jwt.InvalidAudienceError:
        raise TokenValidationError("Invalid audience")
    except jwt.InvalidSignatureError:
        raise TokenValidationError("Invalid signature")
    except jwt.PyJWTError as exc:
        raise TokenValidationError(f"Token validation failed: {exc}")

    if expected_issuer and payload.get("iss") != expected_issuer:
        raise TokenValidationError(
            f"Issuer mismatch: expected {expected_issuer}, got {payload.get('iss')}"
        )

    # Check delegation depth
    depth = _count_delegation_depth(payload)
    if depth > max_delegation_depth:
        raise TokenValidationError(
            f"Delegation depth {depth} exceeds maximum {max_delegation_depth}"
        )

    return payload


def _count_delegation_depth(payload: dict[str, Any]) -> int:
    """Count the depth of nested ``act`` claims in a token payload."""
    depth = 0
    current = payload
    while "act" in current:
        depth += 1
        act = current["act"]
        if not isinstance(act, dict):
            break
        current = act
        if depth > MAX_DELEGATION_DEPTH:
            break
    return depth
