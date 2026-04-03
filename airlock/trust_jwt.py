"""Short-lived HS256 JWTs proving a successful Airlock VERIFIED outcome."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt


def mint_verified_trust_token(
    *,
    subject_did: str,
    session_id: str,
    trust_score: float,
    issuer_did: str,
    secret: str,
    ttl_seconds: int,
) -> str:
    """Mint a JWT with standard time claims and Airlock-specific fields."""
    now = datetime.now(UTC)
    exp = now + timedelta(seconds=ttl_seconds)
    payload: dict[str, Any] = {
        "sub": subject_did,
        "sid": session_id,
        "ver": "VERIFIED",
        "ts": trust_score,
        "iss": issuer_did,
        "aud": "airlock-agent",
        "iat": now,
        "exp": exp,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_trust_token(
    token: str, secret: str, *, audience: str = "airlock-agent"
) -> dict[str, Any]:
    """Validate signature, expiry, issuer audience, and return claims."""
    result: dict[str, Any] = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        audience=audience,
        options={"require": ["exp", "iat", "sub", "sid", "ver"]},
    )
    return result


SESSION_VIEW_AUDIENCE = "airlock-session-view"


def mint_session_view_token(
    *,
    session_id: str,
    initiator_did: str,
    issuer_did: str,
    secret: str,
    ttl_seconds: int,
) -> str:
    """Mint a JWT allowing read access to a single verification session (poll / WS)."""
    now = datetime.now(UTC)
    exp = now + timedelta(seconds=ttl_seconds)
    payload: dict[str, Any] = {
        "sub": initiator_did,
        "sid": session_id,
        "typ": "session_view",
        "iss": issuer_did,
        "aud": SESSION_VIEW_AUDIENCE,
        "iat": now,
        "exp": exp,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_session_view_token(token: str, secret: str) -> dict[str, Any]:
    """Validate a session viewer JWT."""
    result: dict[str, Any] = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        audience=SESSION_VIEW_AUDIENCE,
        options={"require": ["exp", "iat", "sub", "sid", "typ"]},
    )
    return result
