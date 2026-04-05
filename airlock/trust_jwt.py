"""Short-lived HS256 JWTs proving a successful Airlock VERIFIED outcome."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

import jwt

logger = logging.getLogger(__name__)


class TokenRevokedError(Exception):
    """Raised when a trust token's subject DID has been revoked or suspended."""

    def __init__(self, did: str, message: str | None = None) -> None:
        self.did = did
        super().__init__(message or f"Token subject DID is revoked: {did}")


@runtime_checkable
class RevocationChecker(Protocol):
    """Structural protocol for revocation lookup (avoids gateway import)."""

    def is_revoked_sync(self, did: str) -> bool: ...


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
    token: str,
    secret: str,
    *,
    audience: str = "airlock-agent",
    revocation_store: RevocationChecker | None = None,
) -> dict[str, Any]:
    """Validate signature, expiry, audience, and optionally check revocation.

    Parameters
    ----------
    token:
        The encoded HS256 JWT.
    secret:
        The shared HMAC secret.
    audience:
        Expected ``aud`` claim (default ``"airlock-agent"``).
    revocation_store:
        Any object implementing ``is_revoked_sync(did) -> bool``.
        When provided the decoded ``sub`` DID is checked; if revoked a
        :class:`TokenRevokedError` is raised.  When *None* the check is
        skipped (backward compatible).

    Raises
    ------
    jwt.PyJWTError
        On invalid signature, expiry, missing claims, etc.
    TokenRevokedError
        When the token's subject DID is revoked/suspended.
    """
    result: dict[str, Any] = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        audience=audience,
        options={"require": ["exp", "iat", "sub", "sid", "ver"]},
    )

    if revocation_store is not None:
        subject_did: str = result["sub"]
        if revocation_store.is_revoked_sync(subject_did):
            logger.warning("Trust token rejected — DID revoked: %s", subject_did)
            raise TokenRevokedError(subject_did)

    return result


def is_token_revoked(
    token_payload: dict[str, Any],
    revocation_store: RevocationChecker,
) -> bool:
    """Check whether the ``sub`` DID in an already-decoded token payload is revoked.

    This is a convenience utility for callers that decode the token
    separately and want a simple boolean revocation check.
    """
    subject_did: str = token_payload.get("sub", "")
    if not subject_did:
        return False
    return revocation_store.is_revoked_sync(subject_did)


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
