from __future__ import annotations

"""FastAPI dependency injection helpers for OAuth-protected routes."""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import HTTPException, Request

from airlock.oauth.models import AgentIdentity
from airlock.oauth.token_validator import OAuthTokenError, validate_access_token

logger = logging.getLogger(__name__)


async def get_agent_identity(request: Request) -> AgentIdentity | None:
    """Extract and validate an OAuth bearer token from the request.

    Returns ``None`` when no ``Authorization: Bearer`` header is present
    (allows optional authentication).
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None

    token = auth_header[7:].strip()
    if not token:
        return None

    config: Any = request.app.state.config
    airlock_kp: Any = request.app.state.airlock_kp
    oauth_store: Any = getattr(request.app.state, "oauth_store", None)

    if oauth_store is None:
        return None

    try:
        claims = validate_access_token(
            token,
            airlock_kp.verify_key,
            revocation_check=oauth_store.is_token_revoked,
            max_delegation_depth=getattr(config, "oauth_max_delegation_depth", 5),
        )
    except OAuthTokenError:
        return None

    return AgentIdentity(
        did=claims.get("sub", ""),
        client_id=claims.get("client_id", ""),
        scope=claims.get("scope", ""),
        trust_score=claims.get("airlock:trust_score"),
        trust_tier=claims.get("airlock:trust_tier"),
        authenticated_via="oauth2_bearer",
    )


async def require_oauth_agent(request: Request) -> AgentIdentity:
    """Require a valid OAuth bearer token.

    Raises HTTP 401 when the token is missing or invalid.
    """
    identity = await get_agent_identity(request)
    if identity is None:
        raise HTTPException(
            status_code=401,
            detail="Valid OAuth bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return identity


def require_scope(required: str) -> Callable[..., Any]:
    """Return a FastAPI dependency that checks for a specific scope.

    Usage::

        @app.get("/protected", dependencies=[Depends(require_scope("verify:read"))])
        async def protected(): ...
    """

    async def _check(request: Request) -> AgentIdentity:
        identity = await require_oauth_agent(request)
        granted = set(identity.scope.split())
        if required not in granted:
            raise HTTPException(
                status_code=403,
                detail=f"Scope '{required}' is required",
            )
        return identity

    return _check
