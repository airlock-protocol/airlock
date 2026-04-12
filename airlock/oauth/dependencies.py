from __future__ import annotations

"""FastAPI dependency helpers for OAuth-protected routes."""

import logging
from typing import Any

from fastapi import Depends, Header, HTTPException, Request

from airlock.oauth.models import AgentIdentity
from airlock.oauth.token_validator import TokenValidationError, validate_access_token

logger = logging.getLogger(__name__)


async def get_oauth_store(request: Request) -> Any:
    """Get the OAuthStore from app state."""
    store = getattr(request.app.state, "oauth_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="OAuth not configured")
    return store


async def get_current_agent(
    request: Request,
    authorization: str = Header(..., description="Bearer token"),
) -> AgentIdentity:
    """Extract and validate the agent identity from the Authorization header.

    Usage::

        @router.get("/protected")
        async def protected(agent: AgentIdentity = Depends(get_current_agent)):
            ...
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authorization header must use Bearer scheme",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:]
    kp = getattr(request.app.state, "airlock_kp", None)
    if kp is None:
        raise HTTPException(status_code=503, detail="Gateway keypair not configured")

    cfg = getattr(request.app.state, "config", None)
    max_depth = 5
    if cfg is not None:
        max_depth = cfg.oauth_max_delegation_depth

    try:
        payload = validate_access_token(
            token,
            verify_key=kp.verify_key,
            expected_issuer=kp.did,
            max_delegation_depth=max_depth,
        )
    except TokenValidationError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check revocation
    oauth_store = getattr(request.app.state, "oauth_store", None)
    if oauth_store is not None:
        jti = payload.get("jti", "")
        if jti:
            token_record = oauth_store.get_token(jti)
            if token_record is not None and token_record.revoked:
                raise HTTPException(
                    status_code=401,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )

    return AgentIdentity(
        did=payload.get("sub", ""),
        client_id=payload.get("client_id", ""),
        scope=payload.get("scope", ""),
        trust_score=payload.get("airlock:trust_score", 0.0),
        trust_tier=payload.get("airlock:trust_tier", 0),
        authenticated_via="oauth2",
    )


async def require_scope(required: str) -> Any:
    """Create a dependency that requires a specific scope.

    Usage::

        @router.get("/admin", dependencies=[Depends(require_scope("agent:manage"))])
        async def admin_endpoint():
            ...
    """

    async def _check(agent: AgentIdentity = Depends(get_current_agent)) -> AgentIdentity:
        scopes = set(agent.scope.split()) if agent.scope else set()
        if required not in scopes:
            raise HTTPException(
                status_code=403,
                detail=f"Missing required scope: {required}",
            )
        return agent

    return Depends(_check)
