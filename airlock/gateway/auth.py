"""Authentication helpers for gateway routes (service bearer, session viewer JWT)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import HTTPException, Request, status
from jwt import PyJWTError

from airlock.trust_jwt import decode_session_view_token

if TYPE_CHECKING:
    from airlock.config import AirlockConfig

logger = logging.getLogger(__name__)


def parse_authorization_bearer(raw_header: str | None) -> str | None:
    if not raw_header:
        return None
    parts = raw_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    tok = parts[1].strip()
    return tok or None


def get_bearer_token(request: Request) -> str | None:
    return parse_authorization_bearer(request.headers.get("authorization"))


def service_token_configured(cfg: AirlockConfig) -> bool:
    return bool((cfg.service_token or "").strip())


def session_view_secret_configured(cfg: AirlockConfig) -> bool:
    return bool((cfg.session_view_secret or "").strip())


def verify_service_bearer_token(cfg: AirlockConfig, bearer: str | None) -> bool:
    expected = (cfg.service_token or "").strip()
    if not expected or not bearer:
        return False
    return bearer == expected


def verify_service_bearer(request: Request) -> bool:
    cfg: AirlockConfig = request.app.state.config
    return verify_service_bearer_token(cfg, get_bearer_token(request))


def require_service_bearer(request: Request) -> None:
    """Require configured service token as Authorization Bearer."""
    cfg: AirlockConfig = request.app.state.config
    if not (cfg.service_token or "").strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service authentication is not configured (AIRLOCK_SERVICE_TOKEN)",
        )
    if not verify_service_bearer(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid service token",
        )


def gate_rp_routes(request: Request) -> None:
    """Protect /metrics and /token/introspect when a service token is configured or in production."""
    cfg: AirlockConfig = request.app.state.config
    if cfg.is_production or service_token_configured(cfg):
        require_service_bearer(request)


def parse_session_view_token_raw(cfg: AirlockConfig, token: str | None, session_id: str) -> dict | None:
    secret = (cfg.session_view_secret or "").strip()
    if not secret or not token:
        return None
    try:
        claims = decode_session_view_token(token, secret)
    except PyJWTError:
        logger.debug("Invalid session_view token for session %s", session_id)
        return None
    if claims.get("sid") != session_id:
        return None
    return claims


def parse_session_view_token(request: Request, session_id: str) -> dict | None:
    """Return claims if Bearer is a valid session viewer JWT for ``session_id``."""
    cfg: AirlockConfig = request.app.state.config
    return parse_session_view_token_raw(cfg, get_bearer_token(request), session_id)


def session_access_allows_full_payload(request: Request, session_id: str) -> bool:
    """Full session (including trust_token) for service bearer or valid session viewer JWT."""
    if verify_service_bearer(request):
        return True
    claims = parse_session_view_token(request, session_id)
    return claims is not None


def ws_session_bearer_token(authorization_header: str | None, query_token: str | None) -> str | None:
    return parse_authorization_bearer(authorization_header) or (
        query_token.strip() if query_token and query_token.strip() else None
    )


def require_session_access(request: Request, session_id: str) -> None:
    """Enforce session read authorization."""
    cfg: AirlockConfig = request.app.state.config
    if verify_service_bearer(request):
        return
    if session_view_secret_configured(cfg):
        if parse_session_view_token(request, session_id) is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Valid session viewer token required (use token from handshake ACK or service token)",
            )
        return
    if cfg.is_production:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session access requires AIRLOCK_SESSION_VIEW_SECRET and handshake token",
        )


def build_session_payload(session, *, include_trust_token: bool) -> dict:
    out: dict = {
        "session_id": session.session_id,
        "state": session.state.value,
        "initiator_did": session.initiator_did,
        "target_did": session.target_did,
        "verdict": session.verdict.value if session.verdict else None,
        "trust_score": session.trust_score,
    }
    if include_trust_token and session.attestation:
        out["trust_token"] = session.attestation.trust_token
    if session.challenge_request is not None:
        out["challenge_id"] = session.challenge_request.challenge_id
    return out
