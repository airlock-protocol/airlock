from __future__ import annotations

"""FastAPI router for OAuth 2.1 endpoints."""

import logging

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from airlock.oauth.discovery import build_discovery_metadata, build_jwks
from airlock.oauth.introspection import introspect_token
from airlock.oauth.models import TokenRequest
from airlock.oauth.registration import RegistrationError, RegistrationRequest, register_client
from airlock.oauth.server import OAuthError, handle_token_request

logger = logging.getLogger(__name__)

oauth_router = APIRouter(tags=["oauth"])


@oauth_router.post("/oauth/token")
async def token_endpoint(request: Request) -> JSONResponse:
    """OAuth 2.1 token endpoint supporting client_credentials and token_exchange."""
    form = await request.form()
    token_request = TokenRequest(
        grant_type=str(form.get("grant_type", "")),
        client_assertion=str(form.get("client_assertion", "")) or None,
        client_assertion_type=str(form.get("client_assertion_type", "")) or None,
        scope=str(form.get("scope", "")) or None,
        subject_token=str(form.get("subject_token", "")) or None,
        subject_token_type=str(form.get("subject_token_type", "")) or None,
    )

    kp = request.app.state.airlock_kp
    cfg = request.app.state.config
    oauth_store = request.app.state.oauth_store

    base_url = (cfg.public_base_url or cfg.default_gateway_url).rstrip("/")
    token_endpoint_url = f"{base_url}/oauth/token"

    # Trust score lookup from reputation store
    def _trust_lookup(did: str) -> tuple[float, int]:
        reputation = getattr(request.app.state, "reputation", None)
        if reputation is None:
            return 0.0, 0
        record = reputation.get(did)
        if record is None:
            return 0.0, 0
        return record.score, record.tier

    try:
        response = handle_token_request(
            token_request,
            oauth_store=oauth_store,
            signing_key=kp.signing_key,
            verify_key=kp.verify_key,
            issuer_did=kp.did,
            token_endpoint=token_endpoint_url,
            ttl_seconds=cfg.oauth_token_ttl_seconds,
            max_delegation_depth=cfg.oauth_max_delegation_depth,
            allowed_scopes=cfg.oauth_allowed_scopes,
            trust_score_lookup=_trust_lookup,
        )
    except OAuthError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.error, "error_description": exc.description},
        )

    return JSONResponse(
        status_code=200,
        content=response.model_dump(),
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@oauth_router.post("/oauth/register")
async def registration_endpoint(body: RegistrationRequest, request: Request) -> JSONResponse:
    """Dynamic client registration (RFC 7591)."""
    cfg = request.app.state.config

    if not cfg.oauth_dynamic_registration:
        return JSONResponse(
            status_code=403,
            content={"error": "registration_disabled", "error_description": "Dynamic registration is disabled"},
        )

    oauth_store = request.app.state.oauth_store

    try:
        response = register_client(
            body,
            oauth_store=oauth_store,
            allowed_scopes=cfg.oauth_allowed_scopes,
        )
    except RegistrationError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": exc.error, "error_description": exc.description},
        )

    return JSONResponse(status_code=201, content=response.model_dump(mode="json"))


@oauth_router.post("/oauth/introspect")
async def introspection_endpoint(request: Request) -> JSONResponse:
    """RFC 7662 token introspection."""
    form = await request.form()
    token_str = str(form.get("token", ""))

    if not token_str:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "token parameter is required"},
        )

    kp = request.app.state.airlock_kp
    oauth_store = request.app.state.oauth_store

    def _trust_lookup(did: str) -> tuple[float, int]:
        reputation = getattr(request.app.state, "reputation", None)
        if reputation is None:
            return 0.0, 0
        record = reputation.get(did)
        if record is None:
            return 0.0, 0
        return record.score, record.tier

    response = introspect_token(
        token_str,
        verify_key=kp.verify_key,
        issuer_did=kp.did,
        oauth_store=oauth_store,
        trust_score_lookup=_trust_lookup,
    )

    return JSONResponse(
        status_code=200,
        content=response.model_dump(by_alias=True, exclude_none=True),
    )


@oauth_router.post("/oauth/revoke")
async def revocation_endpoint(request: Request) -> JSONResponse:
    """Token revocation endpoint."""
    form = await request.form()
    token_str = str(form.get("token", ""))

    if not token_str:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "token parameter is required"},
        )

    kp = request.app.state.airlock_kp
    oauth_store = request.app.state.oauth_store

    # Try to decode and revoke
    from airlock.oauth.token_validator import validate_access_token

    try:
        payload = validate_access_token(
            token_str,
            verify_key=kp.verify_key,
            expected_issuer=kp.did,
        )
        jti = payload.get("jti", "")
        if jti:
            oauth_store.revoke_cascade(jti)
    except Exception:
        # Per RFC 7009, always return 200 even if token is invalid
        pass

    return JSONResponse(status_code=200, content={})


@oauth_router.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request) -> JSONResponse:
    """OIDC discovery metadata endpoint."""
    cfg = request.app.state.config
    kp = request.app.state.airlock_kp
    base_url = (cfg.public_base_url or cfg.default_gateway_url).rstrip("/")

    metadata = build_discovery_metadata(
        base_url=base_url,
        issuer_did=kp.did,
    )

    return JSONResponse(status_code=200, content=metadata)


@oauth_router.get("/.well-known/jwks.json")
async def jwks_endpoint(request: Request) -> JSONResponse:
    """JWKS endpoint exposing the gateway's Ed25519 public key."""
    kp = request.app.state.airlock_kp

    jwks = build_jwks(verify_key=kp.verify_key)

    return JSONResponse(
        status_code=200,
        content=jwks,
        headers={"Cache-Control": "public, max-age=3600"},
    )


def register_oauth_routes(app: FastAPI) -> None:
    """Mount all OAuth routes onto the FastAPI application."""
    app.include_router(oauth_router)
    logger.info("OAuth 2.1 routes registered")
