from __future__ import annotations

"""FastAPI routes for the Airlock OAuth 2.1 authorization server."""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from airlock.oauth.discovery import build_jwks, build_openid_configuration
from airlock.oauth.introspection import introspect_token
from airlock.oauth.models import TokenRequest
from airlock.oauth.registration import RegistrationError, register_client
from airlock.oauth.server import OAuthServerError, process_token_request
from airlock.oauth.token_validator import OAuthTokenError, validate_access_token

logger = logging.getLogger(__name__)


def register_oauth_routes(app: FastAPI) -> None:
    """Attach OAuth 2.1 endpoints to the application."""

    @app.post("/oauth/token")
    async def oauth_token(request: Request) -> JSONResponse:
        """OAuth 2.1 token endpoint (client_credentials + token exchange)."""
        body = await request.json()
        token_request = TokenRequest(**body)

        config: Any = request.app.state.config
        airlock_kp: Any = request.app.state.airlock_kp
        oauth_store: Any = request.app.state.oauth_store
        reputation: Any = getattr(request.app.state, "reputation", None)

        try:
            response = process_token_request(
                token_request,
                oauth_store,
                signing_key=airlock_kp.signing_key,
                issuer_did=airlock_kp.did,
                config=config,
                reputation_store=reputation,
                verify_key=airlock_kp.verify_key,
            )
        except OAuthServerError as exc:
            return JSONResponse(
                {"error": exc.error, "error_description": exc.description},
                status_code=exc.status_code,
            )

        return JSONResponse(response.model_dump(exclude_none=True))

    @app.post("/oauth/register")
    async def oauth_register(request: Request) -> JSONResponse:
        """RFC 7591 Dynamic Client Registration endpoint."""
        body = await request.json()
        config: Any = request.app.state.config

        if not getattr(config, "oauth_dynamic_registration", True):
            return JSONResponse(
                {"error": "registration_disabled", "error_description": "Dynamic registration is disabled"},
                status_code=403,
            )

        did = body.get("did", "")
        client_name = body.get("client_name", "")
        grant_types = body.get("grant_types")
        scope = body.get("scope")
        oauth_store: Any = request.app.state.oauth_store

        if not did or not client_name:
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "did and client_name are required"},
                status_code=400,
            )

        try:
            client = register_client(
                did=did,
                client_name=client_name,
                store=oauth_store,
                grant_types=grant_types,
                scope=scope,
            )
        except RegistrationError as exc:
            return JSONResponse(
                {"error": exc.error, "error_description": exc.description},
                status_code=exc.status_code,
            )

        return JSONResponse(client.model_dump(mode="json"), status_code=201)

    @app.post("/oauth/introspect")
    async def oauth_introspect(request: Request) -> JSONResponse:
        """RFC 7662 Token Introspection endpoint."""
        body = await request.json()
        token = body.get("token", "")

        if not token:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "token parameter is required"},
                status_code=400,
            )

        airlock_kp: Any = request.app.state.airlock_kp
        oauth_store: Any = request.app.state.oauth_store
        reputation: Any = getattr(request.app.state, "reputation", None)

        result = await introspect_token(
            token, oauth_store, reputation, airlock_kp.verify_key,
        )
        return JSONResponse(result.model_dump(exclude_none=True))

    @app.post("/oauth/revoke")
    async def oauth_revoke(request: Request) -> JSONResponse:
        """Token revocation endpoint."""
        body = await request.json()
        token = body.get("token", "")

        if not token:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "token parameter is required"},
                status_code=400,
            )

        airlock_kp: Any = request.app.state.airlock_kp
        oauth_store: Any = request.app.state.oauth_store

        try:
            claims = validate_access_token(
                token, airlock_kp.verify_key,
                revocation_check=oauth_store.is_token_revoked,
            )
            jti = claims.get("jti", "")
            if jti:
                oauth_store.revoke_token(jti)
        except OAuthTokenError:
            pass  # RFC 7009: revocation of invalid tokens is not an error

        return JSONResponse({}, status_code=200)

    @app.get("/.well-known/openid-configuration")
    async def openid_configuration(request: Request) -> JSONResponse:
        """OIDC Discovery document."""
        config: Any = request.app.state.config
        airlock_kp: Any = request.app.state.airlock_kp
        base_url = (getattr(config, "public_base_url", "") or "").strip()
        if not base_url:
            base_url = getattr(config, "default_gateway_url", "http://127.0.0.1:8000")
        doc = build_openid_configuration(base_url, airlock_kp.did)
        return JSONResponse(doc)

    @app.get("/.well-known/jwks.json")
    async def jwks(request: Request) -> JSONResponse:
        """JSON Web Key Set endpoint."""
        airlock_kp: Any = request.app.state.airlock_kp
        jwks_doc = build_jwks(airlock_kp.verify_key, kid=airlock_kp.did)
        return JSONResponse(jwks_doc)
