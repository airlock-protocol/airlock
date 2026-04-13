from __future__ import annotations

"""OAuth 2.1 Client Credentials grant handler."""

import logging
from typing import Any

from nacl.signing import SigningKey

from airlock.oauth.models import TokenRequest, TokenResponse
from airlock.oauth.scopes import validate_scopes
from airlock.oauth.server import OAuthServerError, validate_client_assertion
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import generate_access_token

logger = logging.getLogger(__name__)


def handle_client_credentials(
    *,
    request: TokenRequest,
    store: OAuthStore,
    signing_key: SigningKey,
    issuer_did: str,
    config: Any,
    reputation_store: Any = None,
) -> TokenResponse:
    """Process a client_credentials grant request.

    1. Validate the ``private_key_jwt`` client assertion.
    2. Resolve allowed scopes.
    3. Look up the agent's current trust score (if available).
    4. Issue an EdDSA access token with trust claims.
    """
    if not request.client_assertion:
        raise OAuthServerError("invalid_request", "client_assertion is required")
    assertion_type = request.client_assertion_type or ""
    if assertion_type and assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
        raise OAuthServerError(
            "invalid_request",
            f"Unsupported client_assertion_type: {assertion_type}",
        )

    client = validate_client_assertion(request.client_assertion, store)

    # Resolve scopes
    requested = request.scope or client.scope
    allowed_scopes = getattr(config, "oauth_allowed_scopes", client.scope)
    try:
        granted_scope = validate_scopes(requested, allowed_scopes)
    except ValueError as exc:
        raise OAuthServerError("invalid_scope", str(exc)) from exc

    # Look up live trust data
    trust_score: float | None = None
    trust_tier: int | None = None
    if reputation_store is not None:
        try:
            score_record = reputation_store.get(client.did)
            if score_record is not None:
                trust_score = float(score_record.get("score", 0.0)) if isinstance(score_record, dict) else getattr(score_record, "score", None)
                trust_tier = int(score_record.get("tier", 0)) if isinstance(score_record, dict) else getattr(score_record, "tier", None)
        except Exception:
            logger.debug("Could not fetch trust data for %s", client.did, exc_info=True)

    ttl = getattr(config, "oauth_token_ttl_seconds", 3600)
    access_token = generate_access_token(
        subject_did=client.did,
        client_id=client.client_id,
        scope=granted_scope,
        signing_key=signing_key,
        issuer_did=issuer_did,
        ttl_seconds=ttl,
        trust_score=trust_score,
        trust_tier=trust_tier,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ttl,
        scope=granted_scope,
        issued_token_type="urn:ietf:params:oauth:token-type:access_token",
    )
