from __future__ import annotations

"""RFC 8693 Token Exchange grant handler for Airlock delegation chains."""

import logging
from typing import Any

from nacl.signing import SigningKey, VerifyKey

from airlock.oauth.models import TokenRequest, TokenResponse
from airlock.oauth.scopes import is_scope_subset
from airlock.oauth.server import OAuthServerError, validate_client_assertion
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import generate_access_token
from airlock.oauth.token_validator import OAuthTokenError, validate_access_token

logger = logging.getLogger(__name__)


def handle_token_exchange(
    *,
    request: TokenRequest,
    store: OAuthStore,
    signing_key: SigningKey,
    issuer_did: str,
    config: Any,
    verify_key: VerifyKey | None = None,
) -> TokenResponse:
    """Process an RFC 8693 token-exchange grant.

    1. Validate the requesting client's assertion.
    2. Decode and verify the subject_token.
    3. Ensure requested scopes are a subset of the subject token's scopes.
    4. Check delegation depth against config max.
    5. Build a new token with nested ``act`` claims.
    """
    if not request.client_assertion:
        raise OAuthServerError("invalid_request", "client_assertion is required for token exchange")
    if not request.subject_token:
        raise OAuthServerError("invalid_request", "subject_token is required for token exchange")

    # Validate the actor (requesting client)
    actor_client = validate_client_assertion(request.client_assertion, store)

    # Decode the subject token
    if verify_key is None:
        raise OAuthServerError("server_error", "Token verification key not configured")

    max_depth = getattr(config, "oauth_max_delegation_depth", 5)
    try:
        subject_claims = validate_access_token(
            request.subject_token,
            verify_key,
            revocation_check=store.is_token_revoked,
            max_delegation_depth=max_depth,
        )
    except OAuthTokenError as exc:
        raise OAuthServerError("invalid_grant", f"Invalid subject token: {exc}") from exc

    subject_scope = subject_claims.get("scope", "")
    subject_did = subject_claims.get("sub", "")

    # Scope narrowing: requested scopes must be a subset of the subject token's scopes
    requested_scope = request.scope or subject_scope
    if not is_scope_subset(requested_scope, subject_scope):
        raise OAuthServerError(
            "invalid_scope",
            "Requested scopes exceed subject token's scope",
        )

    # Build the delegation chain
    existing_chain: list[str] = []
    act = subject_claims.get("act")
    while isinstance(act, dict):
        act_sub = act.get("sub", "")
        if act_sub:
            existing_chain.append(act_sub)
        act = act.get("act")

    # Chain: original subject -> ... existing actors ... -> current subject
    delegation_chain = [subject_did] + existing_chain

    # Check depth (chain length = delegation depth)
    if len(delegation_chain) >= max_depth:
        raise OAuthServerError(
            "invalid_grant",
            f"Delegation chain would exceed maximum depth ({max_depth})",
        )

    ttl = getattr(config, "oauth_token_ttl_seconds", 3600)
    access_token = generate_access_token(
        subject_did=actor_client.did,
        client_id=actor_client.client_id,
        scope=requested_scope,
        signing_key=signing_key,
        issuer_did=issuer_did,
        ttl_seconds=ttl,
        delegation_chain=delegation_chain,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ttl,
        scope=requested_scope,
        issued_token_type="urn:ietf:params:oauth:token-type:access_token",
    )
