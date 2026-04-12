from __future__ import annotations

"""OAuth 2.1 token endpoint handler."""

import logging
from typing import Any

from nacl.signing import SigningKey, VerifyKey

from airlock.oauth.grants.client_credentials import (
    ClientCredentialsError,
    handle_client_credentials,
)
from airlock.oauth.grants.token_exchange import TokenExchangeError, handle_token_exchange
from airlock.oauth.models import TokenRequest, TokenResponse
from airlock.oauth.store import OAuthStore

logger = logging.getLogger(__name__)


class OAuthError(Exception):
    """Structured OAuth error for HTTP responses."""

    def __init__(self, error: str, description: str, status_code: int = 400) -> None:
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)


def handle_token_request(
    request: TokenRequest,
    *,
    oauth_store: OAuthStore,
    signing_key: SigningKey,
    verify_key: VerifyKey,
    issuer_did: str,
    token_endpoint: str,
    ttl_seconds: int = 3600,
    max_delegation_depth: int = 5,
    allowed_scopes: str | None = None,
    trust_score_lookup: Any | None = None,
) -> TokenResponse:
    """Route a token request to the appropriate grant handler.

    Parameters
    ----------
    request:
        The parsed token request.
    oauth_store:
        OAuth client and token store.
    signing_key:
        Gateway Ed25519 signing key.
    verify_key:
        Gateway Ed25519 verify key.
    issuer_did:
        Gateway DID.
    token_endpoint:
        Token endpoint URL (audience for client assertions).
    ttl_seconds:
        Token TTL in seconds.
    max_delegation_depth:
        Maximum delegation chain depth.
    allowed_scopes:
        Comma-separated allowed scopes.
    trust_score_lookup:
        Callable(did) -> (score, tier) for live trust data.

    Returns
    -------
    TokenResponse with the issued token.

    Raises
    ------
    OAuthError
        On any grant processing failure.
    """
    if request.grant_type == "client_credentials":
        if not request.client_assertion:
            raise OAuthError("invalid_request", "client_assertion is required")
        if not request.client_assertion_type:
            raise OAuthError("invalid_request", "client_assertion_type is required")

        # Look up trust score for the client
        score = 0.0
        tier = 0
        if trust_score_lookup is not None:
            try:
                # Decode assertion to get client DID (without verifying - just for lookup)
                import jwt as _jwt

                unverified = _jwt.decode(
                    request.client_assertion,
                    options={"verify_signature": False},
                    algorithms=["EdDSA"],
                )
                client_id = unverified.get("sub", "")
                client = oauth_store.get_client(client_id)
                if client:
                    score, tier = trust_score_lookup(client.did)
            except Exception:
                pass  # Fall through with default score

        try:
            return handle_client_credentials(
                client_assertion=request.client_assertion,
                client_assertion_type=request.client_assertion_type,
                requested_scope=request.scope,
                oauth_store=oauth_store,
                signing_key=signing_key,
                issuer_did=issuer_did,
                token_endpoint=token_endpoint,
                ttl_seconds=ttl_seconds,
                trust_score=score,
                trust_tier=tier,
                allowed_scopes=allowed_scopes,
            )
        except ClientCredentialsError as exc:
            raise OAuthError(exc.error, exc.description)

    elif request.grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        if not request.subject_token:
            raise OAuthError("invalid_request", "subject_token is required")
        if not request.subject_token_type:
            raise OAuthError("invalid_request", "subject_token_type is required")
        if not request.client_assertion:
            raise OAuthError("invalid_request", "client_assertion is required for token exchange")

        # Verify the actor's identity via client assertion
        import jwt as _jwt

        try:
            unverified = _jwt.decode(
                request.client_assertion,
                options={"verify_signature": False},
                algorithms=["EdDSA"],
            )
        except _jwt.PyJWTError as exc:
            raise OAuthError("invalid_client", f"Cannot decode actor assertion: {exc}")

        actor_client_id = unverified.get("sub", "")
        actor_client = oauth_store.get_client(actor_client_id)
        if actor_client is None:
            raise OAuthError("invalid_client", "Unknown actor client")

        # Look up actor trust
        actor_score = 0.0
        actor_tier = 0
        if trust_score_lookup is not None:
            try:
                actor_score, actor_tier = trust_score_lookup(actor_client.did)
            except Exception:
                pass

        try:
            return handle_token_exchange(
                subject_token=request.subject_token,
                subject_token_type=request.subject_token_type,
                requested_scope=request.scope,
                oauth_store=oauth_store,
                signing_key=signing_key,
                verify_key=verify_key,
                issuer_did=issuer_did,
                actor_did=actor_client.did,
                actor_client_id=actor_client_id,
                ttl_seconds=ttl_seconds,
                max_delegation_depth=max_delegation_depth,
                trust_score=actor_score,
                trust_tier=actor_tier,
            )
        except TokenExchangeError as exc:
            raise OAuthError(exc.error, exc.description)

    else:
        raise OAuthError("unsupported_grant_type", f"Unsupported grant_type: {request.grant_type}")
