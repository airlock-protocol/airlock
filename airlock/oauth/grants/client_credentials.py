from __future__ import annotations

"""Client Credentials grant with Ed25519 private_key_jwt authentication."""

import logging
from datetime import UTC, datetime
from typing import Any

import jwt
from nacl.signing import SigningKey

from airlock.crypto.keys import resolve_public_key
from airlock.oauth.models import OAuthClient, OAuthToken, TokenResponse
from airlock.oauth.scopes import validate_scopes
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import _ed25519_public_key_pem, generate_access_token

logger = logging.getLogger(__name__)


class ClientCredentialsError(Exception):
    """Raised when client credentials grant validation fails."""

    def __init__(self, error: str, description: str) -> None:
        self.error = error
        self.description = description
        super().__init__(description)


def verify_client_assertion(
    assertion: str,
    client: OAuthClient,
    expected_audience: str,
) -> dict[str, Any]:
    """Verify an Ed25519-signed JWT client assertion (private_key_jwt).

    Parameters
    ----------
    assertion:
        The encoded JWT assertion from the client.
    client:
        The registered OAuth client whose public key verifies the assertion.
    expected_audience:
        The token endpoint URL that should appear as ``aud``.

    Returns
    -------
    The decoded assertion payload.

    Raises
    ------
    ClientCredentialsError
        On verification failure.
    """
    try:
        vk = resolve_public_key(client.did)
    except (ValueError, Exception) as exc:
        raise ClientCredentialsError(
            "invalid_client",
            f"Cannot resolve public key for {client.did}: {exc}",
        )

    pem = _ed25519_public_key_pem(bytes(vk))

    try:
        payload: dict[str, Any] = jwt.decode(
            assertion,
            pem,
            algorithms=["EdDSA"],
            audience=expected_audience,
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise ClientCredentialsError("invalid_client", "Client assertion has expired")
    except jwt.InvalidAudienceError:
        raise ClientCredentialsError("invalid_client", "Client assertion audience mismatch")
    except jwt.InvalidSignatureError:
        raise ClientCredentialsError("invalid_client", "Client assertion signature invalid")
    except jwt.PyJWTError as exc:
        raise ClientCredentialsError("invalid_client", f"Client assertion invalid: {exc}")

    # sub must match client_id
    if payload.get("sub") != client.client_id:
        raise ClientCredentialsError(
            "invalid_client",
            "Assertion 'sub' does not match client_id",
        )

    # iss must match client_id
    if payload.get("iss") != client.client_id:
        raise ClientCredentialsError(
            "invalid_client",
            "Assertion 'iss' does not match client_id",
        )

    return payload


def handle_client_credentials(
    *,
    client_assertion: str,
    client_assertion_type: str,
    requested_scope: str | None,
    oauth_store: OAuthStore,
    signing_key: SigningKey,
    issuer_did: str,
    token_endpoint: str,
    ttl_seconds: int = 3600,
    trust_score: float = 0.0,
    trust_tier: int = 0,
    allowed_scopes: str | None = None,
) -> TokenResponse:
    """Process a client_credentials grant request.

    Parameters
    ----------
    client_assertion:
        The encoded JWT assertion from the client.
    client_assertion_type:
        Must be ``urn:ietf:params:oauth:client-assertion-type:jwt-bearer``.
    requested_scope:
        Space-separated scopes requested by the client.
    oauth_store:
        The OAuth store for client/token lookup and persistence.
    signing_key:
        The gateway's Ed25519 signing key for token issuance.
    issuer_did:
        The gateway's DID for the ``iss`` claim.
    token_endpoint:
        The token endpoint URL (audience for client assertion).
    ttl_seconds:
        Token TTL in seconds.
    trust_score:
        The client's current trust score.
    trust_tier:
        The client's current trust tier.
    allowed_scopes:
        Comma-separated allowed scopes from config.

    Returns
    -------
    TokenResponse with the issued access token.

    Raises
    ------
    ClientCredentialsError
        On any validation failure.
    """
    if client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
        raise ClientCredentialsError(
            "invalid_request",
            "client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )

    # Decode assertion header to find the client
    try:
        unverified = jwt.decode(
            client_assertion,
            options={"verify_signature": False},
            algorithms=["EdDSA"],
        )
    except jwt.PyJWTError as exc:
        raise ClientCredentialsError("invalid_client", f"Cannot decode assertion: {exc}")

    client_id = unverified.get("sub", "")
    if not client_id:
        raise ClientCredentialsError("invalid_client", "Assertion missing 'sub' claim")

    client = oauth_store.get_client(client_id)
    if client is None:
        raise ClientCredentialsError("invalid_client", f"Unknown client: {client_id}")

    if client.status != "active":
        raise ClientCredentialsError("invalid_client", f"Client is {client.status}")

    if "client_credentials" not in client.grant_types:
        raise ClientCredentialsError("unauthorized_client", "Grant type not authorized")

    # Verify the assertion signature
    verify_client_assertion(client_assertion, client, expected_audience=token_endpoint)

    # Validate scopes
    scope_str = requested_scope or client.scope or ""
    try:
        validated = validate_scopes(scope_str, allowed_scopes)
    except ValueError as exc:
        raise ClientCredentialsError("invalid_scope", str(exc))

    final_scope = " ".join(validated)

    # Generate access token
    encoded, jti, expires_at = generate_access_token(
        signing_key=signing_key,
        issuer_did=issuer_did,
        subject_did=client.did,
        client_id=client.client_id,
        scope=final_scope,
        trust_score=trust_score,
        trust_tier=trust_tier,
        ttl_seconds=ttl_seconds,
    )

    # Store token metadata
    token_record = OAuthToken(
        access_token=encoded,
        token_type="Bearer",
        expires_in=ttl_seconds,
        scope=final_scope,
        subject_did=client.did,
        trust_score=trust_score,
        trust_tier=trust_tier,
        issued_at=datetime.now(UTC),
        expires_at=expires_at,
        jti=jti,
    )
    oauth_store.store_token(token_record)

    return TokenResponse(
        access_token=encoded,
        token_type="Bearer",
        expires_in=ttl_seconds,
        scope=final_scope,
    )
