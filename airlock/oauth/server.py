from __future__ import annotations

"""OAuth 2.1 authorization server core — client assertion validation and token dispatch."""

import logging
from datetime import UTC, datetime
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from airlock.crypto.keys import resolve_public_key
from airlock.oauth.models import OAuthClient, TokenRequest, TokenResponse
from airlock.oauth.store import OAuthStore

logger = logging.getLogger(__name__)


class OAuthServerError(Exception):
    """Base error for OAuth server operations."""

    def __init__(self, error: str, description: str, status_code: int = 400) -> None:
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)


def validate_client_assertion(assertion: str, store: OAuthStore) -> OAuthClient:
    """Validate a ``private_key_jwt`` client assertion (RFC 7523).

    The assertion is a JWT signed with the client's Ed25519 private key.
    We look up the client by the ``sub`` (or ``iss``) claim, fetch its
    public key from the DID, and verify the signature.

    Returns the :class:`OAuthClient` on success.

    Raises
    ------
    OAuthServerError
        On any validation failure.
    """
    # Decode without verification first to extract the subject
    try:
        unverified: dict[str, Any] = jwt.decode(
            assertion,
            options={"verify_signature": False},
            algorithms=["EdDSA"],
        )
    except jwt.PyJWTError as exc:
        raise OAuthServerError(
            "invalid_client",
            f"Cannot decode client assertion: {exc}",
        ) from exc

    # The sub and iss MUST be the client_id
    client_id = unverified.get("sub") or unverified.get("iss")
    if not client_id or not isinstance(client_id, str):
        raise OAuthServerError("invalid_client", "Assertion must contain 'sub' or 'iss' claim")

    client = store.get_client(client_id)
    if client is None:
        # Try by DID
        client = store.get_client_by_did(client_id)
    if client is None:
        raise OAuthServerError("invalid_client", f"Unknown client: {client_id}")

    if client.status != "active":
        raise OAuthServerError("invalid_client", f"Client is {client.status}")

    # Verify signature using the client's DID public key
    try:
        nacl_vk = resolve_public_key(client.did)
        crypto_pub = Ed25519PublicKey.from_public_bytes(bytes(nacl_vk))
    except (ValueError, Exception) as exc:
        raise OAuthServerError(
            "invalid_client",
            f"Cannot resolve public key for DID {client.did}: {exc}",
        ) from exc

    try:
        jwt.decode(
            assertion,
            crypto_pub,
            algorithms=["EdDSA"],
            options={"verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise OAuthServerError(
            "invalid_client",
            f"Client assertion signature verification failed: {exc}",
        ) from exc

    # Check expiry on the assertion
    exp = unverified.get("exp")
    if exp is not None:
        if datetime.fromtimestamp(exp, tz=UTC) < datetime.now(UTC):
            raise OAuthServerError("invalid_client", "Client assertion has expired")

    return client


def process_token_request(
    request: TokenRequest,
    store: OAuthStore,
    *,
    signing_key: Any,
    issuer_did: str,
    config: Any,
    reputation_store: Any = None,
    verify_key: Any = None,
) -> TokenResponse:
    """Dispatch a token request to the appropriate grant handler.

    Raises
    ------
    OAuthServerError
        On unsupported grant type or handler error.
    """
    if request.grant_type == "client_credentials":
        from airlock.oauth.grants.client_credentials import handle_client_credentials

        return handle_client_credentials(
            request=request,
            store=store,
            signing_key=signing_key,
            issuer_did=issuer_did,
            config=config,
            reputation_store=reputation_store,
        )
    elif request.grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        from airlock.oauth.grants.token_exchange import handle_token_exchange

        return handle_token_exchange(
            request=request,
            store=store,
            signing_key=signing_key,
            issuer_did=issuer_did,
            config=config,
            verify_key=verify_key,
        )
    else:
        raise OAuthServerError(
            "unsupported_grant_type",
            f"Grant type {request.grant_type!r} is not supported",
        )
