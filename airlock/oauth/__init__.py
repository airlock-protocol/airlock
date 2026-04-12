from __future__ import annotations

"""OAuth 2.1 authorization server module for the Airlock Protocol.

Provides client credentials grant with Ed25519 private_key_jwt authentication,
RFC 8693 token exchange for delegation chains, EdDSA-signed JWT access tokens
with trust score claims, and OIDC discovery metadata.
"""

from airlock.oauth.discovery import build_discovery_metadata, build_jwks
from airlock.oauth.introspection import introspect_token
from airlock.oauth.models import (
    AgentIdentity,
    IntrospectionResponse,
    OAuthClient,
    OAuthToken,
    TokenRequest,
    TokenResponse,
)
from airlock.oauth.registration import register_client
from airlock.oauth.scopes import AIRLOCK_SCOPES, is_scope_subset, validate_scopes
from airlock.oauth.server import handle_token_request
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import generate_access_token
from airlock.oauth.token_validator import validate_access_token

__all__ = [
    "AIRLOCK_SCOPES",
    "AgentIdentity",
    "IntrospectionResponse",
    "OAuthClient",
    "OAuthStore",
    "OAuthToken",
    "TokenRequest",
    "TokenResponse",
    "build_discovery_metadata",
    "build_jwks",
    "generate_access_token",
    "handle_token_request",
    "introspect_token",
    "is_scope_subset",
    "register_client",
    "validate_access_token",
    "validate_scopes",
]
