from __future__ import annotations

"""Pydantic v2 models for OAuth 2.1 authorization server."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ClientStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class OAuthClient(BaseModel):
    """Registered OAuth client (agent)."""

    client_id: str
    client_name: str = ""
    did: str
    public_key_multibase: str
    grant_types: list[str] = Field(default_factory=lambda: ["client_credentials"])
    scope: str = ""
    registered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: ClientStatus = ClientStatus.ACTIVE

    @field_validator("did")
    @classmethod
    def did_must_be_key_method(cls, v: str) -> str:
        if not v.startswith("did:key:"):
            raise ValueError("DID must use the did:key method")
        return v


class OAuthToken(BaseModel):
    """Stored access token metadata."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str = ""
    subject_did: str
    trust_score: float = 0.0
    trust_tier: int = 0
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    revoked: bool = False
    jti: str = ""
    parent_jti: str | None = None
    delegation_depth: int = 0
    actor_chain: list[dict[str, Any]] = Field(default_factory=list)


class AgentIdentity(BaseModel):
    """Decoded agent identity from a validated OAuth token."""

    did: str
    client_id: str
    scope: str = ""
    trust_score: float = 0.0
    trust_tier: int = 0
    authenticated_via: str = "oauth2"


class TokenRequest(BaseModel):
    """OAuth token endpoint request."""

    grant_type: str
    client_assertion: str | None = None
    client_assertion_type: str | None = None
    scope: str | None = None
    subject_token: str | None = None
    subject_token_type: str | None = None


class TokenResponse(BaseModel):
    """OAuth token endpoint response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str = ""


class IntrospectionResponse(BaseModel):
    """RFC 7662 introspection response with Airlock trust data."""

    active: bool
    sub: str | None = None
    client_id: str | None = None
    scope: str | None = None
    exp: int | None = None
    iat: int | None = None
    trust_score: float | None = Field(default=None, alias="airlock:trust_score")
    trust_tier: int | None = Field(default=None, alias="airlock:trust_tier")

    model_config = {"populate_by_name": True}
