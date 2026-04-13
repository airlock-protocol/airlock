from __future__ import annotations

"""OAuth 2.1 Pydantic v2 models for the Airlock authorization server."""

from datetime import datetime

from pydantic import BaseModel, field_validator


class OAuthClient(BaseModel):
    """Registered OAuth client (agent)."""

    client_id: str
    client_name: str
    did: str
    public_key_multibase: str
    grant_types: list[str]
    scope: str
    registered_at: datetime
    status: str = "active"

    @field_validator("did")
    @classmethod
    def did_must_be_key_method(cls, v: str) -> str:
        if not v.startswith("did:key:"):
            raise ValueError("DID must use the did:key method")
        return v


class OAuthToken(BaseModel):
    """Internal representation of an issued token."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str
    subject_did: str
    trust_score: float | None = None
    trust_tier: int | None = None
    delegation_chain: list[str] | None = None


class AgentIdentity(BaseModel):
    """Resolved identity from a validated OAuth access token."""

    did: str
    client_id: str
    scope: str
    trust_score: float | None = None
    trust_tier: int | None = None
    authenticated_via: str


class TokenRequest(BaseModel):
    """OAuth token endpoint request body."""

    grant_type: str
    client_assertion: str | None = None
    client_assertion_type: str | None = None
    scope: str | None = None
    subject_token: str | None = None
    subject_token_type: str | None = None
    requested_token_type: str | None = None


class TokenResponse(BaseModel):
    """OAuth token endpoint response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str
    issued_token_type: str | None = None


class IntrospectionResponse(BaseModel):
    """RFC 7662 token introspection response."""

    active: bool
    sub: str | None = None
    client_id: str | None = None
    scope: str | None = None
    exp: int | None = None
    iat: int | None = None
    iss: str | None = None
    trust_score: float | None = None
    trust_tier: int | None = None
