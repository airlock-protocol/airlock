from __future__ import annotations

"""Agent identity models — DID:key resolution and W3C Verifiable Credentials."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class AgentDID(BaseModel):
    did: str
    public_key_multibase: str

    @field_validator("did")
    @classmethod
    def did_must_be_key_method(cls, v: str) -> str:
        if not v.startswith("did:key:"):
            raise ValueError("DID must use the did:key method")
        return v


class AgentCapability(BaseModel):
    name: str
    version: str
    description: str


class AgentProfile(BaseModel):
    did: AgentDID
    display_name: str
    capabilities: list[AgentCapability]
    endpoint_url: str
    protocol_versions: list[str]
    status: Literal["active", "inactive", "suspended"]
    registered_at: datetime
    issuer_did: str | None = None
    a2a_card_url: str | None = None
    a2a_skills: list[str] | None = None


class CredentialType(str, Enum):
    AGENT_AUTHORIZATION = "AgentAuthorization"
    CAPABILITY_GRANT = "CapabilityGrant"
    IDENTITY_ASSERTION = "IdentityAssertion"


class CredentialProof(BaseModel):
    type: Literal["Ed25519Signature2020"]
    created: datetime
    verification_method: str
    proof_purpose: Literal["assertionMethod"]
    proof_value: str


class VerifiableCredential(BaseModel):
    model_config = {"populate_by_name": True}

    context: list[str] = Field(
        default=["https://www.w3.org/2018/credentials/v1"],
        alias="@context",
    )
    id: str
    type: list[str]
    issuer: str
    issuance_date: datetime
    expiration_date: datetime
    credential_subject: dict[str, Any]
    proof: CredentialProof | None = None

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expiration_date
