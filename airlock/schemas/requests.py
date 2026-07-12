"""Pydantic bodies for JSON endpoints that previously accepted raw dicts."""

from __future__ import annotations

from pydantic import AnyHttpUrl, BaseModel, Field

from airlock.schemas.envelope import MessageEnvelope
from airlock.schemas.handshake import SignatureEnvelope
from airlock.schemas.passport import SignedAssertion


class ResolveRequest(BaseModel):
    target_did: str = Field(min_length=1)


class HeartbeatRequest(BaseModel):
    agent_did: str = Field(min_length=1)
    endpoint_url: AnyHttpUrl
    envelope: MessageEnvelope
    signature: SignatureEnvelope | None = None
    # Optional fresh passport directory assertion (heartbeat refresh flow).
    passport_assertion: SignedAssertion | None = None


class IntrospectRequest(BaseModel):
    token: str = Field(min_length=1)
