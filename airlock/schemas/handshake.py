from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from airlock.schemas.envelope import MessageEnvelope
from airlock.schemas.identity import AgentDID, VerifiableCredential
from airlock.schemas.verdict import AirlockAttestation, TrustVerdict


class HandshakeIntent(BaseModel):
    action: str
    description: str
    target_did: str


class SignatureEnvelope(BaseModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    value: str
    signed_at: datetime


class HandshakeRequest(BaseModel):
    envelope: MessageEnvelope
    session_id: str
    initiator: AgentDID
    intent: HandshakeIntent
    credential: VerifiableCredential
    signature: SignatureEnvelope | None = None


class HandshakeResponse(BaseModel):
    envelope: MessageEnvelope
    session_id: str
    verdict: TrustVerdict
    attestation: AirlockAttestation | None = None
    signature: SignatureEnvelope | None = None
