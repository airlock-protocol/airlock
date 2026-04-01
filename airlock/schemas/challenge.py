from __future__ import annotations

"""Semantic challenge and response models for the verification pipeline."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from airlock.schemas.envelope import MessageEnvelope
from airlock.schemas.handshake import SignatureEnvelope


class ChallengeRequest(BaseModel):
    envelope: MessageEnvelope
    session_id: str
    challenge_id: str
    challenge_type: Literal["semantic", "capability_proof"]
    question: str
    context: str
    expires_at: datetime
    signature: SignatureEnvelope | None = None


class ChallengeResponse(BaseModel):
    envelope: MessageEnvelope
    session_id: str
    challenge_id: str
    answer: str
    confidence: float = Field(ge=0.0, le=1.0)
    signature: SignatureEnvelope | None = None
