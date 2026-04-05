from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from airlock.schemas.envelope import MessageEnvelope
from airlock.schemas.handshake import SignatureEnvelope
from airlock.schemas.trust_tier import TrustTier


class TrustScore(BaseModel):
    agent_did: str
    score: float = Field(ge=0.0, le=1.0, default=0.5)
    tier: TrustTier = TrustTier.UNKNOWN
    interaction_count: int = 0
    successful_verifications: int = 0
    failed_verifications: int = 0
    last_interaction: datetime | None = None
    decay_rate: float = 0.02
    created_at: datetime
    updated_at: datetime


class ReputationUpdate(BaseModel):
    agent_did: str
    session_id: str
    delta: float
    reason: str
    timestamp: datetime


class FeedbackReport(BaseModel):
    session_id: str
    reporter_did: str
    subject_did: str
    rating: Literal["positive", "neutral", "negative"]
    detail: str = ""
    timestamp: datetime


class SignedFeedbackReport(BaseModel):
    """Cryptographically signed reputation signal from ``reporter_did``."""

    session_id: str
    reporter_did: str
    subject_did: str
    rating: Literal["positive", "neutral", "negative"]
    detail: str = ""
    timestamp: datetime
    envelope: MessageEnvelope
    signature: SignatureEnvelope | None = None
