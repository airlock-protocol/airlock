from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from airlock.schemas.challenge import ChallengeRequest, ChallengeResponse
from airlock.schemas.handshake import HandshakeRequest
from airlock.schemas.verdict import TrustVerdict


class VerificationEvent(BaseModel):
    event_type: str
    session_id: str
    timestamp: datetime


class ResolveRequested(VerificationEvent):
    event_type: Literal["resolve_requested"] = "resolve_requested"
    target_did: str


class HandshakeReceived(VerificationEvent):
    event_type: Literal["handshake_received"] = "handshake_received"
    request: HandshakeRequest
    callback_url: str | None = None


class SignatureVerified(VerificationEvent):
    event_type: Literal["signature_verified"] = "signature_verified"


class CredentialValidated(VerificationEvent):
    event_type: Literal["credential_validated"] = "credential_validated"


class ChallengeIssued(VerificationEvent):
    event_type: Literal["challenge_issued"] = "challenge_issued"
    challenge: ChallengeRequest


class ChallengeResponseReceived(VerificationEvent):
    event_type: Literal["challenge_response_received"] = "challenge_response_received"
    response: ChallengeResponse


class VerdictReady(VerificationEvent):
    event_type: Literal["verdict_ready"] = "verdict_ready"
    verdict: TrustVerdict
    trust_score: float


class SessionSealed(VerificationEvent):
    event_type: Literal["session_sealed"] = "session_sealed"


class VerificationFailed(VerificationEvent):
    event_type: Literal["verification_failed"] = "verification_failed"
    error: str
    failed_at: str


class AgentRevoked(VerificationEvent):
    event_type: Literal["agent_revoked"] = "agent_revoked"
    target_did: str


class AgentUnrevoked(VerificationEvent):
    event_type: Literal["agent_unrevoked"] = "agent_unrevoked"
    target_did: str


AnyVerificationEvent = (
    ResolveRequested
    | HandshakeReceived
    | SignatureVerified
    | CredentialValidated
    | ChallengeIssued
    | ChallengeResponseReceived
    | VerdictReady
    | SessionSealed
    | VerificationFailed
    | AgentRevoked
    | AgentUnrevoked
)
