from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from airlock.schemas.challenge import ChallengeRequest, ChallengeResponse
from airlock.schemas.envelope import MessageEnvelope
from airlock.schemas.handshake import HandshakeRequest, SignatureEnvelope
from airlock.schemas.verdict import AirlockAttestation, CheckResult, TrustVerdict


class VerificationState(str, Enum):
    INITIATED = "initiated"
    RESOLVING = "resolving"
    RESOLVED = "resolved"
    HANDSHAKE_RECEIVED = "handshake_received"
    SIGNATURE_VERIFIED = "signature_verified"
    CREDENTIAL_VALIDATED = "credential_validated"
    CHALLENGE_ISSUED = "challenge_issued"
    CHALLENGE_RESPONDED = "challenge_responded"
    VERDICT_ISSUED = "verdict_issued"
    SEALED = "sealed"
    FAILED = "failed"


class VerificationSession(BaseModel):
    session_id: str
    state: VerificationState
    initiator_did: str
    target_did: str
    callback_url: str | None = None
    created_at: datetime
    updated_at: datetime
    ttl_seconds: int = 180

    handshake_request: HandshakeRequest | None = None
    check_results: list[CheckResult] = Field(default_factory=list)
    challenge_request: ChallengeRequest | None = None
    challenge_response: ChallengeResponse | None = None
    trust_score: float | None = None
    verdict: TrustVerdict | None = None
    attestation: AirlockAttestation | None = None
    error_message: str | None = None
    failed_at_state: VerificationState | None = None

    def is_expired(self) -> bool:
        elapsed = (datetime.now(timezone.utc) - self.created_at).total_seconds()
        return elapsed > self.ttl_seconds


class SessionSeal(BaseModel):
    envelope: MessageEnvelope
    session_id: str
    verdict: TrustVerdict
    checks_passed: list[CheckResult]
    trust_score: float
    sealed_at: datetime
    signature: SignatureEnvelope | None = None
