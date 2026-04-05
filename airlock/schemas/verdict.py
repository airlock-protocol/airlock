from __future__ import annotations

"""Verdict and trust seal models emitted after verification completes."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from airlock.schemas.trust_tier import TrustTier


class TrustVerdict(StrEnum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"


class VerificationCheck(StrEnum):
    SCHEMA = "schema"
    SIGNATURE = "signature"
    CREDENTIAL = "credential"
    REPUTATION = "reputation"
    SEMANTIC = "semantic"
    LIVENESS = "liveness"
    REVOCATION = "revocation"
    DELEGATION = "delegation"
    CAPABILITY_CROSS_REF = "capability_cross_ref"


class CheckResult(BaseModel):
    check: VerificationCheck
    passed: bool
    detail: str = ""
    degraded: bool = False


class AirlockAttestation(BaseModel):
    session_id: str
    verified_did: str
    checks_passed: list[CheckResult]
    trust_score: float = Field(ge=0.0, le=1.0)
    tier: TrustTier = TrustTier.UNKNOWN
    verdict: TrustVerdict
    issued_at: datetime
    privacy_mode: str = "any"
    fingerprint_flags: list[str] = Field(default_factory=list)
    airlock_signature: str | None = None
    trust_token: str | None = None
