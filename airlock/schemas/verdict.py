from __future__ import annotations

"""Verdict and trust seal models emitted after verification completes."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


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


class CheckResult(BaseModel):
    check: VerificationCheck
    passed: bool
    detail: str = ""


class AirlockAttestation(BaseModel):
    session_id: str
    verified_did: str
    checks_passed: list[CheckResult]
    trust_score: float = Field(ge=0.0, le=1.0)
    verdict: TrustVerdict
    issued_at: datetime
    airlock_signature: str | None = None
    trust_token: str | None = None
