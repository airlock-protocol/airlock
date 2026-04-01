from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class TrustVerdict(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"


class VerificationCheck(str, Enum):
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
