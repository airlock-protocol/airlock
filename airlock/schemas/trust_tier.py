from __future__ import annotations

from datetime import datetime
from enum import IntEnum

from pydantic import BaseModel


class TrustTier(IntEnum):
    """Progressive trust levels. Higher tier = stronger identity assurance."""

    UNKNOWN = 0
    CHALLENGE_VERIFIED = 1
    DOMAIN_VERIFIED = 2
    VC_VERIFIED = 3


# Score ceilings per tier
TIER_CEILINGS: dict[TrustTier, float] = {
    TrustTier.UNKNOWN: 0.50,
    TrustTier.CHALLENGE_VERIFIED: 0.70,
    TrustTier.DOMAIN_VERIFIED: 0.90,
    TrustTier.VC_VERIFIED: 1.00,
}

# Minimum score thresholds for tier promotion
TIER_THRESHOLDS: dict[TrustTier, float] = {
    TrustTier.UNKNOWN: 0.0,
    TrustTier.CHALLENGE_VERIFIED: 0.50,
    TrustTier.DOMAIN_VERIFIED: 0.60,
    TrustTier.VC_VERIFIED: 0.70,
}


class TierAssignment(BaseModel):
    """Tracks an agent's current tier and the evidence that earned it."""

    tier: TrustTier = TrustTier.UNKNOWN
    promoted_at: datetime | None = None
    evidence: str = ""
