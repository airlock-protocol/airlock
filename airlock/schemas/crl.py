"""CRL (Certificate Revocation List) schema models for Airlock Protocol v0.3."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class CRLEntry(BaseModel):
    """Single entry in the Certificate Revocation List."""

    did: str
    status: Literal["revoked", "suspended"]
    reason: str  # RevocationReason value
    revoked_at: datetime


class SignedCRL(BaseModel):
    """Signed Certificate Revocation List distributed by the gateway.

    The CRL is signed with the gateway's Ed25519 key so that consuming
    agents can verify its authenticity without trusting the transport layer.
    """

    version: int = 1
    crl_number: int = Field(description="Monotonically increasing sequence number")
    issuer_did: str
    this_update: datetime
    next_update: datetime
    max_cache_age_seconds: int = 300
    entries: list[CRLEntry] = Field(default_factory=list)
    signature: str | None = Field(
        default=None,
        description="Base64-encoded Ed25519 signature over the canonical CRL body",
    )
