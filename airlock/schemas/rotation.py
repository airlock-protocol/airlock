"""Request and response schemas for key rotation and pre-rotation commitment."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class KeyRotationRequest(BaseModel):
    """Signed rotation request (old key signs).

    The agent generates a new Ed25519 keypair and signs this request with
    the OLD private key to prove control of the current identity before
    transferring it to the new key.
    """

    old_did: str  # did:key:z6Mk... (current)
    new_did: str  # did:key:z6Mk... (new key)
    rotation_chain_id: str  # Must match stored chain_id
    reason: str = "routine"  # "routine" or "compromise"
    timestamp: datetime
    nonce: str  # Replay prevention
    signature: str  # Ed25519 sig by OLD key over canonical payload
    next_key_commitment: str | None = None  # Optional chained pre-commitment digest for N+2


class KeyRotationResponse(BaseModel):
    """Response returned after a successful key rotation."""

    rotated: bool
    chain_id: str
    old_did: str
    new_did: str
    rotation_count: int
    grace_until: datetime | None = None


class PreCommitKeyRequest(BaseModel):
    """Signed pre-rotation commitment request.

    Agents submit a SHA-256 hash commitment to their next public key. When
    a rotation eventually happens, the new public key must match this
    commitment. This prevents an attacker who steals the current private
    key from rotating to an arbitrary new key.
    """

    did: str  # Current DID making the commitment
    alg: str = Field(default="sha256")
    digest: str  # hex(SHA-256(next_public_key_bytes))
    timestamp: datetime
    nonce: str
    signature: str  # Ed25519 sig by current key


class PreCommitKeyResponse(BaseModel):
    """Response returned after storing a pre-rotation commitment."""

    committed: bool
    did: str
    alg: str
    digest: str
    committed_at: datetime
