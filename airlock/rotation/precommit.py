"""Pre-rotation commitment for key continuity assurance.

Implements KERI-inspired pre-rotation: agents commit ``SHA-256(next_pub)``
*before* they need to rotate.  At rotation time, the new public key must
match the stored commitment.  This prevents an attacker who compromises
the current signing key from rotating to an arbitrary replacement.

Commitments have a 72-hour update lockout (configurable) to give the
legitimate key holder time to detect and respond to a compromise before
the attacker can overwrite the commitment.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime

from pydantic import BaseModel

logger = logging.getLogger(__name__)

_DEFAULT_UPDATE_LOCKOUT_HOURS = 72


class PreRotationCommitment(BaseModel):
    """Hash commitment to the next public key.

    Stored in the rotation chain record so it can be verified when the
    agent eventually presents the new key during rotation.
    """

    alg: str = "sha256"  # Hash algorithm identifier
    digest: str  # hex(SHA-256(new_public_key_bytes))
    committed_at: datetime
    committed_by_did: str  # DID that created this commitment
    signature: str  # Ed25519 sig by current key


def compute_key_commitment(public_key_bytes: bytes) -> str:
    """Compute SHA-256 hex digest of raw public key bytes.

    This is the value stored as the pre-rotation commitment.  At rotation
    time, ``SHA-256(new_public_key_bytes)`` is compared against this digest.
    """
    return hashlib.sha256(public_key_bytes).hexdigest()


def verify_commitment(
    commitment: PreRotationCommitment,
    new_public_key_bytes: bytes,
) -> bool:
    """Verify that ``new_public_key_bytes`` matches the stored commitment.

    Returns True if ``SHA-256(new_public_key_bytes) == commitment.digest``
    and the algorithm matches the expected value.
    """
    if commitment.alg != "sha256":
        logger.warning("Unsupported commitment algorithm: %s", commitment.alg)
        return False
    computed = compute_key_commitment(new_public_key_bytes)
    return computed == commitment.digest


def can_update_commitment(
    existing: PreRotationCommitment,
    lockout_hours: int = _DEFAULT_UPDATE_LOCKOUT_HOURS,
) -> bool:
    """Check whether the existing commitment can be replaced.

    Returns False if the commitment was made less than ``lockout_hours``
    ago.  This prevents an attacker who stole the current key from
    quickly overwriting the legitimate commitment.
    """
    now = datetime.now(UTC)
    elapsed = (now - existing.committed_at).total_seconds()
    lockout_seconds = lockout_hours * 3600
    return elapsed >= lockout_seconds
