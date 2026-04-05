"""Hashcash-style Proof-of-Work for anti-Sybil protection.

SHA-256 partial preimage: client must find a nonce such that
SHA-256(prefix || nonce) has N leading zero bits.

Difficulty 20 ~ 0.5-1.5s to solve, ~1us to verify.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class PowChallenge(BaseModel):
    """Server-issued PoW challenge."""

    challenge_id: str
    prefix: str
    difficulty: int = Field(default=20, ge=1, le=32)
    algorithm: str = "sha256"
    issued_at: float
    expires_at: float


class PowSolution(BaseModel):
    """Client-submitted PoW solution."""

    challenge_id: str
    nonce: str


class ProofOfWork(BaseModel):
    """Embedded in HandshakeRequest for anti-Sybil verification."""

    challenge_id: str
    prefix: str
    nonce: str
    difficulty: int = Field(default=20, ge=1, le=32)
    algorithm: str = "sha256"


def issue_pow_challenge(difficulty: int = 20, ttl: int = 120) -> PowChallenge:
    """Issue a new PoW challenge with random prefix."""
    now = time.time()
    return PowChallenge(
        challenge_id=secrets.token_hex(16),
        prefix=secrets.token_hex(32),
        difficulty=difficulty,
        issued_at=now,
        expires_at=now + ttl,
    )


def verify_pow_with_store(
    proof: ProofOfWork,
    challenge_store: dict[str, PowChallenge],
) -> tuple[bool, str | None]:
    """Verify a PoW solution against a server-side challenge store.

    Validates that:
      1. The challenge_id was actually issued by this server.
      2. The challenge has not expired.
      3. The SHA-256 hash meets the difficulty target.

    The challenge is deleted from the store *before* hash verification
    to guarantee one-time use and prevent race-condition replays.

    Returns (success, error_reason).  error_reason is None on success,
    otherwise one of ``"unknown_challenge"``, ``"expired_challenge"``,
    or ``"invalid_proof"``.
    """
    challenge = challenge_store.pop(proof.challenge_id, None)
    if challenge is None:
        return False, "unknown_challenge"

    if time.time() > challenge.expires_at:
        return False, "expired_challenge"

    if not verify_pow(proof):
        return False, "invalid_proof"

    return True, None


def verify_pow(proof: ProofOfWork) -> bool:
    """Verify a PoW solution. O(1), ~1us.

    Checks that SHA-256(prefix || nonce) has at least ``difficulty``
    leading zero bits.
    """
    if proof.algorithm != "sha256":
        return False

    data = f"{proof.prefix}{proof.nonce}".encode()
    digest = hashlib.sha256(data).digest()

    required_bytes = proof.difficulty // 8
    remaining_bits = proof.difficulty % 8

    for i in range(required_bytes):
        if digest[i] != 0:
            return False

    if remaining_bits > 0:
        mask = (0xFF >> remaining_bits) ^ 0xFF
        if digest[required_bytes] & mask != 0:
            return False

    return True


def solve_pow(prefix: str, difficulty: int) -> str:
    """Solve a PoW challenge by brute force. Client-side.

    Returns the nonce as a hex string.
    """
    nonce = 0
    while True:
        nonce_hex = f"{nonce:x}"
        data = f"{prefix}{nonce_hex}".encode()
        digest = hashlib.sha256(data).digest()

        required_bytes = difficulty // 8
        remaining_bits = difficulty % 8
        valid = True

        for i in range(required_bytes):
            if digest[i] != 0:
                valid = False
                break

        if valid and remaining_bits > 0:
            mask = (0xFF >> remaining_bits) ^ 0xFF
            if digest[required_bytes] & mask != 0:
                valid = False

        if valid:
            return nonce_hex
        nonce += 1
