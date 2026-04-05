"""Proof-of-Work for anti-Sybil protection.

Two algorithms are supported:

* **sha256** -- SHA-256 partial preimage (Hashcash).  Client finds a nonce
  such that ``SHA-256(prefix || nonce)`` has *N* leading zero bits.
  Difficulty 20 ~ 0.5-1.5 s to solve, ~1 us to verify.

* **argon2id** -- Memory-hard Argon2id with a SHA-256 pre-filter.  The client
  computes ``argon2id(prefix || nonce, salt=challenge_id, params)`` then
  hashes the 32-byte output with SHA-256.  The SHA-256 digest must have
  ``pre_filter_bits`` leading zero bits.  The server checks the cheap
  SHA-256 filter first (~1 us) and only runs the expensive Argon2id
  verification on proofs that pass.  Three server-assigned presets
  (light / standard / hardened) control memory and iteration costs.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional argon2-cffi import
# ---------------------------------------------------------------------------
try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_hash_raw

    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_AVAILABLE = False
    _Argon2Type = None  # type: ignore[assignment,misc]
    _argon2_hash_raw = None  # type: ignore[assignment]


def argon2_available() -> bool:
    """Return True when the ``argon2-cffi`` library is importable."""
    return _ARGON2_AVAILABLE


# ===================================================================
# SHA-256 Hashcash (original implementation)
# ===================================================================


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
      3. The hash meets the difficulty target (SHA-256 or Argon2id).

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

    # Dispatch to Argon2id path when challenge is Argon2id
    if isinstance(challenge, Argon2idPowChallenge):
        ok, reason = verify_argon2id_pow(proof, challenge)
        if not ok:
            return False, reason or "invalid_proof"
        return True, None

    if not verify_pow(proof):
        return False, "invalid_proof"

    return True, None


def verify_pow(proof: ProofOfWork) -> bool:
    """Verify a PoW solution.  Dispatches on ``proof.algorithm``.

    * ``"sha256"`` -- SHA-256 Hashcash (O(1), ~1 us).
    * ``"argon2id"`` -- requires full challenge context; stateless
      verification always returns False (use :func:`verify_argon2id_pow`).
    """
    if proof.algorithm == "sha256":
        return _verify_sha256(proof)
    if proof.algorithm == "argon2id":
        # Argon2id requires the full challenge (params, salt, pre_filter_bits).
        # Stateless verification is not possible.
        return False
    return False


def _verify_sha256(proof: ProofOfWork) -> bool:
    """Verify SHA-256 Hashcash proof. O(1), ~1 us."""
    data = f"{proof.prefix}{proof.nonce}".encode()
    digest = hashlib.sha256(data).digest()
    return _has_leading_zero_bits(digest, proof.difficulty)


def solve_pow(prefix: str, difficulty: int) -> str:
    """Solve a SHA-256 PoW challenge by brute force. Client-side.

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


# ===================================================================
# Shared bit-checking helper
# ===================================================================


def _has_leading_zero_bits(digest: bytes, required_bits: int) -> bool:
    """Return True when *digest* starts with at least *required_bits* zero bits."""
    full_bytes = required_bits // 8
    remaining = required_bits % 8

    for i in range(full_bytes):
        if digest[i] != 0:
            return False

    if remaining > 0:
        mask = (0xFF >> remaining) ^ 0xFF
        if digest[full_bytes] & mask != 0:
            return False

    return True


# ===================================================================
# Argon2id memory-hard PoW
# ===================================================================


class Argon2idParams(BaseModel):
    """Argon2id cost parameters assigned by the server."""

    memory_cost_kb: int = Field(ge=1024)
    time_cost: int = Field(ge=1)
    parallelism: int = Field(default=1, ge=1)
    hash_len: int = Field(default=32, ge=16, le=64)


ARGON2ID_PRESETS: dict[str, Argon2idParams] = {
    "light": Argon2idParams(memory_cost_kb=32_768, time_cost=2, parallelism=1),
    "standard": Argon2idParams(memory_cost_kb=49_152, time_cost=3, parallelism=1),
    "hardened": Argon2idParams(memory_cost_kb=131_072, time_cost=4, parallelism=1),
}


class Argon2idPowChallenge(PowChallenge):
    """Extended challenge for Argon2id with SHA-256 pre-filter.

    Inherits all fields from :class:`PowChallenge` and adds
    Argon2id-specific parameters.
    """

    algorithm: str = "argon2id"
    preset: str = "standard"
    argon2id_params: Argon2idParams = Field(
        default_factory=lambda: ARGON2ID_PRESETS["standard"],
    )
    pre_filter_bits: int = Field(default=12, ge=4, le=24)
    bound_did: str | None = None


def _require_argon2() -> None:
    """Raise RuntimeError when argon2-cffi is not installed."""
    if not _ARGON2_AVAILABLE:
        raise RuntimeError(
            "argon2-cffi is required for Argon2id PoW but is not installed. "
            "Install with: pip install argon2-cffi"
        )


def issue_argon2id_challenge(
    preset: str = "standard",
    difficulty: int = 20,
    ttl: int = 120,
    bound_did: str | None = None,
    pre_filter_bits: int = 12,
) -> Argon2idPowChallenge:
    """Issue an Argon2id PoW challenge with the given preset.

    Parameters
    ----------
    preset:
        One of ``"light"``, ``"standard"``, ``"hardened"``.
    difficulty:
        SHA-256 difficulty (kept for compatibility; ``pre_filter_bits``
        controls the actual pre-filter).
    ttl:
        Time-to-live in seconds before the challenge expires.
    bound_did:
        When set, the proof is bound to this DID.  Verification rejects
        proofs presented by a different DID, preventing PoW sharing.
    pre_filter_bits:
        Number of leading zero bits required in the SHA-256 pre-filter
        hash.  Higher values increase average solve time linearly.
    """
    if preset not in ARGON2ID_PRESETS:
        raise ValueError(
            f"Unknown Argon2id preset: {preset!r} (valid: {sorted(ARGON2ID_PRESETS)})"
        )

    now = time.time()
    challenge_id = secrets.token_hex(16)

    return Argon2idPowChallenge(
        challenge_id=challenge_id,
        prefix=secrets.token_hex(32),
        difficulty=difficulty,
        preset=preset,
        argon2id_params=ARGON2ID_PRESETS[preset],
        pre_filter_bits=pre_filter_bits,
        issued_at=now,
        expires_at=now + ttl,
        bound_did=bound_did,
    )


def _argon2id_raw(
    password: bytes,
    salt: bytes,
    params: Argon2idParams,
) -> bytes:
    """Compute raw Argon2id hash.

    Parameters match the low-level ``argon2.low_level.hash_secret_raw``
    interface.  The salt is right-padded to 16 bytes if shorter (Argon2
    requires a minimum 8-byte salt; our challenge_ids are 32 hex = 16 bytes).
    """
    _require_argon2()
    # Ensure salt is at least 16 bytes (pad if somehow shorter)
    if len(salt) < 16:
        salt = salt + b"\x00" * (16 - len(salt))
    return _argon2_hash_raw(  # type: ignore[no-any-return]
        secret=password,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kb,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=_Argon2Type.ID,  # type: ignore[union-attr]
    )


def solve_argon2id(challenge: Argon2idPowChallenge) -> str:
    """Solve an Argon2id PoW challenge.  Client-side.

    Iterates nonces until the two-layer condition is met:
      1. ``argon2id(prefix || nonce, salt=challenge_id, params)`` produces
         a 32-byte digest.
      2. ``SHA-256(argon2id_output)`` has ``pre_filter_bits`` leading zero bits.

    Returns the winning nonce as a hex string.
    """
    _require_argon2()

    params = challenge.argon2id_params
    salt = challenge.challenge_id.encode()
    pre_filter = challenge.pre_filter_bits

    nonce = 0
    while True:
        nonce_hex = f"{nonce:x}"
        password = f"{challenge.prefix}{nonce_hex}".encode()

        argon2_out = _argon2id_raw(password, salt, params)
        sha_digest = hashlib.sha256(argon2_out).digest()

        if _has_leading_zero_bits(sha_digest, pre_filter):
            return nonce_hex

        nonce += 1


def verify_argon2id_pow(
    proof: ProofOfWork,
    challenge: Argon2idPowChallenge,
    bound_did: str | None = None,
) -> tuple[bool, str | None]:
    """Two-layer Argon2id verification.

    1. **DID binding** -- when ``challenge.bound_did`` is set, the optional
       *bound_did* parameter must match.
    2. **Argon2id re-computation** -- recomputes the Argon2id hash from the
       proof nonce and challenge parameters.
    3. **SHA-256 pre-filter** -- checks that ``SHA-256(argon2id_output)``
       has the required leading zero bits.

    Returns ``(True, None)`` on success or ``(False, reason)`` on failure.
    """
    _require_argon2()

    # DID binding check
    if challenge.bound_did is not None:
        if bound_did is None or bound_did != challenge.bound_did:
            return False, "bound_did_mismatch"

    params = challenge.argon2id_params
    salt = challenge.challenge_id.encode()
    password = f"{challenge.prefix}{proof.nonce}".encode()

    # Compute Argon2id output for this nonce
    argon2_out = _argon2id_raw(password, salt, params)

    # SHA-256 pre-filter check
    sha_digest = hashlib.sha256(argon2_out).digest()
    if not _has_leading_zero_bits(sha_digest, challenge.pre_filter_bits):
        return False, "pre_filter_failed"

    return True, None


def verify_argon2id_pow_with_store(
    proof: ProofOfWork,
    challenge_store: dict[str, PowChallenge],
    bound_did: str | None = None,
) -> tuple[bool, str | None]:
    """Verify an Argon2id PoW against the server-side challenge store.

    Extends :func:`verify_pow_with_store` with DID-binding and two-layer
    verification.  The challenge is consumed (deleted) from the store before
    verification to guarantee one-time use.

    Returns ``(True, None)`` on success or ``(False, reason)`` on failure.
    """
    challenge = challenge_store.pop(proof.challenge_id, None)
    if challenge is None:
        return False, "unknown_challenge"

    if time.time() > challenge.expires_at:
        return False, "expired_challenge"

    if not isinstance(challenge, Argon2idPowChallenge):
        return False, "algorithm_mismatch"

    ok, reason = verify_argon2id_pow(proof, challenge, bound_did=bound_did)
    if not ok:
        return False, reason or "invalid_proof"

    return True, None
