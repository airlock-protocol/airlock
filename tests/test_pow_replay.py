"""Tests for PoW challenge replay prevention.

Validates that ``verify_pow_with_store`` enforces one-time-use challenges,
rejects unknown/expired challenges, and that the original ``verify_pow``
remains backward-compatible.
"""

from __future__ import annotations

import time

from airlock.pow import (
    PowChallenge,
    ProofOfWork,
    issue_pow_challenge,
    solve_pow,
    verify_pow,
    verify_pow_with_store,
)


class TestPowReplayPrevention:
    """Server-side challenge store prevents replay attacks."""

    def test_valid_pow_flow_with_store(self) -> None:
        """Issue challenge, solve, verify_with_store succeeds on first use."""
        challenge = issue_pow_challenge(difficulty=8, ttl=120)
        store: dict[str, PowChallenge] = {challenge.challenge_id: challenge}

        nonce = solve_pow(challenge.prefix, challenge.difficulty)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
        )

        ok, reason = verify_pow_with_store(proof, store)
        assert ok is True
        assert reason is None
        # Challenge consumed -- store should be empty
        assert challenge.challenge_id not in store

    def test_replay_same_challenge_rejected(self) -> None:
        """Solving the same challenge twice fails on the second attempt."""
        challenge = issue_pow_challenge(difficulty=8, ttl=120)
        store: dict[str, PowChallenge] = {challenge.challenge_id: challenge}

        nonce = solve_pow(challenge.prefix, challenge.difficulty)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
        )

        # First verification succeeds
        ok1, reason1 = verify_pow_with_store(proof, store)
        assert ok1 is True
        assert reason1 is None

        # Replay attempt -- challenge already consumed
        ok2, reason2 = verify_pow_with_store(proof, store)
        assert ok2 is False
        assert reason2 == "unknown_challenge"

    def test_unknown_challenge_rejected(self) -> None:
        """A fabricated challenge_id is rejected immediately."""
        store: dict[str, PowChallenge] = {}
        proof = ProofOfWork(
            challenge_id="fabricated_id_does_not_exist",
            prefix="aabbccdd",
            nonce="0",
            difficulty=8,
        )

        ok, reason = verify_pow_with_store(proof, store)
        assert ok is False
        assert reason == "unknown_challenge"

    def test_expired_challenge_rejected(self) -> None:
        """A challenge whose expires_at is in the past is rejected."""
        challenge = issue_pow_challenge(difficulty=8, ttl=120)
        # Manually backdate so the challenge is already expired
        challenge = challenge.model_copy(
            update={"expires_at": time.time() - 1.0},
        )
        store: dict[str, PowChallenge] = {challenge.challenge_id: challenge}

        nonce = solve_pow(challenge.prefix, challenge.difficulty)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
        )

        ok, reason = verify_pow_with_store(proof, store)
        assert ok is False
        assert reason == "expired_challenge"
        # Expired challenge should still be consumed from the store
        assert challenge.challenge_id not in store

    def test_verify_pow_backward_compat(self) -> None:
        """Original verify_pow() still works without any store involvement."""
        challenge = issue_pow_challenge(difficulty=8)
        nonce = solve_pow(challenge.prefix, challenge.difficulty)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
        )
        # The old function accepts no store and returns a plain bool
        assert verify_pow(proof) is True

    def test_wrong_nonce_rejected(self) -> None:
        """Valid challenge but wrong nonce fails with 'invalid_proof'."""
        challenge = issue_pow_challenge(difficulty=20, ttl=120)
        store: dict[str, PowChallenge] = {challenge.challenge_id: challenge}

        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce="definitely_wrong_nonce",
            difficulty=challenge.difficulty,
        )

        ok, reason = verify_pow_with_store(proof, store)
        assert ok is False
        assert reason == "invalid_proof"
        # Challenge should still be consumed (one-time use even on failure)
        assert challenge.challenge_id not in store
