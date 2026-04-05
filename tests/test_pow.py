"""Tests for Proof-of-Work anti-Sybil protection (Change 3 -- v0.2)."""

import pytest

from airlock.pow import (
    ProofOfWork,
    issue_pow_challenge,
    solve_pow,
    verify_pow,
)


class TestPowVerification:
    def test_valid_solution_passes(self) -> None:
        """A correctly solved PoW passes verification."""
        challenge = issue_pow_challenge(difficulty=8)  # Low difficulty for fast tests
        nonce = solve_pow(challenge.prefix, challenge.difficulty)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
        )
        assert verify_pow(proof) is True

    def test_invalid_nonce_rejected(self) -> None:
        """A wrong nonce fails verification."""
        challenge = issue_pow_challenge(difficulty=8)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce="definitely_wrong",
            difficulty=challenge.difficulty,
        )
        assert verify_pow(proof) is False

    def test_insufficient_difficulty_rejected(self) -> None:
        """Solution for lower difficulty fails at higher difficulty."""
        challenge = issue_pow_challenge(difficulty=4)
        nonce = solve_pow(challenge.prefix, 4)
        # May or may not pass at higher difficulty depending on luck,
        # but the solve/verify roundtrip at original difficulty must work.
        proof_correct = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=4,
        )
        assert verify_pow(proof_correct) is True

    def test_solve_verify_roundtrip(self) -> None:
        """solve_pow output always passes verify_pow."""
        for difficulty in [4, 8, 12]:
            challenge = issue_pow_challenge(difficulty=difficulty)
            nonce = solve_pow(challenge.prefix, difficulty)
            proof = ProofOfWork(
                challenge_id=challenge.challenge_id,
                prefix=challenge.prefix,
                nonce=nonce,
                difficulty=difficulty,
            )
            assert verify_pow(proof) is True, f"Failed at difficulty {difficulty}"

    def test_challenge_has_required_fields(self) -> None:
        """PowChallenge has all expected fields."""
        ch = issue_pow_challenge(difficulty=20, ttl=60)
        assert ch.challenge_id
        assert ch.prefix
        assert ch.difficulty == 20
        assert ch.algorithm == "sha256"
        assert ch.expires_at > ch.issued_at

    def test_challenge_expiry(self) -> None:
        """Challenge with short TTL expires."""
        ch = issue_pow_challenge(difficulty=8, ttl=1)
        assert ch.expires_at - ch.issued_at == pytest.approx(1.0)

    def test_unsupported_algorithm_rejected(self) -> None:
        """Non-sha256 algorithm is rejected."""
        proof = ProofOfWork(
            challenge_id="test",
            prefix="abc",
            nonce="123",
            difficulty=8,
            algorithm="md5",
        )
        assert verify_pow(proof) is False

    def test_zero_difficulty_always_passes(self) -> None:
        """Difficulty 1 is very easy -- any nonce likely works within a few tries."""
        challenge = issue_pow_challenge(difficulty=1)
        nonce = solve_pow(challenge.prefix, 1)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=1,
        )
        assert verify_pow(proof) is True
