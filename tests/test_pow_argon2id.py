"""Tests for Argon2id memory-hard Proof-of-Work with SHA-256 pre-filter.

Validates the two-layer PoW scheme: Argon2id computation followed by a
SHA-256 leading-zero-bits check.  Covers challenge issuance, solve/verify
round-trips, replay prevention, DID binding, preset validation, and
backward compatibility with the original SHA-256 Hashcash path.
"""

from __future__ import annotations

import time

import pytest

from airlock.pow import (
    ARGON2ID_PRESETS,
    Argon2idParams,
    PowChallenge,
    ProofOfWork,
    _has_leading_zero_bits,
    argon2_available,
    issue_argon2id_challenge,
    issue_pow_challenge,
    solve_argon2id,
    solve_pow,
    verify_argon2id_pow,
    verify_argon2id_pow_with_store,
    verify_pow,
    verify_pow_with_store,
)

# All tests in this module require argon2-cffi
pytestmark = pytest.mark.skipif(not argon2_available(), reason="argon2-cffi not installed")

# Use low pre_filter_bits for fast tests (4 bits ~ 1/16 average attempts)
_FAST_BITS = 4


class TestArgon2idChallengeIssue:
    """Challenge issuance produces well-formed Argon2id challenges."""

    def test_argon2id_challenge_issue(self) -> None:
        """Issued challenge has all expected fields and correct defaults."""
        challenge = issue_argon2id_challenge(preset="standard", pre_filter_bits=12)
        assert challenge.algorithm == "argon2id"
        assert challenge.preset == "standard"
        assert challenge.pre_filter_bits == 12
        assert challenge.bound_did is None
        assert challenge.challenge_id
        assert challenge.prefix
        assert challenge.expires_at > challenge.issued_at
        assert challenge.argon2id_params.memory_cost_kb == 49_152
        assert challenge.argon2id_params.time_cost == 3
        assert challenge.argon2id_params.parallelism == 1
        assert challenge.argon2id_params.hash_len == 32

    def test_argon2id_challenge_with_bound_did(self) -> None:
        """Challenge can be bound to a specific DID."""
        did = "did:key:z6MkTestDid"
        challenge = issue_argon2id_challenge(
            preset="light",
            bound_did=did,
            pre_filter_bits=_FAST_BITS,
        )
        assert challenge.bound_did == did

    def test_argon2id_invalid_preset_raises(self) -> None:
        """Unknown preset name raises ValueError."""
        with pytest.raises(ValueError, match="Unknown Argon2id preset"):
            issue_argon2id_challenge(preset="ultra")


class TestArgon2idSolveAndVerify:
    """End-to-end solve/verify round-trips."""

    def test_argon2id_solve_and_verify(self) -> None:
        """Solve a challenge and verify the proof succeeds."""
        challenge = issue_argon2id_challenge(
            preset="light",
            pre_filter_bits=_FAST_BITS,
        )
        nonce = solve_argon2id(challenge)

        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
            algorithm="argon2id",
        )
        ok, reason = verify_argon2id_pow(proof, challenge)
        assert ok is True
        assert reason is None

    def test_argon2id_all_presets_solve_verify(self) -> None:
        """Solve+verify works for each of the three presets."""
        for preset_name in ARGON2ID_PRESETS:
            challenge = issue_argon2id_challenge(
                preset=preset_name,
                pre_filter_bits=_FAST_BITS,
            )
            nonce = solve_argon2id(challenge)
            proof = ProofOfWork(
                challenge_id=challenge.challenge_id,
                prefix=challenge.prefix,
                nonce=nonce,
                difficulty=challenge.difficulty,
                algorithm="argon2id",
            )
            ok, reason = verify_argon2id_pow(proof, challenge)
            assert ok is True, f"Failed for preset {preset_name}: {reason}"

    def test_argon2id_solve_light_preset(self) -> None:
        """Light preset solves in reasonable time (< 30s with low pre_filter)."""
        challenge = issue_argon2id_challenge(
            preset="light",
            pre_filter_bits=_FAST_BITS,
        )
        start = time.monotonic()
        nonce = solve_argon2id(challenge)
        elapsed = time.monotonic() - start

        # Sanity: should finish within 30 seconds even on slow hardware
        assert elapsed < 30.0, f"Light preset took {elapsed:.1f}s"
        assert nonce  # non-empty


class TestArgon2idPreFilter:
    """SHA-256 pre-filter rejects invalid proofs cheaply."""

    def test_argon2id_pre_filter_rejects_garbage(self) -> None:
        """A random nonce almost certainly fails the pre-filter."""
        challenge = issue_argon2id_challenge(
            preset="light",
            pre_filter_bits=_FAST_BITS,
        )
        # Use a nonce that is extremely unlikely to pass
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce="garbage_nonce_will_not_pass",
            difficulty=challenge.difficulty,
            algorithm="argon2id",
        )
        ok, reason = verify_argon2id_pow(proof, challenge)
        # With 4 bits, there is a 1/16 chance this passes by accident.
        # Use multiple nonces to ensure at least one fails.
        if ok:
            # Try again with a different garbage nonce
            proof2 = proof.model_copy(update={"nonce": "another_garbage_0xDEAD"})
            ok2, reason2 = verify_argon2id_pow(proof2, challenge)
            if ok2:
                # Extremely unlikely both pass -- but possible.  Skip gracefully.
                pytest.skip("Unlikely: both garbage nonces passed pre-filter")
            assert reason2 == "pre_filter_failed"
        else:
            assert reason == "pre_filter_failed"

    def test_argon2id_wrong_nonce_rejected(self) -> None:
        """A wrong nonce fails full verification."""
        challenge = issue_argon2id_challenge(
            preset="light",
            pre_filter_bits=_FAST_BITS,
        )
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce="wrong_nonce_value",
            difficulty=challenge.difficulty,
            algorithm="argon2id",
        )
        ok, reason = verify_argon2id_pow(proof, challenge)
        assert ok is False
        # Reason is "pre_filter_failed" since the wrong nonce won't pass
        assert reason == "pre_filter_failed"


class TestArgon2idReplayPrevention:
    """Server-side challenge store enforces one-time use."""

    def test_argon2id_replay_prevention(self) -> None:
        """Same challenge twice fails on second attempt."""
        challenge = issue_argon2id_challenge(
            preset="light",
            pre_filter_bits=_FAST_BITS,
        )
        store: dict[str, PowChallenge] = {challenge.challenge_id: challenge}
        nonce = solve_argon2id(challenge)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
            algorithm="argon2id",
        )

        # First verification succeeds
        ok1, reason1 = verify_argon2id_pow_with_store(proof, store)
        assert ok1 is True
        assert reason1 is None

        # Replay attempt fails
        ok2, reason2 = verify_argon2id_pow_with_store(proof, store)
        assert ok2 is False
        assert reason2 == "unknown_challenge"

    def test_argon2id_expired_challenge(self) -> None:
        """Expired Argon2id challenge is rejected."""
        challenge = issue_argon2id_challenge(
            preset="light",
            pre_filter_bits=_FAST_BITS,
        )
        # Backdate the challenge so it is already expired
        expired = challenge.model_copy(update={"expires_at": time.time() - 1.0})
        store: dict[str, PowChallenge] = {expired.challenge_id: expired}

        nonce = solve_argon2id(challenge)
        proof = ProofOfWork(
            challenge_id=expired.challenge_id,
            prefix=expired.prefix,
            nonce=nonce,
            difficulty=expired.difficulty,
            algorithm="argon2id",
        )
        ok, reason = verify_argon2id_pow_with_store(proof, store)
        assert ok is False
        assert reason == "expired_challenge"


class TestArgon2idBoundDid:
    """DID-binding prevents PoW sharing between agents."""

    def test_argon2id_bound_did_mismatch(self) -> None:
        """Challenge bound to DID A, verified with DID B fails."""
        did_a = "did:key:z6MkAgentA"
        did_b = "did:key:z6MkAgentB"
        challenge = issue_argon2id_challenge(
            preset="light",
            bound_did=did_a,
            pre_filter_bits=_FAST_BITS,
        )
        nonce = solve_argon2id(challenge)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
            algorithm="argon2id",
        )
        ok, reason = verify_argon2id_pow(proof, challenge, bound_did=did_b)
        assert ok is False
        assert reason == "bound_did_mismatch"

    def test_argon2id_bound_did_match(self) -> None:
        """Challenge bound to DID A, verified with DID A succeeds."""
        did_a = "did:key:z6MkAgentA"
        challenge = issue_argon2id_challenge(
            preset="light",
            bound_did=did_a,
            pre_filter_bits=_FAST_BITS,
        )
        nonce = solve_argon2id(challenge)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
            algorithm="argon2id",
        )
        ok, reason = verify_argon2id_pow(proof, challenge, bound_did=did_a)
        assert ok is True
        assert reason is None

    def test_argon2id_bound_did_none_when_challenge_expects(self) -> None:
        """Challenge bound to a DID but no DID provided at verify time fails."""
        challenge = issue_argon2id_challenge(
            preset="light",
            bound_did="did:key:z6MkBound",
            pre_filter_bits=_FAST_BITS,
        )
        nonce = solve_argon2id(challenge)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
            algorithm="argon2id",
        )
        ok, reason = verify_argon2id_pow(proof, challenge, bound_did=None)
        assert ok is False
        assert reason == "bound_did_mismatch"


class TestArgon2idPresets:
    """Preset validation and parameter correctness."""

    def test_argon2id_presets_valid(self) -> None:
        """All three presets produce valid Argon2idParams."""
        assert set(ARGON2ID_PRESETS.keys()) == {"light", "standard", "hardened"}
        for name, params in ARGON2ID_PRESETS.items():
            assert isinstance(params, Argon2idParams), f"{name} not Argon2idParams"
            assert params.memory_cost_kb >= 1024
            assert params.time_cost >= 1
            assert params.parallelism >= 1
            assert params.hash_len == 32

    def test_presets_ordered_by_cost(self) -> None:
        """Hardened is more expensive than standard, which is more expensive than light."""
        light = ARGON2ID_PRESETS["light"]
        standard = ARGON2ID_PRESETS["standard"]
        hardened = ARGON2ID_PRESETS["hardened"]
        assert light.memory_cost_kb < standard.memory_cost_kb < hardened.memory_cost_kb
        assert light.time_cost < standard.time_cost < hardened.time_cost


class TestSha256BackwardCompat:
    """Existing SHA-256 flow still works alongside Argon2id."""

    def test_sha256_backward_compat(self) -> None:
        """SHA-256 solve/verify round-trip unaffected by Argon2id additions."""
        challenge = issue_pow_challenge(difficulty=8, ttl=120)
        nonce = solve_pow(challenge.prefix, challenge.difficulty)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
            algorithm="sha256",
        )
        assert verify_pow(proof) is True

    def test_sha256_with_store_still_works(self) -> None:
        """verify_pow_with_store still works for SHA-256 challenges."""
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


class TestVerifyPowDispatches:
    """verify_pow() routes to the correct algorithm handler."""

    def test_verify_pow_dispatches_correctly(self) -> None:
        """verify_pow routes sha256 to SHA-256 path and argon2id returns False
        (stateless Argon2id is not possible)."""
        # SHA-256 path
        challenge = issue_pow_challenge(difficulty=8)
        nonce = solve_pow(challenge.prefix, challenge.difficulty)
        sha_proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
            algorithm="sha256",
        )
        assert verify_pow(sha_proof) is True

        # Argon2id path (stateless -- always False)
        argon_proof = ProofOfWork(
            challenge_id="test",
            prefix="test",
            nonce="0",
            difficulty=8,
            algorithm="argon2id",
        )
        assert verify_pow(argon_proof) is False

        # Unknown algorithm
        unknown_proof = ProofOfWork(
            challenge_id="test",
            prefix="test",
            nonce="0",
            difficulty=8,
            algorithm="scrypt",
        )
        assert verify_pow(unknown_proof) is False

    def test_verify_pow_with_store_dispatches_argon2id(self) -> None:
        """verify_pow_with_store correctly dispatches Argon2id challenges."""
        challenge = issue_argon2id_challenge(
            preset="light",
            pre_filter_bits=_FAST_BITS,
        )
        store: dict[str, PowChallenge] = {challenge.challenge_id: challenge}
        nonce = solve_argon2id(challenge)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
            algorithm="argon2id",
        )
        ok, reason = verify_pow_with_store(proof, store)
        assert ok is True
        assert reason is None


class TestLeadingZeroBits:
    """Unit tests for the shared _has_leading_zero_bits helper."""

    def test_zero_bytes(self) -> None:
        assert _has_leading_zero_bits(b"\x00\x00\xff", 16) is True

    def test_partial_bits(self) -> None:
        # 0x0f = 0000_1111 => 4 leading zero bits
        assert _has_leading_zero_bits(b"\x0f", 4) is True
        assert _has_leading_zero_bits(b"\x0f", 5) is False

    def test_no_bits_required(self) -> None:
        assert _has_leading_zero_bits(b"\xff", 0) is True
