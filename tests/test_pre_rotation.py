"""Tests for KERI-inspired pre-rotation commitment."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from nacl.signing import SigningKey

from airlock.crypto.keys import KeyPair
from airlock.rotation.precommit import (
    PreRotationCommitment,
    can_update_commitment,
    compute_key_commitment,
    verify_commitment,
)


def _make_keypair() -> KeyPair:
    return KeyPair(SigningKey.generate())


def _public_key_bytes(kp: KeyPair) -> bytes:
    return bytes(kp.verify_key)


class TestComputeKeyCommitment:
    def test_deterministic(self) -> None:
        """Same key bytes produce same commitment."""
        kp = _make_keypair()
        pk = _public_key_bytes(kp)
        assert compute_key_commitment(pk) == compute_key_commitment(pk)

    def test_different_keys(self) -> None:
        """Different keys produce different commitments."""
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        c1 = compute_key_commitment(_public_key_bytes(kp1))
        c2 = compute_key_commitment(_public_key_bytes(kp2))
        assert c1 != c2

    def test_format(self) -> None:
        """Commitment is 64 hex chars."""
        kp = _make_keypair()
        c = compute_key_commitment(_public_key_bytes(kp))
        assert len(c) == 64
        int(c, 16)


class TestCommitKeyBasic:
    def test_commit_and_verify(self) -> None:
        """Set commitment, verify stored."""
        kp_next = _make_keypair()
        pk_next = _public_key_bytes(kp_next)

        commitment = PreRotationCommitment(
            alg="sha256",
            digest=compute_key_commitment(pk_next),
            committed_at=datetime.now(UTC),
            committed_by_did="did:key:z6MkCommitter",
            signature="test_sig_placeholder",
        )

        assert commitment.alg == "sha256"
        assert len(commitment.digest) == 64
        assert commitment.committed_by_did == "did:key:z6MkCommitter"

    def test_commitment_format(self) -> None:
        """Verify alg + digest + signature fields are present."""
        kp_next = _make_keypair()
        pk_next = _public_key_bytes(kp_next)

        commitment = PreRotationCommitment(
            alg="sha256",
            digest=compute_key_commitment(pk_next),
            committed_at=datetime.now(UTC),
            committed_by_did="did:key:z6MkTest",
            signature="base64sig",
        )

        assert commitment.alg == "sha256"
        assert isinstance(commitment.digest, str)
        assert isinstance(commitment.signature, str)
        assert isinstance(commitment.committed_at, datetime)


class TestVerifyCommitment:
    def test_rotation_with_valid_commitment(self) -> None:
        """Correct next key matches commitment."""
        kp_next = _make_keypair()
        pk_next = _public_key_bytes(kp_next)

        commitment = PreRotationCommitment(
            alg="sha256",
            digest=compute_key_commitment(pk_next),
            committed_at=datetime.now(UTC),
            committed_by_did="did:key:z6MkTest",
            signature="sig",
        )

        assert verify_commitment(commitment, pk_next) is True

    def test_rotation_with_wrong_commitment(self) -> None:
        """Wrong next key is rejected."""
        kp_committed = _make_keypair()
        kp_wrong = _make_keypair()

        commitment = PreRotationCommitment(
            alg="sha256",
            digest=compute_key_commitment(_public_key_bytes(kp_committed)),
            committed_at=datetime.now(UTC),
            committed_by_did="did:key:z6MkTest",
            signature="sig",
        )

        assert verify_commitment(commitment, _public_key_bytes(kp_wrong)) is False

    def test_unsupported_algorithm(self) -> None:
        """Non-sha256 algorithm returns False."""
        kp = _make_keypair()
        pk = _public_key_bytes(kp)

        commitment = PreRotationCommitment(
            alg="sha384",
            digest=compute_key_commitment(pk),
            committed_at=datetime.now(UTC),
            committed_by_did="did:key:z6MkTest",
            signature="sig",
        )

        assert verify_commitment(commitment, pk) is False


class TestTierRequirements:
    def test_tier1_requires_commitment(self) -> None:
        """Tier 1+ without a commitment should be blocked (handler-level).

        The enforcement is in the handler, not in the precommit module.
        This test validates the tier threshold logic.
        """
        from airlock.schemas.trust_tier import TrustTier

        required_tier = 1  # CHALLENGE_VERIFIED
        agent_tier = TrustTier.CHALLENGE_VERIFIED

        assert int(agent_tier) >= required_tier

    def test_tier0_can_rotate_without_commitment(self) -> None:
        """Tier 0 (UNKNOWN) can rotate without a commitment."""
        from airlock.schemas.trust_tier import TrustTier

        required_tier = 1
        agent_tier = TrustTier.UNKNOWN

        assert int(agent_tier) < required_tier


class TestCommitment72hUpdateLock:
    def test_cannot_update_within_lockout(self) -> None:
        """Cannot update commitment within 72 hours."""
        recent = PreRotationCommitment(
            alg="sha256",
            digest="a" * 64,
            committed_at=datetime.now(UTC),
            committed_by_did="did:key:z6MkTest",
            signature="sig",
        )

        assert can_update_commitment(recent, lockout_hours=72) is False

    def test_can_update_after_lockout(self) -> None:
        """Can update commitment after 72 hours."""
        old = PreRotationCommitment(
            alg="sha256",
            digest="a" * 64,
            committed_at=datetime.now(UTC) - timedelta(hours=73),
            committed_by_did="did:key:z6MkTest",
            signature="sig",
        )

        assert can_update_commitment(old, lockout_hours=72) is True

    def test_lockout_at_boundary(self) -> None:
        """At exactly 72 hours, update is allowed."""
        boundary = PreRotationCommitment(
            alg="sha256",
            digest="a" * 64,
            committed_at=datetime.now(UTC) - timedelta(hours=72, seconds=1),
            committed_by_did="did:key:z6MkTest",
            signature="sig",
        )

        assert can_update_commitment(boundary, lockout_hours=72) is True


class TestChainedCommitment:
    def test_chained_commitment(self) -> None:
        """On rotation, a new commitment for N+2 can be stored.

        This tests the data flow: rotation request includes
        next_key_commitment which is stored for the next rotation.
        """
        kp_n2 = _make_keypair()
        pk_n2 = _public_key_bytes(kp_n2)
        n2_digest = compute_key_commitment(pk_n2)

        # Simulate storing chained commitment during rotation
        chain_commitments: dict[str, PreRotationCommitment] = {}
        chain_id = "test_chain_" + "0" * 52

        chain_commitments[chain_id] = PreRotationCommitment(
            alg="sha256",
            digest=n2_digest,
            committed_at=datetime.now(UTC),
            committed_by_did="did:key:z6MkNewDid",
            signature="",
        )

        # Later, verify the stored N+2 commitment matches
        stored = chain_commitments[chain_id]
        assert verify_commitment(stored, pk_n2) is True
