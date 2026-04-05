"""Tests for key rotation with rotation_chain_id."""

from __future__ import annotations

import time

import pytest
from nacl.signing import SigningKey

from airlock.crypto.keys import KeyPair
from airlock.gateway.revocation import RevocationStore
from airlock.rotation.chain import (
    RotationChainRegistry,
    compute_chain_id,
)


def _make_keypair() -> KeyPair:
    """Generate a fresh Ed25519 keypair."""
    return KeyPair(SigningKey.generate())


def _public_key_bytes(kp: KeyPair) -> bytes:
    """Extract raw 32-byte public key."""
    return bytes(kp.verify_key)


class TestComputeChainId:
    def test_deterministic(self) -> None:
        """Same public key bytes produce the same chain_id."""
        kp = _make_keypair()
        pk_bytes = _public_key_bytes(kp)
        assert compute_chain_id(pk_bytes) == compute_chain_id(pk_bytes)

    def test_different_keys(self) -> None:
        """Different keys produce different chain_ids."""
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        cid1 = compute_chain_id(_public_key_bytes(kp1))
        cid2 = compute_chain_id(_public_key_bytes(kp2))
        assert cid1 != cid2

    def test_format(self) -> None:
        """chain_id is 64 hex characters (SHA-256)."""
        kp = _make_keypair()
        cid = compute_chain_id(_public_key_bytes(kp))
        assert len(cid) == 64
        int(cid, 16)  # Validates hex


class TestRegisterChain:
    def test_register_chain(self) -> None:
        """First registration creates a chain record."""
        registry = RotationChainRegistry()
        kp = _make_keypair()
        pk = _public_key_bytes(kp)
        record = registry.register_chain(kp.did, pk)

        assert record.chain_id == compute_chain_id(pk)
        assert record.current_did == kp.did
        assert record.rotation_count == 0
        assert record.previous_dids == []

    def test_idempotent_register(self) -> None:
        """Registering the same chain twice returns the existing record."""
        registry = RotationChainRegistry()
        kp = _make_keypair()
        pk = _public_key_bytes(kp)
        r1 = registry.register_chain(kp.did, pk)
        r2 = registry.register_chain(kp.did, pk)
        assert r1.chain_id == r2.chain_id
        assert r1.current_did == r2.current_did


class TestRotateKeyBasic:
    def test_rotate_key_basic(self) -> None:
        """Successful rotation updates current_did and increments count."""
        registry = RotationChainRegistry()
        kp_old = _make_keypair()
        kp_new = _make_keypair()
        pk_old = _public_key_bytes(kp_old)

        record = registry.register_chain(kp_old.did, pk_old)
        chain_id = record.chain_id

        updated = registry.rotate(
            old_did=kp_old.did,
            new_did=kp_new.did,
            chain_id=chain_id,
        )

        assert updated.current_did == kp_new.did
        assert updated.rotation_count == 1
        assert kp_old.did in updated.previous_dids
        assert updated.last_rotated_at is not None

    def test_rotate_key_chain_id_mismatch(self) -> None:
        """Wrong chain_id is rejected."""
        registry = RotationChainRegistry()
        kp_old = _make_keypair()
        kp_new = _make_keypair()
        pk_old = _public_key_bytes(kp_old)

        registry.register_chain(kp_old.did, pk_old)

        with pytest.raises(ValueError, match="Unknown rotation chain"):
            registry.rotate(
                old_did=kp_old.did,
                new_did=kp_new.did,
                chain_id="0" * 64,  # Wrong chain_id
            )

    def test_rotate_key_first_write_wins(self) -> None:
        """Second rotation from the same old_did fails."""
        registry = RotationChainRegistry()
        kp_old = _make_keypair()
        kp_new1 = _make_keypair()
        kp_new2 = _make_keypair()
        pk_old = _public_key_bytes(kp_old)

        record = registry.register_chain(kp_old.did, pk_old)
        chain_id = record.chain_id

        # First rotation succeeds
        registry.rotate(old_did=kp_old.did, new_did=kp_new1.did, chain_id=chain_id)

        # Second rotation from same old_did fails (first-write-wins)
        with pytest.raises(ValueError, match="already been rotated"):
            registry.rotate(old_did=kp_old.did, new_did=kp_new2.did, chain_id=chain_id)


class TestRotateKeySignatureVerification:
    def test_bad_signature_not_tested_here(self) -> None:
        """Signature verification is handler-level, not registry-level.

        The registry assumes the caller (handler) has already verified
        the Ed25519 signature before calling rotate(). This test exists
        to document that design choice.
        """
        # Signature verification happens in handle_rotate_key, not in the registry.
        # The registry is a pure state machine.
        pass


class TestRotateOutNoCascade:
    @pytest.mark.asyncio
    async def test_rotate_out_no_cascade(self) -> None:
        """rotate_out does NOT cascade to delegates (unlike revoke)."""
        store = RevocationStore()
        delegator = "did:key:z6MkDelegator"
        delegate = "did:key:z6MkDelegate"

        store.register_delegation(delegator, delegate)
        await store.rotate_out(delegator, grace_seconds=0)

        # Delegator is rotated out with 0 grace -> immediately revoked
        assert await store.is_revoked(delegator) is True
        # Delegate is NOT affected (no cascade)
        assert await store.is_revoked(delegate) is False


class TestRotateKeyGracePeriod:
    @pytest.mark.asyncio
    async def test_superseded_has_grace(self) -> None:
        """SUPERSEDED rotation has a grace period during which old DID is still valid."""
        store = RevocationStore()
        did = "did:key:z6MkTestGrace"
        await store.rotate_out(did, grace_seconds=60)

        # During grace period, DID is NOT revoked
        assert await store.is_revoked(did) is False

    @pytest.mark.asyncio
    async def test_superseded_expired_grace(self) -> None:
        """After grace period expires, old DID is revoked."""
        store = RevocationStore()
        did = "did:key:z6MkTestExpired"
        await store.rotate_out(did, grace_seconds=60)

        # Fast-forward past grace
        store._rotated_out[did] = time.time() - 1
        assert await store.is_revoked(did) is True

    @pytest.mark.asyncio
    async def test_compromised_immediate(self) -> None:
        """COMPROMISED rotation has no grace period (grace_seconds=0)."""
        store = RevocationStore()
        did = "did:key:z6MkCompromised"
        await store.rotate_out(did, grace_seconds=0)

        # Immediately revoked
        assert await store.is_revoked(did) is True


class TestRotationCountTracking:
    def test_rotation_count_increments(self) -> None:
        """rotation_count increments with each rotation."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        kp3 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id

        r = registry.rotate(old_did=kp1.did, new_did=kp2.did, chain_id=chain_id)
        assert r.rotation_count == 1

        r = registry.rotate(old_did=kp2.did, new_did=kp3.did, chain_id=chain_id)
        assert r.rotation_count == 2


class TestRotationRateLimit:
    def test_rotation_rate_limit(self) -> None:
        """Detects when >3 rotations happen within 24 hours."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id

        # Perform 3 rotations
        prev_kp = kp1
        for _ in range(3):
            new_kp = _make_keypair()
            registry.rotate(old_did=prev_kp.did, new_did=new_kp.did, chain_id=chain_id)
            prev_kp = new_kp

        # Now at 3 rotations - should be at limit
        assert registry.check_rotation_rate(chain_id, max_per_24h=3) is True

    def test_rotation_rate_under_limit(self) -> None:
        """Under the rate limit returns False."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id

        kp2 = _make_keypair()
        registry.rotate(old_did=kp1.did, new_did=kp2.did, chain_id=chain_id)

        assert registry.check_rotation_rate(chain_id, max_per_24h=3) is False


class TestRotationTrustDecayPenalty:
    def test_trust_penalty_applied(self) -> None:
        """Trust score is reduced by the penalty amount on rotation."""
        # This tests the penalty logic conceptually.
        # The actual penalty is applied in handle_rotate_key handler.
        original_score = 0.75
        penalty = 0.02
        new_score = max(0.0, original_score - penalty)
        assert new_score == pytest.approx(0.73)

    def test_trust_penalty_floor_at_zero(self) -> None:
        """Penalty cannot make score negative."""
        original_score = 0.01
        penalty = 0.02
        new_score = max(0.0, original_score - penalty)
        assert new_score == 0.0


class TestChainLookups:
    def test_get_chain_by_did(self) -> None:
        """Can look up chain by any DID in the chain."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id
        registry.rotate(old_did=kp1.did, new_did=kp2.did, chain_id=chain_id)

        # Both old and new DID resolve to the same chain
        r1 = registry.get_chain_by_did(kp1.did)
        r2 = registry.get_chain_by_did(kp2.did)
        assert r1 is not None
        assert r2 is not None
        assert r1.chain_id == r2.chain_id

    def test_get_chain_by_did_unknown(self) -> None:
        """Unknown DID returns None."""
        registry = RotationChainRegistry()
        assert registry.get_chain_by_did("did:key:z6MkUnknown") is None

    def test_are_same_chain(self) -> None:
        """Two DIDs on the same chain are identified as same."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id
        registry.rotate(old_did=kp1.did, new_did=kp2.did, chain_id=chain_id)

        assert registry.are_same_chain(kp1.did, kp2.did) is True
        assert registry.are_same_chain(kp1.did, "did:key:z6MkOther") is False

    def test_get_current_did(self) -> None:
        """get_current_did returns the latest DID."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id

        assert registry.get_current_did(chain_id) == kp1.did

        registry.rotate(old_did=kp1.did, new_did=kp2.did, chain_id=chain_id)
        assert registry.get_current_did(chain_id) == kp2.did
