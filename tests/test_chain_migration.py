"""Tests for per-DID state migration to chain_id."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest
from nacl.signing import SigningKey

from airlock.crypto.keys import KeyPair
from airlock.gateway.rate_limit import (
    DIDRateLimiter,
    InMemorySlidingWindow,
    resolve_rate_key,
)
from airlock.gateway.revocation import RevocationStore
from airlock.rotation.chain import (
    RotationChainRegistry,
    compute_chain_id,
)
from airlock.semantic.fingerprint import (
    AnswerFingerprint,
    FingerprintStore,
)


def _make_keypair() -> KeyPair:
    return KeyPair(SigningKey.generate())


def _public_key_bytes(kp: KeyPair) -> bytes:
    return bytes(kp.verify_key)


class TestReputationInheritsViaChainId:
    def test_reputation_inherits_via_chain_id(self) -> None:
        """After rotation, new DID has same score via chain_id.

        Tests the schema-level support: TrustScore now carries
        rotation_chain_id which links the new DID's score to the chain.
        """
        from airlock.schemas.reputation import TrustScore

        kp1 = _make_keypair()
        kp2 = _make_keypair()
        pk1 = _public_key_bytes(kp1)
        chain_id = compute_chain_id(pk1)

        now = datetime.now(UTC)
        original = TrustScore(
            agent_did=kp1.did,
            score=0.85,
            rotation_chain_id=chain_id,
            created_at=now,
            updated_at=now,
        )

        # Simulate transfer: copy score to new DID, apply penalty
        penalty = 0.02
        transferred = original.model_copy(
            update={
                "agent_did": kp2.did,
                "score": max(0.0, original.score - penalty),
                "updated_at": datetime.now(UTC),
            }
        )

        assert transferred.agent_did == kp2.did
        assert transferred.rotation_chain_id == chain_id
        assert transferred.score == pytest.approx(0.83)


class TestRateLimitContinuesViaChainId:
    @pytest.mark.asyncio
    async def test_rate_limit_continues_via_chain_id(self) -> None:
        """Rate limit counter follows chain across rotation."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id

        # Both DIDs should resolve to the same rate-limit key
        key1 = resolve_rate_key(kp1.did, registry)
        assert key1 == f"chain:{chain_id}"

        # After rotation, new DID resolves to same key
        registry.rotate(old_did=kp1.did, new_did=kp2.did, chain_id=chain_id)
        key2 = resolve_rate_key(kp2.did, registry)
        assert key1 == key2

    @pytest.mark.asyncio
    async def test_rate_limit_fallback_without_registry(self) -> None:
        """Without a chain registry, falls back to raw DID."""
        did = "did:key:z6MkTest123"
        key = resolve_rate_key(did, None)
        assert key == did

    @pytest.mark.asyncio
    async def test_did_rate_limiter_with_chain(self) -> None:
        """DIDRateLimiter uses chain_id when registry is available."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        pk1 = _public_key_bytes(kp1)
        registry.register_chain(kp1.did, pk1)

        backend = InMemorySlidingWindow(max_events=5, window_seconds=60.0)
        limiter = DIDRateLimiter(backend, chain_registry=registry)

        # Should not be rate limited initially
        assert await limiter.is_rate_limited(kp1.did) is False


class TestFingerprintSameChainNotFlagged:
    @pytest.mark.asyncio
    async def test_same_chain_not_flagged_exact(self) -> None:
        """Same chain DIDs don't flag as exact duplicate."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id
        registry.rotate(old_did=kp1.did, new_did=kp2.did, chain_id=chain_id)

        store = FingerprintStore(
            window_size=100,
            hamming_threshold=5,
            chain_registry=registry,
        )

        # Old DID submits a fingerprint
        fp1 = AnswerFingerprint(
            session_id="s1",
            agent_did=kp1.did,
            exact_hash="abc123",
            simhash=12345,
            question_hash="q1",
            timestamp=time.time(),
        )
        await store.add(fp1)

        # New DID (same chain) submits identical fingerprint
        fp2 = AnswerFingerprint(
            session_id="s2",
            agent_did=kp2.did,
            exact_hash="abc123",
            simhash=12345,
            question_hash="q1",
            timestamp=time.time(),
        )
        result = await store.check(fp2)

        # Should NOT be flagged as duplicate (same agent, different DID)
        assert result.is_exact_duplicate is False
        assert result.is_near_duplicate is False

    @pytest.mark.asyncio
    async def test_different_chain_flagged(self) -> None:
        """Different chain DIDs DO flag as exact duplicate."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        kp2 = _make_keypair()

        registry.register_chain(kp1.did, _public_key_bytes(kp1))
        registry.register_chain(kp2.did, _public_key_bytes(kp2))

        store = FingerprintStore(
            window_size=100,
            hamming_threshold=5,
            chain_registry=registry,
        )

        fp1 = AnswerFingerprint(
            session_id="s1",
            agent_did=kp1.did,
            exact_hash="same_hash",
            simhash=99999,
            question_hash="q1",
            timestamp=time.time(),
        )
        await store.add(fp1)

        fp2 = AnswerFingerprint(
            session_id="s2",
            agent_did=kp2.did,
            exact_hash="same_hash",
            simhash=99999,
            question_hash="q1",
            timestamp=time.time(),
        )
        result = await store.check(fp2)

        # SHOULD be flagged (different agents with identical answers)
        assert result.is_exact_duplicate is True

    @pytest.mark.asyncio
    async def test_same_chain_near_duplicate_not_flagged(self) -> None:
        """Same chain DIDs don't flag as near duplicate either."""
        registry = RotationChainRegistry()
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id
        registry.rotate(old_did=kp1.did, new_did=kp2.did, chain_id=chain_id)

        store = FingerprintStore(
            window_size=100,
            hamming_threshold=5,
            chain_registry=registry,
        )

        fp1 = AnswerFingerprint(
            session_id="s1",
            agent_did=kp1.did,
            exact_hash="hash1",
            simhash=0b1111111100000000,
            question_hash="q1",
            timestamp=time.time(),
        )
        await store.add(fp1)

        # Near-duplicate simhash (hamming distance = 2)
        fp2 = AnswerFingerprint(
            session_id="s2",
            agent_did=kp2.did,
            exact_hash="hash2",
            simhash=0b1111111100000011,
            question_hash="q1",
            timestamp=time.time(),
        )
        result = await store.check(fp2)

        assert result.is_near_duplicate is False


class TestRevokedOldDidAfterRotation:
    @pytest.mark.asyncio
    async def test_old_did_superseded_not_revoked(self) -> None:
        """Old DID shows as superseded during grace, not permanently revoked."""
        store = RevocationStore()
        old_did = "did:key:z6MkOldDid"

        await store.rotate_out(old_did, grace_seconds=60)

        # During grace: not revoked
        assert await store.is_revoked(old_did) is False
        # Not permanently revoked
        assert store.get_revocation_reason(old_did) is None
        # Not in suspended set
        assert await store.is_suspended(old_did) is False

    @pytest.mark.asyncio
    async def test_rotate_out_already_revoked(self) -> None:
        """Cannot rotate_out a DID that is already permanently revoked."""
        store = RevocationStore()
        did = "did:key:z6MkAlreadyRevoked"

        await store.revoke(did)
        result = await store.rotate_out(did, grace_seconds=60)
        assert result is False

    @pytest.mark.asyncio
    async def test_rotate_out_sync_check(self) -> None:
        """is_revoked_sync respects rotate_out grace period."""
        store = RevocationStore()
        did = "did:key:z6MkSyncCheck"

        await store.rotate_out(did, grace_seconds=60)
        # During grace: not revoked
        assert store.is_revoked_sync(did) is False

        # Fast-forward past grace
        store._rotated_out[did] = time.time() - 1
        assert store.is_revoked_sync(did) is True
