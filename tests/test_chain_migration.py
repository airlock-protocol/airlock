"""Tests for per-DID state migration to chain_id."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from nacl.signing import SigningKey

from airlock.audit.trail import AuditTrail
from airlock.crypto.keys import KeyPair
from airlock.gateway.rate_limit import (
    DIDRateLimiter,
    InMemorySlidingWindow,
    resolve_rate_key,
)
from airlock.gateway.revocation import RevocationStore
from airlock.rotation.chain import (
    RotationChainRecord,
    RotationChainRegistry,
    compute_chain_id,
)
from airlock.schemas.session import VerificationSession, VerificationState
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


# ---------------------------------------------------------------------------
# Unit 3: Session/Audit Chain Migration
# ---------------------------------------------------------------------------


class TestSessionHasRotationChainId:
    def test_session_default_none(self) -> None:
        """VerificationSession.rotation_chain_id defaults to None."""
        now = datetime.now(UTC)
        session = VerificationSession(
            session_id="test-session-1",
            state=VerificationState.INITIATED,
            initiator_did="did:key:z6MkInitiator",
            target_did="did:key:z6MkTarget",
            created_at=now,
            updated_at=now,
        )
        assert session.rotation_chain_id is None

    def test_session_with_chain_id(self) -> None:
        """VerificationSession accepts rotation_chain_id."""
        now = datetime.now(UTC)
        kp = _make_keypair()
        chain_id = compute_chain_id(_public_key_bytes(kp))

        session = VerificationSession(
            session_id="test-session-2",
            state=VerificationState.HANDSHAKE_RECEIVED,
            initiator_did=kp.did,
            target_did="did:key:z6MkTarget",
            created_at=now,
            updated_at=now,
            rotation_chain_id=chain_id,
        )
        assert session.rotation_chain_id == chain_id
        assert len(session.rotation_chain_id) == 64  # SHA-256 hex

    def test_session_serialization_round_trip(self) -> None:
        """rotation_chain_id survives JSON serialization round-trip."""
        now = datetime.now(UTC)
        chain_id = "a" * 64
        session = VerificationSession(
            session_id="test-session-3",
            state=VerificationState.INITIATED,
            initiator_did="did:key:z6MkInitiator",
            target_did="did:key:z6MkTarget",
            created_at=now,
            updated_at=now,
            rotation_chain_id=chain_id,
        )
        data = session.model_dump(mode="json")
        assert data["rotation_chain_id"] == chain_id

        restored = VerificationSession.model_validate(data)
        assert restored.rotation_chain_id == chain_id


class TestAuditEntryChainIdPopulated:
    @pytest.mark.asyncio
    async def test_audit_entry_receives_chain_id(self) -> None:
        """Audit entries receive rotation_chain_id when passed."""
        trail = AuditTrail()
        chain_id = "b" * 64

        entry = await trail.append(
            event_type="handshake_initiated",
            actor_did="did:key:z6MkInitiator",
            subject_did="did:key:z6MkTarget",
            session_id="sess-1",
            rotation_chain_id=chain_id,
        )
        assert entry.rotation_chain_id == chain_id

    @pytest.mark.asyncio
    async def test_audit_entry_none_without_chain(self) -> None:
        """Audit entries default to None when no chain_id provided."""
        trail = AuditTrail()
        entry = await trail.append(
            event_type="agent_registered",
            actor_did="did:key:z6MkSomeAgent",
        )
        assert entry.rotation_chain_id is None

    @pytest.mark.asyncio
    async def test_audit_chain_integrity_with_chain_id(self) -> None:
        """Hash chain stays valid when rotation_chain_id is populated."""
        trail = AuditTrail()
        chain_id = "c" * 64

        await trail.append(
            event_type="first",
            actor_did="did:key:z1",
            rotation_chain_id=chain_id,
        )
        await trail.append(
            event_type="second",
            actor_did="did:key:z2",
            rotation_chain_id=chain_id,
        )
        await trail.append(
            event_type="third",
            actor_did="did:key:z3",
            rotation_chain_id=None,
        )

        valid, msg = await trail.verify_chain()
        assert valid is True
        assert msg == "ok"

    @pytest.mark.asyncio
    async def test_audit_filtered_by_chain_id(self) -> None:
        """get_entries_filtered returns only entries matching chain_id."""
        trail = AuditTrail()
        chain_a = "a" * 64
        chain_b = "b" * 64

        await trail.append(
            event_type="e1", actor_did="did:key:z1", rotation_chain_id=chain_a,
        )
        await trail.append(
            event_type="e2", actor_did="did:key:z2", rotation_chain_id=chain_b,
        )
        await trail.append(
            event_type="e3", actor_did="did:key:z1", rotation_chain_id=chain_a,
        )

        filtered = await trail.get_entries_filtered(chain_id=chain_a)
        assert len(filtered) == 2
        assert all(e.rotation_chain_id == chain_a for e in filtered)

    @pytest.mark.asyncio
    async def test_audit_filtered_by_did(self) -> None:
        """get_entries_filtered returns only entries matching actor_did."""
        trail = AuditTrail()
        did1 = "did:key:z6MkDid1"
        did2 = "did:key:z6MkDid2"

        await trail.append(event_type="e1", actor_did=did1)
        await trail.append(event_type="e2", actor_did=did2)
        await trail.append(event_type="e3", actor_did=did1)

        filtered = await trail.get_entries_filtered(actor_did=did1)
        assert len(filtered) == 2
        assert all(e.actor_did == did1 for e in filtered)

    @pytest.mark.asyncio
    async def test_audit_filtered_combined(self) -> None:
        """get_entries_filtered supports both chain_id and actor_did."""
        trail = AuditTrail()
        chain_a = "a" * 64
        did1 = "did:key:z6MkDid1"
        did2 = "did:key:z6MkDid2"

        await trail.append(
            event_type="e1", actor_did=did1, rotation_chain_id=chain_a,
        )
        await trail.append(
            event_type="e2", actor_did=did2, rotation_chain_id=chain_a,
        )
        await trail.append(
            event_type="e3", actor_did=did1, rotation_chain_id=None,
        )

        filtered = await trail.get_entries_filtered(
            chain_id=chain_a, actor_did=did1,
        )
        assert len(filtered) == 1
        assert filtered[0].event_type == "e1"

    @pytest.mark.asyncio
    async def test_audit_filtered_pagination(self) -> None:
        """get_entries_filtered respects limit and offset."""
        trail = AuditTrail()
        chain_a = "a" * 64

        for i in range(10):
            await trail.append(
                event_type=f"e_{i}",
                actor_did="did:key:z1",
                rotation_chain_id=chain_a,
            )

        page1 = await trail.get_entries_filtered(
            chain_id=chain_a, limit=3, offset=0,
        )
        assert len(page1) == 3

        page2 = await trail.get_entries_filtered(
            chain_id=chain_a, limit=3, offset=3,
        )
        assert len(page2) == 3

        # No overlap
        ids1 = {e.entry_id for e in page1}
        ids2 = {e.entry_id for e in page2}
        assert ids1.isdisjoint(ids2)


class TestReputationResolvesThroughChain:
    def test_orchestrator_reputation_uses_current_did(self) -> None:
        """_node_check_reputation resolves through chain to current_did.

        Uses a mock chain_registry and reputation store to verify that
        when initiator_did is an old rotated DID, the reputation lookup
        uses the chain's current_did instead.
        """
        from airlock.reputation.scoring import INITIAL_SCORE
        from airlock.schemas.reputation import TrustScore

        kp1 = _make_keypair()
        kp2 = _make_keypair()
        pk1 = _public_key_bytes(kp1)

        registry = RotationChainRegistry()
        record = registry.register_chain(kp1.did, pk1)
        chain_id = record.chain_id
        registry.rotate(old_did=kp1.did, new_did=kp2.did, chain_id=chain_id)

        # Create a mock reputation store
        mock_reputation = MagicMock()
        now = datetime.now(UTC)
        trusted_score = TrustScore(
            agent_did=kp2.did,
            score=0.85,
            interaction_count=10,
            successful_verifications=8,
            failed_verifications=2,
            created_at=now,
            updated_at=now,
        )
        mock_reputation.get_or_default.return_value = trusted_score

        # Import and instantiate orchestrator with minimal config
        from airlock.engine.orchestrator import (
            OrchestrationState,
            VerificationOrchestrator,
        )

        orchestrator = VerificationOrchestrator(
            reputation_store=mock_reputation,
            agent_registry={},
            airlock_did="did:key:z6MkGateway",
            chain_registry=registry,
        )

        # Build a state where session.initiator_did is the OLD (rotated) DID
        session = VerificationSession(
            session_id="test-session",
            state=VerificationState.SIGNATURE_VERIFIED,
            initiator_did=kp1.did,  # old DID
            target_did="did:key:z6MkTarget",
            created_at=now,
            updated_at=now,
        )

        state: OrchestrationState = {
            "session": session,
            "handshake": MagicMock(privacy_mode=None),
            "challenge": None,
            "challenge_response": None,
            "check_results": [],
            "trust_score": 0.5,
            "verdict": None,
            "error": None,
            "failed_at": None,
            "_sig_valid": True,
            "_vc_valid": False,
            "_routing": "challenge",
            "_challenge_outcome": None,
            "_tier": 0,
            "_local_only": False,
        }

        result = orchestrator._node_check_reputation(state)

        # Reputation should have been looked up with the CURRENT DID (kp2)
        mock_reputation.get_or_default.assert_called_once_with(kp2.did)
        assert result["trust_score"] == 0.85

    def test_orchestrator_reputation_without_chain_registry(self) -> None:
        """Without chain_registry, reputation falls back to initiator_did."""
        mock_reputation = MagicMock()
        now = datetime.now(UTC)

        from airlock.schemas.reputation import TrustScore

        default_score = TrustScore(
            agent_did="did:key:z6MkOldDid",
            score=0.5,
            created_at=now,
            updated_at=now,
        )
        mock_reputation.get_or_default.return_value = default_score

        from airlock.engine.orchestrator import (
            OrchestrationState,
            VerificationOrchestrator,
        )

        orchestrator = VerificationOrchestrator(
            reputation_store=mock_reputation,
            agent_registry={},
            airlock_did="did:key:z6MkGateway",
            chain_registry=None,
        )

        session = VerificationSession(
            session_id="test-session",
            state=VerificationState.SIGNATURE_VERIFIED,
            initiator_did="did:key:z6MkOldDid",
            target_did="did:key:z6MkTarget",
            created_at=now,
            updated_at=now,
        )

        state: OrchestrationState = {
            "session": session,
            "handshake": MagicMock(privacy_mode=None),
            "challenge": None,
            "challenge_response": None,
            "check_results": [],
            "trust_score": 0.5,
            "verdict": None,
            "error": None,
            "failed_at": None,
            "_sig_valid": True,
            "_vc_valid": False,
            "_routing": "challenge",
            "_challenge_outcome": None,
            "_tier": 0,
            "_local_only": False,
        }

        orchestrator._node_check_reputation(state)

        # Without chain_registry, should use raw initiator_did
        mock_reputation.get_or_default.assert_called_once_with("did:key:z6MkOldDid")


class TestSessionPayloadIncludesChainId:
    def test_build_session_payload_includes_chain_id(self) -> None:
        """build_session_payload includes rotation_chain_id."""
        from airlock.gateway.auth import build_session_payload

        now = datetime.now(UTC)
        chain_id = "d" * 64
        session = VerificationSession(
            session_id="test-session",
            state=VerificationState.INITIATED,
            initiator_did="did:key:z6MkInitiator",
            target_did="did:key:z6MkTarget",
            created_at=now,
            updated_at=now,
            rotation_chain_id=chain_id,
        )

        payload = build_session_payload(session, include_trust_token=False)
        assert payload["rotation_chain_id"] == chain_id

    def test_build_session_payload_none_chain_id(self) -> None:
        """build_session_payload handles None rotation_chain_id."""
        from airlock.gateway.auth import build_session_payload

        now = datetime.now(UTC)
        session = VerificationSession(
            session_id="test-session",
            state=VerificationState.INITIATED,
            initiator_did="did:key:z6MkInitiator",
            target_did="did:key:z6MkTarget",
            created_at=now,
            updated_at=now,
        )

        payload = build_session_payload(session, include_trust_token=False)
        assert payload["rotation_chain_id"] is None


class TestA2AMetadataIncludesChainId:
    def test_attestation_metadata_with_chain_id(self) -> None:
        """A2A metadata includes rotation_chain_id when set on attestation."""
        from airlock.a2a.adapter import airlock_attestation_to_a2a_metadata
        from airlock.schemas.verdict import (
            AirlockAttestation,
            CheckResult,
            TrustVerdict,
            VerificationCheck,
        )

        now = datetime.now(UTC)
        attestation = AirlockAttestation(
            session_id="test-session",
            verified_did="did:key:z6MkVerified",
            checks_passed=[
                CheckResult(
                    check=VerificationCheck.SCHEMA,
                    passed=True,
                    detail="ok",
                )
            ],
            trust_score=0.85,
            verdict=TrustVerdict.VERIFIED,
            issued_at=now,
        )
        # Simulate having rotation_chain_id set dynamically
        attestation_with_chain = attestation.model_copy()
        object.__setattr__(attestation_with_chain, "rotation_chain_id", "e" * 64)

        meta = airlock_attestation_to_a2a_metadata(attestation_with_chain)
        assert meta["airlock_rotation_chain_id"] == "e" * 64

    def test_attestation_metadata_without_chain_id(self) -> None:
        """A2A metadata omits rotation_chain_id when not present."""
        from airlock.a2a.adapter import airlock_attestation_to_a2a_metadata
        from airlock.schemas.verdict import (
            AirlockAttestation,
            CheckResult,
            TrustVerdict,
            VerificationCheck,
        )

        now = datetime.now(UTC)
        attestation = AirlockAttestation(
            session_id="test-session",
            verified_did="did:key:z6MkVerified",
            checks_passed=[
                CheckResult(
                    check=VerificationCheck.SCHEMA,
                    passed=True,
                    detail="ok",
                )
            ],
            trust_score=0.85,
            verdict=TrustVerdict.VERIFIED,
            issued_at=now,
        )

        meta = airlock_attestation_to_a2a_metadata(attestation)
        assert "airlock_rotation_chain_id" not in meta

    def test_a2a_summary_extraction_with_chain_id(self) -> None:
        """a2a_metadata_to_attestation_summary extracts rotation_chain_id."""
        from airlock.a2a.adapter import a2a_metadata_to_attestation_summary

        meta = {
            "airlock_session_id": "test-session",
            "airlock_verified_did": "did:key:z6MkVerified",
            "airlock_verdict": "verified",
            "airlock_trust_score": 0.85,
            "airlock_issued_at": "2026-01-01T00:00:00+00:00",
            "airlock_checks": [],
            "airlock_rotation_chain_id": "f" * 64,
        }

        summary = a2a_metadata_to_attestation_summary(meta)
        assert summary is not None
        assert summary["rotation_chain_id"] == "f" * 64

    def test_a2a_summary_extraction_without_chain_id(self) -> None:
        """a2a_metadata_to_attestation_summary omits chain_id when absent."""
        from airlock.a2a.adapter import a2a_metadata_to_attestation_summary

        meta = {
            "airlock_session_id": "test-session",
            "airlock_verified_did": "did:key:z6MkVerified",
            "airlock_verdict": "verified",
            "airlock_trust_score": 0.85,
            "airlock_issued_at": "2026-01-01T00:00:00+00:00",
            "airlock_checks": [],
        }

        summary = a2a_metadata_to_attestation_summary(meta)
        assert summary is not None
        assert "rotation_chain_id" not in summary
