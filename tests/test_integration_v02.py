"""Integration tests for v0.2 features working together.

Tests the interaction between trust tiers, scoring, PoW, fingerprinting,
and attestation — the full flow an agent goes through in a real deployment.
"""

from __future__ import annotations

from datetime import UTC, datetime

from airlock.pow import ProofOfWork, issue_pow_challenge, solve_pow, verify_pow
from airlock.reputation.scoring import routing_decision, update_score
from airlock.schemas.reputation import TrustScore
from airlock.schemas.trust_tier import TIER_CEILINGS, TrustTier
from airlock.schemas.verdict import AirlockAttestation, TrustVerdict
from airlock.semantic.fingerprint import FingerprintStore

# ---------------------------------------------------------------------------
# Tier + Scoring Integration
# ---------------------------------------------------------------------------


class TestTierAndScoringIntegration:
    """Tests for trust tier transitions combined with scoring."""

    def test_unknown_agent_journey(self) -> None:
        """Simulate an agent's journey from UNKNOWN through challenge verification."""
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkNew",
            score=0.5,
            tier=TrustTier.UNKNOWN,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )

        # Start: score 0.5 -> routes to challenge
        assert routing_decision(ts.score) == "challenge"

        # First VERIFIED: promote to CHALLENGE_VERIFIED, score capped at 0.70
        ts = update_score(ts, TrustVerdict.VERIFIED)
        assert ts.tier == TrustTier.CHALLENGE_VERIFIED
        assert ts.score <= TIER_CEILINGS[TrustTier.CHALLENGE_VERIFIED]

        # Multiple verifications: still capped at 0.70
        for _ in range(10):
            ts = update_score(ts, TrustVerdict.VERIFIED)
        assert ts.score <= 0.70 + 0.001  # Float tolerance
        # Can't reach fast_path (0.75) at this tier
        assert routing_decision(ts.score) == "challenge"

    def test_rejected_agent_drops_toward_blacklist(self) -> None:
        """Agent that fails repeatedly drops toward blacklist threshold."""
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkBad",
            score=0.5,
            tier=TrustTier.UNKNOWN,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )

        for _ in range(5):
            ts = update_score(ts, TrustVerdict.REJECTED)

        assert ts.score < 0.15
        assert routing_decision(ts.score) == "blacklist"

    def test_deferred_agent_gradual_decline(self) -> None:
        """Agent receiving DEFERRED verdicts slowly loses trust."""
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkAmbiguous",
            score=0.5,
            tier=TrustTier.UNKNOWN,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )

        initial_score = ts.score
        for _ in range(10):
            ts = update_score(ts, TrustVerdict.DEFERRED)

        assert ts.score < initial_score
        # Should still be in challenge range, not blacklisted
        assert routing_decision(ts.score) == "challenge"

    def test_tier_persists_through_verdicts(self) -> None:
        """Once promoted, tier should not regress on REJECTED/DEFERRED."""
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkTest",
            score=0.5,
            tier=TrustTier.CHALLENGE_VERIFIED,
            interaction_count=5,
            successful_verifications=3,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )

        ts = update_score(ts, TrustVerdict.REJECTED)
        assert ts.tier == TrustTier.CHALLENGE_VERIFIED  # Tier preserved

        ts = update_score(ts, TrustVerdict.DEFERRED)
        assert ts.tier == TrustTier.CHALLENGE_VERIFIED  # Still preserved

    def test_vc_verified_agent_higher_ceiling(self) -> None:
        """VC_VERIFIED tier allows scores up to 1.00 (highest ceiling)."""
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkVC",
            score=0.6,
            tier=TrustTier.VC_VERIFIED,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )

        for _ in range(20):
            ts = update_score(ts, TrustVerdict.VERIFIED)

        assert ts.score <= 1.00 + 0.001  # VC_VERIFIED ceiling is 1.0
        # Can potentially reach fast_path at 0.75+
        assert ts.score > 0.70  # Should exceed Tier 1 ceiling


# ---------------------------------------------------------------------------
# PoW + Handshake Integration
# ---------------------------------------------------------------------------


class TestPoWAndHandshakeIntegration:
    """Tests for the complete PoW challenge-solve-verify flow."""

    def test_full_pow_flow(self) -> None:
        """Complete PoW flow: issue -> solve -> verify."""
        challenge = issue_pow_challenge(difficulty=8, ttl=120)

        # Client solves the challenge
        nonce = solve_pow(challenge.prefix, challenge.difficulty)

        # Gateway verifies
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=challenge.difficulty,
        )
        assert verify_pow(proof) is True

    def test_pow_with_varying_difficulties(self) -> None:
        """PoW works correctly at multiple difficulty levels."""
        for difficulty in [1, 4, 8, 12]:
            challenge = issue_pow_challenge(difficulty=difficulty)
            nonce = solve_pow(challenge.prefix, challenge.difficulty)
            proof = ProofOfWork(
                challenge_id=challenge.challenge_id,
                prefix=challenge.prefix,
                nonce=nonce,
                difficulty=challenge.difficulty,
            )
            assert verify_pow(proof) is True, f"Failed at difficulty {difficulty}"

    def test_pow_ttl_propagated(self) -> None:
        """TTL from challenge issuance is preserved in expires_at."""
        challenge = issue_pow_challenge(difficulty=4, ttl=300)
        effective_ttl = challenge.expires_at - challenge.issued_at
        assert abs(effective_ttl - 300) < 1.0  # Float tolerance


# ---------------------------------------------------------------------------
# Fingerprint + Trust Integration
# ---------------------------------------------------------------------------


class TestFingerprintAndTrustIntegration:
    """Tests for fingerprint detection in multi-agent scenarios."""

    async def test_fingerprint_across_tiers(self) -> None:
        """Fingerprint detection works regardless of agent trust tier."""
        store = FingerprintStore(window_size=100, hamming_threshold=3)

        # Higher-tier agent answers first
        fp1 = store.build_fingerprint(
            session_id="s1",
            agent_did="did:key:z6MkTier2Agent",
            answer="Ed25519 uses Curve25519 for efficient signature operations with strong security",
            question="Explain Ed25519",
        )
        await store.add(fp1)

        # Lower-tier agent gives exact same answer (bot copying)
        fp2 = store.build_fingerprint(
            session_id="s2",
            agent_did="did:key:z6MkTier0Agent",
            answer="Ed25519 uses Curve25519 for efficient signature operations with strong security",
            question="Explain Ed25519",
        )
        match = await store.check(fp2)
        assert match.is_exact_duplicate is True
        assert match.matching_agent_did == "did:key:z6MkTier2Agent"

    async def test_fingerprint_sliding_window_eviction(self) -> None:
        """Old fingerprints are evicted when window fills up."""
        store = FingerprintStore(window_size=5, hamming_threshold=3)

        # Fill the window with 5 different fingerprints
        for i in range(5):
            fp = store.build_fingerprint(
                session_id=f"s{i}",
                agent_did=f"did:key:z6MkAgent{i}",
                answer=f"unique answer {i} about protocol design and verification",
                question="test",
            )
            await store.add(fp)

        # Add 5 more, which should evict the first 5
        for i in range(5, 10):
            fp = store.build_fingerprint(
                session_id=f"s{i}",
                agent_did=f"did:key:z6MkAgent{i}",
                answer=f"different answer {i} about network security and trust models",
                question="test",
            )
            await store.add(fp)

        # Now try to match the first answer — should NOT match (evicted)
        fp_old = store.build_fingerprint(
            session_id="s_check",
            agent_did="did:key:z6MkChecker",
            answer="unique answer 0 about protocol design and verification",
            question="test",
        )
        match = await store.check(fp_old)
        assert not match.is_exact_duplicate

    async def test_multiple_bot_farm_waves(self) -> None:
        """Detect multiple waves of bot farm answers."""
        store = FingerprintStore(window_size=100, hamming_threshold=3)

        # Wave 1: 3 bots give the same answer
        answer_wave1 = "cryptographic nonces prevent replay attacks in protocols"
        for i in range(3):
            fp = store.build_fingerprint(
                session_id=f"wave1-{i}",
                agent_did=f"did:key:z6MkWave1Bot{i}",
                answer=answer_wave1,
                question="nonce question",
            )
            if i > 0:
                match = await store.check(fp)
                assert match.is_exact_duplicate
            await store.add(fp)

        # Wave 2: 3 different bots give a different (but identical) answer
        answer_wave2 = "TLS handshake establishes shared session keys using Diffie-Hellman"
        for i in range(3):
            fp = store.build_fingerprint(
                session_id=f"wave2-{i}",
                agent_did=f"did:key:z6MkWave2Bot{i}",
                answer=answer_wave2,
                question="tls question",
            )
            if i > 0:
                match = await store.check(fp)
                assert match.is_exact_duplicate
            await store.add(fp)


# ---------------------------------------------------------------------------
# Attestation Completeness
# ---------------------------------------------------------------------------


class TestAttestationCompleteness:
    """Tests that AirlockAttestation correctly carries v0.2 fields."""

    def test_attestation_has_all_v02_fields(self) -> None:
        """AirlockAttestation includes tier, privacy_mode, and fingerprint_flags."""
        att = AirlockAttestation(
            session_id="test",
            verified_did="did:key:z6MkTest",
            checks_passed=[],
            trust_score=0.65,
            tier=TrustTier.CHALLENGE_VERIFIED,
            verdict=TrustVerdict.VERIFIED,
            issued_at=datetime.now(UTC),
            privacy_mode="any",
            fingerprint_flags=[],
        )

        assert att.tier == TrustTier.CHALLENGE_VERIFIED
        assert att.privacy_mode == "any"
        assert att.fingerprint_flags == []
        assert att.trust_score == 0.65

    def test_attestation_backward_compat(self) -> None:
        """AirlockAttestation works without new fields (backward compat)."""
        att = AirlockAttestation(
            session_id="test",
            verified_did="did:key:z6MkTest",
            checks_passed=[],
            trust_score=0.5,
            verdict=TrustVerdict.DEFERRED,
            issued_at=datetime.now(UTC),
        )
        # New fields should have defaults
        assert att.tier == TrustTier.UNKNOWN
        assert att.privacy_mode == "any"
        assert att.fingerprint_flags == []

    def test_attestation_with_fingerprint_flags(self) -> None:
        """Attestation can carry fingerprint warning flags."""
        att = AirlockAttestation(
            session_id="test",
            verified_did="did:key:z6MkBot",
            checks_passed=[],
            trust_score=0.3,
            verdict=TrustVerdict.REJECTED,
            issued_at=datetime.now(UTC),
            tier=TrustTier.UNKNOWN,
            fingerprint_flags=["exact_duplicate", "bot_farm_suspected"],
        )
        assert len(att.fingerprint_flags) == 2
        assert "exact_duplicate" in att.fingerprint_flags

    def test_attestation_serialization_roundtrip(self) -> None:
        """Attestation survives JSON serialization roundtrip."""
        att = AirlockAttestation(
            session_id="test",
            verified_did="did:key:z6MkTest",
            checks_passed=[],
            trust_score=0.65,
            tier=TrustTier.CHALLENGE_VERIFIED,
            verdict=TrustVerdict.VERIFIED,
            issued_at=datetime.now(UTC),
            privacy_mode="local_only",
            fingerprint_flags=["near_duplicate"],
        )
        json_str = att.model_dump_json()
        restored = AirlockAttestation.model_validate_json(json_str)

        assert restored.tier == TrustTier.CHALLENGE_VERIFIED
        assert restored.privacy_mode == "local_only"
        assert restored.fingerprint_flags == ["near_duplicate"]
        assert restored.trust_score == 0.65

    def test_attestation_all_tiers(self) -> None:
        """Every TrustTier can be stored in an attestation."""
        for tier in TrustTier:
            att = AirlockAttestation(
                session_id="test",
                verified_did="did:key:z6MkTest",
                checks_passed=[],
                trust_score=0.5,
                tier=tier,
                verdict=TrustVerdict.VERIFIED,
                issued_at=datetime.now(UTC),
            )
            assert att.tier == tier


# ---------------------------------------------------------------------------
# End-to-End Flow
# ---------------------------------------------------------------------------


class TestEndToEndFlow:
    """Tests simulating a complete agent verification lifecycle."""

    def test_new_agent_pow_then_verify(self) -> None:
        """New agent: PoW challenge -> solve -> score update -> attestation."""
        # 1. Gateway issues PoW challenge
        pow_challenge = issue_pow_challenge(difficulty=8)

        # 2. Agent solves PoW
        nonce = solve_pow(pow_challenge.prefix, pow_challenge.difficulty)
        proof = ProofOfWork(
            challenge_id=pow_challenge.challenge_id,
            prefix=pow_challenge.prefix,
            nonce=nonce,
            difficulty=pow_challenge.difficulty,
        )
        assert verify_pow(proof) is True

        # 3. Agent passes semantic challenge -> update score
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkNewAgent",
            score=0.5,
            tier=TrustTier.UNKNOWN,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )
        ts = update_score(ts, TrustVerdict.VERIFIED)

        # 4. Build attestation
        att = AirlockAttestation(
            session_id="new-agent-session",
            verified_did=ts.agent_did,
            checks_passed=[],
            trust_score=ts.score,
            tier=ts.tier,
            verdict=TrustVerdict.VERIFIED,
            issued_at=datetime.now(UTC),
            privacy_mode="any",
            fingerprint_flags=[],
        )

        assert att.tier == TrustTier.CHALLENGE_VERIFIED
        assert att.trust_score <= 0.70
        assert att.verdict == TrustVerdict.VERIFIED

    async def test_bot_detected_and_rejected(self) -> None:
        """Bot farm agent: fingerprint match -> rejection flow."""
        store = FingerprintStore(window_size=100, hamming_threshold=3)

        # Legitimate agent answers
        fp1 = store.build_fingerprint(
            session_id="legit-session",
            agent_did="did:key:z6MkLegit",
            answer="Nonces prevent replay attacks by making each message unique",
            question="What prevents replay attacks?",
        )
        await store.add(fp1)

        # Bot gives same answer
        fp2 = store.build_fingerprint(
            session_id="bot-session",
            agent_did="did:key:z6MkBot",
            answer="Nonces prevent replay attacks by making each message unique",
            question="What prevents replay attacks?",
        )
        match = await store.check(fp2)
        assert match.is_exact_duplicate

        # Score update: REJECTED
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkBot",
            score=0.5,
            tier=TrustTier.UNKNOWN,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )
        ts = update_score(ts, TrustVerdict.REJECTED)

        # Build attestation with fingerprint flags
        att = AirlockAttestation(
            session_id="bot-session",
            verified_did=ts.agent_did,
            checks_passed=[],
            trust_score=ts.score,
            tier=ts.tier,
            verdict=TrustVerdict.REJECTED,
            issued_at=datetime.now(UTC),
            fingerprint_flags=["exact_duplicate"],
        )

        assert att.verdict == TrustVerdict.REJECTED
        assert "exact_duplicate" in att.fingerprint_flags
        assert att.trust_score < 0.5
