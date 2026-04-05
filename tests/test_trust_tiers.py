"""Tests for the trust tier system (Change 1 -- v0.2)."""

from datetime import UTC, datetime

from airlock.reputation.scoring import routing_decision, update_score
from airlock.schemas.reputation import TrustScore
from airlock.schemas.trust_tier import TIER_CEILINGS, TIER_THRESHOLDS, TierAssignment, TrustTier
from airlock.schemas.verdict import AirlockAttestation, TrustVerdict


def _make_score(
    score: float = 0.5,
    tier: TrustTier = TrustTier.UNKNOWN,
    interaction_count: int = 0,
    successful: int = 0,
) -> TrustScore:
    now = datetime.now(UTC)
    return TrustScore(
        agent_did="did:key:z6MkTest",
        score=score,
        tier=tier,
        interaction_count=interaction_count,
        successful_verifications=successful,
        failed_verifications=0,
        last_interaction=now,
        created_at=now,
        updated_at=now,
    )


class TestTierCeilingClamp:
    def test_unknown_capped_at_050(self) -> None:
        """UNKNOWN tier score cannot exceed 0.50 when not promoted.

        A REJECTED verdict does not trigger promotion, so the ceiling stays at 0.50.
        A VERIFIED verdict would promote to CHALLENGE_VERIFIED (ceiling 0.70).
        """
        ts = _make_score(score=0.49, tier=TrustTier.UNKNOWN)
        result = update_score(ts, TrustVerdict.DEFERRED)
        assert result.score <= TIER_CEILINGS[TrustTier.UNKNOWN]
        assert result.tier == TrustTier.UNKNOWN

    def test_challenge_verified_capped_at_070(self) -> None:
        """CHALLENGE_VERIFIED tier score cannot exceed 0.70."""
        ts = _make_score(score=0.69, tier=TrustTier.CHALLENGE_VERIFIED)
        result = update_score(ts, TrustVerdict.VERIFIED)
        assert result.score <= TIER_CEILINGS[TrustTier.CHALLENGE_VERIFIED]

    def test_domain_verified_capped_at_090(self) -> None:
        """DOMAIN_VERIFIED tier score cannot exceed 0.90."""
        ts = _make_score(score=0.89, tier=TrustTier.DOMAIN_VERIFIED)
        result = update_score(ts, TrustVerdict.VERIFIED)
        assert result.score <= TIER_CEILINGS[TrustTier.DOMAIN_VERIFIED]

    def test_vc_verified_can_reach_100(self) -> None:
        """VC_VERIFIED tier has no effective ceiling (1.0)."""
        ts = _make_score(score=0.95, tier=TrustTier.VC_VERIFIED)
        result = update_score(ts, TrustVerdict.VERIFIED)
        assert result.score <= 1.0


class TestTierPromotion:
    def test_auto_promote_unknown_to_challenge_verified(self) -> None:
        """First VERIFIED verdict promotes UNKNOWN to CHALLENGE_VERIFIED."""
        ts = _make_score(score=0.5, tier=TrustTier.UNKNOWN)
        result = update_score(ts, TrustVerdict.VERIFIED)
        assert result.tier == TrustTier.CHALLENGE_VERIFIED

    def test_no_auto_promote_above_tier_1(self) -> None:
        """Tier 2 and 3 require explicit promotion, not auto."""
        ts = _make_score(score=0.69, tier=TrustTier.CHALLENGE_VERIFIED)
        result = update_score(ts, TrustVerdict.VERIFIED)
        assert result.tier == TrustTier.CHALLENGE_VERIFIED  # NOT promoted


class TestTierRouting:
    def test_tier_1_at_070_gets_challenge(self) -> None:
        """Tier 1 agent at ceiling (0.70) still routes to challenge, not fast-path."""
        decision = routing_decision(0.70)
        assert decision == "challenge"

    def test_tier_in_attestation(self) -> None:
        """AirlockAttestation includes the tier field."""
        att = AirlockAttestation(
            session_id="test",
            verified_did="did:key:z6MkTest",
            checks_passed=[],
            trust_score=0.7,
            tier=TrustTier.CHALLENGE_VERIFIED,
            verdict=TrustVerdict.VERIFIED,
            issued_at=datetime.now(UTC),
        )
        assert att.tier == TrustTier.CHALLENGE_VERIFIED


class TestTierConstants:
    """Verify tier constants are consistent."""

    def test_tier_ceilings_exist_for_all_tiers(self) -> None:
        """Every TrustTier has a ceiling defined."""
        for tier in TrustTier:
            assert tier in TIER_CEILINGS

    def test_tier_thresholds_exist_for_all_tiers(self) -> None:
        """Every TrustTier has a threshold defined."""
        for tier in TrustTier:
            assert tier in TIER_THRESHOLDS

    def test_ceilings_monotonically_increase(self) -> None:
        """Higher tiers have higher or equal ceilings."""
        tiers = sorted(TrustTier, key=lambda t: t.value)
        for i in range(1, len(tiers)):
            assert TIER_CEILINGS[tiers[i]] >= TIER_CEILINGS[tiers[i - 1]]

    def test_tier_assignment_defaults(self) -> None:
        """TierAssignment has sensible defaults."""
        assignment = TierAssignment()
        assert assignment.tier == TrustTier.UNKNOWN
        assert assignment.promoted_at is None
        assert assignment.evidence == ""
