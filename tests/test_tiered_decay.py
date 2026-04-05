"""Tests for tiered decay with floor (Change 2 — v0.2)."""

import math
from datetime import UTC, datetime, timedelta

import pytest

from airlock.reputation.scoring import apply_half_life_decay
from airlock.schemas.reputation import TrustScore
from airlock.schemas.trust_tier import TrustTier


def _make_score(
    score: float = 0.8,
    tier: TrustTier = TrustTier.UNKNOWN,
    successful: int = 0,
    days_ago: float = 30.0,
) -> TrustScore:
    now = datetime.now(UTC)
    return TrustScore(
        agent_did="did:key:z6MkTest",
        score=score,
        tier=tier,
        interaction_count=successful,
        successful_verifications=successful,
        failed_verifications=0,
        last_interaction=now - timedelta(days=days_ago),
        created_at=now - timedelta(days=90),
        updated_at=now - timedelta(days=days_ago),
    )


class TestTieredDecay:
    def test_tier_0_fast_decay(self) -> None:
        """UNKNOWN tier uses 30-day half-life (fast decay)."""
        ts = _make_score(score=0.8, tier=TrustTier.UNKNOWN, days_ago=30)
        decayed = apply_half_life_decay(ts)
        # After 30 days at half-life 30: should decay significantly toward 0.5
        # Expected: 0.5 + (0.8 - 0.5) * 0.5 = 0.65
        assert decayed == pytest.approx(0.65, abs=0.02)

    def test_tier_3_slow_decay(self) -> None:
        """VC_VERIFIED tier uses 365-day half-life (slow decay)."""
        ts = _make_score(score=0.8, tier=TrustTier.VC_VERIFIED, days_ago=30)
        decayed = apply_half_life_decay(ts)
        # After 30 days at half-life 365: barely decays
        expected_factor = math.pow(2.0, -30.0 / 365.0)
        expected = 0.5 + (0.8 - 0.5) * expected_factor
        assert decayed == pytest.approx(expected, abs=0.02)
        assert decayed > 0.78  # Should barely decay

    def test_tier_1_medium_decay(self) -> None:
        """CHALLENGE_VERIFIED tier uses 90-day half-life."""
        ts = _make_score(score=0.7, tier=TrustTier.CHALLENGE_VERIFIED, days_ago=90)
        decayed = apply_half_life_decay(ts)
        # After 90 days at half-life 90: halfway back to neutral
        expected = 0.5 + (0.7 - 0.5) * 0.5
        assert decayed == pytest.approx(expected, abs=0.02)

    def test_tier_2_decay(self) -> None:
        """DOMAIN_VERIFIED tier uses 180-day half-life."""
        ts = _make_score(score=0.9, tier=TrustTier.DOMAIN_VERIFIED, days_ago=180)
        decayed = apply_half_life_decay(ts)
        # After 180 days at half-life 180: halfway back to neutral
        expected = 0.5 + (0.9 - 0.5) * 0.5
        assert decayed == pytest.approx(expected, abs=0.02)

    def test_floor_at_10_interactions(self) -> None:
        """Agent with 10+ successful verifications doesn't drop below 0.60."""
        ts = _make_score(score=0.8, tier=TrustTier.UNKNOWN, days_ago=365, successful=15)
        decayed = apply_half_life_decay(ts)
        # After 365 days at half-life 30, without floor would be near 0.5
        # But floor is 0.60
        assert decayed >= 0.60

    def test_floor_not_applied_under_10(self) -> None:
        """Agent with fewer than 10 verifications can drop below 0.60."""
        ts = _make_score(score=0.8, tier=TrustTier.UNKNOWN, days_ago=365, successful=3)
        decayed = apply_half_life_decay(ts)
        # Should decay well below 0.60 with only 3 interactions
        assert decayed < 0.60

    def test_no_decay_without_interaction(self) -> None:
        """Score doesn't decay if last_interaction is None."""
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkTest",
            score=0.8,
            tier=TrustTier.UNKNOWN,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=None,
            created_at=now,
            updated_at=now,
        )
        decayed = apply_half_life_decay(ts)
        assert decayed == 0.8

    def test_higher_tier_decays_slower(self) -> None:
        """Verify tier ordering: higher tiers always decay slower."""
        tiers = [
            TrustTier.UNKNOWN,
            TrustTier.CHALLENGE_VERIFIED,
            TrustTier.DOMAIN_VERIFIED,
            TrustTier.VC_VERIFIED,
        ]
        results: list[float] = []
        for tier in tiers:
            ts = _make_score(score=0.8, tier=tier, days_ago=60)
            results.append(apply_half_life_decay(ts))
        # Each tier should produce a higher (less decayed) score
        for i in range(len(results) - 1):
            assert results[i] < results[i + 1], (
                f"Tier {tiers[i].name} decayed to {results[i]} "
                f"but tier {tiers[i + 1].name} decayed to {results[i + 1]}"
            )

    def test_floor_exactly_at_threshold(self) -> None:
        """Agent with exactly 10 successful verifications gets the floor."""
        ts = _make_score(score=0.8, tier=TrustTier.UNKNOWN, days_ago=365, successful=10)
        decayed = apply_half_life_decay(ts)
        assert decayed >= 0.60
