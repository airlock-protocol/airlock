from __future__ import annotations

import math
from datetime import UTC, datetime

from airlock.config import get_config
from airlock.schemas.reputation import TrustScore
from airlock.schemas.trust_tier import TIER_CEILINGS, TrustTier
from airlock.schemas.verdict import TrustVerdict

# -----------------------------------------------------------------------
# Config accessor
# -----------------------------------------------------------------------


def _cfg() -> tuple[float, float, float, float, float, float, float, float]:
    """Return scoring parameters from the global config.

    Returns (initial, half_life_days, verified_delta, rejected_delta,
             deferred_delta, threshold_high, threshold_blacklist, diminishing_factor).
    """
    c = get_config()
    return (
        c.scoring_initial,
        c.scoring_half_life_days,
        c.scoring_verified_delta,
        c.scoring_rejected_delta,
        c.scoring_deferred_delta,
        c.scoring_threshold_high,
        c.scoring_threshold_blacklist,
        c.scoring_diminishing_factor,
    )


# -----------------------------------------------------------------------
# Backward-compatible module-level constants.
# These are the DEFAULTS and are re-exported so existing imports still
# work (tests, store.py, admin_routes.py, etc.).  The actual functions
# below always read the live config at call time.
# -----------------------------------------------------------------------

INITIAL_SCORE: float = 0.5
HALF_LIFE_DAYS: float = 30.0
VERIFIED_BASE_DELTA: float = 0.05
REJECTED_DELTA: float = -0.15
DEFERRED_DELTA: float = -0.02
DIMINISHING_FACTOR: float = 0.1
THRESHOLD_HIGH: float = 0.75
THRESHOLD_BLACKLIST: float = 0.15

SCORE_MIN: float = 0.0
SCORE_MAX: float = 1.0


def apply_half_life_decay(score: TrustScore) -> float:
    """Return the score after applying tier-aware half-life decay.

    Uses the standard radioactive decay formula:
        decayed = neutral + (current - neutral) * 2^(-elapsed_days / half_life)

    The neutral point is 0.5 -- scores decay toward neutral, not toward zero.
    This means a high-trust agent who goes quiet gradually becomes "unknown"
    rather than "suspect", which matches real-world trust intuitions.

    v0.2: Half-life is now per-tier (higher tiers decay slower).
    Established agents (N+ successful verifications) have a decay floor.
    """
    if score.last_interaction is None:
        return score.score

    now = datetime.now(UTC)
    elapsed_days = (now - score.last_interaction).total_seconds() / 86400.0

    if elapsed_days <= 0:
        return score.score

    cfg = get_config()

    # Select half-life based on tier
    tier = getattr(score, "tier", TrustTier.UNKNOWN)
    half_life_map: dict[TrustTier, float] = {
        TrustTier.UNKNOWN: cfg.scoring_decay_half_life_tier_0,
        TrustTier.CHALLENGE_VERIFIED: cfg.scoring_decay_half_life_tier_1,
        TrustTier.DOMAIN_VERIFIED: cfg.scoring_decay_half_life_tier_2,
        TrustTier.VC_VERIFIED: cfg.scoring_decay_half_life_tier_3,
    }
    half_life = half_life_map.get(tier, cfg.scoring_decay_half_life_tier_0)

    decay_factor = math.pow(2.0, -elapsed_days / half_life)
    neutral = 0.5
    decayed = neutral + (score.score - neutral) * decay_factor

    # Floor clamp for established agents
    if score.successful_verifications >= cfg.scoring_decay_floor_min_interactions:
        decayed = max(decayed, cfg.scoring_decay_floor)

    return float(max(SCORE_MIN, min(SCORE_MAX, decayed)))


def compute_delta(verdict: TrustVerdict, interaction_count: int) -> float:
    """Compute the score delta for a completed verification.

    VERIFIED: diminishing positive gain (rewards consistency, not just volume)
    REJECTED: fixed penalty
    DEFERRED: small negative nudge (ambiguity is a mild signal)
    """
    (
        _initial,
        _half_life,
        verified_delta,
        rejected_delta,
        deferred_delta,
        _threshold_high,
        _threshold_blacklist,
        diminishing_factor,
    ) = _cfg()

    if verdict == TrustVerdict.VERIFIED:
        gain = verified_delta / (1.0 + interaction_count * diminishing_factor)
        return round(gain, 6)
    elif verdict == TrustVerdict.REJECTED:
        return rejected_delta
    else:  # DEFERRED
        return deferred_delta


def _get_tier_ceiling(tier: TrustTier) -> float:
    """Return the score ceiling for a given tier, using config overrides if set."""
    c = get_config()
    config_ceilings: dict[TrustTier, float] = {
        TrustTier.UNKNOWN: c.scoring_tier_0_ceiling,
        TrustTier.CHALLENGE_VERIFIED: c.scoring_tier_1_ceiling,
        TrustTier.DOMAIN_VERIFIED: c.scoring_tier_2_ceiling,
        TrustTier.VC_VERIFIED: c.scoring_tier_3_ceiling,
    }
    return config_ceilings.get(tier, TIER_CEILINGS.get(tier, 1.0))


def update_score(score: TrustScore, verdict: TrustVerdict) -> TrustScore:
    """Return a new TrustScore with decay applied then verdict delta applied.

    Does not mutate the input -- returns a fresh instance.
    Applies tier ceiling clamping and auto-promotes UNKNOWN -> CHALLENGE_VERIFIED
    on first VERIFIED verdict.
    """
    now = datetime.now(UTC)

    # 1. Apply decay since last interaction
    decayed = apply_half_life_decay(score)

    # 2. Apply verdict delta
    delta = compute_delta(verdict, score.interaction_count)
    new_raw = decayed + delta
    new_score = float(max(SCORE_MIN, min(SCORE_MAX, new_raw)))

    # 3. Determine tier: auto-promote UNKNOWN -> CHALLENGE_VERIFIED on first VERIFIED
    new_tier = score.tier
    if score.tier == TrustTier.UNKNOWN and verdict == TrustVerdict.VERIFIED:
        new_tier = TrustTier.CHALLENGE_VERIFIED

    # 4. Clamp score to tier ceiling
    ceiling = _get_tier_ceiling(new_tier)
    new_score = min(new_score, ceiling)

    # 5. Update counters
    new_successful = score.successful_verifications + (1 if verdict == TrustVerdict.VERIFIED else 0)
    new_failed = score.failed_verifications + (1 if verdict == TrustVerdict.REJECTED else 0)

    return TrustScore(
        agent_did=score.agent_did,
        score=new_score,
        tier=new_tier,
        interaction_count=score.interaction_count + 1,
        successful_verifications=new_successful,
        failed_verifications=new_failed,
        last_interaction=now,
        decay_rate=score.decay_rate,
        created_at=score.created_at,
        updated_at=now,
    )


def routing_decision(score: float) -> str:
    """Map a trust score to a routing hint for the orchestrator.

    Returns one of: 'fast_path', 'challenge', 'blacklist'
    """
    (
        _initial,
        _half_life,
        _verified,
        _rejected,
        _deferred,
        threshold_high,
        threshold_blacklist,
        _diminishing,
    ) = _cfg()

    if score >= threshold_high:
        return "fast_path"
    elif score <= threshold_blacklist:
        return "blacklist"
    else:
        return "challenge"
