from __future__ import annotations

import math
from datetime import datetime, timezone

from airlock.schemas.reputation import TrustScore
from airlock.schemas.verdict import TrustVerdict

# -----------------------------------------------------------------------
# Scoring constants
# -----------------------------------------------------------------------

INITIAL_SCORE: float = 0.5          # new agents start neutral
HALF_LIFE_DAYS: float = 30.0        # inactive score decays toward 0.5 over 30 days
VERIFIED_BASE_DELTA: float = 0.05   # max gain per successful verification
REJECTED_DELTA: float = -0.15       # penalty for failed verification
DEFERRED_DELTA: float = -0.02       # small nudge for ambiguous outcome
SCORE_MIN: float = 0.0
SCORE_MAX: float = 1.0

# Diminishing returns: each extra interaction contributes less
# gain = VERIFIED_BASE_DELTA / (1 + interaction_count * DIMINISHING_FACTOR)
DIMINISHING_FACTOR: float = 0.1

# Thresholds for routing decisions
THRESHOLD_HIGH: float = 0.75        # skip challenge, fast-path to VERIFIED
THRESHOLD_BLACKLIST: float = 0.15   # reject immediately without challenge


def apply_half_life_decay(score: TrustScore) -> float:
    """Return the score after applying half-life decay since last interaction.

    Uses the standard radioactive decay formula:
        decayed = neutral + (current - neutral) * 2^(-elapsed_days / half_life)

    The neutral point is 0.5 — scores decay toward neutral, not toward zero.
    This means a high-trust agent who goes quiet gradually becomes "unknown"
    rather than "suspect", which matches real-world trust intuitions.
    """
    if score.last_interaction is None:
        return score.score

    now = datetime.now(timezone.utc)
    elapsed_days = (now - score.last_interaction).total_seconds() / 86400.0

    if elapsed_days <= 0:
        return score.score

    decay_factor = math.pow(2.0, -elapsed_days / HALF_LIFE_DAYS)
    neutral = 0.5
    decayed = neutral + (score.score - neutral) * decay_factor
    return float(max(SCORE_MIN, min(SCORE_MAX, decayed)))


def compute_delta(verdict: TrustVerdict, interaction_count: int) -> float:
    """Compute the score delta for a completed verification.

    VERIFIED: diminishing positive gain (rewards consistency, not just volume)
    REJECTED: fixed penalty
    DEFERRED: small negative nudge (ambiguity is a mild signal)
    """
    if verdict == TrustVerdict.VERIFIED:
        gain = VERIFIED_BASE_DELTA / (1.0 + interaction_count * DIMINISHING_FACTOR)
        return round(gain, 6)
    elif verdict == TrustVerdict.REJECTED:
        return REJECTED_DELTA
    else:  # DEFERRED
        return DEFERRED_DELTA


def update_score(score: TrustScore, verdict: TrustVerdict) -> TrustScore:
    """Return a new TrustScore with decay applied then verdict delta applied.

    Does not mutate the input — returns a fresh instance.
    """
    now = datetime.now(timezone.utc)

    # 1. Apply decay since last interaction
    decayed = apply_half_life_decay(score)

    # 2. Apply verdict delta
    delta = compute_delta(verdict, score.interaction_count)
    new_raw = decayed + delta
    new_score = float(max(SCORE_MIN, min(SCORE_MAX, new_raw)))

    # 3. Update counters
    new_successful = score.successful_verifications + (
        1 if verdict == TrustVerdict.VERIFIED else 0
    )
    new_failed = score.failed_verifications + (
        1 if verdict == TrustVerdict.REJECTED else 0
    )

    return TrustScore(
        agent_did=score.agent_did,
        score=new_score,
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
    if score >= THRESHOLD_HIGH:
        return "fast_path"
    elif score <= THRESHOLD_BLACKLIST:
        return "blacklist"
    else:
        return "challenge"
