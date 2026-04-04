from __future__ import annotations

import math
from datetime import UTC, datetime

from airlock.config import get_config
from airlock.schemas.reputation import TrustScore
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
    """Return the score after applying half-life decay since last interaction.

    Uses the standard radioactive decay formula:
        decayed = neutral + (current - neutral) * 2^(-elapsed_days / half_life)

    The neutral point is 0.5 -- scores decay toward neutral, not toward zero.
    This means a high-trust agent who goes quiet gradually becomes "unknown"
    rather than "suspect", which matches real-world trust intuitions.
    """
    if score.last_interaction is None:
        return score.score

    now = datetime.now(UTC)
    elapsed_days = (now - score.last_interaction).total_seconds() / 86400.0

    if elapsed_days <= 0:
        return score.score

    (
        _initial, half_life_days, _verified, _rejected,
        _deferred, _threshold_high, _threshold_blacklist, _diminishing,
    ) = _cfg()

    decay_factor = math.pow(2.0, -elapsed_days / half_life_days)
    neutral = 0.5
    decayed = neutral + (score.score - neutral) * decay_factor
    return float(max(SCORE_MIN, min(SCORE_MAX, decayed)))


def compute_delta(verdict: TrustVerdict, interaction_count: int) -> float:
    """Compute the score delta for a completed verification.

    VERIFIED: diminishing positive gain (rewards consistency, not just volume)
    REJECTED: fixed penalty
    DEFERRED: small negative nudge (ambiguity is a mild signal)
    """
    (
        _initial, _half_life, verified_delta, rejected_delta,
        deferred_delta, _threshold_high, _threshold_blacklist, diminishing_factor,
    ) = _cfg()

    if verdict == TrustVerdict.VERIFIED:
        gain = verified_delta / (1.0 + interaction_count * diminishing_factor)
        return round(gain, 6)
    elif verdict == TrustVerdict.REJECTED:
        return rejected_delta
    else:  # DEFERRED
        return deferred_delta


def update_score(score: TrustScore, verdict: TrustVerdict) -> TrustScore:
    """Return a new TrustScore with decay applied then verdict delta applied.

    Does not mutate the input -- returns a fresh instance.
    """
    now = datetime.now(UTC)

    # 1. Apply decay since last interaction
    decayed = apply_half_life_decay(score)

    # 2. Apply verdict delta
    delta = compute_delta(verdict, score.interaction_count)
    new_raw = decayed + delta
    new_score = float(max(SCORE_MIN, min(SCORE_MAX, new_raw)))

    # 3. Update counters
    new_successful = score.successful_verifications + (1 if verdict == TrustVerdict.VERIFIED else 0)
    new_failed = score.failed_verifications + (1 if verdict == TrustVerdict.REJECTED else 0)

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
    (
        _initial, _half_life, _verified, _rejected,
        _deferred, threshold_high, threshold_blacklist, _diminishing,
    ) = _cfg()

    if score >= threshold_high:
        return "fast_path"
    elif score <= threshold_blacklist:
        return "blacklist"
    else:
        return "challenge"
