"""Unit tests for the reputation store and scoring module."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from airlock.reputation.scoring import (
    INITIAL_SCORE,
    THRESHOLD_BLACKLIST,
    THRESHOLD_HIGH,
    apply_half_life_decay,
    routing_decision,
)
from airlock.reputation.store import ReputationStore
from airlock.schemas.reputation import TrustScore
from airlock.schemas.verdict import TrustVerdict


@pytest.fixture
def store(tmp_path):
    db_dir = str(tmp_path / "rep.lance")
    s = ReputationStore(db_path=db_dir)
    s.open()
    yield s
    s.close()


def _score(did: str, value: float, interactions: int = 0) -> TrustScore:
    now = datetime.now(UTC)
    return TrustScore(
        agent_did=did,
        score=value,
        interaction_count=interactions,
        successful_verifications=0,
        failed_verifications=0,
        last_interaction=now,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# Store tests
# ---------------------------------------------------------------------------


def test_store_get_missing_returns_none(store):
    assert store.get("did:key:nonexistent") is None


def test_store_get_or_default_creates_neutral(store):
    ts = store.get_or_default("did:key:new")
    assert ts.score == INITIAL_SCORE
    assert ts.interaction_count == 0


def test_store_upsert_and_get(store):
    ts = _score("did:key:agent1", 0.7)
    store.upsert(ts)
    fetched = store.get("did:key:agent1")
    assert fetched is not None
    assert abs(fetched.score - 0.7) < 1e-6


def test_store_upsert_replaces_existing(store):
    store.upsert(_score("did:key:agent1", 0.6))
    store.upsert(_score("did:key:agent1", 0.8))
    fetched = store.get("did:key:agent1")
    assert fetched is not None
    assert abs(fetched.score - 0.8) < 1e-6


def test_store_count(store):
    assert store.count() == 0
    store.upsert(_score("did:key:a", 0.5))
    store.upsert(_score("did:key:b", 0.6))
    assert store.count() == 2


def test_store_all_scores(store):
    store.upsert(_score("did:key:a", 0.5))
    store.upsert(_score("did:key:b", 0.7))
    all_scores = store.all_scores()
    dids = {s.agent_did for s in all_scores}
    assert "did:key:a" in dids
    assert "did:key:b" in dids


def test_store_apply_verdict_verified(store):
    updated = store.apply_verdict("did:key:agent1", TrustVerdict.VERIFIED)
    assert updated.score > INITIAL_SCORE
    assert updated.successful_verifications == 1


def test_store_apply_verdict_rejected(store):
    updated = store.apply_verdict("did:key:agent1", TrustVerdict.REJECTED)
    assert updated.score < INITIAL_SCORE
    assert updated.failed_verifications == 1


def test_store_requires_open():
    store = ReputationStore(db_path="./nonexistent")
    with pytest.raises(RuntimeError, match="not open"):
        store.get("did:key:x")


# ---------------------------------------------------------------------------
# Scoring tests
# ---------------------------------------------------------------------------


def test_routing_fast_path():
    assert routing_decision(THRESHOLD_HIGH) == "fast_path"
    assert routing_decision(1.0) == "fast_path"


def test_routing_blacklist():
    assert routing_decision(THRESHOLD_BLACKLIST) == "blacklist"
    assert routing_decision(0.0) == "blacklist"


def test_routing_challenge():
    assert routing_decision(0.5) == "challenge"
    assert routing_decision(THRESHOLD_BLACKLIST + 0.01) == "challenge"
    assert routing_decision(THRESHOLD_HIGH - 0.01) == "challenge"


def test_half_life_no_last_interaction():
    """If last_interaction is None, score is returned unchanged."""
    now = datetime.now(UTC)
    ts = TrustScore(
        agent_did="did:key:x",
        score=0.8,
        interaction_count=0,
        successful_verifications=0,
        failed_verifications=0,
        last_interaction=None,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    assert apply_half_life_decay(ts) == 0.8


def test_half_life_recent_interaction_minimal_decay():
    """A very recent interaction should barely decay."""
    now = datetime.now(UTC)
    ts = TrustScore(
        agent_did="did:key:x",
        score=0.9,
        interaction_count=1,
        successful_verifications=1,
        failed_verifications=0,
        last_interaction=now - timedelta(seconds=10),
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    decayed = apply_half_life_decay(ts)
    assert abs(decayed - 0.9) < 0.001  # virtually no decay in 10 seconds


def test_half_life_60_days_decay():
    """After 2 half-lives (60 days), score should be ~3/4 of the way to neutral."""
    past = datetime.now(UTC) - timedelta(days=60)
    ts = TrustScore(
        agent_did="did:key:x",
        score=0.9,
        interaction_count=1,
        successful_verifications=1,
        failed_verifications=0,
        last_interaction=past,
        decay_rate=0.02,
        created_at=past,
        updated_at=past,
    )
    decayed = apply_half_life_decay(ts)
    # After 2 half-lives: 0.5 + (0.9 - 0.5) * 0.25 = 0.5 + 0.1 = 0.6
    assert abs(decayed - 0.6) < 0.01
