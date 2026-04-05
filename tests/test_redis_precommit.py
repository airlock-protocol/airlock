"""Tests for RedisPreCommitmentStore using fakeredis."""

from __future__ import annotations

from datetime import UTC, datetime

import fakeredis.aioredis
import pytest

from airlock.rotation.precommit import PreRotationCommitment
from airlock.rotation.redis_precommit import RedisPreCommitmentStore


def _make_commitment(chain_id: str = "chain1") -> PreRotationCommitment:
    """Create a test commitment."""
    return PreRotationCommitment(
        alg="sha256",
        digest="a" * 64,
        committed_at=datetime.now(UTC),
        committed_by_did=f"did:key:z6Mk{chain_id}",
        signature="sig_" + chain_id,
    )


@pytest.fixture
async def redis():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


@pytest.fixture
async def store(redis):
    return RedisPreCommitmentStore(redis)


# ------------------------------------------------------------------
# get / put / delete
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_missing(store):
    """Getting a non-existent commitment returns None."""
    assert await store.get("nonexistent") is None


@pytest.mark.asyncio
async def test_put_and_get(store):
    """Storing and retrieving a commitment round-trips correctly."""
    commitment = _make_commitment("chain1")
    await store.put("chain1", commitment)

    result = await store.get("chain1")
    assert result is not None
    assert result.alg == commitment.alg
    assert result.digest == commitment.digest
    assert result.committed_by_did == commitment.committed_by_did
    assert result.signature == commitment.signature


@pytest.mark.asyncio
async def test_put_overwrites(store):
    """Putting a new commitment for the same chain overwrites the old one."""
    commitment1 = _make_commitment("chain1")
    commitment2 = PreRotationCommitment(
        alg="sha256",
        digest="b" * 64,
        committed_at=datetime.now(UTC),
        committed_by_did="did:key:z6Mkchain1",
        signature="sig_new",
    )

    await store.put("chain1", commitment1)
    await store.put("chain1", commitment2)

    result = await store.get("chain1")
    assert result is not None
    assert result.digest == "b" * 64
    assert result.signature == "sig_new"


@pytest.mark.asyncio
async def test_delete(store):
    """Deleting a commitment removes it."""
    commitment = _make_commitment("chain1")
    await store.put("chain1", commitment)

    await store.delete("chain1")
    assert await store.get("chain1") is None


@pytest.mark.asyncio
async def test_delete_missing(store):
    """Deleting a non-existent commitment is a no-op."""
    await store.delete("nonexistent")  # should not raise


# ------------------------------------------------------------------
# Multiple commitments
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multiple_commitments(store):
    """Multiple commitments for different chains coexist correctly."""
    c1 = _make_commitment("chain1")
    c2 = _make_commitment("chain2")

    await store.put("chain1", c1)
    await store.put("chain2", c2)

    r1 = await store.get("chain1")
    r2 = await store.get("chain2")

    assert r1 is not None
    assert r2 is not None
    assert r1.committed_by_did != r2.committed_by_did


# ------------------------------------------------------------------
# Deterministic JSON
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deterministic_json(store, redis):
    """Stored JSON uses deterministic formatting (sorted keys, no spaces)."""
    commitment = _make_commitment("chain1")
    await store.put("chain1", commitment)

    raw = await redis.hget("airlock:precommit", "chain1")
    assert raw is not None
    # Deterministic: no spaces after separators
    assert ": " not in raw
    assert ", " not in raw
