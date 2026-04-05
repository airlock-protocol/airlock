"""Tests for RedisRotationChainRegistry using fakeredis."""

from __future__ import annotations

import asyncio
import hashlib

import fakeredis.aioredis
import pytest

from airlock.rotation.chain import RotationChainRecord, compute_chain_id
from airlock.rotation.redis_chain import RedisRotationChainRegistry


def _make_key_bytes(label: str = "agent1") -> bytes:
    """Generate deterministic 32-byte key material for tests."""
    return hashlib.sha256(label.encode()).digest()


def _make_did(label: str = "agent1") -> str:
    """Generate a did:key string from a label."""
    return f"did:key:z6Mk{label}"


@pytest.fixture
async def redis():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


@pytest.fixture
async def registry(redis):
    return RedisRotationChainRegistry(redis)


# ------------------------------------------------------------------
# register_chain
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_chain(registry):
    """Registering a new chain creates a record with correct fields."""
    key_bytes = _make_key_bytes("agent1")
    did = _make_did("agent1")
    expected_chain_id = compute_chain_id(key_bytes)

    record = await registry.register_chain_async(did, key_bytes)

    assert record.chain_id == expected_chain_id
    assert record.current_did == did
    assert record.previous_dids == []
    assert record.rotation_count == 0


@pytest.mark.asyncio
async def test_register_chain_idempotent(registry):
    """Registering the same chain twice returns the existing record."""
    key_bytes = _make_key_bytes("agent1")
    did = _make_did("agent1")

    record1 = await registry.register_chain_async(did, key_bytes)
    record2 = await registry.register_chain_async(did, key_bytes)

    assert record1.chain_id == record2.chain_id
    assert record1.current_did == record2.current_did


# ------------------------------------------------------------------
# rotate
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotate(registry):
    """Rotating updates current_did, previous_dids, and rotation_count."""
    key_bytes = _make_key_bytes("agent1")
    old_did = _make_did("agent1")
    new_did = _make_did("agent1_v2")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(old_did, key_bytes)
    record = await registry.rotate(old_did, new_did, chain_id)

    assert record.current_did == new_did
    assert record.previous_dids == [old_did]
    assert record.rotation_count == 1
    assert record.last_rotated_at is not None


@pytest.mark.asyncio
async def test_rotate_first_write_wins(registry):
    """A DID that was already rotated out cannot be used as old_did again."""
    key_bytes = _make_key_bytes("agent1")
    old_did = _make_did("agent1")
    new_did_1 = _make_did("agent1_v2")
    new_did_2 = _make_did("agent1_v3")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(old_did, key_bytes)
    await registry.rotate(old_did, new_did_1, chain_id)

    # Attempting to rotate from old_did again should fail
    with pytest.raises(ValueError, match="already been rotated|current DID mismatch"):
        await registry.rotate(old_did, new_did_2, chain_id)


@pytest.mark.asyncio
async def test_rotate_unknown_chain(registry):
    """Rotating on a non-existent chain raises ValueError."""
    with pytest.raises(ValueError, match="Unknown rotation chain"):
        await registry.rotate("did:key:z6MkOld", "did:key:z6MkNew", "nonexistent")


@pytest.mark.asyncio
async def test_rotate_wrong_current_did(registry):
    """Rotating with wrong old_did raises ValueError."""
    key_bytes = _make_key_bytes("agent1")
    did = _make_did("agent1")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(did, key_bytes)

    with pytest.raises(ValueError, match="mismatch"):
        await registry.rotate("did:key:z6MkWrong", "did:key:z6MkNew", chain_id)


# ------------------------------------------------------------------
# get_chain_by_did / are_same_chain
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_chain_by_did(registry):
    """get_chain_by_did returns the chain for both current and previous DIDs."""
    key_bytes = _make_key_bytes("agent1")
    old_did = _make_did("agent1")
    new_did = _make_did("agent1_v2")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(old_did, key_bytes)
    await registry.rotate(old_did, new_did, chain_id)

    # Current DID
    record = await registry.get_chain_by_did(new_did)
    assert record is not None
    assert record.chain_id == chain_id
    assert record.current_did == new_did

    # Previous DID (via secondary index)
    record_old = await registry.get_chain_by_did(old_did)
    assert record_old is not None
    assert record_old.chain_id == chain_id

    # Unknown DID
    assert await registry.get_chain_by_did("did:key:z6MkUnknown") is None


@pytest.mark.asyncio
async def test_are_same_chain(registry):
    """are_same_chain_async returns True for DIDs in the same chain."""
    key_bytes = _make_key_bytes("agent1")
    old_did = _make_did("agent1")
    new_did = _make_did("agent1_v2")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(old_did, key_bytes)
    await registry.rotate(old_did, new_did, chain_id)

    assert await registry.are_same_chain_async(old_did, new_did) is True
    assert await registry.are_same_chain_async(old_did, "did:key:z6MkOther") is False


# ------------------------------------------------------------------
# Index reconciliation
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_index_reconciliation(redis):
    """reconcile_index rebuilds the DID-to-chain secondary index."""
    registry = RedisRotationChainRegistry(redis)
    key_bytes = _make_key_bytes("agent1")
    old_did = _make_did("agent1")
    new_did = _make_did("agent1_v2")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(old_did, key_bytes)
    await registry.rotate(old_did, new_did, chain_id)

    # Wipe the secondary index to simulate a Phase 2 failure
    await redis.delete("airlock:did_to_chain")

    # Verify index is gone
    assert await redis.hget("airlock:did_to_chain", new_did) is None

    # Reconcile
    mappings = await registry.reconcile_index()
    assert mappings >= 2  # at least old_did + new_did

    # Verify index is rebuilt
    assert await redis.hget("airlock:did_to_chain", new_did) == chain_id
    assert await redis.hget("airlock:did_to_chain", old_did) == chain_id


# ------------------------------------------------------------------
# Concurrent rotation
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_rotation(redis):
    """Two concurrent rotations on the same chain: only one succeeds."""
    registry = RedisRotationChainRegistry(redis)
    key_bytes = _make_key_bytes("agent1")
    old_did = _make_did("agent1")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(old_did, key_bytes)

    new_did_a = _make_did("agent1_a")
    new_did_b = _make_did("agent1_b")

    results: list[RotationChainRecord | Exception] = []

    async def do_rotate(new_did: str) -> None:
        try:
            record = await registry.rotate(old_did, new_did, chain_id)
            results.append(record)
        except ValueError as exc:
            results.append(exc)

    await asyncio.gather(do_rotate(new_did_a), do_rotate(new_did_b))

    # Exactly one should succeed, one should fail
    successes = [r for r in results if isinstance(r, RotationChainRecord)]
    failures = [r for r in results if isinstance(r, Exception)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert successes[0].rotation_count == 1


# ------------------------------------------------------------------
# get_chain and get_current_did
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_chain(registry):
    """get_chain returns the chain record by chain_id."""
    key_bytes = _make_key_bytes("agent1")
    did = _make_did("agent1")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(did, key_bytes)

    record = await registry.get_chain(chain_id)
    assert record is not None
    assert record.chain_id == chain_id
    assert record.current_did == did

    assert await registry.get_chain("nonexistent") is None


@pytest.mark.asyncio
async def test_get_current_did(registry):
    """get_current_did returns the active DID for a chain."""
    key_bytes = _make_key_bytes("agent1")
    did = _make_did("agent1")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(did, key_bytes)

    assert await registry.get_current_did(chain_id) == did
    assert await registry.get_current_did("nonexistent") is None


# ------------------------------------------------------------------
# check_rotation_rate_async
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_rotation_rate_async(registry):
    """check_rotation_rate_async detects rate limit exceeded."""
    key_bytes = _make_key_bytes("agent1")
    did_0 = _make_did("agent_r0")
    chain_id = compute_chain_id(key_bytes)

    await registry.register_chain_async(did_0, key_bytes)

    # Rotate 3 times
    did_prev = did_0
    for i in range(1, 4):
        did_new = _make_did(f"agent_r{i}")
        await registry.rotate(did_prev, did_new, chain_id)
        did_prev = did_new

    assert await registry.check_rotation_rate_async(chain_id, max_per_24h=3) is True
    assert await registry.check_rotation_rate_async(chain_id, max_per_24h=10) is False
