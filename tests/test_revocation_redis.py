"""Tests for RedisRevocationStore using fakeredis."""

import fakeredis.aioredis
import pytest

from airlock.gateway.revocation import RedisRevocationStore


@pytest.fixture
async def redis():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


@pytest.fixture
async def store(redis):
    return RedisRevocationStore(redis)


@pytest.mark.asyncio
async def test_revoke_new_did(store):
    assert await store.revoke("did:key:abc") is True


@pytest.mark.asyncio
async def test_revoke_duplicate(store):
    await store.revoke("did:key:abc")
    assert await store.revoke("did:key:abc") is False


@pytest.mark.asyncio
async def test_is_revoked(store):
    assert await store.is_revoked("did:key:abc") is False
    await store.revoke("did:key:abc")
    assert await store.is_revoked("did:key:abc") is True


@pytest.mark.asyncio
async def test_suspend_and_reinstate(store):
    await store.suspend("did:key:abc")
    assert await store.is_revoked("did:key:abc") is True
    assert await store.reinstate("did:key:abc") is True
    assert await store.is_revoked("did:key:abc") is False


@pytest.mark.asyncio
async def test_reinstate_not_suspended(store):
    assert await store.reinstate("did:key:abc") is False


@pytest.mark.asyncio
async def test_list_revoked(store):
    await store.revoke("did:key:zzz")
    await store.revoke("did:key:aaa")
    result = await store.list_revoked()
    assert result == ["did:key:aaa", "did:key:zzz"]


@pytest.mark.asyncio
async def test_is_revoked_sync_uses_local_cache(store):
    assert store.is_revoked_sync("did:key:abc") is False
    await store.suspend("did:key:abc")
    # After suspend, local cache is updated
    assert store.is_revoked_sync("did:key:abc") is True
    await store.reinstate("did:key:abc")
    assert store.is_revoked_sync("did:key:abc") is False


@pytest.mark.asyncio
async def test_sync_cache(store, redis):
    # Directly add to Redis, bypassing the store
    await redis.hset("airlock:revoked", "did:key:external", "key_compromise")
    # Local cache doesn't know about it yet
    assert store.is_revoked_sync("did:key:external") is False
    # After sync, local cache is updated
    await store.sync_cache()
    assert store.is_revoked_sync("did:key:external") is True
