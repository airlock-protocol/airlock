from __future__ import annotations

import pytest

pytest.importorskip("fakeredis")

from fakeredis import FakeAsyncRedis

from airlock.gateway.replay import RedisReplayGuard


@pytest.mark.asyncio
async def test_redis_replay_guard_set_nx():
    r = FakeAsyncRedis(decode_responses=True)
    g = RedisReplayGuard(r, ttl_seconds=60.0)
    assert await g.check_and_remember("did:key:a", "n1") is True
    assert await g.check_and_remember("did:key:a", "n1") is False
    assert await g.check_and_remember("did:key:a", "n2") is True
