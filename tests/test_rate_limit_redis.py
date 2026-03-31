from __future__ import annotations

import pytest

pytest.importorskip("fakeredis")

from fakeredis import FakeAsyncRedis

from airlock.gateway.rate_limit import RedisSlidingWindow


@pytest.mark.asyncio
async def test_redis_sliding_window_allow():
    r = FakeAsyncRedis(decode_responses=True)
    lim = RedisSlidingWindow(r, max_events=2, window_seconds=60.0)
    assert await lim.allow("ip:1") is True
    assert await lim.allow("ip:1") is True
    assert await lim.allow("ip:1") is False


@pytest.mark.asyncio
async def test_redis_sliding_window_distinct_keys():
    r = FakeAsyncRedis(decode_responses=True)
    lim = RedisSlidingWindow(r, max_events=1, window_seconds=60.0)
    assert await lim.allow("a") is True
    assert await lim.allow("b") is True
