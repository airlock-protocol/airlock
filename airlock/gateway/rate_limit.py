from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class RateLimitBackend(Protocol):
    async def allow(self, key: str) -> bool:
        """Return True if request is under limit."""


class InMemorySlidingWindow:
    """Sliding-window limiter (in-process)."""

    def __init__(
        self,
        max_events: int,
        window_seconds: float = 60.0,
    ) -> None:
        self._max = max_events
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = {}
        self._now: Callable[[], float] = time.monotonic

    def _allow_sync(self, key: str) -> bool:
        now = self._now()
        cutoff = now - self._window
        seq = self._buckets.setdefault(key, [])
        while seq and seq[0] < cutoff:
            seq.pop(0)
        if len(seq) >= self._max:
            return False
        seq.append(now)
        return True

    async def allow(self, key: str) -> bool:
        return self._allow_sync(key)


class RedisSlidingWindow:
    """Redis sorted-set sliding window (shared across replicas)."""

    def __init__(
        self,
        redis: Any,
        max_events: int,
        window_seconds: float = 60.0,
        key_prefix: str = "airlock:rl:",
    ) -> None:
        self._redis = redis
        self._max = max_events
        self._window = window_seconds
        self._prefix = key_prefix

    def _key(self, logical_key: str) -> str:
        return f"{self._prefix}{logical_key}"

    async def allow(self, key: str) -> bool:
        rk = self._key(key)
        now = time.time()
        window_start = now - self._window
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(rk, 0, window_start)
        pipe.zcard(rk)
        results = await pipe.execute()
        count = int(results[1])
        if count >= self._max:
            return False
        member = f"{now}:{uuid.uuid4().hex}"
        await self._redis.zadd(rk, {member: now})
        await self._redis.expire(rk, int(self._window) + 1)
        return True
