from __future__ import annotations

import math
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Outcome of a rate-limit check with RFC 6585 metadata."""

    allowed: bool
    limit: int
    remaining: int
    reset_at: float  # Unix timestamp when the window resets

    @property
    def retry_after(self) -> int:
        """Seconds until the window resets (ceiling, minimum 1)."""
        delta = self.reset_at - time.time()
        return max(1, math.ceil(delta))


@runtime_checkable
class RateLimitBackend(Protocol):
    async def allow(self, key: str) -> bool:
        """Return True if request is under limit."""

    async def check(self, key: str) -> RateLimitResult:
        """Return structured rate-limit info and record the event if allowed."""


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
        self._wall: Callable[[], float] = time.time

    def _prune(self, key: str) -> list[float]:
        """Remove expired entries and return the pruned sequence."""
        now = self._now()
        cutoff = now - self._window
        seq = self._buckets.setdefault(key, [])
        while seq and seq[0] < cutoff:
            seq.pop(0)
        return seq

    def _allow_sync(self, key: str) -> bool:
        seq = self._prune(key)
        if len(seq) >= self._max:
            return False
        seq.append(self._now())
        return True

    async def allow(self, key: str) -> bool:
        return self._allow_sync(key)

    async def check(self, key: str) -> RateLimitResult:
        seq = self._prune(key)
        wall_now = self._wall()
        reset_at = wall_now + self._window

        if len(seq) >= self._max:
            return RateLimitResult(
                allowed=False,
                limit=self._max,
                remaining=0,
                reset_at=reset_at,
            )

        seq.append(self._now())
        remaining = max(0, self._max - len(seq))
        return RateLimitResult(
            allowed=True,
            limit=self._max,
            remaining=remaining,
            reset_at=reset_at,
        )


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
        result = await self.check(key)
        return result.allowed

    async def check(self, key: str) -> RateLimitResult:
        rk = self._key(key)
        now = time.time()
        window_start = now - self._window
        reset_at = now + self._window

        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(rk, 0, window_start)
        pipe.zcard(rk)
        results = await pipe.execute()
        count = int(results[1])

        if count >= self._max:
            return RateLimitResult(
                allowed=False,
                limit=self._max,
                remaining=0,
                reset_at=reset_at,
            )

        member = f"{now}:{uuid.uuid4().hex}"
        await self._redis.zadd(rk, {member: now})
        await self._redis.expire(rk, int(self._window) + 1)

        remaining = max(0, self._max - (count + 1))
        return RateLimitResult(
            allowed=True,
            limit=self._max,
            remaining=remaining,
            reset_at=reset_at,
        )
