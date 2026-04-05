from __future__ import annotations

import logging
import math
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

_DID_PATTERN = re.compile(r"^did:key:z[a-km-zA-HJ-NP-Z1-9]+$")


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


class DIDRateLimiter:
    """Identity-based rate limiter keyed on DID strings.

    Wraps any :class:`RateLimitBackend` (in-memory or Redis) and adds
    DID format validation before recording or checking requests.  Invalid
    DIDs are rejected immediately so they never pollute the backing store.
    """

    def __init__(
        self,
        backend: InMemorySlidingWindow | RedisSlidingWindow,
        *,
        key_prefix: str = "did:",
    ) -> None:
        self._backend = backend
        self._key_prefix = key_prefix

    @staticmethod
    def is_valid_did(did: str) -> bool:
        """Return ``True`` if *did* matches the ``did:key:z...`` pattern."""
        return bool(_DID_PATTERN.match(did))

    def _make_key(self, did: str) -> str:
        return f"{self._key_prefix}{did}:handshake"

    async def is_rate_limited(self, did: str) -> bool:
        """Return ``True`` when *did* has exceeded its rate limit.

        Invalid DIDs are always considered rate-limited (rejected).
        """
        if not self.is_valid_did(did):
            logger.warning("DIDRateLimiter: rejected invalid DID format: %s", did)
            return True
        result = await self._backend.check(self._make_key(did))
        return not result.allowed

    async def record_request(self, did: str) -> None:
        """Record a request from *did* without returning a limit check.

        Raises :class:`ValueError` if *did* has an invalid format.
        """
        if not self.is_valid_did(did):
            raise ValueError(f"Invalid DID format: {did}")
        await self._backend.allow(self._make_key(did))

    async def check(self, did: str) -> RateLimitResult:
        """Check and record a request, returning full :class:`RateLimitResult`.

        Invalid DIDs receive an immediate denial result.
        """
        if not self.is_valid_did(did):
            logger.warning("DIDRateLimiter: rejected invalid DID format: %s", did)
            return RateLimitResult(
                allowed=False,
                limit=0,
                remaining=0,
                reset_at=time.time() + 60,
            )
        return await self._backend.check(self._make_key(did))
