from __future__ import annotations

"""Replay protection: single-use nonces per sender DID.

In-memory (default) or Redis (``AIRLOCK_REDIS_URL``) for multi-replica deploys.
"""

import time
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ReplayBackend(Protocol):
    async def check_and_remember(self, sender_did: str, nonce: str) -> bool:
        """Return True if nonce is fresh; False on replay."""


class InMemoryReplayGuard:
    """Reject reuse of (sender_did, nonce) within a TTL window (in-process)."""

    def __init__(self, ttl_seconds: float = 600.0, max_entries: int = 100_000) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._seen: dict[str, float] = {}
        self._now: Callable[[], float] = time.monotonic

    def _purge_old(self, now: float) -> None:
        cutoff = now - self._ttl
        dead = [k for k, t in self._seen.items() if t < cutoff]
        for k in dead:
            del self._seen[k]
        if len(self._seen) > self._max:
            oldest = sorted(self._seen.items(), key=lambda x: x[1])[: len(self._seen) - self._max]
            for k, _ in oldest:
                del self._seen[k]

    def _check_sync(self, sender_did: str, nonce: str) -> bool:
        key = f"{sender_did}:{nonce}"
        now = self._now()
        self._purge_old(now)
        if key in self._seen:
            return False
        self._seen[key] = now
        return True

    async def check_and_remember(self, sender_did: str, nonce: str) -> bool:
        return self._check_sync(sender_did, nonce)


class RedisReplayGuard:
    """Atomic nonce TTL via ``SET key NX EX`` (shared across gateway replicas)."""

    def __init__(self, redis: Any, ttl_seconds: float = 600.0, key_prefix: str = "airlock:replay:") -> None:
        self._redis = redis
        self._ttl = max(1, int(ttl_seconds))
        self._prefix = key_prefix

    def _key(self, sender_did: str, nonce: str) -> str:
        return f"{self._prefix}{sender_did}:{nonce}"

    async def check_and_remember(self, sender_did: str, nonce: str) -> bool:
        ok = await self._redis.set(
            self._key(sender_did, nonce),
            "1",
            nx=True,
            ex=self._ttl,
        )
        return bool(ok)
