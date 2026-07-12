"""Verifier-side nonce replay cache for web-bot-auth signatures.

No deployed Web Bot Auth verifier observed as of mid-2026 validates
nonces, so within its validity window a captured signature replays
against the same authority (draft-singh-webbotauth-hosted-directories-00
section 7, finding 4). This module supplies the missing cache: after a
signature verifies, the verifier records ``(keyid, nonce)`` for the
remainder of the signature's validity window and rejects any second
sighting as a replay.

``InMemoryNonceCache`` covers the single-process wall. ``RedisNonceCache``
mirrors the gateway's atomic ``SET NX EX`` replay-guard pattern
(:mod:`airlock.gateway.replay`) for multi-replica walls; the Redis client
is injected so the dependency stays optional, exactly like the rest of
the repo's optional-Redis integrations.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class NonceCache(Protocol):
    """Records seen nonces per signing key."""

    async def add(self, keyid: str, nonce: str, ttl_seconds: float) -> bool:
        """Remember ``(keyid, nonce)`` for ``ttl_seconds``.

        Returns True when the pair is fresh (now recorded), False when it
        was already seen inside its window — a replay.
        """
        ...  # pragma: no cover - Protocol body


class InMemoryNonceCache:
    """Single-process nonce cache: dict with per-entry expiry.

    Mutations happen synchronously between awaits, so a single asyncio
    loop needs no locking. Expired entries are purged on every call and
    the cache is capped at ``max_entries`` (oldest-expiry first), the
    same policy as the gateway's in-memory replay guard.
    """

    def __init__(
        self,
        max_entries: int = 100_000,
        time_source: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max = max_entries
        self._now = time_source
        self._expires_at: dict[str, float] = {}

    def _purge(self, now: float) -> None:
        dead = [key for key, expiry in self._expires_at.items() if expiry <= now]
        for key in dead:
            del self._expires_at[key]
        if len(self._expires_at) > self._max:
            overflow = len(self._expires_at) - self._max
            for key, _ in sorted(self._expires_at.items(), key=lambda item: item[1])[:overflow]:
                del self._expires_at[key]

    async def add(self, keyid: str, nonce: str, ttl_seconds: float) -> bool:
        key = f"{keyid}:{nonce}"
        now = self._now()
        self._purge(now)
        if key in self._expires_at:
            return False
        self._expires_at[key] = now + max(ttl_seconds, 0.0)
        return True


class RedisNonceCache:
    """Shared nonce cache via atomic ``SET key NX EX`` for replica fleets.

    Mirrors :class:`airlock.gateway.replay.RedisReplayGuard`; the
    ``redis.asyncio`` client is injected, keeping the redis extra
    optional.
    """

    def __init__(self, redis: Any, key_prefix: str = "airlock:passport:nonce:") -> None:
        self._redis = redis
        self._prefix = key_prefix

    async def add(self, keyid: str, nonce: str, ttl_seconds: float) -> bool:
        ok = await self._redis.set(
            f"{self._prefix}{keyid}:{nonce}",
            "1",
            nx=True,
            ex=max(1, int(ttl_seconds)),
        )
        return bool(ok)
