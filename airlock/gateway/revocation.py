"""In-memory and Redis-backed revocation store for agent DIDs."""
from __future__ import annotations
import logging
from typing import Any

logger = logging.getLogger(__name__)


class RevocationStore:
    """O(1) agent revocation lookups backed by an in-memory set."""
    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._delegations: dict[str, set[str]] = {}  # delegator -> {delegate, ...}

    def register_delegation(self, delegator_did: str, delegate_did: str) -> None:
        """Record that delegator_did has delegated to delegate_did."""
        if delegator_did not in self._delegations:
            self._delegations[delegator_did] = set()
        self._delegations[delegator_did].add(delegate_did)
        logger.info("Delegation registered: %s -> %s", delegator_did, delegate_did)

    async def revoke(self, did: str) -> bool:
        if did in self._revoked:
            return False
        self._revoked.add(did)
        logger.info("Agent revoked: %s", did)
        # Cascade revocation to all delegates
        delegates = self._delegations.get(did, set())
        for delegate_did in delegates:
            if delegate_did not in self._revoked:
                self._revoked.add(delegate_did)
                logger.info("Cascade revoked delegate: %s (delegator: %s)", delegate_did, did)
        return True

    async def unrevoke(self, did: str) -> bool:
        if did not in self._revoked:
            return False
        self._revoked.discard(did)
        logger.info("Agent unrevoked: %s", did)
        return True

    async def is_revoked(self, did: str) -> bool:
        return did in self._revoked

    def is_revoked_sync(self, did: str) -> bool:
        return did in self._revoked

    async def list_revoked(self) -> list[str]:
        return sorted(self._revoked)


class RedisRevocationStore:
    """Revocation store backed by a Redis SET for multi-replica deployments.

    Uses ``SADD``/``SREM``/``SISMEMBER`` for durable, shared state and keeps
    a local ``_local_cache`` set so that the orchestrator's synchronous
    ``is_revoked_sync`` calls stay fast without hitting the network.
    """

    _REDIS_KEY = "airlock:revoked_dids"

    def __init__(self, redis: Any) -> None:
        self._redis = redis
        self._local_cache: set[str] = set()

    async def revoke(self, did: str) -> bool:
        added = await self._redis.sadd(self._REDIS_KEY, did)
        if added:
            self._local_cache.add(did)
            logger.info("Agent revoked (Redis): %s", did)
            return True
        return False

    async def unrevoke(self, did: str) -> bool:
        removed = await self._redis.srem(self._REDIS_KEY, did)
        if removed:
            self._local_cache.discard(did)
            logger.info("Agent unrevoked (Redis): %s", did)
            return True
        return False

    async def is_revoked(self, did: str) -> bool:
        return bool(await self._redis.sismember(self._REDIS_KEY, did))

    def is_revoked_sync(self, did: str) -> bool:
        """Synchronous check against the local cache (fast path)."""
        return did in self._local_cache

    async def list_revoked(self) -> list[str]:
        members = await self._redis.smembers(self._REDIS_KEY)
        return sorted(members)

    async def sync_cache(self) -> None:
        """Refresh the local cache from Redis."""
        members = await self._redis.smembers(self._REDIS_KEY)
        self._local_cache = set(members)
        logger.debug("Revocation cache synced: %d entries", len(self._local_cache))
