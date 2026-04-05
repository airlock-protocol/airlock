"""In-memory and Redis-backed revocation store for agent DIDs."""

from __future__ import annotations

import logging
import time
from enum import StrEnum
from typing import Any

try:
    from cachetools import TTLCache
except ImportError:  # pragma: no cover
    TTLCache = None

logger = logging.getLogger(__name__)

_GRACE_KEY_PREFIX = "airlock:grace:"


class RevocationReason(StrEnum):
    """Reason for permanently revoking an agent DID."""

    KEY_COMPROMISE = "key_compromise"
    SUPERSEDED = "superseded"
    CEASED_OPERATION = "ceased_operation"
    POLICY_VIOLATION = "policy_violation"
    SYBIL_DETECTED = "sybil_detected"
    INVESTIGATION = "investigation"
    OWNER_REQUEST = "owner_request"


class RevocationStore:
    """O(1) agent revocation lookups backed by in-memory dicts/sets.

    Permanent revocations (``revoke``) are irreversible.
    Suspensions (``suspend``) are reversible via ``reinstate``.
    ``is_revoked`` returns True for both permanently revoked and suspended DIDs.
    """

    def __init__(self) -> None:
        self._revoked: dict[str, RevocationReason] = {}
        self._suspended: set[str] = set()
        self._delegations: dict[str, set[str]] = {}  # delegator -> {delegate, ...}
        self._rotated_out: dict[str, float] = {}  # did -> grace_until unix timestamp

    def register_delegation(self, delegator_did: str, delegate_did: str) -> None:
        """Record that delegator_did has delegated to delegate_did."""
        if delegator_did not in self._delegations:
            self._delegations[delegator_did] = set()
        self._delegations[delegator_did].add(delegate_did)
        logger.info("Delegation registered: %s -> %s", delegator_did, delegate_did)

    async def revoke(
        self,
        did: str,
        reason: RevocationReason = RevocationReason.KEY_COMPROMISE,
    ) -> bool:
        """Permanently revoke *did*. This action is irreversible.

        If the DID was previously suspended, the suspension is removed and
        replaced by a permanent revocation.  Returns False if already
        permanently revoked (idempotent).
        """
        if did in self._revoked:
            return False
        self._revoked[did] = reason
        # If it was merely suspended, remove from suspended set
        self._suspended.discard(did)
        logger.info("Agent permanently revoked: %s (reason=%s)", did, reason.value)
        # Cascade revocation to all delegates
        delegates = self._delegations.get(did, set())
        for delegate_did in delegates:
            if delegate_did not in self._revoked:
                self._revoked[delegate_did] = reason
                self._suspended.discard(delegate_did)
                logger.info(
                    "Cascade revoked delegate: %s (delegator: %s, reason=%s)",
                    delegate_did,
                    did,
                    reason.value,
                )
        return True

    async def suspend(self, did: str) -> bool:
        """Reversibly suspend *did*. Returns False if already suspended or permanently revoked."""
        if did in self._revoked or did in self._suspended:
            return False
        self._suspended.add(did)
        logger.info("Agent suspended: %s", did)
        return True

    async def reinstate(self, did: str) -> bool:
        """Reinstate a suspended DID. Fails if DID is permanently revoked."""
        if did in self._revoked:
            logger.warning(
                "Cannot reinstate permanently revoked DID: %s",
                did,
            )
            return False
        if did not in self._suspended:
            return False
        self._suspended.discard(did)
        logger.info("Agent reinstated: %s", did)
        return True

    async def rotate_out(self, did: str, grace_seconds: int = 60) -> bool:
        """Mark a DID as superseded by key rotation with an optional grace period.

        Unlike ``revoke()``, this does NOT cascade to delegates.  The DID
        remains valid until ``grace_until`` passes, allowing in-flight
        requests to complete.

        Returns False if the DID is already permanently revoked.
        """
        if did in self._revoked:
            return False
        grace_until = time.time() + grace_seconds
        self._rotated_out[did] = grace_until
        logger.info(
            "DID rotated out (superseded): %s grace_until=%.0f",
            did,
            grace_until,
        )
        return True

    async def is_revoked(self, did: str) -> bool:
        """Return True if *did* is permanently revoked, suspended, or past grace period."""
        if did in self._revoked or did in self._suspended:
            return True
        grace_until = self._rotated_out.get(did)
        if grace_until is not None and time.time() > grace_until:
            return True
        return False

    def is_revoked_sync(self, did: str) -> bool:
        """Synchronous variant of :meth:`is_revoked`."""
        if did in self._revoked or did in self._suspended:
            return True
        grace_until = self._rotated_out.get(did)
        if grace_until is not None and time.time() > grace_until:
            return True
        return False

    async def is_suspended(self, did: str) -> bool:
        """Return True only if *did* is suspended (not permanently revoked)."""
        return did in self._suspended and did not in self._revoked

    def get_revocation_reason(self, did: str) -> RevocationReason | None:
        """Return the revocation reason, or None if not permanently revoked."""
        return self._revoked.get(did)

    async def list_revoked(self) -> list[str]:
        """Return all permanently revoked DIDs (sorted)."""
        return sorted(self._revoked)

    async def list_suspended(self) -> list[str]:
        """Return all suspended DIDs (sorted)."""
        return sorted(self._suspended)

    def get_revoked_with_reasons(self) -> dict[str, RevocationReason]:
        """Return a copy of all permanently revoked DIDs with their reasons."""
        return dict(self._revoked)


class RedisRevocationStore:
    """Revocation store backed by Redis for multi-replica deployments.

    Uses a Redis hash ``airlock:revoked`` (``{did: reason}``) for permanent
    revocations and a Redis set ``airlock:suspended`` for reversible
    suspensions.  A local cache keeps ``is_revoked_sync`` fast.
    """

    _REVOKED_KEY = "airlock:revoked"
    _SUSPENDED_KEY = "airlock:suspended"
    _ROTATED_OUT_KEY = "airlock:rotated_out"
    # Keep the legacy key constant for any external tooling that references it
    _REDIS_KEY = "airlock:revoked"

    def __init__(self, redis: Any) -> None:
        self._redis = redis
        self._local_revoked: dict[str, RevocationReason] = {}
        self._local_suspended: set[str] = set()
        # Micro-cache for is_revoked_sync grace period lookups (TTL=5s)
        self._grace_cache: Any = (
            TTLCache(maxsize=10000, ttl=5) if TTLCache is not None else {}
        )

    async def revoke(
        self,
        did: str,
        reason: RevocationReason = RevocationReason.KEY_COMPROMISE,
    ) -> bool:
        """Permanently revoke *did* (irreversible). Returns False if already revoked."""
        existing = await self._redis.hget(self._REVOKED_KEY, did)
        if existing is not None:
            return False
        await self._redis.hset(self._REVOKED_KEY, did, reason.value)
        # Remove from suspended if present
        await self._redis.srem(self._SUSPENDED_KEY, did)
        self._local_revoked[did] = reason
        self._local_suspended.discard(did)
        logger.info("Agent permanently revoked (Redis): %s (reason=%s)", did, reason.value)
        return True

    async def suspend(self, did: str) -> bool:
        """Reversibly suspend *did*. Returns False if already suspended or permanently revoked."""
        if await self._redis.hget(self._REVOKED_KEY, did) is not None:
            return False
        added = await self._redis.sadd(self._SUSPENDED_KEY, did)
        if added:
            self._local_suspended.add(did)
            logger.info("Agent suspended (Redis): %s", did)
            return True
        return False

    async def reinstate(self, did: str) -> bool:
        """Reinstate a suspended DID. Fails if permanently revoked."""
        if await self._redis.hget(self._REVOKED_KEY, did) is not None:
            logger.warning("Cannot reinstate permanently revoked DID (Redis): %s", did)
            return False
        removed = await self._redis.srem(self._SUSPENDED_KEY, did)
        if removed:
            self._local_suspended.discard(did)
            logger.info("Agent reinstated (Redis): %s", did)
            return True
        return False

    async def rotate_out(self, did: str, grace_seconds: int = 60) -> bool:
        """Mark a DID as superseded by key rotation with an optional grace period.

        Unlike ``revoke()``, this does NOT cascade to delegates.  The DID
        remains valid until the grace key expires in Redis, allowing in-flight
        requests to complete.

        Grace periods are stored in Redis via ``SETEX airlock:grace:{did}``
        so they are shared across all replicas.  The DID is also added to
        the ``airlock:rotated_out`` set so we know it was rotated even after
        the grace key expires.

        Returns False if the DID is already permanently revoked.
        """
        if await self._redis.hget(self._REVOKED_KEY, did) is not None:
            return False
        # Record that this DID was rotated out (permanent marker)
        await self._redis.sadd(self._ROTATED_OUT_KEY, did)
        # Set grace period key with TTL -- while it exists, DID is still valid
        grace_key = f"{_GRACE_KEY_PREFIX}{did}"
        ttl = max(1, int(grace_seconds))
        await self._redis.setex(grace_key, ttl, "1")
        logger.info(
            "DID rotated out (superseded, Redis): %s grace_seconds=%d",
            did,
            ttl,
        )
        return True

    async def is_revoked(self, did: str) -> bool:
        """Return True if *did* is permanently revoked, suspended, or past grace period.

        Grace periods are checked via Redis:
        - ``airlock:rotated_out`` set records all DIDs that were rotated out.
        - ``airlock:grace:{did}`` is a TTL key that exists during the grace window.
        - If DID is in rotated_out AND grace key has expired -> revoked.
        - If DID is in rotated_out AND grace key still exists -> NOT revoked.
        """
        if await self._redis.hget(self._REVOKED_KEY, did) is not None:
            return True
        if bool(await self._redis.sismember(self._SUSPENDED_KEY, did)):
            return True
        # Check if DID was rotated out
        if bool(await self._redis.sismember(self._ROTATED_OUT_KEY, did)):
            # Was rotated out -- check if grace period is still active
            grace_key = f"{_GRACE_KEY_PREFIX}{did}"
            grace_exists = await self._redis.exists(grace_key)
            if not grace_exists:
                # Grace expired -> revoked
                return True
            # Grace still active -> NOT revoked yet
        return False

    def is_revoked_sync(self, did: str) -> bool:
        """Synchronous check against the local cache (fast path).

        Uses a TTL micro-cache (5s) to avoid stale grace period state
        across replicas.  The cache is populated by :meth:`is_revoked`
        (async) and :meth:`sync_cache`.
        """
        if did in self._local_revoked or did in self._local_suspended:
            return True
        # Check micro-cache for grace period state
        cached = self._grace_cache.get(did)
        if cached is not None:
            return bool(cached)
        return False

    async def is_suspended(self, did: str) -> bool:
        """Return True only if *did* is suspended (not permanently revoked)."""
        if await self._redis.hget(self._REVOKED_KEY, did) is not None:
            return False
        return bool(await self._redis.sismember(self._SUSPENDED_KEY, did))

    def get_revocation_reason(self, did: str) -> RevocationReason | None:
        """Return the revocation reason from local cache, or None."""
        return self._local_revoked.get(did)

    async def list_revoked(self) -> list[str]:
        """Return all permanently revoked DIDs (sorted)."""
        members = await self._redis.hkeys(self._REVOKED_KEY)
        return sorted(members)

    async def list_suspended(self) -> list[str]:
        """Return all suspended DIDs (sorted)."""
        members = await self._redis.smembers(self._SUSPENDED_KEY)
        return sorted(members)

    def get_revoked_with_reasons(self) -> dict[str, RevocationReason]:
        """Return a copy of all permanently revoked DIDs with their reasons from local cache."""
        return dict(self._local_revoked)

    async def sync_cache(self) -> None:
        """Refresh the local cache from Redis.

        Also refreshes the grace period micro-cache for any rotated-out DIDs.
        """
        raw = await self._redis.hgetall(self._REVOKED_KEY)
        self._local_revoked = {did: RevocationReason(reason) for did, reason in raw.items()}
        suspended = await self._redis.smembers(self._SUSPENDED_KEY)
        self._local_suspended = set(suspended)

        # Refresh grace period micro-cache
        rotated_out = await self._redis.smembers(self._ROTATED_OUT_KEY)
        for did in rotated_out:
            grace_key = f"{_GRACE_KEY_PREFIX}{did}"
            grace_exists = await self._redis.exists(grace_key)
            # Cache True (revoked) if grace expired, False if still in grace
            self._grace_cache[did] = not bool(grace_exists)

        logger.debug(
            "Revocation cache synced: %d revoked, %d suspended, %d rotated_out",
            len(self._local_revoked),
            len(self._local_suspended),
            len(rotated_out),
        )
