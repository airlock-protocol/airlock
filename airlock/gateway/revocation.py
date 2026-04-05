"""In-memory and Redis-backed revocation store for agent DIDs."""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


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

    async def is_revoked(self, did: str) -> bool:
        """Return True if *did* is permanently revoked OR suspended."""
        return did in self._revoked or did in self._suspended

    def is_revoked_sync(self, did: str) -> bool:
        """Synchronous variant of :meth:`is_revoked`."""
        return did in self._revoked or did in self._suspended

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
    # Keep the legacy key constant for any external tooling that references it
    _REDIS_KEY = "airlock:revoked"

    def __init__(self, redis: Any) -> None:
        self._redis = redis
        self._local_revoked: dict[str, RevocationReason] = {}
        self._local_suspended: set[str] = set()

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

    async def is_revoked(self, did: str) -> bool:
        """Return True if *did* is permanently revoked OR suspended."""
        if await self._redis.hget(self._REVOKED_KEY, did) is not None:
            return True
        return bool(await self._redis.sismember(self._SUSPENDED_KEY, did))

    def is_revoked_sync(self, did: str) -> bool:
        """Synchronous check against the local cache (fast path)."""
        return did in self._local_revoked or did in self._local_suspended

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
        """Refresh the local cache from Redis."""
        raw = await self._redis.hgetall(self._REVOKED_KEY)
        self._local_revoked = {did: RevocationReason(reason) for did, reason in raw.items()}
        suspended = await self._redis.smembers(self._SUSPENDED_KEY)
        self._local_suspended = set(suspended)
        logger.debug(
            "Revocation cache synced: %d revoked, %d suspended",
            len(self._local_revoked),
            len(self._local_suspended),
        )
