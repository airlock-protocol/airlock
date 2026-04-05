"""Tests for v0.3 revocation hardening: irreversible revoke + suspension support.

Covers:
  - Permanent revocation is irreversible (no unrevoke path)
  - Revocation reasons are stored and retrievable
  - Suspension is reversible via reinstate
  - Reinstating a permanently revoked DID fails
  - is_revoked returns True for both revoked and suspended DIDs
  - Cascade revocation propagates reason
  - Default reason is KEY_COMPROMISE
  - Revoking twice is idempotent
  - Suspended DID can be permanently revoked
  - RedisRevocationStore sync works for both revoked and suspended
"""

from __future__ import annotations

import fakeredis.aioredis
import pytest

from airlock.gateway.revocation import (
    RedisRevocationStore,
    RevocationReason,
    RevocationStore,
)

# ---------------------------------------------------------------------------
# In-memory RevocationStore tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_is_permanent() -> None:
    """Once a DID is permanently revoked it stays revoked; there is no undo."""
    store = RevocationStore()
    await store.revoke("did:key:zCompromised")
    assert await store.is_revoked("did:key:zCompromised") is True

    # There is no unrevoke method
    assert not hasattr(store, "unrevoke")

    # reinstate must also refuse
    assert await store.reinstate("did:key:zCompromised") is False
    assert await store.is_revoked("did:key:zCompromised") is True


@pytest.mark.asyncio
async def test_revoke_with_reason() -> None:
    """Revocation reason is stored and retrievable."""
    store = RevocationStore()
    await store.revoke("did:key:zBad", reason=RevocationReason.POLICY_VIOLATION)
    assert store.get_revocation_reason("did:key:zBad") == RevocationReason.POLICY_VIOLATION


@pytest.mark.asyncio
async def test_suspend_and_reinstate() -> None:
    """Suspension is reversible via reinstate."""
    store = RevocationStore()
    assert await store.suspend("did:key:zTemp") is True
    assert await store.is_revoked("did:key:zTemp") is True
    assert await store.is_suspended("did:key:zTemp") is True

    assert await store.reinstate("did:key:zTemp") is True
    assert await store.is_revoked("did:key:zTemp") is False
    assert await store.is_suspended("did:key:zTemp") is False


@pytest.mark.asyncio
async def test_reinstate_revoked_fails() -> None:
    """Permanently revoked DIDs cannot be reinstated."""
    store = RevocationStore()
    await store.revoke("did:key:zGone", reason=RevocationReason.KEY_COMPROMISE)
    assert await store.reinstate("did:key:zGone") is False
    assert await store.is_revoked("did:key:zGone") is True


@pytest.mark.asyncio
async def test_is_revoked_includes_suspended() -> None:
    """is_revoked returns True for both permanently revoked and suspended DIDs."""
    store = RevocationStore()
    await store.revoke("did:key:zPerm")
    await store.suspend("did:key:zSusp")

    assert await store.is_revoked("did:key:zPerm") is True
    assert await store.is_revoked("did:key:zSusp") is True
    assert store.is_revoked_sync("did:key:zPerm") is True
    assert store.is_revoked_sync("did:key:zSusp") is True


@pytest.mark.asyncio
async def test_cascade_revocation_with_reason() -> None:
    """Cascade revocation propagates the same reason to delegates."""
    store = RevocationStore()
    store.register_delegation("did:key:zDelegator", "did:key:zDelegate1")
    store.register_delegation("did:key:zDelegator", "did:key:zDelegate2")

    await store.revoke("did:key:zDelegator", reason=RevocationReason.SYBIL_DETECTED)

    assert store.get_revocation_reason("did:key:zDelegator") == RevocationReason.SYBIL_DETECTED
    assert store.get_revocation_reason("did:key:zDelegate1") == RevocationReason.SYBIL_DETECTED
    assert store.get_revocation_reason("did:key:zDelegate2") == RevocationReason.SYBIL_DETECTED


@pytest.mark.asyncio
async def test_revocation_reason_default() -> None:
    """Default revocation reason is KEY_COMPROMISE."""
    store = RevocationStore()
    await store.revoke("did:key:zDefault")
    assert store.get_revocation_reason("did:key:zDefault") == RevocationReason.KEY_COMPROMISE


@pytest.mark.asyncio
async def test_multiple_revocations_idempotent() -> None:
    """Revoking the same DID twice returns False the second time (no error)."""
    store = RevocationStore()
    assert await store.revoke("did:key:zTwice") is True
    assert await store.revoke("did:key:zTwice") is False
    assert await store.is_revoked("did:key:zTwice") is True


@pytest.mark.asyncio
async def test_suspend_then_revoke() -> None:
    """A suspended DID can be permanently revoked, replacing the suspension."""
    store = RevocationStore()
    await store.suspend("did:key:zEscalate")
    assert await store.is_suspended("did:key:zEscalate") is True

    await store.revoke("did:key:zEscalate", reason=RevocationReason.KEY_COMPROMISE)
    assert await store.is_suspended("did:key:zEscalate") is False
    assert await store.is_revoked("did:key:zEscalate") is True
    assert store.get_revocation_reason("did:key:zEscalate") == RevocationReason.KEY_COMPROMISE

    # Cannot reinstate after permanent revocation
    assert await store.reinstate("did:key:zEscalate") is False


@pytest.mark.asyncio
async def test_suspend_already_revoked_fails() -> None:
    """Suspending a permanently revoked DID returns False."""
    store = RevocationStore()
    await store.revoke("did:key:zAlready")
    assert await store.suspend("did:key:zAlready") is False


@pytest.mark.asyncio
async def test_suspend_already_suspended_fails() -> None:
    """Suspending an already-suspended DID returns False."""
    store = RevocationStore()
    await store.suspend("did:key:zDup")
    assert await store.suspend("did:key:zDup") is False


@pytest.mark.asyncio
async def test_reinstate_not_suspended_returns_false() -> None:
    """Reinstating a DID that is not suspended returns False."""
    store = RevocationStore()
    assert await store.reinstate("did:key:zNowhere") is False


@pytest.mark.asyncio
async def test_get_revocation_reason_none_for_unknown() -> None:
    """get_revocation_reason returns None for unknown DIDs."""
    store = RevocationStore()
    assert store.get_revocation_reason("did:key:zUnknown") is None


@pytest.mark.asyncio
async def test_list_revoked_excludes_suspended() -> None:
    """list_revoked returns only permanently revoked DIDs, not suspended ones."""
    store = RevocationStore()
    await store.revoke("did:key:zPerm")
    await store.suspend("did:key:zSusp")
    result = await store.list_revoked()
    assert "did:key:zPerm" in result
    assert "did:key:zSusp" not in result


# ---------------------------------------------------------------------------
# RedisRevocationStore tests
# ---------------------------------------------------------------------------


@pytest.fixture
async def redis():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


@pytest.fixture
async def redis_store(redis):
    return RedisRevocationStore(redis)


@pytest.mark.asyncio
async def test_redis_revoke_is_permanent(redis_store: RedisRevocationStore) -> None:
    """Redis: permanent revocation cannot be undone."""
    await redis_store.revoke("did:key:zR1")
    assert await redis_store.is_revoked("did:key:zR1") is True
    assert await redis_store.reinstate("did:key:zR1") is False
    assert await redis_store.is_revoked("did:key:zR1") is True


@pytest.mark.asyncio
async def test_redis_revoke_with_reason(redis_store: RedisRevocationStore) -> None:
    """Redis: reason is stored and retrievable after sync."""
    await redis_store.revoke("did:key:zR2", reason=RevocationReason.SUPERSEDED)
    # Local cache updated immediately
    assert redis_store.get_revocation_reason("did:key:zR2") == RevocationReason.SUPERSEDED


@pytest.mark.asyncio
async def test_redis_suspend_and_reinstate(redis_store: RedisRevocationStore) -> None:
    """Redis: suspension is reversible."""
    assert await redis_store.suspend("did:key:zR3") is True
    assert await redis_store.is_revoked("did:key:zR3") is True
    assert await redis_store.is_suspended("did:key:zR3") is True

    assert await redis_store.reinstate("did:key:zR3") is True
    assert await redis_store.is_revoked("did:key:zR3") is False
    assert await redis_store.is_suspended("did:key:zR3") is False


@pytest.mark.asyncio
async def test_redis_reinstate_revoked_fails(redis_store: RedisRevocationStore) -> None:
    """Redis: permanently revoked DID cannot be reinstated."""
    await redis_store.revoke("did:key:zR4")
    assert await redis_store.reinstate("did:key:zR4") is False


@pytest.mark.asyncio
async def test_redis_store_sync(redis, redis_store: RedisRevocationStore) -> None:
    """Redis: sync_cache picks up both revoked and suspended entries."""
    # Write directly to Redis, bypassing the store
    await redis.hset("airlock:revoked", "did:key:zExtRev", "policy_violation")
    await redis.sadd("airlock:suspended", "did:key:zExtSusp")

    # Local cache does not know yet
    assert redis_store.is_revoked_sync("did:key:zExtRev") is False
    assert redis_store.is_revoked_sync("did:key:zExtSusp") is False

    await redis_store.sync_cache()

    assert redis_store.is_revoked_sync("did:key:zExtRev") is True
    assert redis_store.is_revoked_sync("did:key:zExtSusp") is True
    assert redis_store.get_revocation_reason("did:key:zExtRev") == RevocationReason.POLICY_VIOLATION


@pytest.mark.asyncio
async def test_redis_suspend_then_revoke(redis_store: RedisRevocationStore) -> None:
    """Redis: suspended DID can be permanently revoked."""
    await redis_store.suspend("did:key:zR5")
    assert await redis_store.is_suspended("did:key:zR5") is True

    await redis_store.revoke("did:key:zR5", reason=RevocationReason.KEY_COMPROMISE)
    assert await redis_store.is_suspended("did:key:zR5") is False
    assert await redis_store.is_revoked("did:key:zR5") is True


@pytest.mark.asyncio
async def test_redis_revoke_idempotent(redis_store: RedisRevocationStore) -> None:
    """Redis: revoking twice returns False the second time."""
    assert await redis_store.revoke("did:key:zR6") is True
    assert await redis_store.revoke("did:key:zR6") is False


@pytest.mark.asyncio
async def test_redis_list_revoked_excludes_suspended(redis_store: RedisRevocationStore) -> None:
    """Redis: list_revoked returns only permanently revoked DIDs."""
    await redis_store.revoke("did:key:zRPerm")
    await redis_store.suspend("did:key:zRSusp")
    result = await redis_store.list_revoked()
    assert "did:key:zRPerm" in result
    assert "did:key:zRSusp" not in result
