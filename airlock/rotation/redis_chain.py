"""Redis-backed rotation chain registry for multi-replica deployments.

Uses a per-chain Redis Hash ``airlock:chain:{chain_id}`` for chain records,
and a global Hash ``airlock:did_to_chain`` as a secondary DID-to-chain index.

Rotation is atomic via a single-key Lua script (Cluster-safe).  The secondary
index is updated outside the Lua script and reconciled on startup.

When Lua scripting is unavailable (e.g. fakeredis in tests), falls back to
Python-side Redis transactions (WATCH/MULTI/EXEC).

JSON serialization uses deterministic formatting:
``json.dumps(data, sort_keys=True, separators=(",", ":"))``
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime

from typing import Any

from redis import WatchError

from airlock.rotation.chain import RotationChainRecord, compute_chain_id

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deterministic JSON helpers
# ---------------------------------------------------------------------------


def _json_dumps(data: object) -> str:
    """Deterministic JSON: sorted keys, no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Lua scripts (single-key, Cluster-safe)
# ---------------------------------------------------------------------------

_REGISTER_LUA = """\
-- KEYS[1] = airlock:chain:{chain_id}
-- ARGV[1] = chain_id
-- ARGV[2] = current_did
-- ARGV[3] = created_at (ISO string)
-- ARGV[4] = previous_dids JSON ("[]")
-- ARGV[5] = rotated_from JSON ("[]")
-- ARGV[6] = rotation_timestamps JSON ("[]")

if redis.call("EXISTS", KEYS[1]) == 1 then
    return 0
end

redis.call("HSET", KEYS[1],
    "chain_id", ARGV[1],
    "current_did", ARGV[2],
    "created_at", ARGV[3],
    "last_rotated_at", "",
    "rotation_count", 0,
    "previous_dids", ARGV[4],
    "rotated_from", ARGV[5],
    "rotation_timestamps", ARGV[6])
return 1
"""

_ROTATE_LUA = """\
-- KEYS[1] = airlock:chain:{chain_id}
-- ARGV[1] = old_did
-- ARGV[2] = new_did
-- ARGV[3] = chain_id
-- ARGV[4] = last_rotated_at (ISO string)
-- ARGV[5] = unix_timestamp
-- ARGV[6] = updated previous_dids JSON
-- ARGV[7] = updated rotation_timestamps JSON
-- ARGV[8] = updated rotated_from JSON (includes old_did)

-- 1. Chain must exist
if redis.call("EXISTS", KEYS[1]) == 0 then
    return redis.error_reply("UNKNOWN_CHAIN")
end

-- 2. Current DID must match (primary first-write-wins check)
local current = redis.call("HGET", KEYS[1], "current_did")
if current ~= ARGV[1] then
    return redis.error_reply("CURRENT_DID_MISMATCH")
end

-- 3. Defense-in-depth: explicit rotated-from check (per-chain)
--    Use cjson.decode when available (real Redis), fall back to
--    string.find for environments without cjson (fakeredis/testing).
local rf_raw = redis.call("HGET", KEYS[1], "rotated_from")
if rf_raw and rf_raw ~= "[]" then
    local ok, cjson = pcall(require, "cjson")
    if ok then
        local rf = cjson.decode(rf_raw)
        for _, v in ipairs(rf) do
            if v == ARGV[1] then
                return redis.error_reply("ALREADY_ROTATED")
            end
        end
    else
        -- Fallback: quoted string search in JSON array
        local needle = '"' .. ARGV[1] .. '"'
        if string.find(rf_raw, needle, 1, true) then
            return redis.error_reply("ALREADY_ROTATED")
        end
    end
end

-- 4. Atomic mutation (single key, Cluster-safe)
redis.call("HSET", KEYS[1], "current_did", ARGV[2])
redis.call("HINCRBY", KEYS[1], "rotation_count", 1)
redis.call("HSET", KEYS[1], "last_rotated_at", ARGV[4])
redis.call("HSET", KEYS[1], "previous_dids", ARGV[6])
redis.call("HSET", KEYS[1], "rotation_timestamps", ARGV[7])
redis.call("HSET", KEYS[1], "rotated_from", ARGV[8])

return redis.call("HGET", KEYS[1], "rotation_count")
"""

# ---------------------------------------------------------------------------
# Key constants
# ---------------------------------------------------------------------------

_CHAIN_KEY_PREFIX = "airlock:chain:"
_DID_TO_CHAIN_KEY = "airlock:did_to_chain"


class RedisRotationChainRegistry:
    """Redis-backed rotation chain registry for multi-replica deployments.

    Follows the same public API as :class:`RotationChainRegistry` but uses
    Redis for storage, enabling horizontal scaling.

    Uses Lua scripts for atomicity when available (real Redis), and falls
    back to Python-side Redis transactions when Lua is unavailable
    (e.g. fakeredis in tests).

    Parameters
    ----------
    redis:
        An ``redis.asyncio.Redis`` client (must have ``decode_responses=True``).
    """

    def __init__(self, redis: Any) -> None:
        self._redis = redis
        self._lua_available: bool | None = None  # None = not yet tested
        self._register_sha: str | None = None
        self._rotate_sha: str | None = None

    async def _check_lua(self) -> bool:
        """Test Lua availability once and cache result."""
        if self._lua_available is not None:
            return self._lua_available
        try:
            await self._redis.eval('return 1', 0)
            self._lua_available = True
            # Pre-load scripts
            self._register_sha = await self._redis.script_load(_REGISTER_LUA)
            self._rotate_sha = await self._redis.script_load(_ROTATE_LUA)
        except Exception:
            self._lua_available = False
            logger.info("Lua scripting unavailable, using Python-side transactions")
        return self._lua_available

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _chain_key(chain_id: str) -> str:
        return f"{_CHAIN_KEY_PREFIX}{chain_id}"

    @staticmethod
    def _parse_record(raw: dict[str, str]) -> RotationChainRecord:
        """Parse a Redis Hash (all string values) into a RotationChainRecord."""
        created_at_str = raw.get("created_at", "")
        last_rotated_str = raw.get("last_rotated_at", "")

        created_at = datetime.fromisoformat(created_at_str) if created_at_str else datetime.now(UTC)
        last_rotated_at: datetime | None = None
        if last_rotated_str:
            last_rotated_at = datetime.fromisoformat(last_rotated_str)

        previous_dids_raw = raw.get("previous_dids", "[]")
        rotation_timestamps_raw = raw.get("rotation_timestamps", "[]")
        rotation_count_raw = raw.get("rotation_count", "0")

        return RotationChainRecord(
            chain_id=raw.get("chain_id", ""),
            current_did=raw.get("current_did", ""),
            previous_dids=json.loads(previous_dids_raw),
            rotation_count=int(rotation_count_raw),
            created_at=created_at,
            last_rotated_at=last_rotated_at,
            rotation_timestamps=json.loads(rotation_timestamps_raw),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_chain(
        self,
        did: str,
        public_key_bytes: bytes,
    ) -> RotationChainRecord:
        """Synchronous register_chain is not supported on the Redis variant.

        Use :meth:`register_chain_async` instead.  This exists for API
        compatibility but raises ``NotImplementedError``.
        """
        raise NotImplementedError(
            "RedisRotationChainRegistry.register_chain() is async-only. "
            "Use register_chain_async()."
        )

    async def register_chain_async(
        self,
        did: str,
        public_key_bytes: bytes,
    ) -> RotationChainRecord:
        """Register the first DID in a new rotation chain.

        Idempotent: if the chain already exists, returns the existing record
        unchanged.
        """
        chain_id = compute_chain_id(public_key_bytes)
        now = datetime.now(UTC)
        chain_key = self._chain_key(chain_id)

        use_lua = await self._check_lua()

        if use_lua:
            result = await self._redis.evalsha(
                self._register_sha,
                1,
                chain_key,
                chain_id,
                did,
                now.isoformat(),
                _json_dumps([]),
                _json_dumps([]),
                _json_dumps([]),
            )
            created = result == 1
        else:
            created = await self._register_chain_fallback(chain_key, chain_id, did, now)

        if created:
            # New chain -- update secondary index
            await self._redis.hset(_DID_TO_CHAIN_KEY, did, chain_id)
            logger.info(
                "Rotation chain registered (Redis): chain=%s did=%s",
                chain_id[:16],
                did,
            )
            return RotationChainRecord(
                chain_id=chain_id,
                current_did=did,
                created_at=now,
            )

        # Chain already existed -- read and return current state
        raw = await self._redis.hgetall(chain_key)
        return self._parse_record(raw)

    async def _register_chain_fallback(
        self,
        chain_key: str,
        chain_id: str,
        did: str,
        now: datetime,
    ) -> bool:
        """Register via SETNX-style check + HSET (Python fallback)."""
        exists = await self._redis.exists(chain_key)
        if exists:
            return False
        mapping: dict[str, str] = {
            "chain_id": chain_id,
            "current_did": did,
            "created_at": now.isoformat(),
            "last_rotated_at": "",
            "rotation_count": "0",
            "previous_dids": _json_dumps([]),
            "rotated_from": _json_dumps([]),
            "rotation_timestamps": _json_dumps([]),
        }
        await self._redis.hset(chain_key, mapping=mapping)
        return True

    async def rotate(
        self,
        old_did: str,
        new_did: str,
        chain_id: str,
    ) -> RotationChainRecord:
        """Atomically rotate from ``old_did`` to ``new_did`` within a chain.

        Uses a single-key Lua script for atomicity.  The secondary DID
        index is updated after the Lua script (eventually consistent).
        """
        chain_key = self._chain_key(chain_id)

        # Read current state to build updated lists
        raw = await self._redis.hgetall(chain_key)
        if not raw:
            raise ValueError(f"Unknown rotation chain: {chain_id}")

        previous_dids: list[str] = json.loads(raw.get("previous_dids", "[]"))
        rotation_timestamps: list[float] = json.loads(
            raw.get("rotation_timestamps", "[]")
        )
        rotated_from: list[str] = json.loads(raw.get("rotated_from", "[]"))

        now = datetime.now(UTC)
        unix_ts = time.time()

        updated_previous = [*previous_dids, old_did]
        updated_timestamps = [*rotation_timestamps, unix_ts]
        updated_rotated_from = [*rotated_from, old_did]

        use_lua = await self._check_lua()

        if use_lua:
            try:
                result = await self._redis.evalsha(
                    self._rotate_sha,
                    1,
                    chain_key,
                    old_did,
                    new_did,
                    chain_id,
                    now.isoformat(),
                    str(unix_ts),
                    _json_dumps(updated_previous),
                    _json_dumps(updated_timestamps),
                    _json_dumps(updated_rotated_from),
                )
            except Exception as exc:
                err_msg = str(exc)
                if "UNKNOWN_CHAIN" in err_msg:
                    raise ValueError(
                        f"Unknown rotation chain: {chain_id}"
                    ) from exc
                if "CURRENT_DID_MISMATCH" in err_msg:
                    raise ValueError(
                        f"Chain {chain_id[:16]} current DID mismatch: "
                        f"expected {old_did}"
                    ) from exc
                if "ALREADY_ROTATED" in err_msg:
                    raise ValueError(
                        f"DID {old_did} has already been rotated out "
                        f"(first-write-wins)"
                    ) from exc
                raise
            rotation_count = int(result)
        else:
            rotation_count = await self._rotate_fallback(
                chain_key,
                old_did,
                new_did,
                now,
                unix_ts,
                updated_previous,
                updated_timestamps,
                updated_rotated_from,
                rotated_from,
            )

        # Phase 2: Non-atomic secondary index update (idempotent)
        await self._redis.hset(_DID_TO_CHAIN_KEY, new_did, chain_id)

        logger.info(
            "Key rotated (Redis): chain=%s old=%s new=%s count=%d",
            chain_id[:16],
            old_did,
            new_did,
            rotation_count,
        )

        return RotationChainRecord(
            chain_id=chain_id,
            current_did=new_did,
            previous_dids=updated_previous,
            rotation_count=rotation_count,
            created_at=datetime.fromisoformat(
                raw.get("created_at", now.isoformat())
            ),
            last_rotated_at=now,
            rotation_timestamps=updated_timestamps,
        )

    async def _rotate_fallback(
        self,
        chain_key: str,
        old_did: str,
        new_did: str,
        now: datetime,
        unix_ts: float,
        updated_previous: list[str],
        updated_timestamps: list[float],
        updated_rotated_from: list[str],
        current_rotated_from: list[str],
    ) -> int:
        """Python-side rotation using Redis WATCH/MULTI/EXEC (test fallback).

        Mirrors the Lua script's validation logic.
        """
        # Re-read inside a WATCH to ensure consistency
        async with self._redis.pipeline() as pipe:
            while True:
                try:
                    await pipe.watch(chain_key)

                    raw = await pipe.hgetall(chain_key)
                    if not raw:
                        raise ValueError(
                            f"Unknown rotation chain: {chain_key}"
                        )

                    current_did = raw.get("current_did", "")
                    if current_did != old_did:
                        raise ValueError(
                            f"Chain current DID mismatch: "
                            f"expected {old_did}, got {current_did}"
                        )

                    # Defense-in-depth: rotated-from check
                    rf_list: list[str] = json.loads(
                        raw.get("rotated_from", "[]")
                    )
                    if old_did in rf_list:
                        raise ValueError(
                            f"DID {old_did} has already been rotated out "
                            f"(first-write-wins)"
                        )

                    current_count = int(raw.get("rotation_count", "0"))
                    new_count = current_count + 1

                    pipe.multi()
                    pipe.hset(chain_key, "current_did", new_did)
                    pipe.hset(
                        chain_key, "rotation_count", str(new_count)
                    )
                    pipe.hset(chain_key, "last_rotated_at", now.isoformat())
                    pipe.hset(
                        chain_key,
                        "previous_dids",
                        _json_dumps(updated_previous),
                    )
                    pipe.hset(
                        chain_key,
                        "rotation_timestamps",
                        _json_dumps(updated_timestamps),
                    )
                    pipe.hset(
                        chain_key,
                        "rotated_from",
                        _json_dumps(updated_rotated_from),
                    )
                    await pipe.execute()
                    return new_count
                except WatchError:
                    # Concurrent modification -- retry
                    continue

    async def get_chain_by_did(self, did: str) -> RotationChainRecord | None:
        """Look up the chain record for any DID (current or historical)."""
        chain_id = await self._redis.hget(_DID_TO_CHAIN_KEY, did)
        if chain_id is None:
            return None
        raw = await self._redis.hgetall(self._chain_key(chain_id))
        if not raw:
            return None
        return self._parse_record(raw)

    async def get_chain(self, chain_id: str) -> RotationChainRecord | None:
        """Look up a chain record by its chain_id."""
        raw = await self._redis.hgetall(self._chain_key(chain_id))
        if not raw:
            return None
        return self._parse_record(raw)

    async def get_current_did(self, chain_id: str) -> str | None:
        """Return the currently active DID for a chain, or None."""
        result: str | None = await self._redis.hget(self._chain_key(chain_id), "current_did")
        return result

    def get_chain_id_for_did(self, did: str) -> str | None:
        """Synchronous DID-to-chain lookup.

        This reads from the secondary index.  For the Redis variant, this
        is NOT synchronous -- callers in async contexts should use
        :meth:`get_chain_id_for_did_async`.

        Returns None unconditionally to maintain API compatibility with
        synchronous callers (rate limiter, fingerprint).  Use the async
        variant for correct results.
        """
        return None

    async def get_chain_id_for_did_async(self, did: str) -> str | None:
        """Async DID-to-chain lookup via Redis."""
        result: str | None = await self._redis.hget(_DID_TO_CHAIN_KEY, did)
        return result

    def are_same_chain(self, did_a: str, did_b: str) -> bool:
        """Synchronous same-chain check.

        Returns False unconditionally for the Redis variant.  Use
        :meth:`are_same_chain_async` in async contexts.
        """
        return False

    async def are_same_chain_async(self, did_a: str, did_b: str) -> bool:
        """Return True if both DIDs belong to the same rotation chain."""
        chain_a = await self._redis.hget(_DID_TO_CHAIN_KEY, did_a)
        chain_b = await self._redis.hget(_DID_TO_CHAIN_KEY, did_b)
        if chain_a is None or chain_b is None:
            return False
        return bool(chain_a == chain_b)

    def check_rotation_rate(
        self,
        chain_id: str,
        max_per_24h: int = 3,
    ) -> bool:
        """Synchronous rate check -- not supported, always returns False.

        Use :meth:`check_rotation_rate_async` in async contexts.
        """
        return False

    async def check_rotation_rate_async(
        self,
        chain_id: str,
        max_per_24h: int = 3,
    ) -> bool:
        """Return True if the chain has exceeded the rotation rate limit."""
        raw_ts = await self._redis.hget(
            self._chain_key(chain_id), "rotation_timestamps"
        )
        if not raw_ts:
            return False
        timestamps: list[float] = json.loads(raw_ts)
        cutoff = time.time() - 86400.0
        recent = sum(1 for ts in timestamps if ts > cutoff)
        return recent >= max_per_24h

    # ------------------------------------------------------------------
    # Index reconciliation
    # ------------------------------------------------------------------

    async def reconcile_index(self) -> int:
        """Rebuild the ``did_to_chain`` secondary index from all chain records.

        Returns the number of DID mappings written.  Should be called on
        startup to heal any Phase 2 failures from previous runs.
        """
        cursor: int = 0
        total_mappings = 0
        prefix = _CHAIN_KEY_PREFIX

        while True:
            cursor, keys = await self._redis.scan(
                cursor=cursor,
                match=f"{prefix}*",
                count=100,
            )
            for key in keys:
                raw = await self._redis.hgetall(key)
                if not raw:
                    continue
                chain_id = raw.get("chain_id", "")
                current_did = raw.get("current_did", "")
                previous_dids: list[str] = json.loads(
                    raw.get("previous_dids", "[]")
                )

                if current_did and chain_id:
                    await self._redis.hset(
                        _DID_TO_CHAIN_KEY, current_did, chain_id
                    )
                    total_mappings += 1

                for prev_did in previous_dids:
                    if prev_did and chain_id:
                        await self._redis.hset(
                            _DID_TO_CHAIN_KEY, prev_did, chain_id
                        )
                        total_mappings += 1

            if cursor == 0:
                break

        logger.info(
            "Index reconciliation complete: %d DID mappings rebuilt",
            total_mappings,
        )
        return total_mappings
