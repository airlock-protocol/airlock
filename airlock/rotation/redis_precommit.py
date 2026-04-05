"""Redis-backed pre-rotation commitment store for multi-replica deployments.

Uses a global Redis Hash ``airlock:precommit`` where each field is a
``chain_id`` and each value is the JSON-serialised ``PreRotationCommitment``.

JSON serialization uses deterministic formatting:
``json.dumps(data, sort_keys=True, separators=(",", ":"))``
"""

from __future__ import annotations

import json
import logging

from typing import Any

from airlock.rotation.precommit import PreRotationCommitment

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PRECOMMIT_KEY = "airlock:precommit"


def _json_dumps(data: object) -> str:
    """Deterministic JSON: sorted keys, no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


class RedisPreCommitmentStore:
    """Redis-backed pre-rotation commitment store.

    Follows the same public API as :class:`PreCommitmentStore` but uses
    Redis HGET/HSET/HDEL on ``airlock:precommit`` for shared storage
    across replicas.

    Parameters
    ----------
    redis:
        An ``redis.asyncio.Redis`` client (must have ``decode_responses=True``).
    """

    def __init__(self, redis: Any) -> None:
        self._redis = redis

    async def get(self, chain_id: str) -> PreRotationCommitment | None:
        """Return the commitment for *chain_id*, or ``None``."""
        raw = await self._redis.hget(_PRECOMMIT_KEY, chain_id)
        if raw is None:
            return None
        data = json.loads(raw)
        return PreRotationCommitment.model_validate(data)

    async def put(self, chain_id: str, commitment: PreRotationCommitment) -> None:
        """Store (or overwrite) a commitment."""
        serialised = _json_dumps(commitment.model_dump(mode="json"))
        await self._redis.hset(_PRECOMMIT_KEY, chain_id, serialised)
        logger.debug("Pre-rotation commitment stored (Redis): chain=%s", chain_id[:16])

    async def delete(self, chain_id: str) -> None:
        """Remove the commitment for *chain_id* (no-op if absent)."""
        await self._redis.hdel(_PRECOMMIT_KEY, chain_id)
        logger.debug("Pre-rotation commitment deleted (Redis): chain=%s", chain_id[:16])
