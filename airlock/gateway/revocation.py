"""In-memory revocation store for agent DIDs."""
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


class RevocationStore:
    """O(1) agent revocation lookups backed by an in-memory set."""
    def __init__(self) -> None:
        self._revoked: set[str] = set()

    async def revoke(self, did: str) -> bool:
        if did in self._revoked:
            return False
        self._revoked.add(did)
        logger.info("Agent revoked: %s", did)
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
