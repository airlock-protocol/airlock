from __future__ import annotations

"""Thread-safe agent inventory for compliance tracking."""

import logging
import threading
from datetime import UTC, datetime

from airlock.compliance.schemas import AgentInventoryEntry, RiskLevel

logger = logging.getLogger(__name__)


class AgentInventory:
    """Thread-safe in-memory agent inventory registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, AgentInventoryEntry] = {}

    def register(self, entry: AgentInventoryEntry) -> AgentInventoryEntry:
        """Register a new agent in the inventory."""
        with self._lock:
            self._entries[entry.did] = entry
            logger.info("Agent registered in inventory: %s", entry.did)
            return entry

    def get(self, did: str) -> AgentInventoryEntry | None:
        """Retrieve an agent entry by DID."""
        with self._lock:
            return self._entries.get(did)

    def update(self, did: str, **kwargs: object) -> AgentInventoryEntry | None:
        """Update fields on an existing agent entry."""
        with self._lock:
            entry = self._entries.get(did)
            if entry is None:
                return None
            data = entry.model_dump()
            data.update(kwargs)
            data["last_assessed_at"] = datetime.now(UTC)
            updated = AgentInventoryEntry(**data)
            self._entries[did] = updated
            logger.info("Agent inventory updated: %s", did)
            return updated

    def remove(self, did: str) -> bool:
        """Remove an agent from the inventory. Returns True if removed."""
        with self._lock:
            if did in self._entries:
                del self._entries[did]
                logger.info("Agent removed from inventory: %s", did)
                return True
            return False

    def list_all(self) -> list[AgentInventoryEntry]:
        """Return all inventory entries."""
        with self._lock:
            return list(self._entries.values())

    def list_by_risk(self, risk_level: RiskLevel) -> list[AgentInventoryEntry]:
        """Return entries filtered by risk level."""
        with self._lock:
            return [e for e in self._entries.values() if e.risk_level == risk_level]

    def count_by_risk(self) -> dict[str, int]:
        """Return a count of agents grouped by risk level."""
        with self._lock:
            counts: dict[str, int] = {}
            for entry in self._entries.values():
                key = entry.risk_level.value
                counts[key] = counts.get(key, 0) + 1
            return counts

    def search(self, query: str) -> list[AgentInventoryEntry]:
        """Search entries by display name or DID substring (case-insensitive)."""
        q = query.lower()
        with self._lock:
            return [
                e
                for e in self._entries.values()
                if q in e.did.lower() or q in e.display_name.lower()
            ]
