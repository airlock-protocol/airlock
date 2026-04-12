"""Thread-safe AI agent/model inventory for supervisory inspection -- FREE-AI Rec #14."""

from __future__ import annotations

import logging
import threading
from typing import Any

from airlock.compliance.schemas import AgentInventoryEntry, RiskLevel

logger = logging.getLogger(__name__)


class AgentInventory:
    """Thread-safe AI agent/model inventory for supervisory inspection."""

    def __init__(self) -> None:
        self._entries: dict[str, AgentInventoryEntry] = {}
        self._lock = threading.Lock()

    def register(self, entry: AgentInventoryEntry) -> None:
        """Register a new agent in the inventory."""
        if not entry.did.startswith("did:key:"):
            msg = f"Invalid DID format: {entry.did}"
            raise ValueError(msg)
        with self._lock:
            self._entries[entry.did] = entry
        logger.info("Agent registered in inventory: %s", entry.did)

    def get(self, did: str) -> AgentInventoryEntry | None:
        """Get an agent entry by DID."""
        with self._lock:
            return self._entries.get(did)

    def update(self, did: str, **kwargs: Any) -> AgentInventoryEntry | None:
        """Update fields on an existing inventory entry. Returns updated entry or None."""
        with self._lock:
            entry = self._entries.get(did)
            if entry is None:
                return None
            data = entry.model_dump()
            data.update(kwargs)
            updated = AgentInventoryEntry(**data)
            self._entries[did] = updated
            return updated

    def remove(self, did: str) -> bool:
        """Remove an agent from the inventory. Returns True if it existed."""
        with self._lock:
            return self._entries.pop(did, None) is not None

    def list_all(self) -> list[AgentInventoryEntry]:
        """Return all inventory entries."""
        with self._lock:
            return list(self._entries.values())

    def list_by_risk(self, risk_level: RiskLevel) -> list[AgentInventoryEntry]:
        """Return entries matching a specific risk level."""
        with self._lock:
            return [e for e in self._entries.values() if e.risk_level == risk_level]

    def count_by_risk(self) -> dict[str, int]:
        """Return counts grouped by risk level."""
        counts: dict[str, int] = {level.value: 0 for level in RiskLevel}
        with self._lock:
            for entry in self._entries.values():
                counts[entry.risk_level.value] += 1
        return counts

    def search(self, query: str) -> list[AgentInventoryEntry]:
        """Search entries by DID, display name, or description (case-insensitive)."""
        q = query.lower()
        with self._lock:
            return [
                e
                for e in self._entries.values()
                if q in e.did.lower()
                or q in e.display_name.lower()
                or q in e.description.lower()
            ]

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
