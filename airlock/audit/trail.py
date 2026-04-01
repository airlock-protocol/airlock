from __future__ import annotations

"""Hash-chained, append-only audit trail for the Airlock protocol.

Each entry's SHA-256 hash includes the previous entry's hash, making it
impossible to alter history without detection.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


GENESIS_HASH = "0" * 64


class AuditEntry(BaseModel):
    """A single tamper-evident audit log entry."""

    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    actor_did: str
    subject_did: str | None = None
    session_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = GENESIS_HASH
    entry_hash: str = ""


def _compute_hash(entry: AuditEntry) -> str:
    """Compute SHA-256 of an entry using canonical JSON (same approach as crypto/signing.py)."""
    payload = {
        "entry_id": entry.entry_id,
        "timestamp": entry.timestamp.isoformat(),
        "event_type": entry.event_type,
        "actor_did": entry.actor_did,
        "subject_did": entry.subject_did,
        "session_id": entry.session_id,
        "detail": entry.detail,
        "previous_hash": entry.previous_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class AuditTrail:
    """In-memory hash-chained audit trail.

    Thread-safe for single-writer async usage (no concurrent appends needed
    since FastAPI handlers run on the same event loop).
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._last_hash: str = GENESIS_HASH
        self._index: dict[str, AuditEntry] = {}  # entry_id -> entry

    async def append(
        self,
        event_type: str,
        actor_did: str,
        subject_did: str | None = None,
        session_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Create and append a new audit entry, chaining its hash to the previous."""
        entry = AuditEntry(
            event_type=event_type,
            actor_did=actor_did,
            subject_did=subject_did,
            session_id=session_id,
            detail=detail or {},
            previous_hash=self._last_hash,
        )
        entry.entry_hash = _compute_hash(entry)
        self._last_hash = entry.entry_hash

        self._entries.append(entry)
        self._index[entry.entry_id] = entry
        return entry

    async def get_entries(self, limit: int = 100, offset: int = 0) -> list[AuditEntry]:
        """Return entries with pagination (newest first)."""
        reversed_entries = list(reversed(self._entries))
        return reversed_entries[offset : offset + limit]

    async def verify_chain(self) -> tuple[bool, str]:
        """Walk the chain and verify every hash link.

        Returns (True, "ok") if intact, or (False, reason) on first failure.
        """
        if not self._entries:
            return True, "ok"

        expected_prev = GENESIS_HASH
        for i, entry in enumerate(self._entries):
            if entry.previous_hash != expected_prev:
                return False, f"Entry {i} ({entry.entry_id}): previous_hash mismatch"
            recomputed = _compute_hash(entry)
            if entry.entry_hash != recomputed:
                return False, f"Entry {i} ({entry.entry_id}): entry_hash mismatch"
            expected_prev = entry.entry_hash

        return True, "ok"

    async def get_entry(self, entry_id: str) -> AuditEntry | None:
        """Look up an entry by its UUID."""
        return self._index.get(entry_id)

    @property
    def length(self) -> int:
        """Number of entries in the trail."""
        return len(self._entries)
