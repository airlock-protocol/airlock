from __future__ import annotations

"""Hash-chained, append-only audit trail for the Airlock protocol.

Each entry's SHA-256 hash includes the previous entry's hash, making it
impossible to alter history without detection.

Optionally backed by SQLite for persistence across gateway restarts.
"""

import asyncio
import hashlib
import json
import logging
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from datetime import UTC, datetime

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


class AuditEntry(BaseModel):
    """A single tamper-evident audit log entry."""

    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str
    actor_did: str
    subject_did: str | None = None
    session_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = GENESIS_HASH
    entry_hash: str = ""
    rotation_chain_id: str | None = None


def _compute_hash(entry: AuditEntry) -> str:
    """Compute SHA-256 of an entry using canonical JSON (same approach as crypto/signing.py)."""
    payload = {
        "entry_id": entry.entry_id,
        "timestamp": entry.timestamp.isoformat(),
        "event_type": entry.event_type,
        "actor_did": entry.actor_did,
        "subject_did": entry.subject_did,
        "session_id": entry.session_id,
        "rotation_chain_id": entry.rotation_chain_id,
        "detail": entry.detail,
        "previous_hash": entry.previous_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    return hashlib.sha256(canonical).hexdigest()


_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS audit_entries (
    sequence_number   INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id          TEXT UNIQUE NOT NULL,
    timestamp         TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    actor_did         TEXT NOT NULL,
    subject_did       TEXT,
    session_id        TEXT,
    detail_json       TEXT NOT NULL DEFAULT '{}',
    previous_hash     TEXT NOT NULL,
    entry_hash        TEXT NOT NULL,
    rotation_chain_id TEXT
)
"""

_CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_audit_chain_id ON audit_entries(rotation_chain_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_entries(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_audit_actor_did ON audit_entries(actor_did)",
]


class AuditStore:
    """SQLite-backed persistent audit storage.

    All public methods that touch the database are async, wrapping synchronous
    ``sqlite3`` calls via ``asyncio.to_thread()`` so the FastAPI event loop is
    never blocked.

    Write serialization is handled by ``sqlite3.connect(path, timeout=10.0)``
    which retries internally for up to 10 seconds when the database is locked.
    WAL journal mode allows concurrent reads during writes.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._conn: sqlite3.Connection | None = None
        self._last_hash: str = GENESIS_HASH
        self._sequence_counter: int = 0

    # -- lifecycle ------------------------------------------------------------

    def open(self) -> None:
        """Open (or create) the SQLite database and initialise the schema.

        Must be called once at startup, before any async methods.
        """
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            self._path, timeout=10.0, check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(_CREATE_TABLE_SQL)
        for idx_sql in _CREATE_INDEXES_SQL:
            self._conn.execute(idx_sql)
        self._conn.commit()

        # Restore chain state from the highest sequence entry.
        row = self._conn.execute(
            "SELECT entry_hash, sequence_number FROM audit_entries "
            "ORDER BY sequence_number DESC LIMIT 1"
        ).fetchone()
        if row is not None:
            self._last_hash = row[0]
            self._sequence_counter = row[1]
        else:
            self._last_hash = GENESIS_HASH
            self._sequence_counter = 0

        logger.info(
            "AuditStore opened (path=%s, entries=%d, last_seq=%d)",
            self._path,
            self._sequence_counter,
            self._sequence_counter,
        )

    def close(self) -> None:
        """Close the SQLite connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            logger.info("AuditStore closed (path=%s)", self._path)

    # -- properties -----------------------------------------------------------

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def sequence_counter(self) -> int:
        return self._sequence_counter

    # -- async public API -----------------------------------------------------

    async def append(self, entry: AuditEntry, sequence_number: int) -> None:
        """Persist an audit entry to SQLite."""
        await asyncio.to_thread(self._append_sync, entry, sequence_number)

    async def get_entries(self, limit: int, offset: int) -> list[AuditEntry]:
        """Return entries with pagination (newest first)."""
        return await asyncio.to_thread(self._get_entries_sync, limit, offset)

    async def get_all_entries_ordered(self) -> list[AuditEntry]:
        """Return all entries ordered by sequence (oldest first).

        Uses ``fetchmany(1000)`` for constant-memory streaming.
        """
        return await asyncio.to_thread(self._get_all_entries_ordered_sync)

    async def get_entries_filtered(
        self,
        chain_id: str | None = None,
        actor_did: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Return entries filtered by chain_id and/or actor_did (newest first)."""
        return await asyncio.to_thread(
            self._get_entries_filtered_sync, chain_id, actor_did, limit, offset,
        )

    async def count(self) -> int:
        """Return the total number of audit entries."""
        return await asyncio.to_thread(self._count_sync)

    # -- sync internals (run in thread pool) ----------------------------------

    def _append_sync(self, entry: AuditEntry, sequence_number: int) -> None:
        assert self._conn is not None
        detail_json = json.dumps(entry.detail, sort_keys=True, separators=(",", ":"), default=str)
        self._conn.execute(
            "INSERT INTO audit_entries "
            "(entry_id, timestamp, event_type, actor_did, subject_did, session_id, "
            " detail_json, previous_hash, entry_hash, rotation_chain_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.entry_id,
                entry.timestamp.isoformat(),
                entry.event_type,
                entry.actor_did,
                entry.subject_did,
                entry.session_id,
                detail_json,
                entry.previous_hash,
                entry.entry_hash,
                entry.rotation_chain_id,
            ),
        )
        self._conn.commit()
        self._last_hash = entry.entry_hash
        self._sequence_counter = sequence_number

    def _get_entries_sync(self, limit: int, offset: int) -> list[AuditEntry]:
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT entry_id, timestamp, event_type, actor_did, subject_did, "
            "       session_id, detail_json, previous_hash, entry_hash, rotation_chain_id "
            "FROM audit_entries ORDER BY sequence_number DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def _get_all_entries_ordered_sync(self) -> list[AuditEntry]:
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT entry_id, timestamp, event_type, actor_did, subject_did, "
            "       session_id, detail_json, previous_hash, entry_hash, rotation_chain_id "
            "FROM audit_entries ORDER BY sequence_number ASC"
        )
        entries: list[AuditEntry] = []
        while True:
            batch = cursor.fetchmany(1000)
            if not batch:
                break
            entries.extend(self._row_to_entry(row) for row in batch)
        return entries

    def _get_entries_filtered_sync(
        self,
        chain_id: str | None,
        actor_did: str | None,
        limit: int,
        offset: int,
    ) -> list[AuditEntry]:
        assert self._conn is not None
        conditions: list[str] = []
        params: list[object] = []
        if chain_id is not None:
            conditions.append("rotation_chain_id = ?")
            params.append(chain_id)
        if actor_did is not None:
            conditions.append("actor_did = ?")
            params.append(actor_did)
        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)
        query = (
            "SELECT entry_id, timestamp, event_type, actor_did, subject_did, "
            "       session_id, detail_json, previous_hash, entry_hash, rotation_chain_id "
            f"FROM audit_entries {where} ORDER BY sequence_number DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        cursor = self._conn.execute(query, params)
        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def _count_sync(self) -> int:
        assert self._conn is not None
        row = self._conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()
        return row[0] if row else 0

    @staticmethod
    def _row_to_entry(row: tuple[Any, ...]) -> AuditEntry:
        """Convert a SQLite row tuple into an AuditEntry."""
        detail = json.loads(row[6]) if row[6] else {}
        return AuditEntry(
            entry_id=row[0],
            timestamp=datetime.fromisoformat(row[1]),
            event_type=row[2],
            actor_did=row[3],
            subject_did=row[4],
            session_id=row[5],
            detail=detail,
            previous_hash=row[7],
            entry_hash=row[8],
            rotation_chain_id=row[9],
        )


class AuditTrail:
    """Hash-chained audit trail with optional SQLite persistence.

    Thread-safe for single-writer async usage (no concurrent appends needed
    since FastAPI handlers run on the same event loop).

    When a ``store`` is provided, entries are written to both the in-memory list
    and SQLite.  Reads prefer the store when available.
    """

    def __init__(self, store: AuditStore | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._store = store
        self._index: dict[str, AuditEntry] = {}  # entry_id -> entry

        if store is not None:
            self._last_hash: str = store.last_hash
            self._sequence: int = store.sequence_counter
        else:
            self._last_hash = GENESIS_HASH
            self._sequence = 0

    async def append(
        self,
        event_type: str,
        actor_did: str,
        subject_did: str | None = None,
        session_id: str | None = None,
        detail: dict[str, Any] | None = None,
        rotation_chain_id: str | None = None,
    ) -> AuditEntry:
        """Create and append a new audit entry, chaining its hash to the previous."""
        entry = AuditEntry(
            event_type=event_type,
            actor_did=actor_did,
            subject_did=subject_did,
            session_id=session_id,
            detail=detail or {},
            previous_hash=self._last_hash,
            rotation_chain_id=rotation_chain_id,
        )
        entry.entry_hash = _compute_hash(entry)
        self._last_hash = entry.entry_hash
        self._sequence += 1

        self._entries.append(entry)
        self._index[entry.entry_id] = entry

        if self._store is not None:
            await self._store.append(entry, self._sequence)

        return entry

    async def get_entries(self, limit: int = 100, offset: int = 0) -> list[AuditEntry]:
        """Return entries with pagination (newest first)."""
        if self._store is not None:
            return await self._store.get_entries(limit, offset)
        reversed_entries = list(reversed(self._entries))
        return reversed_entries[offset : offset + limit]

    async def verify_chain(self) -> tuple[bool, str]:
        """Walk the chain and verify every hash link.

        Returns (True, "ok") if intact, or (False, reason) on first failure.
        When a store is present, uses streamed verification from SQLite.
        """
        if self._store is not None:
            entries = await self._store.get_all_entries_ordered()
        else:
            entries = self._entries

        if not entries:
            return True, "ok"

        expected_prev = GENESIS_HASH
        for i, entry in enumerate(entries):
            if entry.previous_hash != expected_prev:
                return False, f"Entry {i} ({entry.entry_id}): previous_hash mismatch"
            recomputed = _compute_hash(entry)
            if entry.entry_hash != recomputed:
                return False, f"Entry {i} ({entry.entry_id}): entry_hash mismatch"
            expected_prev = entry.entry_hash

        return True, "ok"

    async def get_entries_filtered(
        self,
        chain_id: str | None = None,
        actor_did: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Return entries filtered by chain_id and/or actor_did (newest first).

        When a SQLite store is present, delegates to the indexed query.
        Otherwise filters the in-memory list.
        """
        if self._store is not None:
            return await self._store.get_entries_filtered(
                chain_id=chain_id,
                actor_did=actor_did,
                limit=limit,
                offset=offset,
            )
        # In-memory fallback
        filtered = list(reversed(self._entries))
        if chain_id is not None:
            filtered = [e for e in filtered if e.rotation_chain_id == chain_id]
        if actor_did is not None:
            filtered = [e for e in filtered if e.actor_did == actor_did]
        return filtered[offset : offset + limit]

    async def get_entry(self, entry_id: str) -> AuditEntry | None:
        """Look up an entry by its UUID."""
        return self._index.get(entry_id)

    @property
    def length(self) -> int:
        """Number of entries in the trail."""
        if self._store is not None:
            return self._sequence
        return len(self._entries)
