"""Persistent agent registry (LanceDB) with in-memory dict cache on the gateway."""

from __future__ import annotations

import logging
import os
import threading
from datetime import UTC
from typing import Any

import pyarrow as pa

from airlock.schemas.identity import AgentProfile

logger = logging.getLogger(__name__)

_TABLE_NAME = "agents"

_SCHEMA = pa.schema(
    [
        pa.field("did", pa.string()),
        pa.field("profile_json", pa.string()),
        pa.field("updated_at", pa.timestamp("us", tz="UTC")),
    ]
)


class AgentRegistryStore:
    """LanceDB-backed agent profile store."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._db: Any = None
        self._table: Any = None
        self._lock = threading.Lock()

    def open(self) -> None:
        import lancedb  # noqa: PLC0415

        os.makedirs(self._db_path, exist_ok=True)
        self._db = lancedb.connect(self._db_path)
        existing = self._db.list_tables()
        if _TABLE_NAME in existing:
            self._table = self._db.open_table(_TABLE_NAME)
            logger.info("AgentRegistryStore opened existing table at %s", self._db_path)
        else:
            try:
                self._table = self._db.create_table(
                    _TABLE_NAME, schema=_SCHEMA, mode="create"
                )
                logger.info("AgentRegistryStore created new table at %s", self._db_path)
            except ValueError as exc:
                if "already exists" in str(exc).lower():
                    self._table = self._db.open_table(_TABLE_NAME)
                    logger.info("AgentRegistryStore opened table after race at %s", self._db_path)
                else:
                    raise

    def close(self) -> None:
        self._db = None
        self._table = None

    def _require_open(self) -> None:
        if self._table is None:
            raise RuntimeError("AgentRegistryStore is not open — call open() first")

    def upsert(self, profile: AgentProfile) -> None:
        self._require_open()
        from datetime import datetime  # noqa: PLC0415

        did = profile.did.did
        row = {
            "did": did,
            "profile_json": profile.model_dump_json(),
            "updated_at": datetime.now(UTC).isoformat(),
        }
        with self._lock:
            _where = f"did = '{_escape(did)}'"
            existing = self._table.search().where(_where, prefilter=True).limit(1).to_list()
            if existing:
                self._table.delete(f"did = '{_escape(did)}'")
            self._table.add([row])

    def delete(self, did: str) -> None:
        self._require_open()
        with self._lock:
            self._table.delete(f"did = '{_escape(did)}'")

    def get(self, did: str) -> AgentProfile | None:
        self._require_open()
        rows = (
            self._table.search()
            .where(f"did = '{_escape(did)}'", prefilter=True)
            .limit(1)
            .to_list()
        )
        if not rows:
            return None
        return AgentProfile.model_validate_json(rows[0]["profile_json"])

    def hydrate_mapping(self, mapping: dict[str, AgentProfile]) -> int:
        """Load all rows into supplied dict (clears conflicting keys by overwrite)."""
        self._require_open()
        rows = self._table.search().limit(50_000).to_list()
        for r in rows:
            p = AgentProfile.model_validate_json(r["profile_json"])
            mapping[p.did.did] = p
        return len(rows)

    def count_rows(self) -> int:
        self._require_open()
        return self._table.count_rows()


def _escape(value: str) -> str:
    return value.replace("'", "''")
