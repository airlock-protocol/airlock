from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import pyarrow as pa

from airlock.schemas.reputation import TrustScore
from airlock.schemas.verdict import TrustVerdict
from airlock.reputation.scoring import update_score, INITIAL_SCORE

logger = logging.getLogger(__name__)

# LanceDB table schema as a PyArrow schema
_SCHEMA = pa.schema(
    [
        pa.field("agent_did", pa.string()),
        pa.field("score", pa.float64()),
        pa.field("interaction_count", pa.int64()),
        pa.field("successful_verifications", pa.int64()),
        pa.field("failed_verifications", pa.int64()),
        pa.field("last_interaction", pa.timestamp("us", tz="UTC")),
        pa.field("decay_rate", pa.float64()),
        pa.field("created_at", pa.timestamp("us", tz="UTC")),
        pa.field("updated_at", pa.timestamp("us", tz="UTC")),
    ]
)

_TABLE_NAME = "reputation"


class ReputationStore:
    """LanceDB-backed reputation store.

    Stores one TrustScore record per agent DID.  Supports upsert semantics:
    if a record exists it is replaced; otherwise a new row is inserted.

    LanceDB is embedded (no server), so the store lives at a local path.
    """

    def __init__(self, db_path: str = "./data/reputation.lance") -> None:
        self._db_path = db_path
        self._db: Any = None
        self._table: Any = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Open (or create) the LanceDB database and table."""
        import lancedb  # imported here so the rest of the module is importable without lancedb

        os.makedirs(self._db_path, exist_ok=True)
        self._db = lancedb.connect(self._db_path)

        existing = self._db.list_tables()
        if _TABLE_NAME in existing:
            self._table = self._db.open_table(_TABLE_NAME)
            logger.info("ReputationStore opened existing table at %s", self._db_path)
        else:
            self._table = self._db.create_table(
                _TABLE_NAME, schema=_SCHEMA, mode="create"
            )
            logger.info("ReputationStore created new table at %s", self._db_path)

    def close(self) -> None:
        """No-op for LanceDB embedded — included for symmetry."""
        self._db = None
        self._table = None

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, agent_did: str) -> TrustScore | None:
        """Return the TrustScore for an agent, or None if not found."""
        self._require_open()
        results = (
            self._table.search()
            .where(f"agent_did = '{_escape(agent_did)}'", prefilter=True)
            .limit(1)
            .to_list()
        )
        if not results:
            return None
        return _row_to_trust_score(results[0])

    def get_or_default(self, agent_did: str) -> TrustScore:
        """Return existing score or a fresh neutral score for new agents."""
        existing = self.get(agent_did)
        if existing is not None:
            return existing
        now = datetime.now(timezone.utc)
        return TrustScore(
            agent_did=agent_did,
            score=INITIAL_SCORE,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=None,
            decay_rate=0.02,
            created_at=now,
            updated_at=now,
        )

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def upsert(self, score: TrustScore) -> None:
        """Insert or replace the record for score.agent_did."""
        self._require_open()
        row = _trust_score_to_row(score)

        existing = self.get(score.agent_did)
        if existing is not None:
            self._table.delete(f"agent_did = '{_escape(score.agent_did)}'")

        self._table.add([row])
        logger.debug(
            "ReputationStore upserted %s -> %.4f", score.agent_did, score.score
        )

    def apply_verdict(self, agent_did: str, verdict: TrustVerdict) -> TrustScore:
        """Apply a verdict to an agent's score and persist the result.

        Fetches current score (or creates default), applies decay + delta,
        persists, and returns the updated TrustScore.
        """
        current = self.get_or_default(agent_did)
        updated = update_score(current, verdict)
        self.upsert(updated)
        logger.info(
            "Reputation updated: %s  %.4f -> %.4f  (%s)",
            agent_did,
            current.score,
            updated.score,
            verdict.value,
        )
        return updated

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def all_scores(self) -> list[TrustScore]:
        """Return all records (for analytics / debugging)."""
        self._require_open()
        rows = self._table.search().limit(10_000).to_list()
        return [_row_to_trust_score(r) for r in rows]

    def count(self) -> int:
        """Return the number of agents in the store."""
        self._require_open()
        return self._table.count_rows()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_open(self) -> None:
        if self._table is None:
            raise RuntimeError("ReputationStore is not open — call open() first")


def _escape(value: str) -> str:
    """Minimal SQL-injection guard for DID strings used in WHERE clauses."""
    return value.replace("'", "''")


def _trust_score_to_row(score: TrustScore) -> dict:
    """Convert a TrustScore to a dict suitable for LanceDB insertion."""

    def _ts(dt: datetime | None) -> Any:
        if dt is None:
            return None
        # Ensure UTC-aware then convert to ISO string; LanceDB accepts ISO-8601
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    return {
        "agent_did": score.agent_did,
        "score": score.score,
        "interaction_count": score.interaction_count,
        "successful_verifications": score.successful_verifications,
        "failed_verifications": score.failed_verifications,
        "last_interaction": _ts(score.last_interaction),
        "decay_rate": score.decay_rate,
        "created_at": _ts(score.created_at),
        "updated_at": _ts(score.updated_at),
    }


def _row_to_trust_score(row: dict) -> TrustScore:
    """Convert a LanceDB row dict back to a TrustScore."""

    def _dt(val: Any) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val
        # String ISO-8601 (from our _ts encoder)
        if isinstance(val, str):
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        # pandas Timestamp (if pandas is available in the environment)
        try:
            import pandas as pd  # noqa: PLC0415
            if isinstance(val, pd.Timestamp):
                dt = val.to_pydatetime()
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt
        except ImportError:
            pass
        return val  # type: ignore[return-value]

    return TrustScore(
        agent_did=row["agent_did"],
        score=float(row["score"]),
        interaction_count=int(row["interaction_count"]),
        successful_verifications=int(row["successful_verifications"]),
        failed_verifications=int(row["failed_verifications"]),
        last_interaction=_dt(row.get("last_interaction")),
        decay_rate=float(row["decay_rate"]),
        created_at=_dt(row["created_at"]) or datetime.now(timezone.utc),
        updated_at=_dt(row["updated_at"]) or datetime.now(timezone.utc),
    )
