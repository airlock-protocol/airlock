"""Persistent pre-rotation commitment store backed by a JSON file.

Writes are atomic (write to temp file, then rename) to prevent
corruption on crash. Thread-safe via threading.Lock.

When ``path`` is None the store operates entirely in-memory, which is
the default for dev and test environments.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path

from airlock.rotation.precommit import PreRotationCommitment

logger = logging.getLogger(__name__)


class PreCommitmentStore:
    """Persistent pre-rotation commitment store.

    Parameters
    ----------
    path:
        Filesystem path for the backing JSON file.  When *None*, the
        store is purely in-memory (suitable for tests and development).
    """

    def __init__(self, path: str | None = None) -> None:
        self._path: str | None = path
        self._data: dict[str, PreRotationCommitment] = {}
        self._lock = threading.Lock()

        if path and os.path.exists(path):
            self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, chain_id: str) -> PreRotationCommitment | None:
        """Return the commitment for *chain_id*, or ``None``."""
        with self._lock:
            return self._data.get(chain_id)

    def put(self, chain_id: str, commitment: PreRotationCommitment) -> None:
        """Store (or overwrite) a commitment and persist to disk."""
        with self._lock:
            self._data[chain_id] = commitment
            self._persist()

    def delete(self, chain_id: str) -> None:
        """Remove the commitment for *chain_id* (no-op if absent)."""
        with self._lock:
            self._data.pop(chain_id, None)
            self._persist()

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Deserialise commitments from the backing JSON file."""
        if self._path is None:
            return
        try:
            raw = Path(self._path).read_text(encoding="utf-8")
            entries: dict[str, object] = json.loads(raw)
            for chain_id, blob in entries.items():
                self._data[chain_id] = PreRotationCommitment.model_validate(blob)
            logger.info(
                "Loaded %d pre-rotation commitments from %s",
                len(self._data),
                self._path,
            )
        except Exception:
            logger.exception("Failed to load precommit store from %s", self._path)

    def _persist(self) -> None:
        """Atomically write the current state to disk.

        Writes to a temporary sibling file first, then renames it into
        place.  On POSIX this is atomic; on Windows ``os.replace`` is
        used which is atomic on NTFS.
        """
        if self._path is None:
            return
        serialised: dict[str, object] = {}
        for chain_id, commitment in self._data.items():
            serialised[chain_id] = commitment.model_dump(mode="json")

        tmp_path = self._path + ".tmp"
        try:
            Path(tmp_path).write_text(
                json.dumps(serialised, indent=2),
                encoding="utf-8",
            )
            os.replace(tmp_path, self._path)
        except Exception:
            logger.exception("Failed to persist precommit store to %s", self._path)
