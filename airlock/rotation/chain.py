"""Rotation chain registry for DID key rotation.

Links successive DIDs to a stable ``rotation_chain_id`` derived from the
first public key: ``hex(SHA-256(first_public_key_bytes))``.  This allows
trust history (reputation, rate limits, fingerprints) to follow an agent
across key rotations without depending on any single DID.

The registry is in-memory and keyed by both ``chain_id`` and ``DID`` for
O(1) lookups in either direction.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from datetime import UTC, datetime

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class RotationChainRecord(BaseModel):
    """Links a DID to its rotation chain.

    The ``chain_id`` is deterministic from the first public key and never
    changes.  ``current_did`` always points to the most recently rotated
    DID, while ``previous_dids`` records the ordered history.
    """

    chain_id: str  # SHA-256(first_public_key) hex
    current_did: str  # Currently active DID
    previous_dids: list[str] = []  # Ordered history
    rotation_count: int = 0
    created_at: datetime
    last_rotated_at: datetime | None = None
    rotation_timestamps: list[float] = []  # Unix timestamps of recent rotations


def compute_chain_id(public_key_bytes: bytes) -> str:
    """Derive the rotation chain identifier from raw public key bytes.

    Returns the full 64 hex-character SHA-256 digest.  This value is
    deterministic and self-certifying: any party with the public key can
    independently compute the same chain_id.
    """
    return hashlib.sha256(public_key_bytes).hexdigest()


class RotationChainRegistry:
    """In-memory registry mapping DIDs to rotation chains.

    Thread-safe via a reentrant lock.  All mutations are atomic with
    respect to the two index dicts (``_by_chain_id`` and ``_by_did``).
    """

    def __init__(self) -> None:
        self._by_chain_id: dict[str, RotationChainRecord] = {}
        self._by_did: dict[str, str] = {}  # did -> chain_id
        self._rotated_from: set[str] = set()  # DIDs that have been rotated away
        self._lock = threading.Lock()

    def register_chain(
        self,
        did: str,
        public_key_bytes: bytes,
    ) -> RotationChainRecord:
        """Register the first DID in a new rotation chain.

        If the DID already belongs to a chain, returns the existing record
        unchanged.  Otherwise derives ``chain_id`` from the public key and
        creates a fresh record.
        """
        chain_id = compute_chain_id(public_key_bytes)
        now = datetime.now(UTC)

        with self._lock:
            # Already registered
            existing = self._by_chain_id.get(chain_id)
            if existing is not None:
                return existing

            record = RotationChainRecord(
                chain_id=chain_id,
                current_did=did,
                created_at=now,
            )
            self._by_chain_id[chain_id] = record
            self._by_did[did] = chain_id
            logger.info("Rotation chain registered: chain=%s did=%s", chain_id[:16], did)
            return record

    def rotate(
        self,
        old_did: str,
        new_did: str,
        chain_id: str,
    ) -> RotationChainRecord:
        """Atomically rotate from ``old_did`` to ``new_did`` within a chain.

        Enforces first-write-wins: if ``old_did`` has already been rotated
        out, the call raises ``ValueError``.  The caller must verify the
        cryptographic signature and any pre-rotation commitment *before*
        calling this method.

        Returns the updated chain record on success.
        """
        now = datetime.now(UTC)

        with self._lock:
            record = self._by_chain_id.get(chain_id)
            if record is None:
                raise ValueError(f"Unknown rotation chain: {chain_id}")

            if record.current_did != old_did:
                raise ValueError(
                    f"Chain {chain_id[:16]} current DID is {record.current_did}, "
                    f"not {old_did}"
                )

            # First-write-wins: if old_did was already rotated, reject
            if old_did in self._rotated_from:
                raise ValueError(
                    f"DID {old_did} has already been rotated out (first-write-wins)"
                )

            self._rotated_from.add(old_did)

            # Update the record
            updated = record.model_copy(
                update={
                    "current_did": new_did,
                    "previous_dids": [*record.previous_dids, old_did],
                    "rotation_count": record.rotation_count + 1,
                    "last_rotated_at": now,
                    "rotation_timestamps": [
                        *record.rotation_timestamps,
                        time.time(),
                    ],
                }
            )
            self._by_chain_id[chain_id] = updated
            self._by_did[new_did] = chain_id
            # Keep old DID in the index for reverse lookups
            # but it is now in _rotated_from

            logger.info(
                "Key rotated: chain=%s old=%s new=%s count=%d",
                chain_id[:16],
                old_did,
                new_did,
                updated.rotation_count,
            )
            return updated

    def get_chain_by_did(self, did: str) -> RotationChainRecord | None:
        """Look up the chain record for any DID (current or historical)."""
        with self._lock:
            chain_id = self._by_did.get(did)
            if chain_id is None:
                return None
            return self._by_chain_id.get(chain_id)

    def get_chain(self, chain_id: str) -> RotationChainRecord | None:
        """Look up a chain record by its chain_id."""
        with self._lock:
            return self._by_chain_id.get(chain_id)

    def get_current_did(self, chain_id: str) -> str | None:
        """Return the currently active DID for a chain, or None."""
        with self._lock:
            record = self._by_chain_id.get(chain_id)
            if record is None:
                return None
            return record.current_did

    def get_chain_id_for_did(self, did: str) -> str | None:
        """Return the chain_id a DID belongs to, or None."""
        with self._lock:
            return self._by_did.get(did)

    def are_same_chain(self, did_a: str, did_b: str) -> bool:
        """Return True if both DIDs belong to the same rotation chain."""
        with self._lock:
            chain_a = self._by_did.get(did_a)
            chain_b = self._by_did.get(did_b)
            if chain_a is None or chain_b is None:
                return False
            return chain_a == chain_b

    def check_rotation_rate(
        self,
        chain_id: str,
        max_per_24h: int = 3,
    ) -> bool:
        """Return True if the chain has exceeded the rotation rate limit.

        Counts rotations within the last 24 hours.
        """
        with self._lock:
            record = self._by_chain_id.get(chain_id)
            if record is None:
                return False
            cutoff = time.time() - 86400.0
            recent = sum(1 for ts in record.rotation_timestamps if ts > cutoff)
            return recent >= max_per_24h
