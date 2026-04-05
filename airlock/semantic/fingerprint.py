"""Answer fingerprinting for bot farm detection.

Uses SHA-256 for exact duplicate detection and SimHash (Charikar, 2002)
for near-duplicate detection of paraphrased answers.

SimHash is a locality-sensitive hash -- similar texts produce hashes with
small Hamming distance. Hamming distance <= threshold indicates suspicious
similarity between answers from different agents.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from collections import deque

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class AnswerFingerprint(BaseModel):
    """Stored fingerprint for a challenge answer."""

    session_id: str
    agent_did: str
    exact_hash: str
    simhash: int
    question_hash: str
    timestamp: float


class FingerprintMatch(BaseModel):
    """Result of fingerprint comparison."""

    is_exact_duplicate: bool = False
    is_near_duplicate: bool = False
    hamming_distance: int | None = None
    matching_session_id: str | None = None
    matching_agent_did: str | None = None


def compute_simhash(text: str, hash_bits: int = 64) -> int:
    """Compute SimHash (Charikar, 2002) for near-duplicate detection.

    1. Tokenize into words
    2. Hash each word with SHA-256
    3. For each bit position: +1 if bit is 1, -1 if bit is 0
    4. Final hash: bit i = 1 if sum[i] > 0, else 0
    """
    tokens = re.findall(r"[a-z]+", text.lower())
    if not tokens:
        return 0

    v = [0] * hash_bits
    for token in tokens:
        token_hash = int(hashlib.sha256(token.encode()).hexdigest(), 16)
        for i in range(hash_bits):
            if token_hash & (1 << i):
                v[i] += 1
            else:
                v[i] -= 1

    fingerprint = 0
    for i in range(hash_bits):
        if v[i] > 0:
            fingerprint |= 1 << i
    return fingerprint


def hamming_distance(a: int, b: int) -> int:
    """Count differing bits between two integers."""
    return bin(a ^ b).count("1")


def compute_exact_hash(text: str) -> str:
    """SHA-256 hash of normalized text for exact duplicate detection."""
    normalized = " ".join(text.lower().split())
    return hashlib.sha256(normalized.encode()).hexdigest()


class FingerprintStore:
    """Async-safe sliding window store for answer fingerprints.

    Stores the last ``window_size`` fingerprints and checks new answers
    against them for exact and near-duplicate matches.

    Uses ``asyncio.Lock`` to avoid blocking the event loop.  The lock only
    guards fast in-memory dict/deque mutations; CPU-heavy SimHash computation
    happens in ``build_fingerprint()`` *before* the caller acquires the lock.
    """

    def __init__(self, window_size: int = 1000, hamming_threshold: int = 3) -> None:
        self._window_size = window_size
        self._hamming_threshold = hamming_threshold
        self._fingerprints: deque[AnswerFingerprint] = deque(maxlen=window_size)
        self._exact_hashes: dict[str, AnswerFingerprint] = {}
        self._lock = asyncio.Lock()

    async def check(self, fingerprint: AnswerFingerprint) -> FingerprintMatch:
        """Check a fingerprint against the store.

        Returns match info if duplicate or near-duplicate found.
        """
        async with self._lock:
            # 1. Check exact hash
            if fingerprint.exact_hash in self._exact_hashes:
                existing = self._exact_hashes[fingerprint.exact_hash]
                # Don't flag same agent re-answering (retries)
                if existing.agent_did != fingerprint.agent_did:
                    return FingerprintMatch(
                        is_exact_duplicate=True,
                        hamming_distance=0,
                        matching_session_id=existing.session_id,
                        matching_agent_did=existing.agent_did,
                    )

            # 2. Check SimHash near-duplicates
            for stored in self._fingerprints:
                if stored.agent_did == fingerprint.agent_did:
                    continue  # Skip self
                if stored.question_hash != fingerprint.question_hash:
                    continue  # Only compare answers to the same question

                dist = hamming_distance(fingerprint.simhash, stored.simhash)
                if dist <= self._hamming_threshold:
                    return FingerprintMatch(
                        is_near_duplicate=True,
                        hamming_distance=dist,
                        matching_session_id=stored.session_id,
                        matching_agent_did=stored.agent_did,
                    )

        return FingerprintMatch()

    async def add(self, fingerprint: AnswerFingerprint) -> None:
        """Add a fingerprint to the store."""
        async with self._lock:
            # If deque is at capacity, the leftmost entry will be evicted on
            # append.  Remove its exact-hash entry so we don't produce false
            # positives against answers that fell outside the sliding window.
            if len(self._fingerprints) >= self._window_size:
                evicted = self._fingerprints[0]
                # Only delete if the dict still points to the evicted entry
                # (a newer entry with the same hash should be kept).
                stored = self._exact_hashes.get(evicted.exact_hash)
                if stored is not None and stored.session_id == evicted.session_id:
                    del self._exact_hashes[evicted.exact_hash]

            self._fingerprints.append(fingerprint)
            self._exact_hashes[fingerprint.exact_hash] = fingerprint

    def check_sync(self, fingerprint: AnswerFingerprint) -> FingerprintMatch:
        """Synchronous wrapper -- for use outside an async context only."""
        loop: asyncio.AbstractEventLoop | None = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        if loop is not None and loop.is_running():
            # We're inside a running event loop (e.g. pytest-asyncio).
            # The caller should use ``await check()`` instead.  Fall back
            # to a direct (unlocked) check so sync tests still work.
            return self._check_unlocked(fingerprint)
        return asyncio.run(self.check(fingerprint))

    def add_sync(self, fingerprint: AnswerFingerprint) -> None:
        """Synchronous wrapper -- for use outside an async context only."""
        loop: asyncio.AbstractEventLoop | None = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        if loop is not None and loop.is_running():
            self._add_unlocked(fingerprint)
            return
        asyncio.run(self.add(fingerprint))

    # ------------------------------------------------------------------
    # Internal helpers used by sync wrappers (no lock, no await)
    # ------------------------------------------------------------------

    def _check_unlocked(self, fingerprint: AnswerFingerprint) -> FingerprintMatch:
        """Lock-free check -- only safe when no concurrent access."""
        if fingerprint.exact_hash in self._exact_hashes:
            existing = self._exact_hashes[fingerprint.exact_hash]
            if existing.agent_did != fingerprint.agent_did:
                return FingerprintMatch(
                    is_exact_duplicate=True,
                    hamming_distance=0,
                    matching_session_id=existing.session_id,
                    matching_agent_did=existing.agent_did,
                )

        for stored in self._fingerprints:
            if stored.agent_did == fingerprint.agent_did:
                continue
            if stored.question_hash != fingerprint.question_hash:
                continue

            dist = hamming_distance(fingerprint.simhash, stored.simhash)
            if dist <= self._hamming_threshold:
                return FingerprintMatch(
                    is_near_duplicate=True,
                    hamming_distance=dist,
                    matching_session_id=stored.session_id,
                    matching_agent_did=stored.agent_did,
                )

        return FingerprintMatch()

    def _add_unlocked(self, fingerprint: AnswerFingerprint) -> None:
        """Lock-free add -- only safe when no concurrent access."""
        if len(self._fingerprints) >= self._window_size:
            evicted = self._fingerprints[0]
            stored = self._exact_hashes.get(evicted.exact_hash)
            if stored is not None and stored.session_id == evicted.session_id:
                del self._exact_hashes[evicted.exact_hash]

        self._fingerprints.append(fingerprint)
        self._exact_hashes[fingerprint.exact_hash] = fingerprint

    def build_fingerprint(
        self,
        session_id: str,
        agent_did: str,
        answer: str,
        question: str,
    ) -> AnswerFingerprint:
        """Build an AnswerFingerprint from answer text.

        This is intentionally synchronous -- it does pure CPU work (hashing)
        with no I/O.  Callers can run it in an executor if needed.
        """
        return AnswerFingerprint(
            session_id=session_id,
            agent_did=agent_did,
            exact_hash=compute_exact_hash(answer),
            simhash=compute_simhash(answer),
            question_hash=compute_exact_hash(question),
            timestamp=time.time(),
        )


# Module-level singleton
_default_store: FingerprintStore | None = None


def get_fingerprint_store() -> FingerprintStore:
    """Return the global FingerprintStore singleton."""
    global _default_store  # noqa: PLW0603
    if _default_store is None:
        from airlock.config import get_config

        cfg = get_config()
        _default_store = FingerprintStore(
            window_size=cfg.fingerprint_window_size,
            hamming_threshold=cfg.fingerprint_hamming_threshold,
        )
    return _default_store


def _reset_fingerprint_store() -> None:
    """Reset the singleton -- for tests only."""
    global _default_store  # noqa: PLW0603
    _default_store = None
