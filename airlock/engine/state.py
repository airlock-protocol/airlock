from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Iterator

from airlock.schemas.session import VerificationSession, VerificationState

logger = logging.getLogger(__name__)

_CLEANUP_INTERVAL = 30  # seconds between expired-session sweeps


class SessionManager:
    """In-memory session store with TTL-based auto-expiry.

    Each session is a VerificationSession accumulator that grows as the
    protocol progresses through its phases.  Expired sessions are evicted
    lazily on access and proactively by a background sweep task.
    """

    def __init__(self, default_ttl: int = 180) -> None:
        self._sessions: dict[str, VerificationSession] = {}
        self._default_ttl = default_ttl
        self._lock = asyncio.Lock()
        self._sweep_task: asyncio.Task | None = None  # type: ignore[type-arg]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background expiry sweep."""
        self._sweep_task = asyncio.create_task(self._sweep_loop())
        logger.info("SessionManager sweep loop started (interval=%ds)", _CLEANUP_INTERVAL)

    async def stop(self) -> None:
        """Stop the background sweep."""
        if self._sweep_task is not None:
            self._sweep_task.cancel()
            try:
                await self._sweep_task
            except asyncio.CancelledError:
                pass
        logger.info("SessionManager stopped")

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create(
        self,
        initiator_did: str,
        target_did: str,
        callback_url: str | None = None,
        ttl: int | None = None,
    ) -> VerificationSession:
        """Create a new session and store it."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        session = VerificationSession(
            session_id=session_id,
            state=VerificationState.INITIATED,
            initiator_did=initiator_did,
            target_did=target_did,
            callback_url=callback_url,
            created_at=now,
            updated_at=now,
            ttl_seconds=ttl if ttl is not None else self._default_ttl,
        )
        async with self._lock:
            self._sessions[session_id] = session
        logger.debug("Session created: %s", session_id)
        return session

    async def get(self, session_id: str) -> VerificationSession | None:
        """Retrieve a session, returning None if missing or expired."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.is_expired():
                del self._sessions[session_id]
                logger.debug("Session expired on access: %s", session_id)
                return None
            return session

    async def update(self, session: VerificationSession) -> None:
        """Persist an updated session (caller mutates and passes back)."""
        session.updated_at = datetime.now(timezone.utc)
        async with self._lock:
            self._sessions[session.session_id] = session

    async def transition(
        self, session_id: str, new_state: VerificationState
    ) -> VerificationSession | None:
        """Transition a session to a new state and persist it.

        Returns the updated session, or None if the session is not found.
        """
        session = await self.get(session_id)
        if session is None:
            logger.warning("transition: session not found: %s", session_id)
            return None
        old_state = session.state
        session.state = new_state
        await self.update(session)
        logger.debug(
            "Session %s: %s -> %s", session_id, old_state.value, new_state.value
        )
        return session

    async def delete(self, session_id: str) -> None:
        """Remove a session from the store."""
        async with self._lock:
            self._sessions.pop(session_id, None)

    # ------------------------------------------------------------------
    # Iteration helpers
    # ------------------------------------------------------------------

    async def active_sessions(self) -> list[VerificationSession]:
        """Return all non-expired sessions."""
        async with self._lock:
            return [s for s in self._sessions.values() if not s.is_expired()]

    def __len__(self) -> int:
        return len(self._sessions)

    # ------------------------------------------------------------------
    # Background sweep
    # ------------------------------------------------------------------

    async def _sweep_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(_CLEANUP_INTERVAL)
                await self._evict_expired()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("SessionManager sweep error")

    async def _evict_expired(self) -> None:
        async with self._lock:
            expired = [
                sid for sid, s in self._sessions.items() if s.is_expired()
            ]
            for sid in expired:
                del self._sessions[sid]
        if expired:
            logger.debug("SessionManager evicted %d expired sessions", len(expired))
