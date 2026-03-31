from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest

from airlock.engine.state import SessionManager
from airlock.schemas.session import VerificationSession, VerificationState


@pytest.mark.asyncio
async def test_session_subscribe_receives_put_copies():
    mgr = SessionManager(default_ttl=300)
    await mgr.start()
    sid = str(uuid.uuid4())
    q = await mgr.subscribe(sid)
    now = datetime.now(UTC)
    sess = VerificationSession(
        session_id=sid,
        state=VerificationState.HANDSHAKE_RECEIVED,
        initiator_did="did:key:a",
        target_did="did:key:b",
        created_at=now,
        updated_at=now,
    )
    await mgr.put(sess)
    out = await asyncio.wait_for(q.get(), timeout=2.0)
    assert out.session_id == sid
    assert out.state == VerificationState.HANDSHAKE_RECEIVED
    await mgr.stop()
