from __future__ import annotations

from datetime import UTC, datetime

from airlock.engine.event_bus import EventBus
from airlock.schemas.events import ResolveRequested


def test_try_publish_returns_false_when_queue_full():
    bus = EventBus(maxsize=1)
    e = ResolveRequested(
        session_id="s",
        timestamp=datetime.now(UTC),
        target_did="did:key:t",
    )
    assert bus.try_publish(e) is True
    assert bus.try_publish(e) is False
    assert bus.dead_letter_count == 1
