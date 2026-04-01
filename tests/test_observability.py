from __future__ import annotations

import io
import json
import logging

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.gateway.app import create_app
from airlock.gateway.logging_config import JsonLogFormatter, configure_airlock_logging


@pytest.mark.asyncio
async def test_metrics_endpoint_increments_counters(tmp_path) -> None:
    cfg = AirlockConfig(lancedb_path=str(tmp_path / "obs.lance"))
    app = create_app(cfg)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            await client.get("/health")
            # First scrape is emitted before the scrape request is counted; scrape twice.
            await client.get("/metrics")
            r = await client.get("/metrics")
            assert r.status_code == 200
            text = r.text
    assert "airlock_http_requests_total" in text
    assert 'method="GET"' in text
    assert "/health" in text
    assert "/metrics" in text


def test_json_log_formatter_outputs_object() -> None:
    log = logging.getLogger("airlock.test_json")
    log.handlers.clear()
    h = logging.StreamHandler()
    h.setFormatter(JsonLogFormatter())
    log.addHandler(h)
    log.setLevel(logging.INFO)
    log.propagate = False

    buf = io.StringIO()
    h.stream = buf
    log.info("hello", extra={"request_id": "abc"})
    line = buf.getvalue().strip()
    data = json.loads(line)
    assert data["message"] == "hello"
    assert data["request_id"] == "abc"


def test_configure_airlock_logging_twice_no_crash() -> None:
    configure_airlock_logging(log_json=False, log_level="INFO")
    configure_airlock_logging(log_json=False, log_level="INFO")
