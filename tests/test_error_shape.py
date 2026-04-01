"""RFC 7807-shaped error bodies from global exception handlers."""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.gateway.app import create_app


@pytest.mark.asyncio
async def test_problem_json_on_422(tmp_path):
    cfg = AirlockConfig(lancedb_path=str(tmp_path / "prob.lance"))
    app = create_app(cfg)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            r = await client.post("/resolve", json={})
    assert r.status_code == 422
    b = r.json()
    assert b["title"] == "Validation Error"
    assert b["status"] == 422
    assert "type" in b and "instance" in b
