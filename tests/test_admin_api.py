from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from fastapi.testclient import TestClient

from airlock.config import AirlockConfig
from airlock.gateway.app import create_app


def test_admin_not_mounted_when_token_unset(tmp_path):
    cfg = AirlockConfig(lancedb_path=str(tmp_path / "adm0.lance"), admin_token="")
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.get("/admin/sessions")
    assert r.status_code == 404


def test_admin_wrong_bearer_returns_403(tmp_path):
    cfg = AirlockConfig(lancedb_path=str(tmp_path / "adm2.lance"), admin_token="correct-secret")
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.get(
            "/admin/sessions",
            headers={"Authorization": "Bearer wrong-secret"},
        )
    assert r.status_code == 403


def test_admin_sessions_with_bearer(tmp_path):
    cfg = AirlockConfig(lancedb_path=str(tmp_path / "adm1.lance"), admin_token="sekrit")
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.get("/admin/sessions", headers={"Authorization": "Bearer sekrit"})
    assert r.status_code == 200
    body = r.json()
    assert "active_count" in body
    assert body["active_count"] == 0
