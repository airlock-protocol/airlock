from __future__ import annotations

from fastapi.testclient import TestClient

from airlock.config import AirlockConfig
from airlock.gateway.app import create_app


def test_ws_unknown_session_reports_error(tmp_path):
    cfg = AirlockConfig(lancedb_path=str(tmp_path / "ws.lance"))
    app = create_app(cfg)
    with TestClient(app) as client:
        with client.websocket_connect("/ws/session/does-not-exist") as ws:
            data = ws.receive_json()
            assert data.get("error") == "session_not_found"
