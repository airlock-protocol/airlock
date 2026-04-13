"""Verify app works without litellm installed."""
from __future__ import annotations

from airlock.config import AirlockConfig


class TestLitellmOptional:
    def test_config_loads(self) -> None:
        cfg = AirlockConfig()
        assert cfg.env == "development"

    def test_app_creates(self) -> None:
        from airlock.gateway.app import create_app

        app = create_app()
        assert app is not None
        assert app.version == "1.0.0"
