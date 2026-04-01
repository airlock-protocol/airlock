"""Production startup validation and auth gates."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair
from airlock.gateway.app import create_app
from airlock.gateway.startup_validate import AirlockStartupError, validate_startup_config
from airlock.reputation.scoring import THRESHOLD_HIGH
from airlock.schemas.reputation import TrustScore
from tests.test_gateway import _make_agent_profile, _make_signed_handshake


def test_validate_production_requires_seed() -> None:
    cfg = AirlockConfig(
        env="production",
        gateway_seed_hex="",
        cors_origins="https://a.example",
        vc_issuer_allowlist="did:key:x",
        service_token="svc",
        session_view_secret="s" * 32,
    )
    with pytest.raises(AirlockStartupError, match="GATEWAY_SEED"):
        validate_startup_config(cfg)


def test_validate_production_requires_non_wildcard_cors() -> None:
    cfg = AirlockConfig(
        env="production",
        gateway_seed_hex="a" * 64,
        cors_origins="*",
        vc_issuer_allowlist="did:key:x",
        service_token="svc",
        session_view_secret="s" * 32,
    )
    with pytest.raises(AirlockStartupError, match="CORS"):
        validate_startup_config(cfg)


@pytest.mark.asyncio
async def test_metrics_requires_service_bearer_when_configured(tmp_path) -> None:
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "m.lance"),
        service_token="operator-secret-test",
    )
    app = create_app(cfg)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            r = await client.get("/metrics")
            assert r.status_code == 401
            ok = await client.get(
                "/metrics",
                headers={"Authorization": "Bearer operator-secret-test"},
            )
            assert ok.status_code == 200


@pytest.mark.asyncio
async def test_session_redacts_trust_token_without_viewer_jwt(tmp_path) -> None:
    """Development without session_view_secret: verified session JSON omits trust_token."""
    agent_kp = KeyPair.from_seed(b"a" * 32)
    issuer_kp = KeyPair.from_seed(b"b" * 32)
    target_kp = KeyPair.from_seed(b"c" * 32)

    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "rd.lance"),
        trust_token_secret="trust_secret_for_redaction_test_xxx",
    )
    app = create_app(cfg)
    async with LifespanManager(app):
        now = datetime.now(UTC)
        app.state.reputation.upsert(
            TrustScore(
                agent_did=agent_kp.did,
                score=THRESHOLD_HIGH + 0.05,
                interaction_count=1,
                successful_verifications=1,
                failed_verifications=0,
                last_interaction=now,
                decay_rate=0.02,
                created_at=now,
                updated_at=now,
            )
        )
        profile = _make_agent_profile(agent_kp)
        hs = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            await client.post(
                "/register",
                content=profile.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            ack = await client.post(
                "/handshake",
                content=hs.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert ack.status_code == 200
            sid = ack.json()["session_id"]
            for _ in range(100):
                r = await client.get(f"/session/{sid}")
                data = r.json()
                if data.get("verdict") == "VERIFIED":
                    assert "trust_token" not in data
                    return
                await asyncio.sleep(0.05)
            pytest.fail("expected VERIFIED")


@pytest.mark.asyncio
async def test_ready_returns_503_when_shutting_down(tmp_path) -> None:
    cfg = AirlockConfig(lancedb_path=str(tmp_path / "ready.lance"))
    app = create_app(cfg)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            ok = await client.get("/ready")
            assert ok.status_code == 200

    app2 = create_app(cfg)
    async with LifespanManager(app2):
        app2.state.shutting_down = True
        async with AsyncClient(transport=ASGITransport(app=app2), base_url="http://t") as client:
            r = await client.get("/ready")
            assert r.status_code == 503
