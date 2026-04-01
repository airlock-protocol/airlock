from __future__ import annotations

"""Phase 3 integration tests: Airlock Gateway (FastAPI + in-process ASGI)."""

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from asgi_lifespan import LifespanManager
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair, issue_credential
from airlock.crypto.signing import sign_model
from airlock.gateway.app import create_app
from airlock.reputation.scoring import THRESHOLD_HIGH
from airlock.schemas import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    HandshakeIntent,
    HandshakeRequest,
    create_envelope,
)
from airlock.schemas.challenge import ChallengeResponse
from airlock.schemas.reputation import TrustScore
from airlock.schemas.requests import HeartbeatRequest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway_config(tmp_path):
    return AirlockConfig(lancedb_path=str(tmp_path / "rep.lance"))


@pytest.fixture
async def gateway_app(gateway_config):
    app = create_app(gateway_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
def agent_kp():
    return KeyPair.from_seed(b"gw_agent_seed_000000000000000000")


@pytest.fixture
def issuer_kp():
    return KeyPair.from_seed(b"gw_issuer_seed_00000000000000000")


@pytest.fixture
def target_kp():
    return KeyPair.from_seed(b"gw_target_seed_00000000000000000")


def _make_signed_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    session_id: str | None = None,
    validity_days: int = 365,
    sign: bool = True,
) -> HandshakeRequest:
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims={"role": "agent"},
        validity_days=validity_days,
    )
    envelope = create_envelope(sender_did=agent_kp.did)
    request = HandshakeRequest(
        envelope=envelope,
        session_id=session_id or str(uuid.uuid4()),
        initiator=AgentDID(did=agent_kp.did, public_key_multibase=agent_kp.public_key_multibase),
        intent=HandshakeIntent(action="connect", description="test", target_did=target_did),
        credential=vc,
        signature=None,
    )
    if sign:
        request.signature = sign_model(request, agent_kp.signing_key)
    return request


def _make_agent_profile(kp: KeyPair) -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did=kp.did, public_key_multibase=kp.public_key_multibase),
        display_name="Test Agent",
        capabilities=[AgentCapability(name="test", version="1.0", description="test cap")],
        endpoint_url="http://localhost:9999",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_returns_ok(gateway_app):
    """GET /health returns ok with subsystem flags."""
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["subsystems"]["reputation"] is True
    assert data["subsystems"]["agent_registry"] is True
    assert data["subsystems"]["event_bus"] is True
    assert data["subsystems"]["trust_tokens"] is False
    assert "sessions_active" in data
    assert "event_bus_queue_depth" in data
    assert "event_bus_dead_letters" in data
    assert data["event_bus_dead_letters"] == 0
    assert data.get("uptime_seconds") is not None


@pytest.mark.asyncio
async def test_token_introspect_ok(tmp_path):
    """POST /token/introspect validates a minted JWT when secret is configured."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "tok.lance"),
        trust_token_secret="introspect_test_gateway_secret_value",
    )
    app = create_app(cfg)
    async with LifespanManager(app):
        from airlock.trust_jwt import mint_verified_trust_token

        tok = mint_verified_trust_token(
            subject_did="did:key:agent",
            session_id="session-xyz",
            trust_score=0.77,
            issuer_did=app.state.airlock_kp.did,
            secret=cfg.trust_token_secret,
            ttl_seconds=600,
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/token/introspect", json={"token": tok})
    assert resp.status_code == 200
    body = resp.json()
    assert body["active"] is True
    assert body["claims"]["sid"] == "session-xyz"
    assert body["claims"]["ver"] == "VERIFIED"


@pytest.mark.asyncio
async def test_health_trust_tokens_enabled_when_configured(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "ht.lance"),
        trust_token_secret="health_subsystem_secret_test_xx",
    )
    app = create_app(cfg)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
    assert resp.json()["subsystems"]["trust_tokens"] is True


@pytest.mark.asyncio
async def test_register_hourly_cap_per_ip(tmp_path):
    """Third registration from same IP fails when hourly cap is 2."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "reg_hour.lance"),
        register_max_per_ip_per_hour=2,
        rate_limit_per_ip_per_minute=10_000,
    )
    app = create_app(cfg)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            for seed in (b"r" * 32, b"s" * 32):
                kp = KeyPair.from_seed(seed)
                profile = _make_agent_profile(kp)
                resp = await client.post(
                    "/register",
                    content=profile.model_dump_json(),
                    headers={"Content-Type": "application/json"},
                )
                assert resp.status_code == 200
            kp3 = KeyPair.from_seed(b"t" * 32)
            resp3 = await client.post(
                "/register",
                content=_make_agent_profile(kp3).model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp3.status_code == 429


@pytest.mark.asyncio
async def test_register_agent(gateway_app, agent_kp):
    """POST /register with a valid AgentProfile returns {"registered": True}."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["registered"] is True
    assert data["did"] == agent_kp.did


@pytest.mark.asyncio
async def test_resolve_registered_agent(gateway_app, agent_kp):
    """Register then POST /resolve returns found: True."""
    profile = _make_agent_profile(agent_kp)
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        await client.post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        resp = await client.post("/resolve", json={"target_did": agent_kp.did})
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["registry_source"] == "local"
    assert data["profile"]["did"]["did"] == agent_kp.did


@pytest.mark.asyncio
async def test_resolve_unknown_agent(gateway_app):
    """POST /resolve for unknown DID returns found: False."""
    unknown_did = "did:key:zunknown000000000000000000000000"
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post("/resolve", json={"target_did": unknown_did})
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is False
    assert data["did"] == unknown_did


@pytest.mark.asyncio
async def test_handshake_valid_signature_returns_ack(gateway_app, agent_kp, issuer_kp, target_kp):
    """A properly signed HandshakeRequest returns status ACCEPTED."""
    request = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/handshake",
            content=request.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ACCEPTED"


@pytest.mark.asyncio
async def test_get_session_reflects_orchestrator_verdict(tmp_path, agent_kp, issuer_kp, target_kp):
    """After /handshake, GET /session/{id} shows progress and final VERIFIED + trust_token."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "sess_gw.lance"),
        trust_token_secret="gateway_session_jwt_secret_32bytes_test_",
        session_view_secret="gateway_session_view_secret_32byte_test",
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
        hs = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            ack = await client.post(
                "/handshake",
                content=hs.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert ack.json()["status"] == "ACCEPTED"
            sid = ack.json()["session_id"]
            sv = ack.json()["session_view_token"]
            assert sv
            auth = {"Authorization": f"Bearer {sv}"}
            s0 = await client.get(f"/session/{sid}", headers=auth)
            assert s0.status_code == 200
            last = s0.json()
            # Orchestrator may seal immediately when reputation already clears the bar.
            assert last["state"] in ("handshake_received", "sealed")
            for _ in range(100):
                await asyncio.sleep(0.05)
                r = await client.get(f"/session/{sid}", headers=auth)
                last = r.json()
                if last.get("verdict") == "VERIFIED":
                    break
            assert last["verdict"] == "VERIFIED"
            assert last.get("trust_token")
            assert isinstance(last.get("trust_score"), float)


@pytest.mark.asyncio
async def test_handshake_invalid_signature_returns_nack(
    gateway_app, agent_kp, issuer_kp, target_kp
):
    """A HandshakeRequest with no signature returns status REJECTED."""
    request = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did, sign=False)
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/handshake",
            content=request.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "REJECTED"
    assert data["error_code"] == "INVALID_SIGNATURE"


@pytest.mark.asyncio
async def test_handshake_expired_vc_returns_ack(gateway_app, agent_kp, issuer_kp, target_kp):
    """Gateway ACKs immediately for a valid signature even with expired VC.

    The gateway only checks the transport-layer signature synchronously.
    Async orchestrator handles VC validation and may reject later.
    """
    request = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did, validity_days=-1)
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/handshake",
            content=request.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ACCEPTED"


@pytest.mark.asyncio
async def test_get_reputation_unknown(gateway_app):
    """GET /reputation/{did} returns score 0.5 for an unknown agent."""
    unknown_did = "did:key:zunknownreputationdid00000000000"
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.get(f"/reputation/{unknown_did}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 0.5
    assert data["found"] is False


@pytest.mark.asyncio
async def test_heartbeat(gateway_app, agent_kp):
    """POST /heartbeat returns acknowledged: True."""
    env = create_envelope(sender_did=agent_kp.did)
    hb = HeartbeatRequest(
        agent_did=agent_kp.did,
        endpoint_url="http://localhost:9999",
        envelope=env,
        signature=None,
    )
    hb.signature = sign_model(hb, agent_kp.signing_key)
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/heartbeat",
            content=hb.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["acknowledged"] is True
    assert data["agent_did"] == agent_kp.did


@pytest.mark.asyncio
async def test_challenge_response_valid_signature(gateway_app, agent_kp):
    """A signed ChallengeResponse returns status ACCEPTED."""
    from airlock.crypto.signing import sign_model as _sign_model

    envelope = create_envelope(sender_did=agent_kp.did)
    challenge_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())

    response = ChallengeResponse(
        envelope=envelope,
        session_id=session_id,
        challenge_id=challenge_id,
        answer="A nonce is a random value used once to prevent replay attacks.",
        confidence=0.9,
        signature=None,
    )
    response.signature = _sign_model(response, agent_kp.signing_key)

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/challenge-response",
            content=response.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ACCEPTED"


def test_ws_session_happy_path_fast_path_verified(tmp_path, agent_kp, issuer_kp, target_kp):
    """WebSocket streams session payloads until SEALED after fast-path VERIFIED."""
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "ws_happy.lance"),
        trust_token_secret="gateway_ws_jwt_secret_32bytes_test___",
        session_view_secret="gateway_ws_session_view_secret_32bytes__",
    )
    app = create_app(cfg)
    with TestClient(app) as client:
        now = datetime.now(UTC)
        client.app.state.reputation.upsert(
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
        hs = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
        ack = client.post(
            "/handshake",
            content=hs.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        assert ack.status_code == 200
        assert ack.json()["status"] == "ACCEPTED"
        sid = ack.json()["session_id"]
        tok = ack.json()["session_view_token"]
        assert tok

        with client.websocket_connect(
            f"/ws/session/{sid}",
            headers={"Authorization": f"Bearer {tok}"},
        ) as ws:
            seen = False
            for _ in range(80):
                try:
                    msg = ws.receive_json()
                except Exception:
                    break
                if msg.get("type") != "session":
                    continue
                pl = msg.get("payload") or {}
                if pl.get("state") == "sealed" and pl.get("verdict") == "VERIFIED":
                    seen = True
                    assert pl.get("trust_token")
                    break
            assert seen, "expected sealed VERIFIED over WebSocket"
