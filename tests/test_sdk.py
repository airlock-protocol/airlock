from __future__ import annotations

"""Phase 3 integration tests: Airlock SDK (AirlockClient + AirlockMiddleware)."""

import json
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair, issue_credential, sign_model
from airlock.gateway.app import create_app
from airlock.schemas import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    HandshakeIntent,
    HandshakeRequest,
    create_envelope,
)
from airlock.schemas.envelope import TransportAck, TransportNack
from airlock.sdk.client import AirlockClient
from airlock.sdk.middleware import AirlockMiddleware


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sdk_config(tmp_path):
    return AirlockConfig(lancedb_path=str(tmp_path / "sdk_rep.lance"))


@pytest.fixture
async def sdk_app(sdk_config):
    app = create_app(sdk_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
def agent_kp():
    return KeyPair.from_seed(b"sdk_agent_seed_0000000000000000x")


@pytest.fixture
def issuer_kp():
    return KeyPair.from_seed(b"sdk_issuer_seed_000000000000000x")


@pytest.fixture
def target_kp():
    return KeyPair.from_seed(b"sdk_target_seed_000000000000000x")


def _make_signed_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    session_id: str | None = None,
    sign: bool = True,
) -> HandshakeRequest:
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims={"role": "agent"},
    )
    envelope = create_envelope(sender_did=agent_kp.did)
    request = HandshakeRequest(
        envelope=envelope,
        session_id=session_id or str(uuid.uuid4()),
        initiator=AgentDID(did=agent_kp.did, public_key_multibase=agent_kp.public_key_multibase),
        intent=HandshakeIntent(action="connect", description="sdk test", target_did=target_did),
        credential=vc,
        signature=None,
    )
    if sign:
        request.signature = sign_model(request, agent_kp.signing_key)
    return request


def _make_agent_profile(kp: KeyPair) -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did=kp.did, public_key_multibase=kp.public_key_multibase),
        display_name="SDK Test Agent",
        capabilities=[AgentCapability(name="test", version="1.0", description="sdk test cap")],
        endpoint_url="http://localhost:9998",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(timezone.utc),
    )


def _make_test_client(app, agent_kp: KeyPair) -> AirlockClient:
    """Build an AirlockClient wired to the in-process ASGI app."""
    transport = ASGITransport(app=app)
    inner = httpx.AsyncClient(transport=transport, base_url="http://test", timeout=10.0)
    sdk_client = AirlockClient(base_url="http://test", agent_keypair=agent_kp)
    # Inject the in-process transport client
    sdk_client._client = inner
    return sdk_client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_health(sdk_app, agent_kp):
    """AirlockClient.health() returns {"status": "ok"}."""
    client = _make_test_client(sdk_app, agent_kp)
    try:
        result = await client.health()
    finally:
        await client.close()
    assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_client_register_and_resolve(sdk_app, agent_kp):
    """Register a profile then resolve it — found should be True."""
    profile = _make_agent_profile(agent_kp)
    client = _make_test_client(sdk_app, agent_kp)
    try:
        reg_result = await client.register(profile)
        assert reg_result["registered"] is True

        resolve_result = await client.resolve(agent_kp.did)
        assert resolve_result["found"] is True
        assert resolve_result["profile"]["did"]["did"] == agent_kp.did
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_client_handshake_valid(sdk_app, agent_kp, issuer_kp, target_kp):
    """AirlockClient.handshake() with a valid signed request returns a TransportAck."""
    request = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
    client = _make_test_client(sdk_app, agent_kp)
    try:
        result = await client.handshake(request)
    finally:
        await client.close()
    assert isinstance(result, TransportAck)
    assert result.status == "ACCEPTED"


@pytest.mark.asyncio
async def test_client_handshake_invalid_sig(sdk_app, agent_kp, issuer_kp, target_kp):
    """AirlockClient.handshake() with unsigned request returns a TransportNack."""
    request = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did, sign=False)
    client = _make_test_client(sdk_app, agent_kp)
    try:
        result = await client.handshake(request)
    finally:
        await client.close()
    assert isinstance(result, TransportNack)
    assert result.status == "REJECTED"


@pytest.mark.asyncio
async def test_client_get_reputation(sdk_app, agent_kp):
    """AirlockClient.get_reputation() returns a dict with a 'score' key."""
    client = _make_test_client(sdk_app, agent_kp)
    try:
        result = await client.get_reputation(agent_kp.did)
    finally:
        await client.close()
    assert "score" in result
    assert isinstance(result["score"], float)


@pytest.mark.asyncio
async def test_middleware_protect_valid_request(sdk_app, agent_kp, issuer_kp, target_kp):
    """@airlock.protect passes a valid HandshakeRequest through to the handler."""
    transport = ASGITransport(app=sdk_app)
    inner = httpx.AsyncClient(transport=transport, base_url="http://test", timeout=10.0)
    sdk_client = AirlockClient(base_url="http://test", agent_keypair=agent_kp)
    sdk_client._client = inner

    middleware = AirlockMiddleware(airlock_url="http://test", agent_private_key=agent_kp)
    middleware._client = sdk_client

    handler_called = []

    @middleware.protect
    async def my_handler(request: HandshakeRequest) -> str:
        handler_called.append(True)
        return "handler_result"

    request = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
    result = await my_handler(request)

    await sdk_client.close()

    assert result == "handler_result"
    assert handler_called == [True]


@pytest.mark.asyncio
async def test_middleware_protect_invalid_request(sdk_app, agent_kp, issuer_kp, target_kp):
    """@airlock.protect raises PermissionError for an unsigned HandshakeRequest."""
    transport = ASGITransport(app=sdk_app)
    inner = httpx.AsyncClient(transport=transport, base_url="http://test", timeout=10.0)
    sdk_client = AirlockClient(base_url="http://test", agent_keypair=agent_kp)
    sdk_client._client = inner

    middleware = AirlockMiddleware(airlock_url="http://test", agent_private_key=agent_kp)
    middleware._client = sdk_client

    @middleware.protect
    async def my_handler(request: HandshakeRequest) -> str:
        return "should_not_reach"

    request = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did, sign=False)

    with pytest.raises(PermissionError, match="Airlock rejected handshake"):
        await my_handler(request)

    await sdk_client.close()


@pytest.mark.asyncio
async def test_middleware_protect_starlette_request(sdk_app, agent_kp, issuer_kp, target_kp):
    """@protect accepts Starlette Request and parses JSON into HandshakeRequest."""
    transport = ASGITransport(app=sdk_app)
    inner = httpx.AsyncClient(transport=transport, base_url="http://test", timeout=10.0)
    sdk_client = AirlockClient(base_url="http://test", agent_keypair=agent_kp)
    sdk_client._client = inner

    middleware = AirlockMiddleware(airlock_url="http://test", agent_private_key=agent_kp)
    middleware._client = sdk_client

    hs = _make_signed_handshake(agent_kp, issuer_kp, target_kp.did)
    payload = json.dumps(hs.model_dump(mode="json")).encode()

    async def receive() -> dict:
        return {"type": "http.request", "body": payload, "more_body": False}

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/t",
        "raw_path": b"/t",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("testclient", 50000),
        "server": ("test", 80),
    }
    starlette_req = Request(scope, receive)

    @middleware.protect
    async def my_handler(request: HandshakeRequest) -> str:
        assert request.session_id == hs.session_id
        return "ok"

    assert await my_handler(starlette_req) == "ok"
    await sdk_client.close()
