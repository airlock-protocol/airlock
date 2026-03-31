from __future__ import annotations

import json

import httpx
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto import KeyPair
from airlock.gateway.app import create_app
from airlock.registry.remote import resolve_remote_profile
from tests.test_gateway import _make_agent_profile


@pytest.fixture
def agent_kp() -> KeyPair:
    return KeyPair.from_seed(b"remote_reg_agent_seed_0000000000")


@pytest.mark.asyncio
async def test_resolve_remote_profile_found(agent_kp: KeyPair) -> None:
    prof = _make_agent_profile(agent_kp)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/resolve" or request.method != "POST":
            return httpx.Response(404)
        body = json.loads(request.content)
        if body.get("target_did") == agent_kp.did:
            return httpx.Response(
                200,
                json={"found": True, "profile": prof.model_dump(mode="json")},
            )
        return httpx.Response(200, json={"found": False, "did": body.get("target_did")})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://reg") as client:
        got = await resolve_remote_profile(client, agent_kp.did)
    assert got is not None
    assert got.did.did == agent_kp.did


@pytest.mark.asyncio
async def test_resolve_remote_profile_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"found": False})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://reg") as client:
        got = await resolve_remote_profile(client, "did:key:zzz")
    assert got is None


@pytest.mark.asyncio
async def test_resolve_remote_profile_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://reg") as client:
        got = await resolve_remote_profile(client, "did:key:any")
    assert got is None


@pytest.mark.asyncio
async def test_gateway_resolve_delegates_to_remote_registry(tmp_path, agent_kp: KeyPair) -> None:
    upstream_cfg = AirlockConfig(lancedb_path=str(tmp_path / "up.lance"))
    upstream = create_app(upstream_cfg)
    consumer_cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "down.lance"),
        default_registry_url="http://remote.test",
    )
    consumer = create_app(consumer_cfg)

    async with LifespanManager(upstream), LifespanManager(consumer):
        async with AsyncClient(transport=ASGITransport(app=upstream), base_url="http://u") as up:
            await up.post(
                "/register",
                content=_make_agent_profile(agent_kp).model_dump_json(),
                headers={"Content-Type": "application/json"},
            )

        old = consumer.state.registry_http_client
        assert old is not None
        await old.aclose()
        consumer.state.registry_http_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=upstream),
            base_url="http://remote.test",
        )

        async with AsyncClient(transport=ASGITransport(app=consumer), base_url="http://c") as cli:
            resp = await cli.post("/resolve", json={"target_did": agent_kp.did})

    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["registry_source"] == "remote"
    assert data["profile"]["did"]["did"] == agent_kp.did
