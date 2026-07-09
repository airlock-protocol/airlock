"""Gateway tests for the passport endpoints: the well-known key directory
and the passport status endpoint, including feature-flag and DID
validation behavior. Uses asgi-lifespan per repo convention."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI

from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair
from airlock.gateway.app import create_app
from airlock.passport.base import DIRECTORY_MEDIA_TYPE, WELL_KNOWN_DIRECTORY_PATH
from airlock.passport.directory import jwk_thumbprint, key_to_jwk
from airlock.schemas import AgentCapability, AgentDID, AgentProfile


@pytest.fixture
def passport_config(tmp_path: object) -> AirlockConfig:
    return AirlockConfig(lancedb_path=f"{tmp_path}/rep.lance", passport_enabled=True)


@pytest.fixture
async def passport_app(passport_config: AirlockConfig) -> AsyncIterator[FastAPI]:
    app = create_app(passport_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
async def client(passport_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=passport_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def make_profile(kp: KeyPair, name: str = "Passport Test Agent") -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did=kp.did, public_key_multibase=kp.public_key_multibase),
        display_name=name,
        capabilities=[AgentCapability(name="web-bot-auth", version="0.1.0", description="t")],
        endpoint_url="https://localhost",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )


async def register(client: httpx.AsyncClient, kp: KeyPair) -> None:
    resp = await client.post(
        "/register",
        content=make_profile(kp).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Key directory
# ---------------------------------------------------------------------------


class TestDirectoryEndpoint:
    async def test_empty_directory(self, client: httpx.AsyncClient) -> None:
        resp = await client.get(WELL_KNOWN_DIRECTORY_PATH)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith(DIRECTORY_MEDIA_TYPE)
        assert "max-age=" in resp.headers["cache-control"]
        assert resp.json() == {"keys": []}

    async def test_registered_agent_appears(self, client: httpx.AsyncClient) -> None:
        kp = KeyPair.generate()
        await register(client, kp)
        resp = await client.get(WELL_KNOWN_DIRECTORY_PATH)
        assert resp.status_code == 200
        keys = resp.json()["keys"]
        expected = key_to_jwk(kp.verify_key)
        assert {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": expected.x,
            "kid": jwk_thumbprint(expected),
        } in keys

    async def test_revoked_agent_is_excluded(
        self, client: httpx.AsyncClient, passport_app: FastAPI
    ) -> None:
        kp = KeyPair.generate()
        await register(client, kp)
        await passport_app.state.revocation_store.revoke(kp.did)
        resp = await client.get(WELL_KNOWN_DIRECTORY_PATH)
        xs = [k["x"] for k in resp.json()["keys"]]
        assert key_to_jwk(kp.verify_key).x not in xs


# ---------------------------------------------------------------------------
# Passport status
# ---------------------------------------------------------------------------


class TestStatusEndpoint:
    async def test_registered_agent_status(self, client: httpx.AsyncClient) -> None:
        kp = KeyPair.generate()
        await register(client, kp)
        resp = await client.get(f"/passport/{kp.did}/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["did"] == kp.did
        assert body["registered"] is True
        assert body["revoked"] is False
        assert body["reputation"]["score"] == pytest.approx(0.5)
        assert body["key_thumbprint"] == jwk_thumbprint(key_to_jwk(kp.verify_key))

    async def test_unregistered_agent_status(self, client: httpx.AsyncClient) -> None:
        kp = KeyPair.generate()
        resp = await client.get(f"/passport/{kp.did}/status")
        assert resp.status_code == 200
        assert resp.json()["registered"] is False

    async def test_revoked_agent_status(
        self, client: httpx.AsyncClient, passport_app: FastAPI
    ) -> None:
        kp = KeyPair.generate()
        await register(client, kp)
        await passport_app.state.revocation_store.revoke(kp.did)
        resp = await client.get(f"/passport/{kp.did}/status")
        assert resp.json()["revoked"] is True

    @pytest.mark.parametrize(
        "bad_did",
        ["garbage", "did:web:example.com", "did:key:notmultibase", "did:key:z0OIl"],
    )
    async def test_invalid_did_rejected(
        self, client: httpx.AsyncClient, bad_did: str
    ) -> None:
        resp = await client.get(f"/passport/{bad_did}/status")
        assert resp.status_code == 422
        body = resp.json()
        assert body["status"] == 422  # repo problem-details error shape
        assert "DID" in str(body["detail"])


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------


class TestFeatureFlag:
    async def test_endpoints_404_when_flag_off(self, tmp_path: object) -> None:
        app = create_app(AirlockConfig(lancedb_path=f"{tmp_path}/off.lance"))
        async with LifespanManager(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                resp = await c.get(WELL_KNOWN_DIRECTORY_PATH)
                assert resp.status_code == 404
                assert resp.json()["status"] == 404
                kp = KeyPair.generate()
                resp = await c.get(f"/passport/{kp.did}/status")
                assert resp.status_code == 404

    async def test_flag_default_is_off(self) -> None:
        assert AirlockConfig(lancedb_path="ignored").passport_enabled is False
