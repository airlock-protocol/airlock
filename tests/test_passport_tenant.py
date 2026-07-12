"""Per-tenant directory authority tests (F2): Host-header routing of the
key directory and assertions endpoints, tenant label derivation and
collision handling at registration, flat fallback, and the status
endpoint's tenant discovery fields."""

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
from airlock.passport.assertions import WELL_KNOWN_ASSERTIONS_PATH, sign_assertion
from airlock.passport.base import WELL_KNOWN_DIRECTORY_PATH
from airlock.passport.directory import (
    is_valid_passport_label,
    key_to_jwk,
    slugify_passport_label,
    tenant_directory_url,
)
from airlock.schemas import AgentCapability, AgentDID, AgentProfile

TENANT_BASE = "agents.registry.test"


# ---------------------------------------------------------------------------
# Label primitives
# ---------------------------------------------------------------------------


class TestLabelPrimitives:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("Alice", "alice"),
            ("Alice Agent!", "alice-agent"),
            ("  --Weird__Name--  ", "weird-name"),
            ("ünïcödé", "n-c-d"),
            ("!!!", "agent"),
            ("A" * 200, "a" * 63),
        ],
    )
    def test_slugify(self, name: str, expected: str) -> None:
        slug = slugify_passport_label(name)
        assert slug == expected
        assert is_valid_passport_label(slug)

    @pytest.mark.parametrize("label", ["alice", "a", "a-1", "0x9", "a" * 63])
    def test_valid_labels(self, label: str) -> None:
        assert is_valid_passport_label(label) is True

    @pytest.mark.parametrize(
        "label", ["", "Alice", "-alice", "alice-", "a_b", "a.b", "a" * 64]
    )
    def test_invalid_labels(self, label: str) -> None:
        assert is_valid_passport_label(label) is False

    def test_tenant_directory_url(self) -> None:
        assert (
            tenant_directory_url("agents.airlock.ing", "alice")
            == "https://alice.agents.airlock.ing"
        )
        assert (
            tenant_directory_url(" Agents.Example. ", "bob") == "https://bob.agents.example"
        )
        with pytest.raises(ValueError):
            tenant_directory_url("agents.example", "Not Valid")
        with pytest.raises(ValueError):
            tenant_directory_url("  ", "alice")


# ---------------------------------------------------------------------------
# Gateway fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def tenant_app(tmp_path: object) -> AsyncIterator[FastAPI]:
    config = AirlockConfig(
        lancedb_path=f"{tmp_path}/tenant.lance",
        passport_enabled=True,
        passport_tenant_domain_base=TENANT_BASE,
    )
    app = create_app(config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
async def client(tenant_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=tenant_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def make_profile(
    kp: KeyPair, name: str, label: str | None = None
) -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did=kp.did, public_key_multibase=kp.public_key_multibase),
        display_name=name,
        capabilities=[AgentCapability(name="web-bot-auth", version="0.1.0", description="t")],
        endpoint_url="https://localhost",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
        passport_label=label,
    )


async def register(
    client: httpx.AsyncClient, kp: KeyPair, name: str, label: str | None = None
) -> httpx.Response:
    return await client.post(
        "/register",
        content=make_profile(kp, name, label).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )


def tenant_host(label: str) -> dict[str, str]:
    return {"host": f"{label}.{TENANT_BASE}"}


# ---------------------------------------------------------------------------
# Host-based routing
# ---------------------------------------------------------------------------


class TestTenantRouting:
    async def test_tenant_host_serves_only_that_tenants_key(
        self, client: httpx.AsyncClient
    ) -> None:
        alice, bob = KeyPair.generate(), KeyPair.generate()
        assert (await register(client, alice, "Alice")).status_code == 200
        assert (await register(client, bob, "Bob")).status_code == 200

        resp = await client.get(WELL_KNOWN_DIRECTORY_PATH, headers=tenant_host("alice"))
        assert resp.status_code == 200
        keys = resp.json()["keys"]
        assert [k["x"] for k in keys] == [key_to_jwk(alice.verify_key).x]

        resp = await client.get(WELL_KNOWN_DIRECTORY_PATH, headers=tenant_host("bob"))
        assert [k["x"] for k in resp.json()["keys"]] == [key_to_jwk(bob.verify_key).x]

    async def test_tenant_host_with_port_is_routed(self, client: httpx.AsyncClient) -> None:
        alice = KeyPair.generate()
        await register(client, alice, "Alice")
        resp = await client.get(
            WELL_KNOWN_DIRECTORY_PATH, headers={"host": f"alice.{TENANT_BASE}:8443"}
        )
        assert resp.status_code == 200
        assert len(resp.json()["keys"]) == 1

    async def test_unknown_label_is_structured_404(self, client: httpx.AsyncClient) -> None:
        resp = await client.get(WELL_KNOWN_DIRECTORY_PATH, headers=tenant_host("ghost"))
        assert resp.status_code == 404
        body = resp.json()
        assert body["status"] == 404
        assert "ghost" in str(body["detail"])

    async def test_multi_level_prefix_is_404(self, client: httpx.AsyncClient) -> None:
        alice = KeyPair.generate()
        await register(client, alice, "Alice")
        resp = await client.get(
            WELL_KNOWN_DIRECTORY_PATH, headers={"host": f"x.alice.{TENANT_BASE}"}
        )
        assert resp.status_code == 404

    async def test_base_host_serves_flat_directory(self, client: httpx.AsyncClient) -> None:
        alice, bob = KeyPair.generate(), KeyPair.generate()
        await register(client, alice, "Alice")
        await register(client, bob, "Bob")
        resp = await client.get(WELL_KNOWN_DIRECTORY_PATH, headers={"host": TENANT_BASE})
        assert len(resp.json()["keys"]) == 2

    async def test_unrelated_host_serves_flat_directory(
        self, client: httpx.AsyncClient
    ) -> None:
        alice, bob = KeyPair.generate(), KeyPair.generate()
        await register(client, alice, "Alice")
        await register(client, bob, "Bob")
        resp = await client.get(WELL_KNOWN_DIRECTORY_PATH)  # Host: testserver
        assert len(resp.json()["keys"]) == 2

    async def test_assertions_are_filtered_per_tenant(
        self, client: httpx.AsyncClient
    ) -> None:
        alice, bob = KeyPair.generate(), KeyPair.generate()
        alice_assertion = sign_assertion(alice, f"https://alice.{TENANT_BASE}")
        bob_assertion = sign_assertion(bob, f"https://bob.{TENANT_BASE}")
        profile_a = make_profile(alice, "Alice").model_copy(
            update={"passport_assertion": alice_assertion}
        )
        profile_b = make_profile(bob, "Bob").model_copy(
            update={"passport_assertion": bob_assertion}
        )
        for profile in (profile_a, profile_b):
            resp = await client.post(
                "/register",
                content=profile.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 200

        resp = await client.get(WELL_KNOWN_ASSERTIONS_PATH, headers=tenant_host("alice"))
        assertions = resp.json()["assertions"]
        assert len(assertions) == 1
        assert assertions[0]["payload"]["sub"] == alice_assertion.payload.sub

        flat = await client.get(WELL_KNOWN_ASSERTIONS_PATH)
        assert len(flat.json()["assertions"]) == 2

    async def test_revoked_tenant_serves_empty_directory(
        self, client: httpx.AsyncClient, tenant_app: FastAPI
    ) -> None:
        alice = KeyPair.generate()
        await register(client, alice, "Alice")
        await tenant_app.state.revocation_store.revoke(alice.did)
        resp = await client.get(WELL_KNOWN_DIRECTORY_PATH, headers=tenant_host("alice"))
        assert resp.status_code == 200  # the authority exists; the key is gone
        assert resp.json() == {"keys": []}

    async def test_no_tenant_base_means_flat_everywhere(self, tmp_path: object) -> None:
        config = AirlockConfig(
            lancedb_path=f"{tmp_path}/flat.lance", passport_enabled=True
        )
        app = create_app(config)
        async with LifespanManager(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                alice = KeyPair.generate()
                await register(c, alice, "Alice")
                resp = await c.get(
                    WELL_KNOWN_DIRECTORY_PATH, headers=tenant_host("ghost")
                )
                assert resp.status_code == 200  # no tenant routing configured
                assert len(resp.json()["keys"]) == 1


# ---------------------------------------------------------------------------
# Label assignment at registration
# ---------------------------------------------------------------------------


class TestLabelAssignment:
    async def test_label_derived_from_display_name(
        self, client: httpx.AsyncClient
    ) -> None:
        kp = KeyPair.generate()
        await register(client, kp, "Fancy Research Bot")
        status = await client.get(f"/passport/{kp.did}/status")
        body = status.json()
        assert body["passport_label"] == "fancy-research-bot"
        assert (
            body["tenant_directory_url"] == f"https://fancy-research-bot.{TENANT_BASE}"
        )

    async def test_explicit_label_is_kept(self, client: httpx.AsyncClient) -> None:
        kp = KeyPair.generate()
        resp = await register(client, kp, "Whatever Name", label="custom-label")
        assert resp.status_code == 200
        status = await client.get(f"/passport/{kp.did}/status")
        assert status.json()["passport_label"] == "custom-label"

    async def test_explicit_label_collision_rejected(
        self, client: httpx.AsyncClient
    ) -> None:
        first, second = KeyPair.generate(), KeyPair.generate()
        assert (await register(client, first, "One", label="shared")).status_code == 200
        resp = await register(client, second, "Two", label="shared")
        assert resp.status_code == 409
        assert resp.json()["status"] == 409
        assert "shared" in str(resp.json()["detail"])

    async def test_reregistration_keeps_own_label(self, client: httpx.AsyncClient) -> None:
        kp = KeyPair.generate()
        assert (await register(client, kp, "One", label="mine")).status_code == 200
        assert (await register(client, kp, "One", label="mine")).status_code == 200

    @pytest.mark.parametrize("bad", ["UPPER", "-x", "x-", "a_b", "a.b", "a" * 64])
    async def test_invalid_explicit_label_rejected(
        self, client: httpx.AsyncClient, bad: str
    ) -> None:
        kp = KeyPair.generate()
        resp = await register(client, kp, "Agent", label=bad)
        assert resp.status_code == 422

    async def test_derived_collision_gets_did_bound_suffix(
        self, client: httpx.AsyncClient
    ) -> None:
        first, second = KeyPair.generate(), KeyPair.generate()
        assert (await register(client, first, "Twin Agent")).status_code == 200
        assert (await register(client, second, "Twin Agent")).status_code == 200
        status_1 = (await client.get(f"/passport/{first.did}/status")).json()
        status_2 = (await client.get(f"/passport/{second.did}/status")).json()
        assert status_1["passport_label"] == "twin-agent"
        label_2 = status_2["passport_label"]
        assert label_2 != "twin-agent"
        assert label_2.startswith("twin-agent-")
        assert is_valid_passport_label(label_2)

    async def test_status_without_tenant_base_has_no_tenant_url(
        self, tmp_path: object
    ) -> None:
        config = AirlockConfig(
            lancedb_path=f"{tmp_path}/nolabel.lance", passport_enabled=True
        )
        app = create_app(config)
        async with LifespanManager(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                kp = KeyPair.generate()
                await register(c, kp, "Alice")
                body = (await c.get(f"/passport/{kp.did}/status")).json()
                assert body["passport_label"] == "alice"  # derived regardless
                assert body["tenant_directory_url"] is None
