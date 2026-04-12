from __future__ import annotations

"""Tests for OAuth 2.1 token endpoint: client credentials grant, token issuance, invalid assertions."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair
from airlock.gateway.app import create_app
from airlock.oauth.models import OAuthClient
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import _ed25519_private_key_pem

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEED_AGENT = b"32_byte_deterministic_seed______"
SEED_GATEWAY = b"gw_oauth_seed___________________"


def _make_client_assertion(
    agent_kp: KeyPair,
    client_id: str,
    audience: str,
    *,
    expires_in: int = 60,
    iss: str | None = None,
    sub: str | None = None,
) -> str:
    """Build a signed JWT client assertion for private_key_jwt auth."""
    now = datetime.now(UTC)
    payload = {
        "iss": iss or client_id,
        "sub": sub or client_id,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "jti": str(uuid.uuid4()),
    }
    pem = _ed25519_private_key_pem(agent_kp.signing_key)
    return jwt.encode(payload, pem, algorithm="EdDSA")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def agent_kp() -> KeyPair:
    return KeyPair.from_seed(SEED_AGENT)


@pytest.fixture
def gateway_config(tmp_path):
    return AirlockConfig(
        lancedb_path=str(tmp_path / "rep.lance"),
        oauth_enabled=True,
        oauth_dynamic_registration=True,
    )


@pytest.fixture
async def gateway_app(gateway_config):
    app = create_app(gateway_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
def registered_client(gateway_app, agent_kp) -> OAuthClient:
    """Pre-register an OAuth client in the store."""
    oauth_store: OAuthStore = gateway_app.state.oauth_store
    client = OAuthClient(
        client_id="test_client_001",
        client_name="Test Agent",
        did=agent_kp.did,
        public_key_multibase=agent_kp.public_key_multibase,
        grant_types=["client_credentials"],
        scope="verify:read trust:write",
    )
    oauth_store.register_client(client)
    return client


# ---------------------------------------------------------------------------
# Tests: Client Credentials Grant
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_credentials_success(gateway_app, agent_kp, registered_client):
    """Client credentials grant with valid assertion returns a Bearer token."""
    cfg = gateway_app.state.config
    base_url = (cfg.public_base_url or cfg.default_gateway_url).rstrip("/")
    token_endpoint = f"{base_url}/oauth/token"

    assertion = _make_client_assertion(
        agent_kp,
        registered_client.client_id,
        audience=token_endpoint,
    )

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
                "scope": "verify:read",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["token_type"] == "Bearer"
    assert "access_token" in data
    assert data["expires_in"] > 0
    assert data["scope"] == "verify:read"


@pytest.mark.asyncio
async def test_client_credentials_no_assertion(gateway_app, registered_client):
    """Missing client_assertion returns error."""
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
            },
        )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_client_credentials_wrong_assertion_type(gateway_app, agent_kp, registered_client):
    """Wrong client_assertion_type returns error."""
    cfg = gateway_app.state.config
    base_url = (cfg.public_base_url or cfg.default_gateway_url).rstrip("/")
    assertion = _make_client_assertion(agent_kp, registered_client.client_id, f"{base_url}/oauth/token")

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": "invalid_type",
                "client_assertion": assertion,
            },
        )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_client_credentials_unknown_client(gateway_app, agent_kp):
    """Assertion from unregistered client returns error."""
    cfg = gateway_app.state.config
    base_url = (cfg.public_base_url or cfg.default_gateway_url).rstrip("/")
    assertion = _make_client_assertion(agent_kp, "unknown_client", f"{base_url}/oauth/token")

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            },
        )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_client_credentials_expired_assertion(gateway_app, agent_kp, registered_client):
    """Expired client assertion returns error."""
    cfg = gateway_app.state.config
    base_url = (cfg.public_base_url or cfg.default_gateway_url).rstrip("/")
    assertion = _make_client_assertion(
        agent_kp,
        registered_client.client_id,
        f"{base_url}/oauth/token",
        expires_in=-10,
    )

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            },
        )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_client_credentials_invalid_signature(gateway_app, registered_client):
    """Assertion signed by wrong key returns error."""
    wrong_kp = KeyPair.generate()
    cfg = gateway_app.state.config
    base_url = (cfg.public_base_url or cfg.default_gateway_url).rstrip("/")
    assertion = _make_client_assertion(
        wrong_kp,
        registered_client.client_id,
        f"{base_url}/oauth/token",
    )

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            },
        )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_unsupported_grant_type(gateway_app):
    """Unsupported grant_type returns error."""
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/token",
            data={"grant_type": "authorization_code"},
        )

    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_invalid_scope_request(gateway_app, agent_kp, registered_client):
    """Requesting unknown scope returns error."""
    cfg = gateway_app.state.config
    base_url = (cfg.public_base_url or cfg.default_gateway_url).rstrip("/")
    assertion = _make_client_assertion(
        agent_kp, registered_client.client_id, f"{base_url}/oauth/token"
    )

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
                "scope": "nonexistent:scope",
            },
        )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


# ---------------------------------------------------------------------------
# Tests: Token validity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_issued_token_is_valid_jwt(gateway_app, agent_kp, registered_client):
    """Issued token can be decoded and contains expected claims."""
    cfg = gateway_app.state.config
    base_url = (cfg.public_base_url or cfg.default_gateway_url).rstrip("/")
    assertion = _make_client_assertion(
        agent_kp, registered_client.client_id, f"{base_url}/oauth/token"
    )

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
                "scope": "verify:read",
            },
        )

    assert resp.status_code == 200
    token_str = resp.json()["access_token"]

    # Decode without verification to inspect claims
    decoded = jwt.decode(token_str, options={"verify_signature": False}, algorithms=["EdDSA"])
    assert decoded["sub"] == agent_kp.did
    assert decoded["client_id"] == registered_client.client_id
    assert decoded["scope"] == "verify:read"
    assert "airlock:trust_score" in decoded
    assert "airlock:trust_tier" in decoded
    assert "jti" in decoded
    assert decoded["iss"] == gateway_app.state.airlock_kp.did


# ---------------------------------------------------------------------------
# Tests: Dynamic registration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dynamic_registration(gateway_app, agent_kp):
    """Register a new client via the registration endpoint."""
    # Use a fresh keypair to avoid conflicts with pre-registered client
    fresh_kp = KeyPair.from_seed(b"fresh_agent_key_________________")

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/register",
            json={
                "client_name": "New Agent",
                "did": fresh_kp.did,
                "public_key_multibase": fresh_kp.public_key_multibase,
                "grant_types": ["client_credentials"],
                "scope": "verify:read",
            },
        )

    assert resp.status_code == 201
    data = resp.json()
    assert "client_id" in data
    assert data["did"] == fresh_kp.did
    assert data["client_name"] == "New Agent"


@pytest.mark.asyncio
async def test_duplicate_registration_rejected(gateway_app, agent_kp, registered_client):
    """Re-registering the same DID returns error."""
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/oauth/register",
            json={
                "did": agent_kp.did,
                "public_key_multibase": agent_kp.public_key_multibase,
            },
        )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


# ---------------------------------------------------------------------------
# Tests: Discovery and JWKS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openid_configuration(gateway_app):
    """GET /.well-known/openid-configuration returns discovery metadata."""
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.get("/.well-known/openid-configuration")

    assert resp.status_code == 200
    data = resp.json()
    assert "token_endpoint" in data
    assert "jwks_uri" in data
    assert data["issuer"] == gateway_app.state.airlock_kp.did
    assert "client_credentials" in data["grant_types_supported"]


@pytest.mark.asyncio
async def test_jwks_endpoint(gateway_app):
    """GET /.well-known/jwks.json returns the gateway public key."""
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.get("/.well-known/jwks.json")

    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data
    assert len(data["keys"]) == 1
    key = data["keys"][0]
    assert key["kty"] == "OKP"
    assert key["crv"] == "Ed25519"
    assert "x" in key
