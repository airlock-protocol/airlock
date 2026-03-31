from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

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
from airlock.schemas.reputation import SignedFeedbackReport


def _make_signed_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    *,
    session_id: str | None = None,
    nonce: str | None = None,
) -> HandshakeRequest:
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims={"role": "agent"},
    )
    env = create_envelope(sender_did=agent_kp.did)
    if nonce is not None:
        env = env.model_copy(update={"nonce": nonce})
    request = HandshakeRequest(
        envelope=env,
        session_id=session_id or str(uuid.uuid4()),
        initiator=AgentDID(did=agent_kp.did, public_key_multibase=agent_kp.public_key_multibase),
        intent=HandshakeIntent(action="connect", description="replay test", target_did=target_did),
        credential=vc,
        signature=None,
    )
    request.signature = sign_model(request, agent_kp.signing_key)
    return request


@pytest.fixture
def rp_agent():
    return KeyPair.from_seed(b"replay_agent_seed_00000000000000")  # 32 bytes


@pytest.fixture
def rp_issuer():
    return KeyPair.from_seed(b"replay_issuer_seed_0000000000000")  # 32 bytes


@pytest.fixture
def rp_target():
    return KeyPair.from_seed(b"replay_target_seed_0000000000000")  # 32 bytes


@pytest.mark.asyncio
async def test_handshake_replay_rejected(tmp_path, rp_agent, rp_issuer, rp_target):
    cfg = AirlockConfig(lancedb_path=str(tmp_path / "replay.lance"))
    app = create_app(cfg)
    hs = _make_signed_handshake(rp_agent, rp_issuer, rp_target.did, nonce="deadbeefcafebabe" * 2)

    hdrs = {"Content-Type": "application/json"}
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            r1 = await client.post("/handshake", content=hs.model_dump_json(), headers=hdrs)
            assert r1.json()["status"] == "ACCEPTED"
            r2 = await client.post("/handshake", content=hs.model_dump_json(), headers=hdrs)
            assert r2.json()["status"] == "REJECTED"
            assert r2.json()["error_code"] == "REPLAY"


def test_agent_registry_store_roundtrip(tmp_path, rp_agent):
    """LanceDB agent table persists across close / reopen (same process)."""
    from airlock.registry.agent_store import AgentRegistryStore

    path = str(tmp_path / "roundtrip.lance")
    profile = AgentProfile(
        did=AgentDID(did=rp_agent.did, public_key_multibase=rp_agent.public_key_multibase),
        display_name="Persist",
        capabilities=[AgentCapability(name="x", version="1.0", description="y")],
        endpoint_url="http://e",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )

    store = AgentRegistryStore(path)
    store.open()
    store.upsert(profile)
    store.close()

    store2 = AgentRegistryStore(path)
    store2.open()
    loaded = store2.get(rp_agent.did)
    store2.close()
    assert loaded is not None
    assert loaded.display_name == "Persist"


@pytest.mark.asyncio
async def test_feedback_negative_hurts_score(tmp_path, rp_agent, rp_issuer, rp_target):
    cfg = AirlockConfig(lancedb_path=str(tmp_path / "fb.lance"))
    app = create_app(cfg)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            fb = SignedFeedbackReport(
                session_id=str(uuid.uuid4()),
                reporter_did=rp_issuer.did,
                subject_did=rp_target.did,
                rating="negative",
                detail="abuse",
                timestamp=datetime.now(UTC),
                envelope=create_envelope(sender_did=rp_issuer.did),
                signature=None,
            )
            fb.signature = sign_model(fb, rp_issuer.signing_key)
            r = await client.post(
                "/feedback",
                content=fb.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            assert r.status_code == 200
            rep = await client.get(f"/reputation/{rp_target.did}")
            assert rep.json()["score"] < 0.5
