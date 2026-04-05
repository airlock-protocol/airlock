"""Tests for signed CRL with pull model and tiered degradation.

Covers:
  - CRL generation and signing
  - Signature verification with gateway public key
  - Monotonically increasing crl_number
  - CRL caching within update interval
  - CRL regeneration after interval expires
  - Revoked DIDs appear in CRL entries
  - Suspended DIDs appear in CRL entries with status "suspended"
  - GET /crl returns valid JSON
  - Correct Cache-Control and ETag headers
  - If-None-Match returns 304 Not Modified
  - CRL freshness assessment: NORMAL, DEGRADED, EMERGENCY, FAIL_CLOSED
  - Separate CRL signing key support
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import verify_signature
from airlock.gateway.app import create_app
from airlock.gateway.crl import CRLGenerator
from airlock.gateway.crl_freshness import CRLFreshnessMode, assess_crl_freshness
from airlock.gateway.revocation import RevocationReason, RevocationStore
from airlock.schemas.crl import CRLEntry, SignedCRL

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway_kp() -> KeyPair:
    return KeyPair.from_seed(b"crl_test_gateway_seed_0000000000")


@pytest.fixture
def revocation_store() -> RevocationStore:
    return RevocationStore()


@pytest.fixture
def crl_generator(revocation_store: RevocationStore, gateway_kp: KeyPair) -> CRLGenerator:
    return CRLGenerator(
        revocation_store=revocation_store,
        signing_key=gateway_kp.signing_key,
        issuer_did=gateway_kp.did,
        update_interval_seconds=60,
        max_cache_age_seconds=300,
    )


@pytest.fixture
def gateway_config(tmp_path) -> AirlockConfig:
    return AirlockConfig(
        lancedb_path=str(tmp_path / "rep.lance"),
        crl_update_interval_seconds=60,
        crl_max_cache_age_seconds=300,
        crl_emergency_cache_age_seconds=3600,
    )


@pytest.fixture
async def gateway_app(gateway_config: AirlockConfig):
    app = create_app(gateway_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
async def client(gateway_app) -> AsyncClient:
    transport = ASGITransport(app=gateway_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Signed CRL Generation Tests
# ---------------------------------------------------------------------------


async def test_signed_crl_generation(
    crl_generator: CRLGenerator,
    revocation_store: RevocationStore,
) -> None:
    """CRL is built and signed."""
    await revocation_store.revoke("did:key:zBadAgent1", reason=RevocationReason.KEY_COMPROMISE)

    crl = await crl_generator.generate()

    assert isinstance(crl, SignedCRL)
    assert crl.version == 1
    assert crl.crl_number == 1
    assert crl.signature is not None
    assert len(crl.signature) > 0
    assert len(crl.entries) == 1


async def test_crl_signature_verification(
    crl_generator: CRLGenerator,
    revocation_store: RevocationStore,
    gateway_kp: KeyPair,
) -> None:
    """Signature verifies with the gateway public key."""
    await revocation_store.revoke("did:key:zBadAgent2")

    crl = await crl_generator.generate()
    assert crl.signature is not None

    # Verify signature by reconstructing the unsigned CRL dict
    crl_dict = crl.model_dump(mode="json")
    assert verify_signature(crl_dict, crl.signature, gateway_kp.verify_key)


async def test_crl_number_monotonic(
    crl_generator: CRLGenerator,
) -> None:
    """Each generation increments crl_number."""
    crl1 = await crl_generator.generate()
    crl2 = await crl_generator.generate()
    crl3 = await crl_generator.generate()

    assert crl1.crl_number == 1
    assert crl2.crl_number == 2
    assert crl3.crl_number == 3
    assert crl3.crl_number > crl2.crl_number > crl1.crl_number


async def test_crl_caching(
    crl_generator: CRLGenerator,
) -> None:
    """Same CRL is returned within update interval (cached)."""
    crl1 = await crl_generator.get_or_generate()
    crl2 = await crl_generator.get_or_generate()

    assert crl1.crl_number == crl2.crl_number
    assert crl1.this_update == crl2.this_update
    assert crl1.signature == crl2.signature


async def test_crl_regeneration(
    revocation_store: RevocationStore,
    gateway_kp: KeyPair,
) -> None:
    """New CRL is generated after interval expires."""
    gen = CRLGenerator(
        revocation_store=revocation_store,
        signing_key=gateway_kp.signing_key,
        issuer_did=gateway_kp.did,
        update_interval_seconds=60,
        max_cache_age_seconds=300,
    )

    crl1 = await gen.get_or_generate()
    assert crl1.crl_number == 1

    # Simulate time passing beyond the update interval
    past_time = datetime.now(UTC) - timedelta(seconds=120)
    gen._cached_crl = crl1.model_copy(update={"next_update": past_time})

    crl2 = await gen.get_or_generate()
    assert crl2.crl_number == 2
    assert crl2.this_update > crl1.this_update


async def test_crl_contains_revoked_dids(
    crl_generator: CRLGenerator,
    revocation_store: RevocationStore,
) -> None:
    """Revoked agents appear in CRL entries."""
    await revocation_store.revoke("did:key:zRevoked1", reason=RevocationReason.POLICY_VIOLATION)
    await revocation_store.revoke("did:key:zRevoked2", reason=RevocationReason.KEY_COMPROMISE)

    crl = await crl_generator.generate()

    revoked_dids = {e.did for e in crl.entries if e.status == "revoked"}
    assert "did:key:zRevoked1" in revoked_dids
    assert "did:key:zRevoked2" in revoked_dids

    # Check that the reason is correct
    entry_map = {e.did: e for e in crl.entries}
    assert entry_map["did:key:zRevoked1"].reason == "policy_violation"
    assert entry_map["did:key:zRevoked2"].reason == "key_compromise"


async def test_crl_contains_suspended_dids(
    crl_generator: CRLGenerator,
    revocation_store: RevocationStore,
) -> None:
    """Suspended agents appear with status 'suspended'."""
    await revocation_store.suspend("did:key:zSuspended1")
    await revocation_store.suspend("did:key:zSuspended2")

    crl = await crl_generator.generate()

    suspended = [e for e in crl.entries if e.status == "suspended"]
    suspended_dids = {e.did for e in suspended}
    assert "did:key:zSuspended1" in suspended_dids
    assert "did:key:zSuspended2" in suspended_dids


async def test_crl_mixed_revoked_and_suspended(
    crl_generator: CRLGenerator,
    revocation_store: RevocationStore,
) -> None:
    """CRL contains both revoked and suspended entries."""
    await revocation_store.revoke("did:key:zRevPerm", reason=RevocationReason.SYBIL_DETECTED)
    await revocation_store.suspend("did:key:zSuspTemp")

    crl = await crl_generator.generate()

    assert len(crl.entries) == 2
    statuses = {e.did: e.status for e in crl.entries}
    assert statuses["did:key:zRevPerm"] == "revoked"
    assert statuses["did:key:zSuspTemp"] == "suspended"


async def test_crl_issuer_did(
    crl_generator: CRLGenerator,
    gateway_kp: KeyPair,
) -> None:
    """CRL issuer_did matches the gateway DID."""
    crl = await crl_generator.generate()
    assert crl.issuer_did == gateway_kp.did


async def test_crl_next_update_offset(
    crl_generator: CRLGenerator,
) -> None:
    """next_update is this_update + update_interval_seconds."""
    crl = await crl_generator.generate()
    expected_offset = timedelta(seconds=60)
    actual_offset = crl.next_update - crl.this_update
    assert abs((actual_offset - expected_offset).total_seconds()) < 1.0


# ---------------------------------------------------------------------------
# CRL Endpoint Tests
# ---------------------------------------------------------------------------


async def test_crl_endpoint_returns_json(client: AsyncClient) -> None:
    """GET /crl returns valid JSON with CRL data."""
    resp = await client.get("/crl")
    assert resp.status_code == 200

    data = resp.json()
    assert "version" in data
    assert "crl_number" in data
    assert "issuer_did" in data
    assert "entries" in data
    assert "signature" in data
    assert data["version"] == 1
    assert data["crl_number"] >= 1


async def test_crl_well_known_endpoint(client: AsyncClient) -> None:
    """GET /.well-known/airlock-crl is an alias for /crl."""
    resp = await client.get("/.well-known/airlock-crl")
    assert resp.status_code == 200

    data = resp.json()
    assert data["version"] == 1
    assert data["crl_number"] >= 1


async def test_crl_endpoint_cache_headers(client: AsyncClient) -> None:
    """Response includes correct Cache-Control and ETag headers."""
    resp = await client.get("/crl")
    assert resp.status_code == 200

    assert "cache-control" in resp.headers
    assert "max-age=" in resp.headers["cache-control"]
    assert "must-revalidate" in resp.headers["cache-control"]

    assert "etag" in resp.headers
    etag = resp.headers["etag"]
    # ETag should be a quoted crl_number
    assert etag.startswith('"') and etag.endswith('"')


async def test_crl_etag_304(client: AsyncClient) -> None:
    """If-None-Match with matching ETag returns 304 Not Modified."""
    resp1 = await client.get("/crl")
    assert resp1.status_code == 200
    etag = resp1.headers["etag"]

    resp2 = await client.get("/crl", headers={"If-None-Match": etag})
    assert resp2.status_code == 304


async def test_crl_etag_mismatch_returns_200(client: AsyncClient) -> None:
    """If-None-Match with non-matching ETag returns 200."""
    resp = await client.get("/crl", headers={"If-None-Match": '"99999"'})
    assert resp.status_code == 200


async def test_crl_endpoint_includes_revoked_agents(gateway_app, client: AsyncClient) -> None:
    """GET /crl includes agents that have been revoked."""
    store = gateway_app.state.revocation_store
    await store.revoke("did:key:zEndpointRevoked", reason=RevocationReason.KEY_COMPROMISE)

    # Force regeneration by invalidating cache
    gen = gateway_app.state.crl_generator
    gen._cached_crl = None

    resp = await client.get("/crl")
    assert resp.status_code == 200

    data = resp.json()
    dids_in_crl = {e["did"] for e in data["entries"]}
    assert "did:key:zEndpointRevoked" in dids_in_crl


# ---------------------------------------------------------------------------
# Tiered Degradation / CRL Freshness Tests
# ---------------------------------------------------------------------------


def test_freshness_normal() -> None:
    """Fresh CRL returns NORMAL."""
    config = AirlockConfig(
        crl_update_interval_seconds=60,
        crl_max_cache_age_seconds=300,
        crl_emergency_cache_age_seconds=3600,
    )
    now = datetime.now(UTC)
    crl = SignedCRL(
        crl_number=1,
        issuer_did="did:key:zTest",
        this_update=now - timedelta(seconds=10),
        next_update=now + timedelta(seconds=50),
    )

    mode = assess_crl_freshness(crl, config)
    assert mode == CRLFreshnessMode.NORMAL


def test_freshness_degraded() -> None:
    """Stale CRL within max_cache returns DEGRADED."""
    config = AirlockConfig(
        crl_update_interval_seconds=60,
        crl_max_cache_age_seconds=300,
        crl_emergency_cache_age_seconds=3600,
    )
    now = datetime.now(UTC)
    crl = SignedCRL(
        crl_number=1,
        issuer_did="did:key:zTest",
        this_update=now - timedelta(seconds=120),
        next_update=now - timedelta(seconds=60),
    )

    mode = assess_crl_freshness(crl, config)
    assert mode == CRLFreshnessMode.DEGRADED


def test_freshness_emergency() -> None:
    """Very stale CRL returns EMERGENCY."""
    config = AirlockConfig(
        crl_update_interval_seconds=60,
        crl_max_cache_age_seconds=300,
        crl_emergency_cache_age_seconds=3600,
    )
    now = datetime.now(UTC)
    crl = SignedCRL(
        crl_number=1,
        issuer_did="did:key:zTest",
        this_update=now - timedelta(seconds=600),
        next_update=now - timedelta(seconds=540),
    )

    mode = assess_crl_freshness(crl, config)
    assert mode == CRLFreshnessMode.EMERGENCY


def test_freshness_fail_closed() -> None:
    """Ancient CRL returns FAIL_CLOSED."""
    config = AirlockConfig(
        crl_update_interval_seconds=60,
        crl_max_cache_age_seconds=300,
        crl_emergency_cache_age_seconds=3600,
    )
    now = datetime.now(UTC)
    crl = SignedCRL(
        crl_number=1,
        issuer_did="did:key:zTest",
        this_update=now - timedelta(seconds=7200),
        next_update=now - timedelta(seconds=7140),
    )

    mode = assess_crl_freshness(crl, config)
    assert mode == CRLFreshnessMode.FAIL_CLOSED


def test_freshness_boundary_normal_to_degraded() -> None:
    """CRL at exact boundary of update interval is DEGRADED."""
    config = AirlockConfig(
        crl_update_interval_seconds=60,
        crl_max_cache_age_seconds=300,
        crl_emergency_cache_age_seconds=3600,
    )
    now = datetime.now(UTC)
    crl = SignedCRL(
        crl_number=1,
        issuer_did="did:key:zTest",
        this_update=now - timedelta(seconds=60),
        next_update=now,
    )

    mode = assess_crl_freshness(crl, config)
    assert mode == CRLFreshnessMode.DEGRADED


def test_freshness_boundary_degraded_to_emergency() -> None:
    """CRL at exact boundary of max_cache_age is EMERGENCY."""
    config = AirlockConfig(
        crl_update_interval_seconds=60,
        crl_max_cache_age_seconds=300,
        crl_emergency_cache_age_seconds=3600,
    )
    now = datetime.now(UTC)
    crl = SignedCRL(
        crl_number=1,
        issuer_did="did:key:zTest",
        this_update=now - timedelta(seconds=300),
        next_update=now - timedelta(seconds=240),
    )

    mode = assess_crl_freshness(crl, config)
    assert mode == CRLFreshnessMode.EMERGENCY


def test_freshness_boundary_emergency_to_fail_closed() -> None:
    """CRL at exact boundary of emergency_cache_age is FAIL_CLOSED."""
    config = AirlockConfig(
        crl_update_interval_seconds=60,
        crl_max_cache_age_seconds=300,
        crl_emergency_cache_age_seconds=3600,
    )
    now = datetime.now(UTC)
    crl = SignedCRL(
        crl_number=1,
        issuer_did="did:key:zTest",
        this_update=now - timedelta(seconds=3600),
        next_update=now - timedelta(seconds=3540),
    )

    mode = assess_crl_freshness(crl, config)
    assert mode == CRLFreshnessMode.FAIL_CLOSED


def test_freshness_mode_is_str_enum() -> None:
    """CRLFreshnessMode values are serializable strings."""
    assert CRLFreshnessMode.NORMAL == "normal"
    assert CRLFreshnessMode.DEGRADED == "degraded"
    assert CRLFreshnessMode.EMERGENCY == "emergency"
    assert CRLFreshnessMode.FAIL_CLOSED == "fail_closed"


# ---------------------------------------------------------------------------
# Separate CRL Signing Key
# ---------------------------------------------------------------------------


async def test_crl_separate_signing_key() -> None:
    """CRL signed with a separate key verifies with that key's public key."""
    store = RevocationStore()
    await store.revoke("did:key:zSepKey", reason=RevocationReason.SUPERSEDED)

    # Generate a separate signing key for CRL
    crl_kp = KeyPair.from_seed(b"crl_separate_key_seed_0000000000")
    gateway_kp = KeyPair.from_seed(b"gateway_key_different_from_crl_k")

    gen = CRLGenerator(
        revocation_store=store,
        signing_key=crl_kp.signing_key,
        issuer_did=gateway_kp.did,
        update_interval_seconds=60,
        max_cache_age_seconds=300,
    )

    crl = await gen.generate()
    assert crl.signature is not None

    # Verify with the CRL key (should pass)
    crl_dict = crl.model_dump(mode="json")
    assert verify_signature(crl_dict, crl.signature, crl_kp.verify_key)

    # Verify with the gateway key (should fail since they differ)
    assert not verify_signature(crl_dict, crl.signature, gateway_kp.verify_key)


async def test_crl_config_separate_signing_key(tmp_path) -> None:
    """App factory uses separate CRL signing key when crl_signing_key_hex is set."""
    crl_kp = KeyPair.from_seed(b"crl_config_sep_key_seed_00000000")
    config = AirlockConfig(
        lancedb_path=str(tmp_path / "rep.lance"),
        crl_signing_key_hex=b"crl_config_sep_key_seed_00000000".hex(),
    )

    app = create_app(config)
    async with LifespanManager(app):
        gen = app.state.crl_generator
        crl = await gen.generate()
        assert crl.signature is not None

        crl_dict = crl.model_dump(mode="json")
        assert verify_signature(crl_dict, crl.signature, crl_kp.verify_key)


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------


def test_crl_entry_model() -> None:
    """CRLEntry model validates correctly."""
    entry = CRLEntry(
        did="did:key:zTest123",
        status="revoked",
        reason="key_compromise",
        revoked_at=datetime.now(UTC),
    )
    assert entry.did == "did:key:zTest123"
    assert entry.status == "revoked"
    assert entry.reason == "key_compromise"


def test_signed_crl_model() -> None:
    """SignedCRL model validates and serializes correctly."""
    now = datetime.now(UTC)
    crl = SignedCRL(
        crl_number=42,
        issuer_did="did:key:zIssuer",
        this_update=now,
        next_update=now + timedelta(seconds=60),
        entries=[
            CRLEntry(
                did="did:key:zTest",
                status="revoked",
                reason="key_compromise",
                revoked_at=now,
            )
        ],
    )
    data = crl.model_dump(mode="json")
    assert data["crl_number"] == 42
    assert data["version"] == 1
    assert len(data["entries"]) == 1
    assert data["signature"] is None


def test_crl_empty_entries() -> None:
    """SignedCRL with no entries is valid."""
    now = datetime.now(UTC)
    crl = SignedCRL(
        crl_number=1,
        issuer_did="did:key:zIssuer",
        this_update=now,
        next_update=now + timedelta(seconds=60),
    )
    assert len(crl.entries) == 0


async def test_crl_empty_store_generates_empty_entries(
    crl_generator: CRLGenerator,
) -> None:
    """CRL from empty revocation store has no entries."""
    crl = await crl_generator.generate()
    assert len(crl.entries) == 0
    assert crl.signature is not None


# ---------------------------------------------------------------------------
# RevocationStore list_suspended / get_revoked_with_reasons tests
# ---------------------------------------------------------------------------


async def test_revocation_store_list_suspended() -> None:
    """list_suspended returns all suspended DIDs."""
    store = RevocationStore()
    await store.suspend("did:key:zS1")
    await store.suspend("did:key:zS2")

    suspended = await store.list_suspended()
    assert "did:key:zS1" in suspended
    assert "did:key:zS2" in suspended


async def test_revocation_store_get_revoked_with_reasons() -> None:
    """get_revoked_with_reasons returns all revoked DIDs with reasons."""
    store = RevocationStore()
    await store.revoke("did:key:zR1", reason=RevocationReason.KEY_COMPROMISE)
    await store.revoke("did:key:zR2", reason=RevocationReason.POLICY_VIOLATION)

    reasons = store.get_revoked_with_reasons()
    assert reasons["did:key:zR1"] == RevocationReason.KEY_COMPROMISE
    assert reasons["did:key:zR2"] == RevocationReason.POLICY_VIOLATION
