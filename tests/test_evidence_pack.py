from __future__ import annotations

"""Tests for the signed evidence pack: composition, signing, CLI export, route."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from click.testing import CliRunner
from httpx import ASGITransport, AsyncClient

from airlock.audit.trail import AuditStore, AuditTrail
from airlock.cli import cli as airlock_cli
from airlock.compliance.evidence_pack import (
    DEFAULT_FRAMEWORK_PROFILES,
    DISCLAIMER,
    EvidencePack,
    build_evidence_pack,
    render_json,
    render_markdown,
    run_cli_export,
    verify_evidence_pack,
)
from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory
from airlock.compliance.regulatory_mapper import FRAMEWORK_PROFILES, RegulatoryMapper
from airlock.compliance.schemas import AgentInventoryEntry, RiskLevel
from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair
from airlock.gateway.app import create_app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_SEED = b"evidence_pack_test_seed_0000_ab!"


def _keypair() -> KeyPair:
    return KeyPair.from_seed(_TEST_SEED)


def _populated_inventory() -> AgentInventory:
    inv = AgentInventory()
    inv.register(
        AgentInventoryEntry(
            did="did:key:z6MkAlpha",
            display_name="Alpha Agent",
            capabilities=["financial_transaction", "data_access"],
            trust_score=0.4,
        )
    )
    inv.register(
        AgentInventoryEntry(
            did="did:key:z6MkBeta",
            display_name="Beta Agent",
            agent_type="assistive",
            trust_score=0.8,
        )
    )
    return inv


def _populated_incident_store(*, one_outside_window: bool = False) -> IncidentStore:
    store = IncidentStore()
    store.report("did:key:z6MkAlpha", RiskLevel.HIGH, "unauthorized_access", "Breach attempt")
    old = store.report("did:key:z6MkBeta", RiskLevel.LOW, "config_drift", "Minor drift")
    if one_outside_window:
        old.detected_at = datetime(2020, 1, 1, tzinfo=UTC)
    return store


async def _populated_trail(entries: int = 3) -> AuditTrail:
    trail = AuditTrail()
    for i in range(entries):
        await trail.append(
            event_type="verification.completed",
            actor_did="did:key:z6MkAlpha",
            detail={"n": i},
        )
    return trail


def _window_around_now() -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    return now - timedelta(hours=1), now + timedelta(hours=1)


async def _build_pack(**overrides: object) -> EvidencePack:
    start, end = _window_around_now()
    kwargs: dict[str, object] = {
        "inventory": _populated_inventory(),
        "incident_store": _populated_incident_store(one_outside_window=True),
        "audit_trail": await _populated_trail(),
        "keypair": _keypair(),
        "period_start": start,
        "period_end": end,
    }
    kwargs.update(overrides)
    return await build_evidence_pack(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


async def test_pack_composition_with_synthetic_data() -> None:
    pack = await _build_pack()

    assert pack.summary.total_agents == 2
    assert len(pack.inventory) == 2
    assert len(pack.risk_classifications) == 2
    assert {c.did for c in pack.risk_classifications} == {"did:key:z6MkAlpha", "did:key:z6MkBeta"}

    # One of the two incidents was moved outside the window.
    assert pack.summary.incidents_in_window == 1
    assert len(pack.incidents) == 1
    assert pack.incidents[0].incident_type == "unauthorized_access"

    assert pack.audit.total_entries_in_trail == 3
    assert pack.audit.entries_in_window == 3
    assert pack.summary.audit_entries_in_window == 3

    assert pack.generated_by == _keypair().did
    assert pack.disclaimer == DISCLAIMER
    assert "not a certification" in pack.disclaimer
    assert pack.period_start.tzinfo is not None


async def test_window_filtering_excludes_out_of_range() -> None:
    pack = await _build_pack(
        period_start=datetime(2020, 1, 1, tzinfo=UTC),
        period_end=datetime(2020, 1, 2, tzinfo=UTC),
        incident_store=_populated_incident_store(),
    )
    # Snapshot data is point-in-time; windowed data is empty for a past window.
    assert pack.summary.total_agents == 2
    assert pack.summary.incidents_in_window == 0
    assert pack.audit.entries_in_window == 0
    assert pack.audit.total_entries_in_trail == 3
    assert pack.audit.chain_verified is True


async def test_invalid_period_rejected() -> None:
    start, end = _window_around_now()
    with pytest.raises(ValueError, match="period_start"):
        await _build_pack(period_start=end, period_end=start)


# ---------------------------------------------------------------------------
# Chain verification verdict
# ---------------------------------------------------------------------------


async def test_chain_verdict_and_head_hash_included() -> None:
    trail = await _populated_trail()
    newest = await trail.get_entries(limit=1)
    pack = await _build_pack(audit_trail=trail)

    assert pack.audit.chain_verified is True
    assert pack.audit.chain_verdict == "ok"
    assert pack.audit.chain_head_hash == newest[0].entry_hash
    assert pack.summary.audit_chain_verified is True


async def test_tampered_chain_verdict_included() -> None:
    trail = await _populated_trail()
    trail._entries[1].event_type = "forged"  # break the hash chain

    pack = await _build_pack(audit_trail=trail)
    assert pack.audit.chain_verified is False
    assert "mismatch" in pack.audit.chain_verdict
    assert pack.summary.audit_chain_verified is False

    md = render_markdown(pack)
    assert "FAIL" in md


# ---------------------------------------------------------------------------
# Signing and tamper detection
# ---------------------------------------------------------------------------


async def test_signature_verifies_on_model_and_json_roundtrip() -> None:
    pack = await _build_pack()
    assert pack.manifest is not None
    assert pack.manifest.signer_did == _keypair().did

    ok, reason = verify_evidence_pack(pack)
    assert (ok, reason) == (True, "ok")

    data = json.loads(render_json(pack))
    ok, reason = verify_evidence_pack(data)
    assert (ok, reason) == (True, "ok")


async def test_tampering_is_detected() -> None:
    pack = await _build_pack()
    bundle = render_json(pack)

    tampered = json.loads(bundle)
    tampered["summary"]["total_agents"] = 99
    ok, reason = verify_evidence_pack(tampered)
    assert ok is False
    assert "bundle_sha256 mismatch" in reason

    bad_sig = json.loads(bundle)
    bad_sig["manifest"]["signature_b64"] = "AAAA" + bad_sig["manifest"]["signature_b64"][4:]
    ok, reason = verify_evidence_pack(bad_sig)
    assert ok is False
    assert "signature" in reason

    unsigned = json.loads(bundle)
    del unsigned["manifest"]
    ok, reason = verify_evidence_pack(unsigned)
    assert ok is False
    assert "manifest" in reason


# ---------------------------------------------------------------------------
# Framework profiles
# ---------------------------------------------------------------------------


async def test_framework_profiles_present() -> None:
    pack = await _build_pack()
    profile_ids = [m.profile_id for m in pack.framework_mappings]
    assert profile_ids == list(DEFAULT_FRAMEWORK_PROFILES)
    assert profile_ids == ["RBI-FREE-AI", "EU-AI-Act", "ISO-42001"]

    by_id = {m.profile_id: m for m in pack.framework_mappings}
    for mapping in pack.framework_mappings:
        assert mapping.controls, f"profile {mapping.profile_id} has no controls"
        assert mapping.issuer
        assert mapping.reference_note

    rbi_controls = {c.control_id: c for c in by_id["RBI-FREE-AI"].controls}
    assert "Recommendation 23" in rbi_controls
    inventory_ctl = rbi_controls["Recommendation 23"]
    assert "agent_inventory" in inventory_ctl.evidence_categories
    assert inventory_ctl.evidence_item_counts["agent_inventory"] == 2
    assert inventory_ctl.evidence_present is True

    eu_controls = {c.control_id: c for c in by_id["EU-AI-Act"].controls}
    assert "Article 12" in eu_controls
    assert "audit_trail" in eu_controls["Article 12"].evidence_categories
    assert "Article 73" in eu_controls

    iso_controls = {c.control_id: c for c in by_id["ISO-42001"].controls}
    assert "A.6.2.8" in iso_controls
    assert "Clause 9.1" in iso_controls


def test_framework_profile_data_is_complete() -> None:
    assert set(DEFAULT_FRAMEWORK_PROFILES) == set(FRAMEWORK_PROFILES.keys())
    for profile in FRAMEWORK_PROFILES.values():
        for control in profile["controls"]:
            assert control["control_id"]
            assert control["title"]
            assert control["evidence"]


def test_mapper_unknown_profile_raises() -> None:
    mapper = RegulatoryMapper()
    with pytest.raises(KeyError, match="Unknown framework profile"):
        mapper.map_evidence_to_framework("SOC-2", {})


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


async def test_markdown_report_sections_and_disclaimer() -> None:
    pack = await _build_pack()
    md = render_markdown(pack)

    assert md.startswith("# Airlock Evidence Pack")
    assert DISCLAIMER in md
    assert "## 6. Audit-trail extract" in md
    assert "## 7. Framework control mapping" in md
    assert "## 8. Integrity and signature" in md
    assert "RBI FREE-AI" in md
    assert "EU AI Act" in md
    assert "ISO/IEC 42001" in md
    assert pack.manifest is not None
    assert pack.manifest.bundle_sha256 in md
    assert pack.manifest.signer_did in md
    assert "Verification instructions" in md


async def test_json_bundle_includes_manifest_and_disclaimer() -> None:
    pack = await _build_pack()
    data = json.loads(render_json(pack))
    assert data["disclaimer"] == DISCLAIMER
    assert data["manifest"]["algorithm"] == "Ed25519"
    assert data["manifest"]["public_key_multibase"].startswith("z")
    assert data["manifest"]["verification_instructions"]


# ---------------------------------------------------------------------------
# CLI export
# ---------------------------------------------------------------------------


def test_cli_export_to_tmpdir(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        airlock_cli,
        [
            "evidence",
            "export",
            "--from",
            "2026-06-01T00:00:00Z",
            "--to",
            "2026-07-01T00:00:00Z",
            "--format",
            "both",
            "--out",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output

    json_files = list(tmp_path.glob("evidence_pack_*.json"))
    md_files = list(tmp_path.glob("evidence_pack_*.md"))
    assert len(json_files) == 1
    assert len(md_files) == 1

    data = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert verify_evidence_pack(data) == (True, "ok")
    assert data["disclaimer"] == DISCLAIMER
    assert md_files[0].read_text(encoding="utf-8").startswith("# Airlock Evidence Pack")


def test_cli_export_rejects_bad_dates(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        airlock_cli,
        ["evidence", "export", "--from", "not-a-date", "--to", "also-bad", "--out", str(tmp_path)],
    )
    assert result.exit_code == 1
    assert "ERROR" in result.output


def test_run_cli_export_reads_persistent_audit_trail(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"

    async def _seed() -> None:
        store = AuditStore(str(db_path))
        store.open()
        trail = AuditTrail(store=store)
        await trail.append(event_type="agent.registered", actor_did="did:key:z6MkAlpha")
        await trail.append(event_type="verification.completed", actor_did="did:key:z6MkAlpha")
        store.close()

    asyncio.run(_seed())

    cfg = AirlockConfig(audit_trail_persist=True, audit_db_path=str(db_path))
    now = datetime.now(UTC)
    written = run_cli_export(
        from_iso=(now - timedelta(hours=1)).isoformat(),
        to_iso=(now + timedelta(hours=1)).isoformat(),
        fmt="json",
        out_dir=str(tmp_path),
        config=cfg,
    )
    assert len(written) == 1

    data = json.loads(written[0].read_text(encoding="utf-8"))
    assert data["audit"]["entries_in_window"] == 2
    assert data["audit"]["chain_verified"] is True
    assert verify_evidence_pack(data) == (True, "ok")


def test_run_cli_export_rejects_bad_format(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Invalid format"):
        run_cli_export(
            from_iso="2026-06-01T00:00:00Z",
            to_iso="2026-07-01T00:00:00Z",
            fmt="pdf",
            out_dir=str(tmp_path),
        )


# ---------------------------------------------------------------------------
# Gateway route (feature flag)
# ---------------------------------------------------------------------------


@pytest.fixture
def flag_off_config(tmp_path):
    return AirlockConfig(lancedb_path=str(tmp_path / "ep_off.lance"))


@pytest.fixture
def flag_on_config(tmp_path):
    return AirlockConfig(
        lancedb_path=str(tmp_path / "ep_on.lance"),
        evidence_pack_enabled=True,
    )


@pytest.fixture
async def flag_off_app(flag_off_config):
    app = create_app(flag_off_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
async def flag_on_app(flag_on_config):
    app = create_app(flag_on_config)
    async with LifespanManager(app):
        yield app


async def test_route_flag_off_returns_404(flag_off_app) -> None:
    transport = ASGITransport(app=flag_off_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/evidence-pack")
    assert r.status_code == 404
    body = r.json()
    assert body["error"] == "feature_disabled"
    assert body["status_code"] == 404


async def test_route_flag_on_returns_signed_json(flag_on_app) -> None:
    transport = ASGITransport(app=flag_on_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/evidence-pack?format=json")
    assert r.status_code == 200
    data = json.loads(r.text)
    assert data["manifest"]["bundle_sha256"]
    assert verify_evidence_pack(data) == (True, "ok")
    assert data["disclaimer"] == DISCLAIMER


async def test_route_markdown_format(flag_on_app) -> None:
    transport = ASGITransport(app=flag_on_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get(
            "/compliance/evidence-pack",
            params={
                "from": "2026-06-01T00:00:00+00:00",
                "to": "2026-07-01T00:00:00+00:00",
                "format": "markdown",
            },
        )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert r.text.startswith("# Airlock Evidence Pack")
    assert DISCLAIMER in r.text


async def test_route_rejects_invalid_format(flag_on_app) -> None:
    transport = ASGITransport(app=flag_on_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/evidence-pack?format=xml")
    assert r.status_code == 422
    assert r.json()["error"] == "validation_error"


async def test_route_rejects_invalid_dates(flag_on_app) -> None:
    transport = ASGITransport(app=flag_on_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/evidence-pack", params={"from": "nope"})
        r2 = await client.get(
            "/compliance/evidence-pack",
            params={"from": "2026-07-01T00:00:00+00:00", "to": "2026-06-01T00:00:00+00:00"},
        )
    assert r.status_code == 422
    assert r2.status_code == 422
