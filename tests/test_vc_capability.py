"""Unit 4: VC Capability Verification — extraction, cross-referencing, and mode tests.

Tests:
  1. extract_capabilities happy path (single subject with valid capabilities)
  2. extract_capabilities missing 'capabilities' field
  3. extract_capabilities malformed data
  4. extract_capabilities multiple subjects with union merge
  5. Cross-ref mode=off (no-op)
  6. Cross-ref mode=audit (logs but doesn't change behavior)
  7. Cross-ref mode=warn (uses VC capabilities for challenge context)
  8. Cross-ref mode=enforce with mismatch (fails)
  9. Cross-ref extraction error degrades gracefully
  10. Cross-ref degraded flag on CheckResult
"""

from __future__ import annotations

import os
import shutil
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest

from airlock.config import AirlockConfig, _reset_config
from airlock.crypto.keys import KeyPair
from airlock.crypto.vc import CapabilityExtractionResult, extract_capabilities
from airlock.crypto.vc import issue_credential
from airlock.crypto.signing import sign_model
from airlock.engine.orchestrator import OrchestrationState, VerificationOrchestrator
from airlock.reputation.store import ReputationStore
from airlock.schemas.challenge import ChallengeRequest
from airlock.schemas.envelope import create_envelope
from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest
from airlock.schemas.identity import AgentCapability, AgentDID, AgentProfile
from airlock.schemas.session import VerificationSession, VerificationState
from airlock.schemas.trust_tier import TrustTier
from airlock.schemas.verdict import CheckResult, TrustVerdict, VerificationCheck
from airlock.gateway.startup_validate import AirlockStartupError, validate_startup_config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path: Any) -> Any:
    db_dir = str(tmp_path / "reputation.lance")
    yield db_dir
    if os.path.exists(db_dir):
        shutil.rmtree(db_dir, ignore_errors=True)


@pytest.fixture
def reputation_store(tmp_db: str) -> Any:
    store = ReputationStore(db_path=tmp_db)
    store.open()
    yield store
    store.close()


@pytest.fixture
def airlock_keypair() -> KeyPair:
    return KeyPair.from_seed(b"airlock_vc_cap_test_seed_000000x")


@pytest.fixture
def agent_keypair() -> KeyPair:
    return KeyPair.from_seed(b"agent_vc_cap_test_seed_00000000x")


@pytest.fixture
def issuer_keypair() -> KeyPair:
    return KeyPair.from_seed(b"issuer_vc_cap_test_seed_0000000x")


@pytest.fixture
def target_keypair() -> KeyPair:
    return KeyPair.from_seed(b"target_vc_cap_test_seed_0000000x")


@pytest.fixture(autouse=True)
def _reset_config_fixture() -> Any:
    """Reset the config singleton before each test to avoid cross-contamination."""
    _reset_config()
    yield
    _reset_config()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    vc_claims: dict[str, Any] | None = None,
    session_id: str | None = None,
) -> HandshakeRequest:
    """Build a signed HandshakeRequest with a VC containing the given claims."""
    claims = vc_claims or {"role": "agent", "scope": "test"}
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims=claims,
        validity_days=365,
    )
    envelope = create_envelope(sender_did=agent_kp.did)
    request = HandshakeRequest(
        envelope=envelope,
        session_id=session_id or str(uuid.uuid4()),
        initiator=AgentDID(did=agent_kp.did, public_key_multibase=agent_kp.public_key_multibase),
        intent=HandshakeIntent(
            action="connect",
            description="VC capability test handshake",
            target_did=target_did,
        ),
        credential=vc,
        signature=None,
    )
    request.signature = sign_model(request, agent_kp.signing_key)
    return request


def _make_agent_profile(did: str, capabilities: list[AgentCapability]) -> AgentProfile:
    """Create a minimal AgentProfile for registry."""
    return AgentProfile(
        did=AgentDID(did=did, public_key_multibase="z" + "0" * 43),
        display_name="Test Agent",
        capabilities=capabilities,
        endpoint_url="http://localhost:9999",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )


def _make_orchestrator(
    reputation_store: ReputationStore,
    airlock_kp: KeyPair,
    registry: dict[str, AgentProfile] | None = None,
) -> VerificationOrchestrator:
    return VerificationOrchestrator(
        reputation_store=reputation_store,
        agent_registry=registry or {},
        airlock_did=airlock_kp.did,
        litellm_model="ollama/llama3",
        litellm_api_base=None,
    )


def _build_initial_state(
    handshake: HandshakeRequest,
) -> OrchestrationState:
    """Build an OrchestrationState as if the graph had run through to validate_delegation."""
    now = datetime.now(UTC)
    session = VerificationSession(
        session_id=handshake.session_id,
        state=VerificationState.CREDENTIAL_VALIDATED,
        initiator_did=handshake.initiator.did,
        target_did=handshake.intent.target_did,
        callback_url=None,
        created_at=now,
        updated_at=now,
        handshake_request=handshake,
    )
    return OrchestrationState(
        session=session,
        handshake=handshake,
        challenge=None,
        challenge_response=None,
        check_results=[
            CheckResult(check=VerificationCheck.SCHEMA, passed=True, detail="ok"),
            CheckResult(check=VerificationCheck.REVOCATION, passed=True, detail="ok"),
            CheckResult(check=VerificationCheck.SIGNATURE, passed=True, detail="ok"),
            CheckResult(check=VerificationCheck.CREDENTIAL, passed=True, detail="ok"),
            CheckResult(check=VerificationCheck.DELEGATION, passed=True, detail="ok"),
        ],
        trust_score=0.5,
        verdict=None,
        error=None,
        failed_at=None,
        _sig_valid=True,
        _vc_valid=True,
        _routing="challenge",
        _challenge_outcome=None,
        _tier=TrustTier.UNKNOWN,
        _local_only=False,
    )


# ===========================================================================
# 1. extract_capabilities — happy path
# ===========================================================================


def test_extract_capabilities_happy_path() -> None:
    """Valid capabilities in credential_subject are parsed correctly."""
    subject = {
        "id": "did:key:z6MkTest",
        "capabilities": [
            {"name": "crypto_security", "version": "1.0", "description": "Ed25519 signing"},
            {"name": "payments", "version": "2.1", "description": "Payment processing"},
        ],
    }
    result = extract_capabilities([subject])

    assert not result.extraction_failed
    assert len(result.capabilities) == 2
    assert result.capabilities[0].name == "crypto_security"
    assert result.capabilities[0].version == "1.0"
    assert result.capabilities[1].name == "payments"
    assert result.capabilities[1].version == "2.1"
    assert result.warnings == []


# ===========================================================================
# 2. extract_capabilities — missing 'capabilities' field
# ===========================================================================


def test_extract_capabilities_missing_field() -> None:
    """Missing 'capabilities' field returns empty list without failure."""
    subject = {
        "id": "did:key:z6MkTest",
        "role": "agent",
    }
    result = extract_capabilities([subject])

    assert not result.extraction_failed
    assert len(result.capabilities) == 0
    assert len(result.warnings) == 1
    assert "no 'capabilities' field" in result.warnings[0]


# ===========================================================================
# 3. extract_capabilities — malformed data
# ===========================================================================


def test_extract_capabilities_malformed_data() -> None:
    """Malformed capabilities data sets extraction_failed=True."""
    subject = {
        "id": "did:key:z6MkTest",
        "capabilities": "not_a_list",
    }
    result = extract_capabilities([subject])

    assert result.extraction_failed
    assert len(result.capabilities) == 0
    assert any("not a list" in w for w in result.warnings)


def test_extract_capabilities_malformed_entry() -> None:
    """One bad entry among good ones: good ones still parsed, extraction_failed set."""
    subject = {
        "id": "did:key:z6MkTest",
        "capabilities": [
            {"name": "valid_cap", "version": "1.0", "description": "Good"},
            "not_a_dict",
            {"name": "another_valid", "version": "2.0", "description": "Also good"},
        ],
    }
    result = extract_capabilities([subject])

    assert result.extraction_failed
    assert len(result.capabilities) == 2
    assert result.capabilities[0].name == "valid_cap"
    assert result.capabilities[1].name == "another_valid"
    assert any("not a dict" in w for w in result.warnings)


def test_extract_capabilities_missing_name() -> None:
    """Capability entry with missing name is skipped with warning."""
    subject = {
        "id": "did:key:z6MkTest",
        "capabilities": [
            {"version": "1.0", "description": "No name"},
        ],
    }
    result = extract_capabilities([subject])

    assert result.extraction_failed
    assert len(result.capabilities) == 0
    assert any("invalid 'name'" in w for w in result.warnings)


# ===========================================================================
# 4. extract_capabilities — multiple subjects (union merge)
# ===========================================================================


def test_extract_capabilities_multiple_subjects_union() -> None:
    """Union merge across two credential subjects deduplicates by (name, version)."""
    subject_a = {
        "id": "did:key:z6MkA",
        "capabilities": [
            {"name": "crypto", "version": "1.0", "description": "Signing"},
            {"name": "payments", "version": "1.0", "description": "UPI"},
        ],
    }
    subject_b = {
        "id": "did:key:z6MkB",
        "capabilities": [
            {"name": "crypto", "version": "1.0", "description": "Duplicate"},
            {"name": "networking", "version": "1.0", "description": "gRPC"},
        ],
    }
    result = extract_capabilities([subject_a, subject_b], merge_strategy="union")

    assert not result.extraction_failed
    assert len(result.capabilities) == 3
    names = [c.name for c in result.capabilities]
    assert "crypto" in names
    assert "payments" in names
    assert "networking" in names


def test_extract_capabilities_intersection() -> None:
    """Intersection merge keeps only capabilities present in all subjects."""
    subject_a = {
        "id": "did:key:z6MkA",
        "capabilities": [
            {"name": "crypto", "version": "1.0", "description": "Signing"},
            {"name": "payments", "version": "1.0", "description": "UPI"},
        ],
    }
    subject_b = {
        "id": "did:key:z6MkB",
        "capabilities": [
            {"name": "crypto", "version": "1.0", "description": "Signing 2"},
        ],
    }
    result = extract_capabilities([subject_a, subject_b], merge_strategy="intersection")

    assert not result.extraction_failed
    assert len(result.capabilities) == 1
    assert result.capabilities[0].name == "crypto"


def test_extract_capabilities_first_strategy() -> None:
    """'first' merge strategy uses only the first subject's capabilities."""
    subject_a = {
        "id": "did:key:z6MkA",
        "capabilities": [
            {"name": "payments", "version": "1.0", "description": "UPI"},
        ],
    }
    subject_b = {
        "id": "did:key:z6MkB",
        "capabilities": [
            {"name": "crypto", "version": "1.0", "description": "Signing"},
        ],
    }
    result = extract_capabilities([subject_a, subject_b], merge_strategy="first")

    assert not result.extraction_failed
    assert len(result.capabilities) == 1
    assert result.capabilities[0].name == "payments"


def test_extract_capabilities_empty_subjects() -> None:
    """Empty credential_subjects list returns empty result."""
    result = extract_capabilities([])
    assert not result.extraction_failed
    assert len(result.capabilities) == 0
    assert any("no credential subjects" in w for w in result.warnings)


def test_extract_capabilities_non_dict_subject() -> None:
    """Non-dict credential subject sets extraction_failed."""
    result = extract_capabilities(["not_a_dict"])  # type: ignore[list-item]
    assert result.extraction_failed
    assert len(result.capabilities) == 0


# ===========================================================================
# 5. Cross-ref mode=off (no-op)
# ===========================================================================


def test_cross_ref_mode_off(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """When vc_capability_mode=off, the cross-ref node is a no-op."""
    with patch.dict(os.environ, {"AIRLOCK_VC_CAPABILITY_MODE": "off"}):
        _reset_config()
        orchestrator = _make_orchestrator(reputation_store, airlock_keypair)

        handshake = _make_handshake(
            agent_keypair,
            issuer_keypair,
            target_keypair.did,
            vc_claims={
                "role": "agent",
                "capabilities": [
                    {"name": "crypto", "version": "1.0", "description": "Signing"},
                ],
            },
        )
        state = _build_initial_state(handshake)
        checks_before = len(state["check_results"])

        result = orchestrator._node_cross_ref_capabilities(state)

        # No new check results added
        assert len(result["check_results"]) == checks_before
        assert result.get("failed_at") is None


# ===========================================================================
# 6. Cross-ref mode=audit (logs, adds CheckResult, doesn't change behavior)
# ===========================================================================


def test_cross_ref_mode_audit(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """mode=audit extracts VC capabilities and adds a CheckResult, but doesn't fail."""
    profile = _make_agent_profile(
        agent_keypair.did,
        [AgentCapability(name="crypto", version="1.0", description="Signing")],
    )
    registry = {agent_keypair.did: profile}

    with patch.dict(os.environ, {"AIRLOCK_VC_CAPABILITY_MODE": "audit"}):
        _reset_config()
        orchestrator = _make_orchestrator(reputation_store, airlock_keypair, registry)

        handshake = _make_handshake(
            agent_keypair,
            issuer_keypair,
            target_keypair.did,
            vc_claims={
                "role": "agent",
                "capabilities": [
                    {"name": "crypto", "version": "1.0", "description": "Signing"},
                ],
            },
        )
        state = _build_initial_state(handshake)
        result = orchestrator._node_cross_ref_capabilities(state)

        # Find the CAPABILITY_CROSS_REF check
        cross_ref_checks = [
            c for c in result["check_results"]
            if c.check == VerificationCheck.CAPABILITY_CROSS_REF
        ]
        assert len(cross_ref_checks) == 1
        assert cross_ref_checks[0].passed is True
        assert "vc_capabilities" in cross_ref_checks[0].detail
        assert result.get("failed_at") is None


def test_cross_ref_mode_audit_with_mismatch(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """mode=audit with mismatched capabilities still passes (audit only)."""
    profile = _make_agent_profile(
        agent_keypair.did,
        [
            AgentCapability(name="crypto", version="1.0", description="Signing"),
            AgentCapability(name="payments", version="1.0", description="UPI"),
        ],
    )
    registry = {agent_keypair.did: profile}

    with patch.dict(os.environ, {"AIRLOCK_VC_CAPABILITY_MODE": "audit"}):
        _reset_config()
        orchestrator = _make_orchestrator(reputation_store, airlock_keypair, registry)

        # VC only has crypto, self-declared has crypto + payments
        handshake = _make_handshake(
            agent_keypair,
            issuer_keypair,
            target_keypair.did,
            vc_claims={
                "role": "agent",
                "capabilities": [
                    {"name": "crypto", "version": "1.0", "description": "Signing"},
                ],
            },
        )
        state = _build_initial_state(handshake)
        result = orchestrator._node_cross_ref_capabilities(state)

        cross_ref_checks = [
            c for c in result["check_results"]
            if c.check == VerificationCheck.CAPABILITY_CROSS_REF
        ]
        assert len(cross_ref_checks) == 1
        assert cross_ref_checks[0].passed is True
        assert "mismatch" in cross_ref_checks[0].detail
        # Audit mode never fails
        assert result.get("failed_at") is None


# ===========================================================================
# 7. Cross-ref mode=warn (uses VC capabilities for challenge context)
# ===========================================================================


def test_cross_ref_mode_warn(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """mode=warn annotates capabilities with trust weights."""
    profile = _make_agent_profile(
        agent_keypair.did,
        [
            AgentCapability(name="crypto", version="1.0", description="Signing"),
            AgentCapability(name="payments", version="1.0", description="UPI"),
        ],
    )
    registry = {agent_keypair.did: profile}

    with patch.dict(os.environ, {"AIRLOCK_VC_CAPABILITY_MODE": "warn"}):
        _reset_config()
        orchestrator = _make_orchestrator(reputation_store, airlock_keypair, registry)

        # VC has crypto only — payments is self-declared only
        handshake = _make_handshake(
            agent_keypair,
            issuer_keypair,
            target_keypair.did,
            vc_claims={
                "role": "agent",
                "capabilities": [
                    {"name": "crypto", "version": "1.0", "description": "Signing"},
                ],
            },
        )
        state = _build_initial_state(handshake)
        result = orchestrator._node_cross_ref_capabilities(state)

        cross_ref_checks = [
            c for c in result["check_results"]
            if c.check == VerificationCheck.CAPABILITY_CROSS_REF
        ]
        assert len(cross_ref_checks) == 1
        assert cross_ref_checks[0].passed is True
        assert "trust_weighted" in cross_ref_checks[0].detail
        assert "vc_attested" in cross_ref_checks[0].detail
        assert result.get("failed_at") is None


# ===========================================================================
# 8. Cross-ref mode=enforce with mismatch (fails)
# ===========================================================================


def test_cross_ref_mode_enforce_mismatch(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """mode=enforce with capability mismatch rejects the agent."""
    profile = _make_agent_profile(
        agent_keypair.did,
        [
            AgentCapability(name="crypto", version="1.0", description="Signing"),
            AgentCapability(name="payments", version="1.0", description="UPI"),
        ],
    )
    registry = {agent_keypair.did: profile}

    with patch.dict(os.environ, {"AIRLOCK_VC_CAPABILITY_MODE": "enforce"}):
        _reset_config()
        orchestrator = _make_orchestrator(reputation_store, airlock_keypair, registry)

        # VC has crypto only — payments is self-declared only = mismatch
        handshake = _make_handshake(
            agent_keypair,
            issuer_keypair,
            target_keypair.did,
            vc_claims={
                "role": "agent",
                "capabilities": [
                    {"name": "crypto", "version": "1.0", "description": "Signing"},
                ],
            },
        )
        state = _build_initial_state(handshake)
        result = orchestrator._node_cross_ref_capabilities(state)

        cross_ref_checks = [
            c for c in result["check_results"]
            if c.check == VerificationCheck.CAPABILITY_CROSS_REF
        ]
        assert len(cross_ref_checks) == 1
        assert cross_ref_checks[0].passed is False
        assert "capability_mismatch" in cross_ref_checks[0].detail
        assert result.get("failed_at") == "cross_ref_capabilities"
        assert result.get("verdict") == TrustVerdict.REJECTED


def test_cross_ref_mode_enforce_no_mismatch(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """mode=enforce with matching capabilities passes."""
    profile = _make_agent_profile(
        agent_keypair.did,
        [AgentCapability(name="crypto", version="1.0", description="Signing")],
    )
    registry = {agent_keypair.did: profile}

    with patch.dict(os.environ, {"AIRLOCK_VC_CAPABILITY_MODE": "enforce"}):
        _reset_config()
        orchestrator = _make_orchestrator(reputation_store, airlock_keypair, registry)

        handshake = _make_handshake(
            agent_keypair,
            issuer_keypair,
            target_keypair.did,
            vc_claims={
                "role": "agent",
                "capabilities": [
                    {"name": "crypto", "version": "1.0", "description": "Signing"},
                ],
            },
        )
        state = _build_initial_state(handshake)
        result = orchestrator._node_cross_ref_capabilities(state)

        cross_ref_checks = [
            c for c in result["check_results"]
            if c.check == VerificationCheck.CAPABILITY_CROSS_REF
        ]
        assert len(cross_ref_checks) == 1
        assert cross_ref_checks[0].passed is True
        assert result.get("failed_at") is None


# ===========================================================================
# 9. Cross-ref extraction error degrades gracefully
# ===========================================================================


def test_cross_ref_extraction_error_degrades_gracefully(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """When VC capabilities are malformed, node falls back gracefully (degraded pass)."""
    with patch.dict(os.environ, {"AIRLOCK_VC_CAPABILITY_MODE": "audit"}):
        _reset_config()
        orchestrator = _make_orchestrator(reputation_store, airlock_keypair)

        # VC has malformed capabilities (string instead of list)
        handshake = _make_handshake(
            agent_keypair,
            issuer_keypair,
            target_keypair.did,
            vc_claims={
                "role": "agent",
                "capabilities": "not_a_list_of_caps",
            },
        )
        state = _build_initial_state(handshake)
        result = orchestrator._node_cross_ref_capabilities(state)

        cross_ref_checks = [
            c for c in result["check_results"]
            if c.check == VerificationCheck.CAPABILITY_CROSS_REF
        ]
        assert len(cross_ref_checks) == 1
        assert cross_ref_checks[0].passed is True
        assert cross_ref_checks[0].degraded is True
        assert "extraction_degraded" in cross_ref_checks[0].detail
        assert result.get("failed_at") is None


# ===========================================================================
# 10. Cross-ref degraded flag on CheckResult
# ===========================================================================


def test_cross_ref_degraded_flag_on_check_result() -> None:
    """CheckResult.degraded defaults to False and can be set to True."""
    normal = CheckResult(
        check=VerificationCheck.CAPABILITY_CROSS_REF,
        passed=True,
        detail="ok",
    )
    assert normal.degraded is False

    degraded = CheckResult(
        check=VerificationCheck.CAPABILITY_CROSS_REF,
        passed=True,
        detail="extraction_degraded",
        degraded=True,
    )
    assert degraded.degraded is True


# ===========================================================================
# Startup validation tests
# ===========================================================================


def test_startup_validate_vc_capability_mode_valid() -> None:
    """Valid vc_capability_mode values pass validation."""
    for mode in ("off", "audit", "warn", "enforce"):
        cfg = AirlockConfig(vc_capability_mode=mode)
        # Should not raise
        validate_startup_config(cfg)


def test_startup_validate_vc_capability_mode_invalid() -> None:
    """Invalid vc_capability_mode raises AirlockStartupError."""
    cfg = AirlockConfig(vc_capability_mode="invalid_mode")
    with pytest.raises(AirlockStartupError, match="AIRLOCK_VC_CAPABILITY_MODE"):
        validate_startup_config(cfg)


# ===========================================================================
# ChallengeRequest new fields
# ===========================================================================


def test_challenge_request_new_fields() -> None:
    """ChallengeRequest accepts new is_trap, trap_domain, capability_source fields."""
    from airlock.schemas.envelope import MessageEnvelope, generate_nonce

    now = datetime.now(UTC)
    envelope = MessageEnvelope(
        protocol_version="0.1.0",
        timestamp=now,
        sender_did="did:key:z6MkTest",
        nonce=generate_nonce(),
    )
    challenge = ChallengeRequest(
        envelope=envelope,
        session_id="test-session",
        challenge_id="test-challenge",
        challenge_type="semantic",
        question="What is Ed25519?",
        context="Test",
        expires_at=now,
        is_trap=True,
        trap_domain="payments",
        capability_source="vc_attested",
    )
    assert challenge.is_trap is True
    assert challenge.trap_domain == "payments"
    assert challenge.capability_source == "vc_attested"


def test_challenge_request_defaults() -> None:
    """ChallengeRequest new fields have correct defaults."""
    from airlock.schemas.envelope import MessageEnvelope, generate_nonce

    now = datetime.now(UTC)
    envelope = MessageEnvelope(
        protocol_version="0.1.0",
        timestamp=now,
        sender_did="did:key:z6MkTest",
        nonce=generate_nonce(),
    )
    challenge = ChallengeRequest(
        envelope=envelope,
        session_id="test-session",
        challenge_id="test-challenge",
        challenge_type="semantic",
        question="What is Ed25519?",
        context="Test",
        expires_at=now,
    )
    assert challenge.is_trap is False
    assert challenge.trap_domain is None
    assert challenge.capability_source == "self_declared"


# ===========================================================================
# VerificationCheck enum
# ===========================================================================


def test_verification_check_capability_cross_ref() -> None:
    """CAPABILITY_CROSS_REF is a valid VerificationCheck enum value."""
    assert VerificationCheck.CAPABILITY_CROSS_REF == "capability_cross_ref"
    assert VerificationCheck.CAPABILITY_CROSS_REF in VerificationCheck


# ===========================================================================
# Cross-ref with no VC capabilities (warn/enforce mode)
# ===========================================================================


def test_cross_ref_no_vc_capabilities_warn_mode(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """When VC has no capabilities field, cross-ref logs and passes."""
    with patch.dict(os.environ, {"AIRLOCK_VC_CAPABILITY_MODE": "warn"}):
        _reset_config()
        orchestrator = _make_orchestrator(reputation_store, airlock_keypair)

        # VC has no capabilities field at all
        handshake = _make_handshake(
            agent_keypair,
            issuer_keypair,
            target_keypair.did,
            vc_claims={"role": "agent", "scope": "test"},
        )
        state = _build_initial_state(handshake)
        result = orchestrator._node_cross_ref_capabilities(state)

        cross_ref_checks = [
            c for c in result["check_results"]
            if c.check == VerificationCheck.CAPABILITY_CROSS_REF
        ]
        assert len(cross_ref_checks) == 1
        assert cross_ref_checks[0].passed is True
        assert cross_ref_checks[0].detail == "no_vc_capabilities"
        assert result.get("failed_at") is None
