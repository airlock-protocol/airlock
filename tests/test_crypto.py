from __future__ import annotations

import base64
from datetime import datetime, timezone, timedelta

import pytest

from airlock.crypto import (
    KeyPair,
    canonicalize,
    issue_credential,
    resolve_public_key,
    sign_message,
    sign_model,
    validate_credential,
    verify_model,
    verify_signature,
)
from airlock.schemas import (
    HandshakeIntent,
    HandshakeRequest,
    VerifiableCredential,
    create_envelope,
)


def test_keypair_generate() -> None:
    kp = KeyPair.generate()
    assert kp.did.startswith("did:key:")
    assert len(kp.did) > 10


def test_keypair_did_format() -> None:
    kp = KeyPair.generate()
    assert kp.did.startswith("did:key:z")


def test_keypair_from_seed_deterministic() -> None:
    seed = b"x" * 32
    kp1 = KeyPair.from_seed(seed)
    kp2 = KeyPair.from_seed(seed)
    assert kp1.did == kp2.did


def test_keypair_from_seed_invalid_length() -> None:
    with pytest.raises(ValueError):
        KeyPair.from_seed(b"short")


def test_keypair_to_agent_did() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    agent_did = kp.to_agent_did()
    assert agent_did.did == kp.did
    assert agent_did.public_key_multibase == kp.public_key_multibase


def test_resolve_public_key_roundtrip() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    resolved = resolve_public_key(kp.did)
    assert resolved.encode() == kp.verify_key.encode()


def test_resolve_public_key_invalid_did() -> None:
    with pytest.raises(ValueError):
        resolve_public_key("did:web:foo")


def test_canonicalize_deterministic() -> None:
    d = {"b": 2, "a": 1, "c": 3}
    assert canonicalize(d) == canonicalize(d)


def test_canonicalize_strips_signature() -> None:
    d = {"a": 1, "signature": "xyz"}
    result = canonicalize(d)
    assert b"signature" not in result


def test_canonicalize_sorted_keys() -> None:
    d = {"z": 3, "a": 1, "m": 2}
    result = canonicalize(d)
    assert result == b'{"a":1,"m":2,"z":3}'


def test_sign_message_returns_base64() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    sig = sign_message({"msg": "hello"}, kp.signing_key)
    assert sig
    base64.b64decode(sig)


def test_verify_signature_valid() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    msg = {"data": "test"}
    sig = sign_message(msg, kp.signing_key)
    assert verify_signature(msg, sig, kp.verify_key) is True


def test_verify_signature_tampered() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    msg = {"data": "test"}
    sig = sign_message(msg, kp.signing_key)
    msg["data"] = "tampered"
    assert verify_signature(msg, sig, kp.verify_key) is False


def test_verify_signature_wrong_key() -> None:
    kp_a = KeyPair.from_seed(b"a" * 32)
    kp_b = KeyPair.from_seed(b"b" * 32)
    msg = {"data": "test"}
    sig = sign_message(msg, kp_a.signing_key)
    assert verify_signature(msg, sig, kp_b.verify_key) is False


def test_sign_model_and_verify_model() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    vc = issue_credential(kp, "did:key:z6MkTarget", "AgentAuthorization", {}, validity_days=365)
    envelope = create_envelope(kp.did)
    intent = HandshakeIntent(action="test", description="test", target_did="did:key:z6MkTarget")
    request = HandshakeRequest(
        envelope=envelope,
        session_id="test-session",
        initiator=kp.to_agent_did(),
        intent=intent,
        credential=vc,
    )
    sig = sign_model(request, kp.signing_key)
    request = request.model_copy(update={"signature": sig})
    assert verify_model(request, kp.verify_key) is True


def test_verify_model_no_signature() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    vc = issue_credential(kp, "did:key:z6MkTarget", "AgentAuthorization", {}, validity_days=365)
    envelope = create_envelope(kp.did)
    intent = HandshakeIntent(action="test", description="test", target_did="did:key:z6MkTarget")
    request = HandshakeRequest(
        envelope=envelope,
        session_id="test-session",
        initiator=kp.to_agent_did(),
        intent=intent,
        credential=vc,
    )
    assert verify_model(request, kp.verify_key) is False


def test_issue_credential() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    vc = issue_credential(kp, "did:key:z6MkTarget", "AgentAuthorization", {"role": "agent"})
    assert vc.proof is not None
    assert vc.proof.proof_value


def test_issue_credential_has_valid_proof() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    vc = issue_credential(kp, "did:key:z6MkTarget", "AgentAuthorization", {})
    valid, msg = validate_credential(vc, kp.verify_key)
    assert valid is True
    assert msg == "valid"


def test_validate_credential_expired() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    vc = issue_credential(kp, "did:key:z6MkTarget", "AgentAuthorization", {}, validity_days=-1)
    valid, msg = validate_credential(vc, kp.verify_key)
    assert valid is False
    assert "credential expired" in msg


def test_validate_credential_tampered() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    vc = issue_credential(kp, "did:key:z6MkTarget", "AgentAuthorization", {"role": "agent"})
    vc = vc.model_copy(
        update={"credential_subject": {"id": "did:key:z6MkTarget", "role": "tampered"}}
    )
    valid, msg = validate_credential(vc, kp.verify_key)
    assert valid is False
    assert "invalid proof signature" in msg


def test_validate_credential_no_proof() -> None:
    kp = KeyPair.from_seed(b"x" * 32)
    now = datetime.now(timezone.utc)
    vc = VerifiableCredential(
        id="urn:test:vc:1",
        type=["VerifiableCredential", "AgentAuthorization"],
        issuer=kp.did,
        issuance_date=now,
        expiration_date=now + timedelta(days=365),
        credential_subject={"id": "did:key:z6MkTarget"},
        proof=None,
    )
    valid, msg = validate_credential(vc, kp.verify_key)
    assert valid is False
    assert "missing proof" in msg
