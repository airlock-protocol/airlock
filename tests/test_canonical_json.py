"""Tests for cross-language canonical JSON serialization (C-09 interop fix).

Verifies that _prepare_for_json() and canonicalize() produce deterministic,
language-agnostic output so that Go/Rust/JS implementations produce identical
canonical bytes and therefore identical Ed25519 signatures.
"""

from __future__ import annotations

import json
import uuid
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timezone
from enum import Enum, IntEnum, StrEnum
from typing import Any

import pytest

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import (
    _prepare_for_json,
    canonicalize,
    sign_message,
    sign_model,
    verify_model,
    verify_signature,
)
from airlock.crypto.vc import issue_credential
from airlock.schemas import (
    HandshakeIntent,
    HandshakeRequest,
    create_envelope,
)

# ── helpers ──────────────────────────────────────────────────────────────


class _SampleIntEnum(IntEnum):
    LOW = 1
    HIGH = 10


class _SampleStrEnum(StrEnum):
    ALPHA = "alpha"
    BETA = "beta"


class _SampleEnum(Enum):
    FOO = 42
    BAR = "bar"


class _UnsupportedType:
    """Arbitrary custom class that _prepare_for_json should reject."""


# ── datetime tests ───────────────────────────────────────────────────────


class TestDatetimeIso8601Format:
    """datetime values are serialized with T separator and timezone offset."""

    def test_aware_utc_datetime(self) -> None:
        dt = datetime(2025, 3, 15, 12, 30, 0, tzinfo=UTC)
        result = _prepare_for_json(dt)
        assert isinstance(result, str)
        assert "T" in result
        assert "+" in result or "Z" in result
        # Must parse back identically
        assert "2025-03-15T12:30:00" in result

    def test_naive_datetime_treated_as_utc(self) -> None:
        dt = datetime(2025, 6, 1, 8, 0, 0)
        result = _prepare_for_json(dt)
        assert isinstance(result, str)
        assert "+00:00" in result

    def test_non_utc_timezone_preserved(self) -> None:
        eastern = timezone(offset=__import__("datetime").timedelta(hours=-5))
        dt = datetime(2025, 1, 1, 17, 0, 0, tzinfo=eastern)
        result = _prepare_for_json(dt)
        assert "-05:00" in result

    def test_datetime_in_dict_canonical(self) -> None:
        dt = datetime(2025, 3, 15, 12, 30, 0, tzinfo=UTC)
        data = {"ts": dt, "x": 1}
        canonical_bytes = canonicalize(data)
        parsed = json.loads(canonical_bytes)
        assert isinstance(parsed["ts"], str)
        assert "T" in parsed["ts"]


# ── enum tests ───────────────────────────────────────────────────────────


class TestEnumSerializedAsValue:
    """IntEnum -> int, StrEnum -> str, plain Enum -> .value."""

    def test_int_enum_to_int(self) -> None:
        result = _prepare_for_json(_SampleIntEnum.HIGH)
        assert result == 10
        assert isinstance(result, int)
        # Not an IntEnum instance -- plain int
        assert type(result) is int

    def test_str_enum_to_str(self) -> None:
        result = _prepare_for_json(_SampleStrEnum.BETA)
        assert result == "beta"
        assert isinstance(result, str)

    def test_plain_enum_to_value(self) -> None:
        assert _prepare_for_json(_SampleEnum.FOO) == 42
        assert _prepare_for_json(_SampleEnum.BAR) == "bar"

    def test_enum_in_dict_canonical(self) -> None:
        data = {"tier": _SampleIntEnum.LOW, "mode": _SampleStrEnum.ALPHA}
        canonical_bytes = canonicalize(data)
        parsed = json.loads(canonical_bytes)
        assert parsed["tier"] == 1
        assert parsed["mode"] == "alpha"


# ── UUID tests ───────────────────────────────────────────────────────────


class TestUuidSerializedLowercase:
    """UUID -> lowercase hyphenated string."""

    def test_uuid_lowercase_hyphenated(self) -> None:
        u = uuid.UUID("A1B2C3D4-E5F6-7890-ABCD-EF1234567890")
        result = _prepare_for_json(u)
        assert result == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    def test_uuid_in_dict(self) -> None:
        u = uuid.uuid4()
        data = {"id": u}
        canonical_bytes = canonicalize(data)
        parsed = json.loads(canonical_bytes)
        assert parsed["id"] == str(u).lower()


# ── bytes tests ──────────────────────────────────────────────────────────


class TestBytesBase64url:
    """bytes -> base64url encoding (no padding)."""

    def test_bytes_base64url_no_padding(self) -> None:
        raw = b"\x00\x01\x02\x03\xff\xfe"
        result = _prepare_for_json(raw)
        expected = urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        assert result == expected
        # No trailing '=' padding
        assert "=" not in result

    def test_empty_bytes(self) -> None:
        result = _prepare_for_json(b"")
        assert result == ""

    def test_bytes_in_dict(self) -> None:
        data = {"payload": b"\xde\xad\xbe\xef"}
        canonical_bytes = canonicalize(data)
        parsed = json.loads(canonical_bytes)
        expected = urlsafe_b64encode(b"\xde\xad\xbe\xef").rstrip(b"=").decode("ascii")
        assert parsed["payload"] == expected


# ── recursive / nested tests ─────────────────────────────────────────────


class TestNestedDictRecursive:
    """Nested structures are properly converted at every level."""

    def test_nested_dict_with_mixed_types(self) -> None:
        dt = datetime(2025, 1, 1, tzinfo=UTC)
        u = uuid.UUID("12345678-1234-5678-1234-567812345678")
        data: dict[str, Any] = {
            "outer": {
                "inner_dt": dt,
                "inner_enum": _SampleIntEnum.HIGH,
                "inner_list": [_SampleStrEnum.ALPHA, u],
            }
        }
        result = _prepare_for_json(data)
        inner = result["outer"]
        assert isinstance(inner["inner_dt"], str)
        assert inner["inner_enum"] == 10
        assert inner["inner_list"][0] == "alpha"
        assert inner["inner_list"][1] == "12345678-1234-5678-1234-567812345678"

    def test_tuple_converted_to_list(self) -> None:
        result = _prepare_for_json((1, "two", 3))
        assert result == [1, "two", 3]

    def test_set_converted_to_sorted_list(self) -> None:
        result = _prepare_for_json({"c", "a", "b"})
        assert result == ["a", "b", "c"]

    def test_deeply_nested(self) -> None:
        data: dict[str, Any] = {"a": {"b": {"c": {"d": _SampleIntEnum.LOW}}}}
        result = _prepare_for_json(data)
        assert result["a"]["b"]["c"]["d"] == 1


# ── error handling tests ─────────────────────────────────────────────────


class TestUnknownTypeRaisesError:
    """Custom class or other unsupported type raises TypeError."""

    def test_custom_class_raises(self) -> None:
        with pytest.raises(TypeError, match="Cannot canonicalize type"):
            _prepare_for_json(_UnsupportedType())

    def test_nested_custom_class_raises(self) -> None:
        with pytest.raises(TypeError, match="Cannot canonicalize type"):
            _prepare_for_json({"key": _UnsupportedType()})

    def test_custom_class_in_list_raises(self) -> None:
        with pytest.raises(TypeError, match="Cannot canonicalize type"):
            _prepare_for_json([1, _UnsupportedType()])


# ── signature roundtrip with typed data ──────────────────────────────────


class TestSignatureRoundtripWithTypedData:
    """Sign data containing mixed Python types, then verify the signature."""

    def test_sign_and_verify_with_datetime(self) -> None:
        kp = KeyPair.from_seed(b"x" * 32)
        data = {"ts": datetime(2025, 6, 1, tzinfo=UTC), "msg": "hello"}
        sig = sign_message(data, kp.signing_key)
        # Reconstruct the same dict for verification
        assert verify_signature(data, sig, kp.verify_key)

    def test_sign_and_verify_with_enum(self) -> None:
        kp = KeyPair.from_seed(b"x" * 32)
        data = {"tier": _SampleIntEnum.HIGH, "mode": _SampleStrEnum.ALPHA}
        sig = sign_message(data, kp.signing_key)
        assert verify_signature(data, sig, kp.verify_key)

    def test_sign_and_verify_with_uuid(self) -> None:
        kp = KeyPair.from_seed(b"x" * 32)
        u = uuid.UUID("12345678-1234-5678-1234-567812345678")
        data = {"id": u, "name": "test"}
        sig = sign_message(data, kp.signing_key)
        assert verify_signature(data, sig, kp.verify_key)

    def test_sign_verify_mixed_types(self) -> None:
        kp = KeyPair.from_seed(b"x" * 32)
        data: dict[str, Any] = {
            "agent": "did:key:z6Mk123",
            "ts": datetime(2025, 3, 15, 12, 30, 0, tzinfo=UTC),
            "tier": _SampleIntEnum.HIGH,
            "mode": _SampleStrEnum.BETA,
            "request_id": uuid.UUID("abcdef12-3456-7890-abcd-ef1234567890"),
            "payload": b"\xde\xad",
            "tags": {"z", "a", "m"},
        }
        sig = sign_message(data, kp.signing_key)
        assert verify_signature(data, sig, kp.verify_key)


# ── determinism tests ────────────────────────────────────────────────────


class TestCanonicalDeterministic:
    """Same input always produces exactly the same canonical bytes."""

    def test_same_dict_same_bytes(self) -> None:
        data = {"b": 2, "a": 1, "c": [3, 2, 1]}
        assert canonicalize(data) == canonicalize(data)

    def test_key_order_irrelevant(self) -> None:
        d1 = {"z": 1, "a": 2}
        d2 = {"a": 2, "z": 1}
        assert canonicalize(d1) == canonicalize(d2)

    def test_typed_data_deterministic(self) -> None:
        dt = datetime(2025, 3, 15, 12, 30, 0, tzinfo=UTC)
        u = uuid.UUID("12345678-1234-5678-1234-567812345678")
        data: dict[str, Any] = {"ts": dt, "id": u, "tier": _SampleIntEnum.LOW}
        first = canonicalize(data)
        second = canonicalize(data)
        assert first == second

    def test_no_whitespace_in_output(self) -> None:
        data = {"a": 1, "b": "hello", "c": [1, 2]}
        result = canonicalize(data)
        text = result.decode("utf-8")
        # No spaces except inside string values
        assert ": " not in text
        assert ", " not in text


# ── sign_model compatibility ─────────────────────────────────────────────


class TestModelDumpCompatibility:
    """sign_model() produces verifiable signatures via model_dump(mode='json')."""

    def test_sign_model_verify_model_roundtrip(self) -> None:
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

    def test_sign_model_raw_dict_cross_check(self) -> None:
        """Verify that sign_model's output matches manual sign_message on the
        same model_dump(mode='json') dict -- proves the paths are equivalent."""
        kp = KeyPair.from_seed(b"y" * 32)
        vc = issue_credential(kp, "did:key:z6MkTarget", "AgentAuthorization", {}, validity_days=365)
        envelope = create_envelope(kp.did)
        intent = HandshakeIntent(
            action="verify", description="cross-check", target_did="did:key:z6MkTarget"
        )
        request = HandshakeRequest(
            envelope=envelope,
            session_id="cross-check-session",
            initiator=kp.to_agent_did(),
            intent=intent,
            credential=vc,
        )
        data = request.model_dump(mode="json")
        manual_sig = sign_message(data, kp.signing_key)
        model_sig = sign_model(request, kp.signing_key)
        # Both signatures must verify
        assert verify_signature(data, manual_sig, kp.verify_key)
        assert verify_signature(data, model_sig.value, kp.verify_key)


# ── JSON-native passthrough tests ────────────────────────────────────────


class TestJsonNativePassthrough:
    """str, int, float, bool, None pass through unchanged."""

    @pytest.mark.parametrize(
        "value",
        [42, 3.14, "hello", True, False, None],
    )
    def test_scalars_pass_through(self, value: Any) -> None:
        assert _prepare_for_json(value) is value or _prepare_for_json(value) == value

    def test_pydantic_model_converted(self) -> None:
        from pydantic import BaseModel

        class _Tiny(BaseModel):
            x: int = 1
            y: str = "hi"

        result = _prepare_for_json(_Tiny())
        assert result == {"x": 1, "y": "hi"}
