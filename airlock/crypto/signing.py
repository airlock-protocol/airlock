from __future__ import annotations

import json
import logging
import uuid as uuid_mod
from base64 import b64decode, b64encode, urlsafe_b64encode
from datetime import UTC, datetime
from enum import Enum, IntEnum, StrEnum
from typing import TYPE_CHECKING, Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel

if TYPE_CHECKING:
    from airlock.schemas.handshake import SignatureEnvelope

logger = logging.getLogger(__name__)

_SIGNATURE_FIELDS = frozenset({"signature", "airlock_signature", "trust_token"})


def _prepare_for_json(obj: Any) -> Any:
    """Recursively convert Python objects to JSON-safe, cross-language types.

    Ensures deterministic serialization that produces identical output in
    Python, Go, Rust, and JavaScript implementations (C-09 interop fix).

    Conversion rules:
    - datetime     -> ISO 8601 with timezone (naive datetimes treated as UTC)
    - IntEnum      -> int value
    - StrEnum      -> str value
    - Enum         -> raw .value
    - UUID         -> lowercase hyphenated string
    - bytes        -> base64url encoding (no padding)
    - BaseModel    -> model.model_dump(mode="json")
    - set          -> sorted list (recursed)
    - dict         -> recurse into values
    - list / tuple -> recurse into elements
    - str, int, float, bool, None -> pass through
    - other        -> TypeError
    """
    # Enums must be checked first: IntEnum is a subclass of int,
    # StrEnum is a subclass of str, so they'd pass the scalar check below.
    # Plain Enum (e.g. Enum with int/str value) is NOT a subclass of int/str.
    if isinstance(obj, IntEnum):
        return int(obj)
    if isinstance(obj, StrEnum):
        return str(obj.value)
    if isinstance(obj, Enum):
        return obj.value

    # JSON-native scalars: pass through unchanged
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj

    if isinstance(obj, datetime):
        if obj.tzinfo is None or obj.tzinfo.utcoffset(obj) is None:
            # Naive datetime: treat as UTC
            obj = obj.replace(tzinfo=UTC)
        return obj.isoformat()

    if isinstance(obj, uuid_mod.UUID):
        return str(obj)

    if isinstance(obj, bytes):
        return urlsafe_b64encode(obj).rstrip(b"=").decode("ascii")

    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")

    if isinstance(obj, set):
        return [_prepare_for_json(item) for item in sorted(obj, key=str)]

    if isinstance(obj, dict):
        return {k: _prepare_for_json(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple)):
        return [_prepare_for_json(item) for item in obj]

    raise TypeError(f"Cannot canonicalize type: {type(obj)}")


def canonicalize(data: dict[str, Any]) -> bytes:
    """Produce deterministic canonical JSON bytes.

    Uses JSON Canonicalization Scheme principles (RFC 8785):
    - Sort keys
    - No whitespace
    - UTF-8 encoding
    - ensure_ascii=False for cross-language consistency

    All values are first normalized via ``_prepare_for_json`` so that
    datetimes, enums, UUIDs, bytes, etc. are converted to language-agnostic
    representations *before* JSON encoding.  This guarantees identical
    canonical bytes across Python, Go, Rust, and JavaScript (C-09 fix).

    Strips known signature/token fields so we sign the unsigned form.
    """
    cleaned = {k: v for k, v in data.items() if k not in _SIGNATURE_FIELDS}
    prepared = _prepare_for_json(cleaned)
    return json.dumps(prepared, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sign_message(message_dict: dict[str, Any], signing_key: SigningKey) -> str:
    """Sign a message dict and return base64-encoded signature.

    1. Remove 'signature' field if present
    2. Canonicalize to deterministic JSON bytes
    3. Sign with Ed25519
    4. Return base64-encoded signature
    """
    canonical = canonicalize(message_dict)
    signature = signing_key.sign(canonical).signature
    return b64encode(signature).decode("ascii")


def verify_signature(
    message_dict: dict[str, Any], signature_b64: str, verify_key: VerifyKey
) -> bool:
    """Verify a base64-encoded Ed25519 signature against a message dict.

    Returns True if valid, False if invalid.
    """
    try:
        signature = b64decode(signature_b64)
        canonical = canonicalize(message_dict)
        verify_key.verify(canonical, signature)
        return True
    except (BadSignatureError, ValueError):
        return False


def sign_model(model: BaseModel, signing_key: SigningKey) -> SignatureEnvelope:
    """Sign a Pydantic model and return a SignatureEnvelope.

    Canonical form excludes the 'signature' field.

    NOTE: ``model.model_dump(mode="json")`` already converts datetimes,
    enums, UUIDs etc. to JSON-safe primitives via Pydantic's serializer,
    so the dict passed to ``sign_message`` → ``canonicalize`` contains only
    str/int/float/bool/None/list/dict.  ``_prepare_for_json`` will simply
    pass these through.  This path is therefore safe for cross-language
    signature verification without additional pre-conversion.
    """
    from airlock.schemas.handshake import SignatureEnvelope

    data = model.model_dump(mode="json")
    signature_b64 = sign_message(data, signing_key)
    return SignatureEnvelope(
        algorithm="Ed25519",
        value=signature_b64,
        signed_at=datetime.now(UTC),
    )


def verify_model(model: BaseModel, verify_key: VerifyKey) -> bool:
    """Verify a signed Pydantic model.

    Expects the model to have a 'signature' field of type SignatureEnvelope.
    Extracts the signature, rebuilds the canonical form, and verifies.
    """
    sig = getattr(model, "signature", None)
    if sig is None:
        return False
    data = model.model_dump(mode="json")
    data.pop("signature", None)
    return verify_signature(data, sig.value, verify_key)


def sign_attestation(attestation: BaseModel, signing_key: SigningKey) -> str:
    """Sign an AirlockAttestation and return a base64-encoded Ed25519 signature.

    Canonical form excludes ``airlock_signature`` and ``trust_token`` fields
    (handled by :func:`canonicalize`).  The returned string is suitable for
    setting on ``AirlockAttestation.airlock_signature``.
    """
    data = attestation.model_dump(mode="json")
    return sign_message(data, signing_key)


def verify_attestation(attestation: BaseModel, public_key: VerifyKey | bytes) -> bool:
    """Verify the ``airlock_signature`` on an :class:`AirlockAttestation`.

    Parameters
    ----------
    attestation:
        The attestation model instance.  Must have an ``airlock_signature``
        field containing a base64-encoded Ed25519 signature string.
    public_key:
        Either a :class:`~nacl.signing.VerifyKey` or raw 32-byte public key.

    Returns
    -------
    bool
        ``True`` if the signature is valid, ``False`` otherwise (including
        when ``airlock_signature`` is ``None``).
    """
    sig_b64 = getattr(attestation, "airlock_signature", None)
    if sig_b64 is None:
        return False
    if isinstance(public_key, bytes):
        public_key = VerifyKey(public_key)
    data = attestation.model_dump(mode="json")
    return verify_signature(data, sig_b64, public_key)
