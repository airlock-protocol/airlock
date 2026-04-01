from __future__ import annotations

import json
from base64 import b64decode, b64encode
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel

if TYPE_CHECKING:
    from airlock.schemas.handshake import SignatureEnvelope


def canonicalize(data: dict) -> bytes:
    """Produce deterministic canonical JSON bytes.

    Uses JSON Canonicalization Scheme principles (RFC 8785):
    - Sort keys
    - No whitespace
    - UTF-8 encoding
    Strips 'signature' key if present (we sign the unsigned form).
    """
    cleaned = {k: v for k, v in data.items() if k != "signature"}
    return json.dumps(cleaned, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_message(message_dict: dict, signing_key: SigningKey) -> str:
    """Sign a message dict and return base64-encoded signature.

    1. Remove 'signature' field if present
    2. Canonicalize to deterministic JSON bytes
    3. Sign with Ed25519
    4. Return base64-encoded signature
    """
    canonical = canonicalize(message_dict)
    signature = signing_key.sign(canonical).signature
    return b64encode(signature).decode("ascii")


def verify_signature(message_dict: dict, signature_b64: str, verify_key: VerifyKey) -> bool:
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
