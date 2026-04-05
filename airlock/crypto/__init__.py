from __future__ import annotations

from airlock.crypto.keys import KeyPair, resolve_public_key
from airlock.crypto.signing import (
    canonicalize,
    sign_attestation,
    sign_message,
    sign_model,
    verify_attestation,
    verify_model,
    verify_signature,
)
from airlock.crypto.vc import issue_credential, validate_credential

__all__ = [
    "KeyPair",
    "canonicalize",
    "issue_credential",
    "resolve_public_key",
    "sign_attestation",
    "sign_message",
    "sign_model",
    "validate_credential",
    "verify_attestation",
    "verify_model",
    "verify_signature",
]
