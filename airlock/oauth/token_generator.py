from __future__ import annotations

"""Generate EdDSA-signed JWT access tokens with Airlock trust claims."""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from nacl.signing import SigningKey

logger = logging.getLogger(__name__)


def _ed25519_private_key_pem(signing_key: SigningKey) -> bytes:
    """Convert a PyNaCl SigningKey to PKCS8 PEM for PyJWT EdDSA signing.

    PyJWT requires PEM-encoded keys for the EdDSA algorithm.  We build
    the DER/PKCS8 envelope manually to avoid pulling in cryptography lib.
    """
    # Ed25519 PKCS8 prefix (RFC 8410)
    pkcs8_prefix = bytes([
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ])
    import base64 as _b64

    der = pkcs8_prefix + bytes(signing_key)
    b64 = _b64.encodebytes(der).decode("ascii").strip()
    return (
        "-----BEGIN PRIVATE KEY-----\n"
        + b64
        + "\n-----END PRIVATE KEY-----\n"
    ).encode("ascii")


def _ed25519_public_key_pem(verify_key_bytes: bytes) -> bytes:
    """Convert raw Ed25519 public key bytes to SubjectPublicKeyInfo PEM."""
    # Ed25519 SubjectPublicKeyInfo prefix (RFC 8410)
    spki_prefix = bytes([
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
        0x70, 0x03, 0x21, 0x00,
    ])
    import base64 as _b64

    der = spki_prefix + verify_key_bytes
    b64 = _b64.encodebytes(der).decode("ascii").strip()
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + b64
        + "\n-----END PUBLIC KEY-----\n"
    ).encode("ascii")


def generate_access_token(
    *,
    signing_key: SigningKey,
    issuer_did: str,
    subject_did: str,
    client_id: str,
    scope: str = "",
    trust_score: float = 0.0,
    trust_tier: int = 0,
    ttl_seconds: int = 3600,
    audience: str = "airlock-gateway",
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, str, datetime]:
    """Generate an EdDSA-signed JWT access token.

    Returns
    -------
    tuple of (encoded_token, jti, expires_at)
    """
    now = datetime.now(UTC)
    exp = now + timedelta(seconds=ttl_seconds)
    jti = str(uuid.uuid4())

    payload: dict[str, Any] = {
        "iss": issuer_did,
        "sub": subject_did,
        "aud": audience,
        "iat": now,
        "exp": exp,
        "jti": jti,
        "client_id": client_id,
        "scope": scope,
        "airlock:trust_score": trust_score,
        "airlock:trust_tier": trust_tier,
    }

    if extra_claims:
        payload.update(extra_claims)

    pem = _ed25519_private_key_pem(signing_key)
    encoded: str = jwt.encode(payload, pem, algorithm="EdDSA")

    logger.debug(
        "Generated OAuth access token: jti=%s sub=%s scope=%s ttl=%d",
        jti,
        subject_did,
        scope,
        ttl_seconds,
    )

    return encoded, jti, exp
