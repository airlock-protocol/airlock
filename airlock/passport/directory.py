"""Key directory helpers for Airlock Passport (Web Bot Auth).

Builds the JWKS served at ``/.well-known/http-message-signatures-directory``
(draft-meunier-webbotauth-httpsig-directory-00) and computes RFC 7638 JWK
SHA-256 thumbprints (Ed25519 rule per RFC 8037 appendix A.3), which the
profile uses as the ``keyid`` signature parameter.

Note: the directory draft RECOMMENDS that a directory include one HTTP
message signature per key over the response (tag
``http-message-signatures-directory``) as proof of key possession. A hosted
registry like Airlock cannot produce those signatures because it never holds
agent private keys — only the agents themselves do. The hosted directory is
therefore served unsigned; see the module docstring of
``airlock.gateway.passport_routes`` for the operational consequences.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable

import base58
from nacl.signing import VerifyKey

from airlock.crypto.keys import MULTICODEC_ED25519_PUB
from airlock.schemas.passport import PassportJWK, SignatureDirectory


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def key_to_jwk(verify_key: VerifyKey, *, kid: str | None = None) -> PassportJWK:
    """Convert an Ed25519 public key to its OKP JWK representation.

    When ``kid`` is omitted it defaults to the RFC 7638 thumbprint, matching
    the directory draft examples.
    """
    jwk = PassportJWK(kty="OKP", crv="Ed25519", x=_b64url(bytes(verify_key)))
    return jwk.model_copy(update={"kid": kid or jwk_thumbprint(jwk)})


def jwk_thumbprint(jwk: PassportJWK) -> str:
    """RFC 7638 JWK SHA-256 thumbprint, base64url without padding.

    For OKP keys the required members are ``crv``, ``kty`` and ``x``,
    serialized in lexicographic order with no whitespace (RFC 8037 A.3).
    """
    canonical = json.dumps(
        {"crv": jwk.crv, "kty": jwk.kty, "x": jwk.x},
        separators=(",", ":"),
        sort_keys=True,
    )
    return _b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def jwk_to_verify_key(jwk: PassportJWK) -> VerifyKey:
    """Decode the ``x`` member of an OKP JWK into an Ed25519 VerifyKey."""
    raw = _b64url_decode(jwk.x)
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return VerifyKey(raw)


def jwk_to_did(jwk: PassportJWK) -> str:
    """Map an OKP Ed25519 JWK to its did:key form.

    Uses the same multicodec + base58btc multibase encoding as
    :class:`airlock.crypto.keys.KeyPair`, so the result round-trips through
    ``airlock.crypto.keys.resolve_public_key``.
    """
    raw = bytes(jwk_to_verify_key(jwk))
    multibase = "z" + base58.b58encode(MULTICODEC_ED25519_PUB + raw).decode("ascii")
    return f"did:key:{multibase}"


def build_directory(keys: Iterable[VerifyKey]) -> SignatureDirectory:
    """Build a JWKS directory from Ed25519 public keys."""
    return SignatureDirectory(keys=[key_to_jwk(vk) for vk in keys])
