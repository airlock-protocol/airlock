"""Key directory helpers for Airlock Passport (Web Bot Auth).

Builds the JWKS served at ``/.well-known/http-message-signatures-directory``
(draft-meunier-webbotauth-httpsig-directory-00) and computes RFC 7638 JWK
SHA-256 thumbprints (Ed25519 rule per RFC 8037 appendix A.3), which the
profile uses as the ``keyid`` signature parameter.

Also hosts the tenant-label primitives for per-tenant directory
authorities (draft-singh-webbotauth-hosted-directories-00 section 4,
remedy 1): each tenant is served under ``<label>.<tenant domain base>``
so verifiers see one principal per tenant instead of one per registry.

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
import re
from collections.abc import Iterable

import base58
from nacl.signing import VerifyKey

from airlock.crypto.keys import MULTICODEC_ED25519_PUB
from airlock.schemas.passport import PassportJWK, SignatureDirectory

# DNS-label-shaped tenant labels: lowercase alphanumerics and hyphens,
# no leading/trailing hyphen, at most 63 characters.
PASSPORT_LABEL_MAX_LENGTH = 63
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_SLUG_STRIP_RE = re.compile(r"[^a-z0-9]+")


def b64url_encode(data: bytes) -> str:
    """base64url without padding (the JWK / thumbprint encoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url (tolerates padded input)."""
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def key_to_jwk(verify_key: VerifyKey, *, kid: str | None = None) -> PassportJWK:
    """Convert an Ed25519 public key to its OKP JWK representation.

    When ``kid`` is omitted it defaults to the RFC 7638 thumbprint, matching
    the directory draft examples.
    """
    jwk = PassportJWK(kty="OKP", crv="Ed25519", x=b64url_encode(bytes(verify_key)))
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
    return b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def jwk_to_verify_key(jwk: PassportJWK) -> VerifyKey:
    """Decode the ``x`` member of an OKP JWK into an Ed25519 VerifyKey."""
    raw = b64url_decode(jwk.x)
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


# ---------------------------------------------------------------------------
# Per-tenant directory authorities
# ---------------------------------------------------------------------------


def is_valid_passport_label(label: str) -> bool:
    """True when ``label`` is a valid tenant label (DNS-label-shaped)."""
    return len(label) <= PASSPORT_LABEL_MAX_LENGTH and bool(_LABEL_RE.match(label))


def slugify_passport_label(name: str) -> str:
    """Derive a tenant label from an agent display name.

    Lowercases, collapses every non-alphanumeric run to a single hyphen,
    trims hyphens, and truncates to the DNS label limit. Falls back to
    ``"agent"`` when nothing usable remains.
    """
    slug = _SLUG_STRIP_RE.sub("-", name.lower()).strip("-")
    slug = slug[:PASSPORT_LABEL_MAX_LENGTH].rstrip("-")
    return slug or "agent"


def tenant_directory_url(base: str, label: str) -> str:
    """The per-tenant directory authority for ``label`` under ``base``.

    E.g. ``tenant_directory_url("agents.airlock.ing", "alice")`` is
    ``https://alice.agents.airlock.ing`` — the URL a tenant should use as
    its ``Signature-Agent`` so verifiers see it as a distinct principal.
    """
    if not is_valid_passport_label(label):
        raise ValueError(f"invalid tenant label: {label!r}")
    cleaned = base.strip().strip(".").lower()
    if not cleaned:
        raise ValueError("tenant domain base must not be empty")
    return f"https://{label}.{cleaned}"
