"""Airlock Passport — Web Bot Auth (RFC 9421) agent identity.

One-command agent identity that gets AI agents through bot walls that
verify the IETF Web Bot Auth profile (Cloudflare, AWS WAF, Vercel and
Akamai as of mid-2026).

Implemented against draft-meunier-webbotauth-httpsig-protocol-00 and
draft-meunier-webbotauth-httpsig-directory-00 (see module docstrings).

This package must never import from ``airlock.gateway`` — the gateway
depends on core, not the reverse.
"""

from __future__ import annotations

from airlock.passport.assertions import (
    WELL_KNOWN_ASSERTIONS_PATH,
    normalize_directory_origin,
    sign_assertion,
    verify_assertion,
)
from airlock.passport.base import (
    DIRECTORY_MEDIA_TYPE,
    WEB_BOT_AUTH_TAG,
    WELL_KNOWN_DIRECTORY_PATH,
)
from airlock.passport.directory import (
    build_directory,
    is_valid_passport_label,
    jwk_thumbprint,
    key_to_jwk,
    slugify_passport_label,
    tenant_directory_url,
)
from airlock.passport.httpx_auth import PassportAuth
from airlock.passport.registration import (
    DEFAULT_KEY_PATH,
    directory_url_for_registry,
    fetch_passport_status,
    load_or_create_passport_key,
    register_passport,
    upload_assertion,
)
from airlock.passport.replay import InMemoryNonceCache, NonceCache, RedisNonceCache
from airlock.passport.signer import PassportSigner
from airlock.passport.verifier import PassportVerifier

__all__ = [
    "DEFAULT_KEY_PATH",
    "DIRECTORY_MEDIA_TYPE",
    "InMemoryNonceCache",
    "NonceCache",
    "PassportAuth",
    "PassportSigner",
    "PassportVerifier",
    "RedisNonceCache",
    "WEB_BOT_AUTH_TAG",
    "WELL_KNOWN_ASSERTIONS_PATH",
    "WELL_KNOWN_DIRECTORY_PATH",
    "build_directory",
    "directory_url_for_registry",
    "fetch_passport_status",
    "is_valid_passport_label",
    "jwk_thumbprint",
    "key_to_jwk",
    "load_or_create_passport_key",
    "normalize_directory_origin",
    "register_passport",
    "sign_assertion",
    "slugify_passport_label",
    "tenant_directory_url",
    "upload_assertion",
    "verify_assertion",
]
