"""Tenant-signed directory assertions — proof of key possession.

The directory draft (draft-meunier-webbotauth-httpsig-directory-00)
RECOMMENDS that a directory prove possession of its keys by signing
directory responses with them. A hosted directory cannot (and must not
be able to) do that: the host never holds tenant private keys. This
module implements the substitute proposed in
draft-singh-webbotauth-hosted-directories-00 section 5, option 2: the
tenant periodically signs, with its own key, a detached assertion
binding its key thumbprint to the directory base origin and a validity
window. The host publishes the assertions alongside the directory at
``/.well-known/http-message-signatures-directory-assertions`` and a
verifier can check possession without the host ever touching a key.

Payload wire format (canonical JSON per the repo-wide RFC 8785 helper)::

    {"typ": "webbotauth-directory-assertion/v1",
     "sub": "<RFC 7638 JWK thumbprint, base64url>",
     "dir": "<directory base origin, lowercase, no trailing slash>",
     "nbf": <unix seconds>, "exp": <unix seconds>,
     "nonce": "<base64url, 16 random bytes>"}

The signature is Ed25519 over the canonical JSON bytes, base64url
without padding. :func:`verify_assertion` returns a result object and
never raises.
"""

from __future__ import annotations

import secrets
import time
from urllib.parse import urlsplit

from nacl.exceptions import BadSignatureError

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import canonicalize
from airlock.passport.base import canonicalize_authority
from airlock.passport.directory import (
    b64url_decode,
    b64url_encode,
    jwk_thumbprint,
    jwk_to_verify_key,
    key_to_jwk,
)
from airlock.schemas.passport import (
    AssertionVerification,
    DirectoryAssertionPayload,
    PassportJWK,
    SignedAssertion,
)

WELL_KNOWN_ASSERTIONS_PATH = "/.well-known/http-message-signatures-directory-assertions"

DEFAULT_ASSERTION_VALIDITY_SECONDS = 604_800  # one week

_ASSERTION_NONCE_BYTES = 16


def normalize_directory_origin(url: str) -> str:
    """Normalize a directory URL to its base origin.

    Lowercase scheme and host, default port elided, no path, query,
    fragment or trailing slash — the ``dir`` binding format. Raises
    ``ValueError`` for non-http(s) or host-less URLs.
    """
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"directory URL must be http(s): {url!r}")
    return f"{scheme}://{canonicalize_authority(url)}"


def assertion_signing_bytes(payload: DirectoryAssertionPayload) -> bytes:
    """Canonical JSON bytes of an assertion payload (the signed message)."""
    return canonicalize(payload.model_dump(mode="json"))


def sign_assertion(
    keypair: KeyPair,
    directory_url: str,
    validity_seconds: int = DEFAULT_ASSERTION_VALIDITY_SECONDS,
    *,
    now: int | None = None,
) -> SignedAssertion:
    """Sign a fresh directory assertion for ``directory_url``.

    ``now`` overrides the clock for deterministic tests. The directory
    URL is normalized to its base origin before signing, so any URL
    under the directory host produces the same binding.
    """
    if validity_seconds < 1:
        raise ValueError("validity_seconds must be >= 1")
    issued_at = int(time.time()) if now is None else now
    payload = DirectoryAssertionPayload(
        sub=jwk_thumbprint(key_to_jwk(keypair.verify_key)),
        dir=normalize_directory_origin(directory_url),
        nbf=issued_at,
        exp=issued_at + validity_seconds,
        nonce=b64url_encode(secrets.token_bytes(_ASSERTION_NONCE_BYTES)),
    )
    signature = keypair.signing_key.sign(assertion_signing_bytes(payload)).signature
    return SignedAssertion(payload=payload, sig=b64url_encode(signature))


def verify_assertion(
    jwk: PassportJWK,
    assertion: SignedAssertion,
    expected_directory: str | None,
    now: float | None = None,
) -> AssertionVerification:
    """Verify one directory assertion against a public key.

    Checks, in order: the assertion subject matches the JWK's RFC 7638
    thumbprint; the bound directory matches ``expected_directory``
    (compared as normalized origins; pass ``None`` to skip, e.g. when a
    hosted registry validates an upload for a directory it serves under
    several authorities); the validity window contains ``now``; and the
    Ed25519 signature verifies under the JWK itself.

    Returns an :class:`AssertionVerification` — never raises.
    """
    payload = assertion.payload
    checked_at = time.time() if now is None else now

    def fail(reason: str) -> AssertionVerification:
        return AssertionVerification(
            valid=False,
            thumbprint=payload.sub,
            directory=payload.dir,
            failure_reason=reason,
        )

    try:
        if payload.sub != jwk_thumbprint(jwk):
            return fail("assertion subject does not match the key thumbprint")
        if expected_directory is not None:
            try:
                matches = normalize_directory_origin(
                    payload.dir
                ) == normalize_directory_origin(expected_directory)
            except ValueError:
                matches = False
            if not matches:
                return fail("assertion is bound to a different directory")
        if payload.exp <= payload.nbf:
            return fail("invalid assertion window (exp <= nbf)")
        if checked_at < payload.nbf:
            return fail("assertion is not yet valid")
        if checked_at > payload.exp:
            return fail("assertion has expired")
        verify_key = jwk_to_verify_key(jwk)
        verify_key.verify(assertion_signing_bytes(payload), b64url_decode(assertion.sig))
    except (BadSignatureError, ValueError):
        return fail("assertion signature verification failed")
    except Exception as exc:  # defensive: malformed input must not raise
        return fail(f"assertion verification error: {exc}")

    return AssertionVerification(
        valid=True,
        thumbprint=payload.sub,
        directory=payload.dir,
        failure_reason=None,
    )
