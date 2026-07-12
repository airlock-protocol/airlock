"""EXPERIMENTAL delegation passports for ephemeral sub-agents.

Airlock extension — not part of any published Web Bot Auth draft; the
construction is offered as input to the delegation appendix discussion
around draft-meunier-webbotauth-httpsig-directory.

The "visitor pass" model: a directory-registered parent agent mints a
short-lived child keypair together with a parent-signed delegation
statement. The registry never sees the child. The child signs requests
with the NORMAL web-bot-auth profile — its own key, the parent's
directory URL as ``Signature-Agent`` — and additionally sends::

    Airlock-Delegation: <b64url(canonical payload JSON)>.<b64url(sig)>

A verifier with ``allow_delegation=True`` that finds the request keyid
absent from the directory validates the chain instead: the statement's
signature under the PARENT key (which must be present in the directory
and pass every normal check, including a possession assertion when the
verifier requires one), the child binding, and the delegation window.
Because the parent is re-resolved against the live directory on every
verification, revoking or removing the parent cascades to all of its
outstanding children with no extra bookkeeping.

Deviation from the payload sketched in the hosted-directories work: the
statement carries ``child_jwk`` (the child's public OKP key) alongside
the ``child`` thumbprint. A thumbprint alone is a hash, so the verifier
could never validate the child's request signature without the key
itself; placing it inside the signed payload keeps the header
self-contained and the key material covered by the parent's signature.
"""

from __future__ import annotations

import time
from collections.abc import Generator

import httpx

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import canonicalize
from airlock.passport.directory import b64url_decode, b64url_encode, jwk_thumbprint, key_to_jwk
from airlock.passport.signer import PassportSigner
from airlock.schemas.passport import DelegationPayload, DelegationStatement, PassportJWK

DELEGATION_HEADER = "Airlock-Delegation"

DEFAULT_DELEGATION_VALIDITY_SECONDS = 900  # 15 minutes — a visitor pass


def delegation_signing_bytes(payload: DelegationPayload) -> bytes:
    """Canonical JSON bytes of a delegation payload (the signed message)."""
    return canonicalize(payload.model_dump(mode="json"))


def mint_child(
    parent_keypair: KeyPair,
    *,
    scope: str | None = None,
    validity_seconds: int = DEFAULT_DELEGATION_VALIDITY_SECONDS,
    now: int | None = None,
) -> tuple[KeyPair, DelegationStatement]:
    """Mint a fresh child keypair plus its parent-signed delegation.

    The child key is generated locally and never leaves the caller;
    ``scope`` is an opaque application string echoed to verifiers. ``now``
    overrides the clock for deterministic tests.
    """
    if validity_seconds < 1:
        raise ValueError("validity_seconds must be >= 1")
    issued_at = int(time.time()) if now is None else now
    child = KeyPair.generate()
    child_jwk = PassportJWK(
        kty="OKP", crv="Ed25519", x=key_to_jwk(child.verify_key).x
    )  # minimal members only — kid et al. stay out of the signed payload
    payload = DelegationPayload(
        parent=jwk_thumbprint(key_to_jwk(parent_keypair.verify_key)),
        child=jwk_thumbprint(child_jwk),
        child_jwk=child_jwk,
        scope=scope,
        nbf=issued_at,
        exp=issued_at + validity_seconds,
    )
    signature = parent_keypair.signing_key.sign(delegation_signing_bytes(payload)).signature
    return child, DelegationStatement(payload=payload, sig=b64url_encode(signature))


def encode_delegation_header(statement: DelegationStatement) -> str:
    """Serialize a delegation statement into the header wire format."""
    return (
        b64url_encode(delegation_signing_bytes(statement.payload)) + "." + statement.sig
    )


def decode_delegation_header(value: str) -> tuple[bytes, DelegationPayload, bytes]:
    """Parse an ``Airlock-Delegation`` header value.

    Returns ``(payload_bytes, payload, signature)`` where
    ``payload_bytes`` are the exact received bytes the parent's signature
    must cover. Raises ``ValueError`` for any malformed input.
    """
    parts = value.strip().split(".")
    if len(parts) != 2:
        raise ValueError("delegation header must be '<payload>.<signature>'")
    payload_bytes = b64url_decode(parts[0])
    signature = b64url_decode(parts[1])
    payload = DelegationPayload.model_validate_json(payload_bytes)
    return payload_bytes, payload, signature


class DelegatedPassportAuth(httpx.Auth):
    """httpx auth hook for a delegated child credential (EXPERIMENTAL).

    Signs every outbound request with the child key under the normal
    web-bot-auth profile — ``directory_url`` must be the PARENT's
    directory — and attaches the ``Airlock-Delegation`` header. Keep the
    signature validity within the delegation window: verifiers reject
    request signatures that outlive the statement.
    """

    requires_request_body = False
    requires_response_body = False

    def __init__(
        self,
        child_keypair: KeyPair,
        statement: DelegationStatement,
        directory_url: str,
        *,
        validity_seconds: int = 60,
    ) -> None:
        self._signer = PassportSigner(
            child_keypair, directory_url, validity_seconds=validity_seconds
        )
        self._header_value = encode_delegation_header(statement)

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        headers = self._signer.sign_request(request.method, str(request.url))
        request.headers.update(headers.as_headers())
        request.headers[DELEGATION_HEADER] = self._header_value
        yield request
