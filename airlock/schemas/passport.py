"""Pydantic schemas for Airlock Passport (Web Bot Auth).

Wire-format models for the RFC 9421 ``web-bot-auth`` profile
(draft-meunier-webbotauth-httpsig-protocol-00) and the key directory
(draft-meunier-webbotauth-httpsig-directory-00).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class PassportJWK(BaseModel):
    """A public Ed25519 key in JWK form (RFC 8037 OKP).

    Only ``kty``, ``crv`` and ``x`` participate in the RFC 7638 thumbprint;
    ``kid``, ``use``, ``nbf`` and ``exp`` are optional standard members
    shown in the directory draft examples. The private ``d`` member is
    intentionally not modelled and must never be published.
    """

    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: str
    kid: str | None = None
    use: str | None = None
    nbf: int | None = None
    exp: int | None = None


class SignatureDirectory(BaseModel):
    """A JWKS key directory served at the well-known directory path."""

    keys: list[PassportJWK] = Field(default_factory=list)

    @classmethod
    def from_untrusted(cls, data: object) -> SignatureDirectory:
        """Parse an untrusted JWKS payload, skipping entries that are not
        valid Ed25519 OKP keys (a directory may also list RSA/EC keys)."""
        keys: list[PassportJWK] = []
        if isinstance(data, dict):
            raw_keys = data.get("keys")
            if isinstance(raw_keys, list):
                for entry in raw_keys:
                    try:
                        keys.append(PassportJWK.model_validate(entry))
                    except ValueError:
                        continue
        return cls(keys=keys)


class SignatureParams(BaseModel):
    """The ``@signature-params`` members for a web-bot-auth signature.

    ``created`` and ``expires`` are Unix timestamps (seconds). ``keyid`` is
    the base64url RFC 7638 JWK SHA-256 thumbprint of the signing key.
    """

    created: int
    expires: int
    keyid: str
    alg: str | None = "ed25519"
    nonce: str | None = None
    tag: str = "web-bot-auth"


class PassportHeaders(BaseModel):
    """The three HTTP headers that carry a web-bot-auth signature."""

    signature_agent: str
    signature_input: str
    signature: str

    def as_headers(self) -> dict[str, str]:
        """Return the headers ready to attach to an outbound request."""
        return {
            "Signature-Agent": self.signature_agent,
            "Signature-Input": self.signature_input,
            "Signature": self.signature,
        }


class PassportVerification(BaseModel):
    """Outcome of verifying an inbound web-bot-auth signed request.

    ``directory_url`` is the Signature-Agent value as sent by the client
    (the directory origin, not the joined well-known URL). ``agent_did``
    is the did:key form of the Ed25519 key that produced the signature.
    """

    valid: bool
    keyid: str | None = None
    agent_did: str | None = None
    directory_url: str | None = None
    created: datetime | None = None
    expires: datetime | None = None
    failure_reason: str | None = None


class ReputationSummary(BaseModel):
    """Compact reputation view embedded in a passport status response."""

    found: bool
    score: float
    interaction_count: int | None = None


class PassportStatus(BaseModel):
    """Response body for ``GET /passport/{did}/status``."""

    did: str
    registered: bool
    revoked: bool
    reputation: ReputationSummary
    key_thumbprint: str | None = None


class PassportRegistrationResult(BaseModel):
    """Outcome of self-registering a passport key with a registry."""

    registered: bool
    did: str
    registry_url: str
    directory_url: str


class WallErrorBody(BaseModel):
    """Structured JSON error emitted by the wall middleware."""

    error: str
    detail: str
    status_code: int
