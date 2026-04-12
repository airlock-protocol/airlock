from __future__ import annotations

"""OIDC discovery metadata and JWKS endpoint data for Airlock OAuth."""

import logging
from base64 import urlsafe_b64encode
from typing import Any

from nacl.signing import VerifyKey

logger = logging.getLogger(__name__)


def build_discovery_metadata(
    *,
    base_url: str,
    issuer_did: str,
) -> dict[str, Any]:
    """Build the OIDC discovery metadata document.

    Parameters
    ----------
    base_url:
        The gateway's public base URL (e.g., ``https://api.airlock.ing``).
    issuer_did:
        The gateway's DID (``did:key:z6Mk...``).

    Returns
    -------
    Dict conforming to OpenID Connect Discovery 1.0.
    """
    base = base_url.rstrip("/")

    return {
        "issuer": issuer_did,
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "introspection_endpoint": f"{base}/oauth/introspect",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "response_types_supported": [],
        "grant_types_supported": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": [
            "verify:read",
            "trust:write",
            "agent:manage",
            "delegation:exchange",
            "compliance:read",
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "service_documentation": "https://github.com/airlock-protocol/airlock",
    }


def build_jwks(
    *,
    verify_key: VerifyKey,
    kid: str | None = None,
) -> dict[str, Any]:
    """Build the JWKS (JSON Web Key Set) document.

    Parameters
    ----------
    verify_key:
        The gateway's Ed25519 public key.
    kid:
        Key ID. Defaults to a truncated base64url encoding of the key.

    Returns
    -------
    Dict containing the ``keys`` array with the Ed25519 public JWK.
    """
    raw_bytes = bytes(verify_key)

    # Base64url encode without padding
    x = urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")

    if kid is None:
        kid = x[:16]

    jwk: dict[str, str] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "kid": kid,
        "x": x,
    }

    return {"keys": [jwk]}
