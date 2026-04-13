from __future__ import annotations

"""OIDC Discovery and JWKS endpoints for the Airlock OAuth server."""

import base64
from typing import Any

from nacl.signing import VerifyKey


def build_openid_configuration(base_url: str, issuer_did: str) -> dict[str, Any]:
    """Build an OpenID Connect discovery document.

    Advertises the Airlock OAuth endpoints and supported features.
    """
    base = base_url.rstrip("/")
    return {
        "issuer": issuer_did,
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "introspection_endpoint": f"{base}/oauth/introspect",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "jwks_uri": f"{base}/.well-known/jwks.json",
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
        "response_types_supported": [],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
    }


def build_jwks(verify_key: VerifyKey, kid: str) -> dict[str, Any]:
    """Export the gateway's Ed25519 public key as a JWK Set (OKP key type).

    Parameters
    ----------
    verify_key:
        The PyNaCl Ed25519 verification key.
    kid:
        Key ID — typically the gateway DID.

    Returns
    -------
    dict
        A JWKS document with a single OKP key.
    """
    raw_bytes = bytes(verify_key)
    # Base64url encode without padding per RFC 7517
    x_b64 = base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "kid": kid,
                "x": x_b64,
            }
        ]
    }
