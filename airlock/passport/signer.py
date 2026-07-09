"""Request signer for the RFC 9421 ``web-bot-auth`` profile.

Produces the ``Signature-Agent``, ``Signature-Input`` and ``Signature``
headers per draft-meunier-webbotauth-httpsig-protocol-00, using the legacy
string form of ``Signature-Agent`` for compatibility with deployed
verifiers (Cloudflare rejects the newer Dictionary form as of mid-2026).

Covered components are exactly ``@authority`` and ``signature-agent`` —
Cloudflare's documented minimum, and sufficient to bind the signature to
the destination host and the key directory.
"""

from __future__ import annotations

import base64
import secrets
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from airlock.crypto.keys import KeyPair
from airlock.passport.base import (
    WEB_BOT_AUTH_TAG,
    ParsedComponent,
    build_signature_base,
    canonicalize_authority,
    serialize_sf_string,
    serialize_signature_params,
)
from airlock.passport.directory import jwk_thumbprint, key_to_jwk
from airlock.schemas.passport import PassportHeaders, SignatureParams

_LABEL_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789*_-.")


class PassportSigner:
    """Sign outbound requests with an Airlock passport (Ed25519 key).

    Args:
        keypair: The agent's Ed25519 key pair.
        directory_url: Base URL of the key directory that publishes this
            key (sent as the ``Signature-Agent`` header). Verifiers fetch
            ``/.well-known/http-message-signatures-directory`` under it.
        validity_seconds: Signature lifetime (``expires - created``).
            Cloudflare recommends short windows; default one minute.
        include_alg: Emit ``alg="ed25519"`` (optional per RFC 9421 but
            present in the draft and Cloudflare examples).
        include_nonce: Emit a random ``nonce`` (64 bytes, base64 — the
            draft recommends 64-byte nonces).
        label: Signature label used in Signature-Input / Signature.
        time_source: Clock returning Unix seconds (injectable for tests).
    """

    def __init__(
        self,
        keypair: KeyPair,
        directory_url: str,
        *,
        validity_seconds: int = 60,
        include_alg: bool = True,
        include_nonce: bool = True,
        label: str = "sig1",
        time_source: Callable[[], float] = time.time,
    ) -> None:
        if validity_seconds < 1:
            raise ValueError("validity_seconds must be >= 1")
        if not label or label[0] not in "abcdefghijklmnopqrstuvwxyz*":
            raise ValueError(f"invalid signature label: {label!r}")
        if any(ch not in _LABEL_CHARS for ch in label):
            raise ValueError(f"invalid signature label: {label!r}")
        scheme = urlsplit(directory_url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError("directory_url must be an http(s) URL")
        self._keypair = keypair
        self._directory_url = directory_url.rstrip("/")
        self._validity_seconds = validity_seconds
        self._include_alg = include_alg
        self._include_nonce = include_nonce
        self._label = label
        self._time_source = time_source
        self._keyid = jwk_thumbprint(key_to_jwk(keypair.verify_key))

    @property
    def keyid(self) -> str:
        """The RFC 7638 JWK thumbprint used as the ``keyid`` parameter."""
        return self._keyid

    @property
    def directory_url(self) -> str:
        return self._directory_url

    def sign_request(
        self,
        method: str,
        url: str,
        *,
        created: int | None = None,
        nonce: str | None = None,
    ) -> PassportHeaders:
        """Produce the three signature headers for one request.

        ``method`` is accepted for API stability but the profile covers
        only ``@authority`` and ``signature-agent``, so it does not enter
        the signature base. ``created``/``nonce`` overrides exist for
        deterministic tests.
        """
        del method  # not covered by the web-bot-auth minimal profile
        created_at = int(self._time_source()) if created is None else created
        expires_at = created_at + self._validity_seconds
        if nonce is None and self._include_nonce:
            nonce = base64.b64encode(secrets.token_bytes(64)).decode("ascii")

        params = SignatureParams(
            created=created_at,
            expires=expires_at,
            keyid=self._keyid,
            alg="ed25519" if self._include_alg else None,
            nonce=nonce,
            tag=WEB_BOT_AUTH_TAG,
        )
        covered = [
            ParsedComponent(name="@authority"),
            ParsedComponent(name="signature-agent"),
        ]
        params_value = serialize_signature_params(covered, params)

        agent_value = serialize_sf_string(self._directory_url)
        base = build_signature_base(
            [
                ('"@authority"', canonicalize_authority(url)),
                ('"signature-agent"', agent_value),
            ],
            params_value,
        )
        signature = self._keypair.signing_key.sign(base.encode("utf-8")).signature
        encoded = base64.b64encode(signature).decode("ascii")
        return PassportHeaders(
            signature_agent=agent_value,
            signature_input=f"{self._label}={params_value}",
            signature=f"{self._label}=:{encoded}:",
        )
