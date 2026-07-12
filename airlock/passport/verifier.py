"""Verifier for the RFC 9421 ``web-bot-auth`` profile.

Implements the wall side of draft-meunier-webbotauth-httpsig-protocol-00
with key discovery per draft-meunier-webbotauth-httpsig-directory-00:
parse the signature headers, validate the time window, fetch the JWKS from
the ``Signature-Agent`` directory (async httpx with a TTL cache), match the
``keyid`` thumbprint, and verify the Ed25519 signature.

:meth:`PassportVerifier.verify` always returns a
:class:`~airlock.schemas.passport.PassportVerification` — invalid input of
any kind (including malformed headers) produces ``valid=False`` with a
``failure_reason``; it never raises.

Accepts both Signature-Agent forms: the legacy string form that Cloudflare
verifies today and the Dictionary form from the current draft.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from nacl.exceptions import BadSignatureError

from airlock.passport.assertions import WELL_KNOWN_ASSERTIONS_PATH, verify_assertion
from airlock.passport.base import (
    WEB_BOT_AUTH_TAG,
    WELL_KNOWN_DIRECTORY_PATH,
    SfValue,
    SignatureAgentValue,
    SignatureInputMember,
    parse_signature_agent,
    parse_signature_header,
    parse_signature_input,
    reconstruct_signature_base,
)
from airlock.passport.delegation import DELEGATION_HEADER, decode_delegation_header
from airlock.passport.directory import jwk_thumbprint, jwk_to_did, jwk_to_verify_key
from airlock.passport.replay import NonceCache
from airlock.schemas.passport import (
    AssertionsDocument,
    DelegationPayload,
    PassportJWK,
    PassportVerification,
    SignatureDirectory,
)

logger = logging.getLogger(__name__)

_MAX_CANDIDATE_SIGNATURES = 3


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Lowercase header names; join duplicates with ", " (RFC 9421 2.1)."""
    normalized: dict[str, str] = {}
    items = headers.multi_items() if isinstance(headers, httpx.Headers) else headers.items()
    for name, value in items:
        key = name.lower()
        if key in normalized:
            normalized[key] = f"{normalized[key]}, {value}"
        else:
            normalized[key] = value
    return normalized


class PassportVerifier:
    """Verify inbound web-bot-auth signed requests.

    Args:
        clock_skew_seconds: Tolerance applied to ``created``/``expires``.
        max_validity_window_seconds: Reject signatures whose
            ``expires - created`` exceeds this (the draft recommends
            windows of no more than 24 hours).
        cache_ttl_seconds: TTL for fetched key directories.
        require_https: Reject ``Signature-Agent`` URLs that are not HTTPS
            (Cloudflare's behavior). Disable for local development only.
        require_assertion: After the keyid matches a directory key, also
            require a valid tenant-signed possession assertion for it from
            the directory's well-known assertions document
            (draft-singh-webbotauth-hosted-directories-00 section 5).
        replay_cache: When set, record each verified signature's
            ``(keyid, nonce)`` for the rest of its validity window and
            reject a second sighting with "nonce replay detected".
        require_nonce: Reject signatures that carry no ``nonce`` parameter
            (it is optional in the profile; without one, replays inside
            the validity window are undetectable).
        allow_delegation: EXPERIMENTAL. When the signing keyid is not in
            the directory, accept an ``Airlock-Delegation`` header whose
            statement is signed by a directory key (see
            :mod:`airlock.passport.delegation`). Off by default.
        http_timeout: Timeout for directory fetches.
        transport: Optional httpx transport (tests inject a MockTransport).
        time_source: Clock returning Unix seconds (injectable for tests).
    """

    def __init__(
        self,
        *,
        clock_skew_seconds: float = 10.0,
        max_validity_window_seconds: int = 86_400,
        cache_ttl_seconds: float = 300.0,
        require_https: bool = True,
        require_assertion: bool = False,
        replay_cache: NonceCache | None = None,
        require_nonce: bool = False,
        allow_delegation: bool = False,
        http_timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        time_source: Callable[[], float] = time.time,
    ) -> None:
        self._clock_skew = clock_skew_seconds
        self._max_window = max_validity_window_seconds
        self._cache_ttl = cache_ttl_seconds
        self._require_https = require_https
        self._require_assertion = require_assertion
        self._replay_cache = replay_cache
        self._require_nonce = require_nonce
        self._allow_delegation = allow_delegation
        self._http_timeout = http_timeout
        self._transport = transport
        self._time_source = time_source
        self._client: httpx.AsyncClient | None = None
        self._cache: dict[str, tuple[float, SignatureDirectory]] = {}
        self._assertions_cache: dict[str, tuple[float, AssertionsDocument]] = {}
        self._cache_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def verify(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
    ) -> PassportVerification:
        """Verify one request. Returns a result — never raises."""
        try:
            return await self._verify(method=method, url=url, headers=headers)
        except Exception as exc:  # defensive: malformed input must not raise
            logger.debug("Passport verification error: %s", exc)
            return _failure(f"verification error: {exc}")

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _verify(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
    ) -> PassportVerification:
        normalized = _normalize_headers(headers)

        raw_input = normalized.get("signature-input")
        raw_signature = normalized.get("signature")
        raw_agent = normalized.get("signature-agent")
        if raw_input is None or raw_signature is None:
            return _failure("missing Signature-Input or Signature header")
        if raw_agent is None:
            return _failure("missing Signature-Agent header")

        try:
            members = parse_signature_input(raw_input)
            signatures = parse_signature_header(raw_signature)
            agent = parse_signature_agent(raw_agent)
        except ValueError as exc:
            return _failure(f"malformed signature headers: {exc}")

        candidates = [m for m in members if _member_tag(m) == WEB_BOT_AUTH_TAG]
        if not candidates:
            return _failure("no signature with tag 'web-bot-auth'")

        last: PassportVerification | None = None
        for member in candidates[:_MAX_CANDIDATE_SIGNATURES]:
            last = await self._verify_member(
                member,
                signatures.get(member.label),
                agent,
                method=method,
                url=url,
                headers=normalized,
            )
            if last.valid:
                return last
        assert last is not None  # candidates is non-empty
        return last

    async def _verify_member(
        self,
        member: SignatureInputMember,
        signature: bytes | None,
        agent: SignatureAgentValue,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
    ) -> PassportVerification:
        if signature is None:
            return _failure(f"no Signature member for label {member.label!r}")

        # --- required parameters -------------------------------------
        try:
            created = _require_int(member, "created")
            expires = _require_int(member, "expires")
            keyid = _require_str(member, "keyid")
        except ValueError as exc:
            return _failure(str(exc))
        created_dt = datetime.fromtimestamp(created, tz=UTC)
        expires_dt = datetime.fromtimestamp(expires, tz=UTC)

        def fail(reason: str, agent_url: str | None = None) -> PassportVerification:
            return PassportVerification(
                valid=False,
                keyid=keyid,
                directory_url=agent_url,
                created=created_dt,
                expires=expires_dt,
                failure_reason=reason,
            )

        alg = member.param("alg")
        if alg is not None and (alg.kind != "string" or alg.text != "ed25519"):
            return fail("unsupported alg (this profile verifies ed25519 only)")

        nonce_value = _nonce_value(member)
        if self._require_nonce and nonce_value is None:
            return fail("signature has no nonce (nonce required by this verifier)")

        # --- time window ----------------------------------------------
        now = self._time_source()
        if expires <= created:
            return fail("invalid validity window (expires <= created)")
        if expires - created > self._max_window:
            return fail(
                f"validity window too long ({expires - created}s > {self._max_window}s)"
            )
        if created > now + self._clock_skew:
            return fail("signature created in the future beyond allowed clock skew")
        if now > expires + self._clock_skew:
            return fail("signature expired")

        # --- covered components ---------------------------------------
        names = [c.name for c in member.components]
        if "@authority" not in names and "@target-uri" not in names:
            return fail("signature must cover @authority or @target-uri")
        agent_components = [c for c in member.components if c.name == "signature-agent"]
        if not agent_components:
            return fail("signature must cover the signature-agent header")

        directory_url = _directory_url_for(agent, agent_components[0].param("key"))
        if directory_url is None:
            return fail("covered signature-agent component does not match the header")

        scheme = urlsplit(directory_url).scheme.lower()
        if scheme not in ("http", "https"):
            return fail("Signature-Agent must be an http(s) URL", directory_url)
        if self._require_https and scheme != "https":
            return fail("Signature-Agent directory must be served over HTTPS", directory_url)

        # --- signature base -------------------------------------------
        try:
            base = reconstruct_signature_base(member, method=method, url=url, headers=headers)
        except ValueError as exc:
            return fail(f"cannot reconstruct signature base: {exc}", directory_url)

        # --- key lookup ------------------------------------------------
        try:
            directory = await self._fetch_directory(directory_url)
        except Exception as exc:
            logger.debug("Directory fetch failed for %s: %s", directory_url, exc)
            return fail(f"could not fetch key directory: {exc}", directory_url)

        jwk = next((k for k in directory.keys if jwk_thumbprint(k) == keyid), None)
        delegation: DelegationPayload | None = None
        parent_jwk: PassportJWK | None = None
        if jwk is None:
            if not self._allow_delegation:
                return fail("keyid does not match any key in the directory", directory_url)
            # EXPERIMENTAL: an unknown keyid may be a delegated child —
            # validate the parent-signed statement instead.
            resolved = self._resolve_delegation(keyid, directory, headers, now)
            if isinstance(resolved, str):
                return fail(resolved, directory_url)
            delegation, parent_jwk = resolved
            if expires > delegation.exp:
                return fail("signature expires after the delegation window", directory_url)
            jwk = delegation.child_jwk
        if jwk.nbf is not None and now + self._clock_skew < jwk.nbf:
            return fail("directory key is not yet valid (nbf)", directory_url)
        if jwk.exp is not None and now - self._clock_skew > jwk.exp:
            return fail("directory key has expired (exp)", directory_url)

        try:
            verify_key = jwk_to_verify_key(jwk)
            verify_key.verify(base.encode("utf-8"), signature)
        except (BadSignatureError, ValueError):
            return fail("signature verification failed", directory_url)

        if self._require_assertion:
            # For delegated requests the possession proof to demand is the
            # PARENT's — children are ephemeral and never publish one.
            if delegation is not None and parent_jwk is not None:
                assertion_failure = await self._check_assertion(
                    delegation.parent, parent_jwk, directory_url
                )
            else:
                assertion_failure = await self._check_assertion(keyid, jwk, directory_url)
            if assertion_failure is not None:
                return fail(assertion_failure, directory_url)

        # Replay tracking is the last gate: only fully-valid signatures
        # consume their nonce.
        if nonce_value is not None and self._replay_cache is not None:
            ttl = max(1.0, expires - now + self._clock_skew)
            if not await self._replay_cache.add(keyid, nonce_value, ttl):
                return fail("nonce replay detected", directory_url)

        return PassportVerification(
            valid=True,
            keyid=keyid,
            agent_did=jwk_to_did(jwk),
            directory_url=directory_url,
            created=created_dt,
            expires=expires_dt,
            failure_reason=None,
            delegated=delegation is not None,
            parent_did=jwk_to_did(parent_jwk) if parent_jwk is not None else None,
            scope=delegation.scope if delegation is not None else None,
        )

    def _resolve_delegation(
        self,
        keyid: str,
        directory: SignatureDirectory,
        headers: Mapping[str, str],
        now: float,
    ) -> tuple[DelegationPayload, PassportJWK] | str:
        """Validate the delegation chain for an unknown signing keyid.

        Returns ``(payload, parent_jwk)`` on success or a failure reason.
        The parent is resolved against the live directory, so removing or
        revoking the parent cascades to every outstanding child.
        """
        raw = headers.get(DELEGATION_HEADER.lower())
        if raw is None:
            return "keyid does not match any key in the directory"
        try:
            payload_bytes, payload, statement_sig = decode_delegation_header(raw)
        except ValueError as exc:
            return f"malformed delegation header: {exc}"
        if payload.child != keyid:
            return "delegation child does not match the signing keyid"
        if jwk_thumbprint(payload.child_jwk) != payload.child:
            return "delegation child_jwk does not match the child thumbprint"
        parent_jwk = next(
            (k for k in directory.keys if jwk_thumbprint(k) == payload.parent), None
        )
        if parent_jwk is None:
            return "delegation parent key is not in the directory"
        if parent_jwk.nbf is not None and now + self._clock_skew < parent_jwk.nbf:
            return "delegation parent key is not yet valid (nbf)"
        if parent_jwk.exp is not None and now - self._clock_skew > parent_jwk.exp:
            return "delegation parent key has expired (exp)"
        if payload.exp <= payload.nbf:
            return "invalid delegation window (exp <= nbf)"
        if payload.nbf > now + self._clock_skew:
            return "delegation statement is not yet valid"
        if now > payload.exp + self._clock_skew:
            return "delegation statement has expired"
        try:
            jwk_to_verify_key(parent_jwk).verify(payload_bytes, statement_sig)
        except (BadSignatureError, ValueError):
            return "delegation statement signature verification failed"
        return payload, parent_jwk

    async def _check_assertion(
        self, keyid: str, jwk: PassportJWK, directory_url: str
    ) -> str | None:
        """Require a valid possession assertion for ``keyid``.

        Returns a failure reason, or ``None`` when a valid assertion for
        the key (bound to this directory, currently within its window)
        is published in the directory's assertions document.
        """
        try:
            document = await self._fetch_assertions(directory_url)
        except Exception as exc:
            logger.debug("Assertions fetch failed for %s: %s", directory_url, exc)
            return f"could not fetch directory assertions: {exc}"
        now = self._time_source()
        for assertion in document.assertions:
            if assertion.payload.sub != keyid:
                continue
            if verify_assertion(jwk, assertion, directory_url, now).valid:
                return None
        return "no valid directory assertion for keyid"

    async def _fetch_directory(self, directory_url: str) -> SignatureDirectory:
        """Fetch (with TTL cache) the JWKS for a directory base URL."""
        now = self._time_source()
        cached = self._cache.get(directory_url)
        if cached is not None and now - cached[0] < self._cache_ttl:
            return cached[1]

        async with self._cache_lock:
            cached = self._cache.get(directory_url)
            if cached is not None and now - cached[0] < self._cache_ttl:
                return cached[1]
            response = await self._get_client().get(_well_known_url(directory_url))
            if response.status_code != 200:
                raise ValueError(f"directory returned HTTP {response.status_code}")
            directory = SignatureDirectory.from_untrusted(response.json())
            self._cache[directory_url] = (self._time_source(), directory)
            return directory

    async def _fetch_assertions(self, directory_url: str) -> AssertionsDocument:
        """Fetch (with TTL cache) the assertions document for a directory."""
        now = self._time_source()
        cached = self._assertions_cache.get(directory_url)
        if cached is not None and now - cached[0] < self._cache_ttl:
            return cached[1]

        async with self._cache_lock:
            cached = self._assertions_cache.get(directory_url)
            if cached is not None and now - cached[0] < self._cache_ttl:
                return cached[1]
            response = await self._get_client().get(_assertions_well_known_url(directory_url))
            if response.status_code != 200:
                raise ValueError(f"assertions document returned HTTP {response.status_code}")
            document = AssertionsDocument.from_untrusted(response.json())
            self._assertions_cache[directory_url] = (self._time_source(), document)
            return document

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._http_timeout),
                transport=self._transport,
                follow_redirects=False,
            )
        return self._client


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _failure(reason: str) -> PassportVerification:
    return PassportVerification(valid=False, failure_reason=reason)


def _member_tag(member: SignatureInputMember) -> str | None:
    tag = member.param("tag")
    if tag is None or tag.kind != "string":
        return None
    return tag.text


def _nonce_value(member: SignatureInputMember) -> str | None:
    """The signature's nonce as a replay-cache key.

    The profile emits sf-string nonces; any other (still-signed) wire
    type is keyed by its canonical serialization so replayed captures
    cannot dodge the cache by using an exotic nonce type.
    """
    nonce = member.param("nonce")
    if nonce is None:
        return None
    if nonce.kind == "string" and nonce.text is not None:
        return nonce.text
    try:
        return nonce.serialize()
    except ValueError:  # unreachable for parser-produced values
        return None


def _require_int(member: SignatureInputMember, key: str) -> int:
    value = member.param(key)
    if value is None:
        raise ValueError(f"missing required signature parameter {key!r}")
    return value.as_int()


def _require_str(member: SignatureInputMember, key: str) -> str:
    value = member.param(key)
    if value is None:
        raise ValueError(f"missing required signature parameter {key!r}")
    return value.as_string()


def _directory_url_for(
    agent: SignatureAgentValue, key_param: SfValue | None
) -> str | None:
    """Pick the directory URL the covered component refers to."""
    if agent.form == "string":
        if key_param is not None:
            return None  # key param requires a dictionary-form header
        return agent.url
    if key_param is None or key_param.kind != "string":
        return None  # dictionary form requires ;key="label" coverage
    member = agent.member(key_param.text or "")
    return member.url if member is not None else None


def _well_known_url(directory_url: str) -> str:
    """Join a directory base URL with the well-known path (idempotent)."""
    trimmed = directory_url.rstrip("/")
    if trimmed.endswith(WELL_KNOWN_DIRECTORY_PATH):
        return trimmed
    return trimmed + WELL_KNOWN_DIRECTORY_PATH


def _assertions_well_known_url(directory_url: str) -> str:
    """The assertions document URL for a directory base URL."""
    trimmed = directory_url.rstrip("/")
    if trimmed.endswith(WELL_KNOWN_ASSERTIONS_PATH):
        return trimmed
    if trimmed.endswith(WELL_KNOWN_DIRECTORY_PATH):
        trimmed = trimmed[: -len(WELL_KNOWN_DIRECTORY_PATH)]
    return trimmed + WELL_KNOWN_ASSERTIONS_PATH
