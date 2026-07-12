"""Tenant-signed directory assertion tests (possession proof, F1):
sign/verify round-trips, tampering (property-based), origin
normalization, the gateway assertions endpoint with registration and
heartbeat-refresh flows, verifier ``require_assertion`` behavior, and
the ``airlock passport attest`` CLI."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from hypothesis import given
from hypothesis import strategies as st

from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_message
from airlock.passport.assertions import (
    WELL_KNOWN_ASSERTIONS_PATH,
    normalize_directory_origin,
    sign_assertion,
    verify_assertion,
)
from airlock.passport.base import DIRECTORY_MEDIA_TYPE, WELL_KNOWN_DIRECTORY_PATH
from airlock.passport.directory import build_directory, jwk_thumbprint, key_to_jwk
from airlock.passport.registration import register_passport, upload_assertion
from airlock.passport.signer import PassportSigner
from airlock.passport.verifier import PassportVerifier
from airlock.schemas.envelope import create_envelope
from airlock.schemas.handshake import SignatureEnvelope
from airlock.schemas.passport import AssertionsDocument, SignedAssertion
from airlock.schemas.requests import HeartbeatRequest

DIRECTORY_URL = "https://directory.test"
SITE_URL = "https://example.com/some/path?q=1"

NOW = 1_750_000_000


@pytest.fixture
def keypair() -> KeyPair:
    return KeyPair.from_seed(b"assertion_test_seed_000000000000")


# ---------------------------------------------------------------------------
# sign_assertion / verify_assertion
# ---------------------------------------------------------------------------


class TestAssertionRoundtrip:
    def test_valid_roundtrip(self, keypair: KeyPair) -> None:
        assertion = sign_assertion(keypair, DIRECTORY_URL, now=NOW)
        jwk = key_to_jwk(keypair.verify_key)
        result = verify_assertion(jwk, assertion, DIRECTORY_URL, NOW + 60)
        assert result.valid is True
        assert result.failure_reason is None
        assert result.thumbprint == jwk_thumbprint(jwk)
        assert result.directory == DIRECTORY_URL

    def test_payload_shape(self, keypair: KeyPair) -> None:
        assertion = sign_assertion(keypair, DIRECTORY_URL, validity_seconds=100, now=NOW)
        payload = assertion.payload
        assert payload.typ == "webbotauth-directory-assertion/v1"
        assert payload.sub == jwk_thumbprint(key_to_jwk(keypair.verify_key))
        assert payload.dir == DIRECTORY_URL
        assert (payload.nbf, payload.exp) == (NOW, NOW + 100)
        # nonce: 16 bytes as unpadded base64url; sig also unpadded base64url.
        assert len(payload.nonce) == 22 and "=" not in payload.nonce
        assert "=" not in assertion.sig and "+" not in assertion.sig

    @pytest.mark.parametrize(
        "equivalent",
        [
            "https://directory.test/",
            "https://DIRECTORY.test",
            "https://directory.test:443",
            "https://directory.test/.well-known/http-message-signatures-directory",
        ],
    )
    def test_equivalent_directory_forms_match(
        self, keypair: KeyPair, equivalent: str
    ) -> None:
        assertion = sign_assertion(keypair, DIRECTORY_URL, now=NOW)
        jwk = key_to_jwk(keypair.verify_key)
        assert verify_assertion(jwk, assertion, equivalent, NOW + 1).valid is True

    def test_none_directory_skips_binding_check(self, keypair: KeyPair) -> None:
        assertion = sign_assertion(keypair, DIRECTORY_URL, now=NOW)
        jwk = key_to_jwk(keypair.verify_key)
        assert verify_assertion(jwk, assertion, None, NOW + 1).valid is True

    def test_different_directory_rejected(self, keypair: KeyPair) -> None:
        assertion = sign_assertion(keypair, DIRECTORY_URL, now=NOW)
        jwk = key_to_jwk(keypair.verify_key)
        result = verify_assertion(jwk, assertion, "https://other.test", NOW + 1)
        assert result.valid is False
        assert result.failure_reason == "assertion is bound to a different directory"

    def test_wrong_key_rejected(self, keypair: KeyPair) -> None:
        other = KeyPair.from_seed(b"another_assertion_seed_000000000")
        assertion = sign_assertion(keypair, DIRECTORY_URL, now=NOW)
        result = verify_assertion(
            key_to_jwk(other.verify_key), assertion, DIRECTORY_URL, NOW + 1
        )
        assert result.valid is False
        assert result.failure_reason is not None
        assert "does not match the key thumbprint" in result.failure_reason

    def test_expired_and_not_yet_valid(self, keypair: KeyPair) -> None:
        assertion = sign_assertion(keypair, DIRECTORY_URL, validity_seconds=60, now=NOW)
        jwk = key_to_jwk(keypair.verify_key)
        expired = verify_assertion(jwk, assertion, DIRECTORY_URL, NOW + 61)
        assert expired.valid is False and expired.failure_reason == "assertion has expired"
        early = verify_assertion(jwk, assertion, DIRECTORY_URL, NOW - 1)
        assert early.valid is False and early.failure_reason == "assertion is not yet valid"

    def test_inverted_window_rejected(self, keypair: KeyPair) -> None:
        assertion = sign_assertion(keypair, DIRECTORY_URL, now=NOW)
        broken = assertion.model_copy(
            update={
                "payload": assertion.payload.model_copy(
                    update={"nbf": NOW, "exp": NOW}
                )
            }
        )
        result = verify_assertion(
            key_to_jwk(keypair.verify_key), broken, DIRECTORY_URL, NOW
        )
        assert result.valid is False
        assert result.failure_reason == "invalid assertion window (exp <= nbf)"

    def test_garbage_signature_never_raises(self, keypair: KeyPair) -> None:
        assertion = sign_assertion(keypair, DIRECTORY_URL, now=NOW)
        for bad_sig in ("", "!!!", "AAAA"):
            broken = assertion.model_copy(update={"sig": bad_sig})
            result = verify_assertion(
                key_to_jwk(keypair.verify_key), broken, DIRECTORY_URL, NOW + 1
            )
            assert result.valid is False

    def test_validity_must_be_positive(self, keypair: KeyPair) -> None:
        with pytest.raises(ValueError):
            sign_assertion(keypair, DIRECTORY_URL, validity_seconds=0)


class TestNormalizeDirectoryOrigin:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://Example.COM/x?y=1#z", "https://example.com"),
            ("https://example.com:443/", "https://example.com"),
            ("http://example.com:80", "http://example.com"),
            ("https://example.com:8443/dir/", "https://example.com:8443"),
            ("HTTPS://alice.agents.test", "https://alice.agents.test"),
        ],
    )
    def test_normalization(self, url: str, expected: str) -> None:
        assert normalize_directory_origin(url) == expected

    @pytest.mark.parametrize("bad", ["ftp://example.com", "example.com", "https://"])
    def test_rejects_non_http_origins(self, bad: str) -> None:
        with pytest.raises(ValueError):
            normalize_directory_origin(bad)


# ---------------------------------------------------------------------------
# Property: any single-field tampering invalidates the assertion
# ---------------------------------------------------------------------------

_PROPERTY_KP = KeyPair.from_seed(b"assertion_property_seed_00000000")
_PROPERTY_JWK = key_to_jwk(_PROPERTY_KP.verify_key)


@given(
    validity=st.integers(min_value=1, max_value=10_000_000),
    now=st.integers(min_value=0, max_value=2**31),
    host=st.from_regex(r"[a-z]([a-z0-9-]{0,10}[a-z0-9])?(\.[a-z]{2,6}){1,2}", fullmatch=True),
)
def test_assertion_roundtrip_property(validity: int, now: int, host: str) -> None:
    """Assertions verify inside their window and directory binding for
    arbitrary hosts and validity windows."""
    directory = f"https://{host}"
    assertion = sign_assertion(_PROPERTY_KP, directory, validity_seconds=validity, now=now)
    assert verify_assertion(_PROPERTY_JWK, assertion, directory, now).valid is True
    assert verify_assertion(_PROPERTY_JWK, assertion, directory, now + validity).valid is True
    assert (
        verify_assertion(_PROPERTY_JWK, assertion, directory, now + validity + 1).valid
        is False
    )


@given(
    field=st.sampled_from(["sub", "dir", "nbf", "exp", "nonce"]),
    fuzz=st.integers(min_value=1, max_value=1_000_000),
)
def test_assertion_tampering_property(field: str, fuzz: int) -> None:
    """Mutating any signed payload field invalidates the assertion."""
    assertion = sign_assertion(_PROPERTY_KP, DIRECTORY_URL, now=NOW)
    original = assertion.payload.model_dump()
    mutated = dict(original)
    if isinstance(original[field], int):
        mutated[field] = original[field] + fuzz
    else:
        mutated[field] = f"{original[field]}x{fuzz}"
    tampered = assertion.model_copy(
        update={"payload": assertion.payload.model_copy(update=mutated)}
    )
    result = verify_assertion(_PROPERTY_JWK, tampered, None, NOW + 1)
    assert result.valid is False


# ---------------------------------------------------------------------------
# Gateway: assertions endpoint + registration/heartbeat upload flows
# ---------------------------------------------------------------------------


@pytest.fixture
def passport_config(tmp_path: object) -> AirlockConfig:
    return AirlockConfig(lancedb_path=f"{tmp_path}/assertions.lance", passport_enabled=True)


@pytest.fixture
async def passport_app(passport_config: AirlockConfig) -> AsyncIterator[FastAPI]:
    from airlock.gateway.app import create_app

    app = create_app(passport_config)
    async with LifespanManager(app):
        yield app


@pytest.fixture
async def client(passport_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=passport_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def register_with_assertion(
    passport_app: FastAPI, kp: KeyPair, assertion: SignedAssertion | None
) -> None:
    result = await register_passport(
        kp,
        "http://testserver",
        transport=httpx.ASGITransport(app=passport_app),
        assertion=assertion,
    )
    assert result.registered is True


class TestGatewayAssertions:
    async def test_empty_document(self, client: httpx.AsyncClient) -> None:
        resp = await client.get(WELL_KNOWN_ASSERTIONS_PATH)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        assert "max-age=" in resp.headers["cache-control"]
        assert resp.json() == {"assertions": []}

    async def test_registration_upload_is_served(
        self, client: httpx.AsyncClient, passport_app: FastAPI, keypair: KeyPair
    ) -> None:
        assertion = sign_assertion(keypair, "http://testserver")
        await register_with_assertion(passport_app, keypair, assertion)
        resp = await client.get(WELL_KNOWN_ASSERTIONS_PATH)
        document = AssertionsDocument.model_validate(resp.json())
        assert len(document.assertions) == 1
        assert document.assertions[0] == assertion

    async def test_invalid_assertion_rejected_at_registration(
        self, passport_app: FastAPI, keypair: KeyPair
    ) -> None:
        other = KeyPair.from_seed(b"imposter_assertion_seed_00000000")
        wrong_key = sign_assertion(other, "http://testserver")
        with pytest.raises(RuntimeError, match="422"):
            await register_with_assertion(passport_app, keypair, wrong_key)

    async def test_heartbeat_refresh_replaces_assertion(
        self, client: httpx.AsyncClient, passport_app: FastAPI, keypair: KeyPair
    ) -> None:
        first = sign_assertion(keypair, "http://testserver", validity_seconds=60)
        await register_with_assertion(passport_app, keypair, first)
        second = sign_assertion(keypair, "http://testserver")
        await upload_assertion(
            keypair,
            "http://testserver",
            second,
            transport=httpx.ASGITransport(app=passport_app),
        )
        resp = await client.get(WELL_KNOWN_ASSERTIONS_PATH)
        document = AssertionsDocument.model_validate(resp.json())
        assert document.assertions == [second]

    async def test_heartbeat_rejects_foreign_assertion(
        self, passport_app: FastAPI, keypair: KeyPair
    ) -> None:
        await register_with_assertion(passport_app, keypair, None)
        other = KeyPair.from_seed(b"imposter_assertion_seed_00000000")
        foreign = sign_assertion(other, "http://testserver")
        with pytest.raises(RuntimeError, match="422"):
            await upload_assertion(
                keypair,
                "http://testserver",
                foreign,
                transport=httpx.ASGITransport(app=passport_app),
            )

    async def test_heartbeat_for_unregistered_agent_404(
        self, passport_app: FastAPI, keypair: KeyPair
    ) -> None:
        assertion = sign_assertion(keypair, "http://testserver")
        with pytest.raises(RuntimeError, match="404"):
            await upload_assertion(
                keypair,
                "http://testserver",
                assertion,
                transport=httpx.ASGITransport(app=passport_app),
            )

    async def test_revoked_agent_assertion_excluded(
        self, client: httpx.AsyncClient, passport_app: FastAPI, keypair: KeyPair
    ) -> None:
        assertion = sign_assertion(keypair, "http://testserver")
        await register_with_assertion(passport_app, keypair, assertion)
        await passport_app.state.revocation_store.revoke(keypair.did)
        resp = await client.get(WELL_KNOWN_ASSERTIONS_PATH)
        assert resp.json() == {"assertions": []}

    async def test_endpoint_404_when_flag_off(self, tmp_path: object) -> None:
        from airlock.gateway.app import create_app

        app = create_app(AirlockConfig(lancedb_path=f"{tmp_path}/off.lance"))
        async with LifespanManager(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as c:
                resp = await c.get(WELL_KNOWN_ASSERTIONS_PATH)
        assert resp.status_code == 404
        assert resp.json()["status"] == 404

    async def test_legacy_heartbeat_without_assertion_field_still_verifies(
        self, client: httpx.AsyncClient, passport_app: FastAPI, keypair: KeyPair
    ) -> None:
        """Clients built before the ``passport_assertion`` field sign a
        canonical form without it — the gateway must keep accepting them."""
        await register_with_assertion(passport_app, keypair, None)
        body = HeartbeatRequest(
            agent_did=keypair.did,
            endpoint_url="https://agent.example",  # type: ignore[arg-type]
            envelope=create_envelope(sender_did=keypair.did),
            signature=None,
        )
        legacy = body.model_dump(mode="json")
        legacy.pop("signature")
        legacy.pop("passport_assertion")  # the old wire form had no such key
        signature = SignatureEnvelope(
            algorithm="Ed25519",
            value=sign_message(legacy, keypair.signing_key),
            signed_at=datetime.now(UTC),
        )
        legacy["signature"] = signature.model_dump(mode="json")
        resp = await client.post("/heartbeat", json=legacy)
        assert resp.status_code == 200
        assert resp.json()["acknowledged"] is True


# ---------------------------------------------------------------------------
# Verifier: require_assertion
# ---------------------------------------------------------------------------


def assertion_verifier(
    kp: KeyPair,
    assertions: list[SignedAssertion] | None,
    *,
    assertions_status: int = 200,
    calls: list[str] | None = None,
    **kwargs: object,
) -> PassportVerifier:
    """Verifier whose transport serves both well-known documents."""
    directory_json = build_directory([kp.verify_key]).model_dump_json(exclude_none=True)

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request.url.path)
        if request.url.path == WELL_KNOWN_ASSERTIONS_PATH:
            if assertions is None:
                return httpx.Response(assertions_status, json={"assertions": []})
            return httpx.Response(
                assertions_status,
                content=AssertionsDocument(assertions=assertions).model_dump_json(),
                headers={"content-type": "application/json"},
            )
        return httpx.Response(
            200, content=directory_json, headers={"content-type": DIRECTORY_MEDIA_TYPE}
        )

    kwargs.setdefault("require_https", False)
    kwargs.setdefault("require_assertion", True)
    return PassportVerifier(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]


class TestVerifierRequireAssertion:
    async def test_valid_assertion_admits(self, keypair: KeyPair) -> None:
        headers = PassportSigner(keypair, DIRECTORY_URL).sign_request("GET", SITE_URL)
        verifier = assertion_verifier(keypair, [sign_assertion(keypair, DIRECTORY_URL)])
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers.as_headers())
        assert result.valid is True
        assert result.agent_did == keypair.did

    async def test_missing_assertion_rejected(self, keypair: KeyPair) -> None:
        headers = PassportSigner(keypair, DIRECTORY_URL).sign_request("GET", SITE_URL)
        verifier = assertion_verifier(keypair, [])
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers.as_headers())
        assert result.valid is False
        assert result.failure_reason == "no valid directory assertion for keyid"

    async def test_assertion_for_other_directory_rejected(self, keypair: KeyPair) -> None:
        headers = PassportSigner(keypair, DIRECTORY_URL).sign_request("GET", SITE_URL)
        verifier = assertion_verifier(
            keypair, [sign_assertion(keypair, "https://elsewhere.test")]
        )
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers.as_headers())
        assert result.valid is False
        assert result.failure_reason == "no valid directory assertion for keyid"

    async def test_unreachable_assertions_document_rejected(self, keypair: KeyPair) -> None:
        headers = PassportSigner(keypair, DIRECTORY_URL).sign_request("GET", SITE_URL)
        verifier = assertion_verifier(keypair, None, assertions_status=500)
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers.as_headers())
        assert result.valid is False
        assert result.failure_reason is not None
        assert "could not fetch directory assertions" in result.failure_reason

    async def test_off_by_default_never_fetches_assertions(self, keypair: KeyPair) -> None:
        calls: list[str] = []
        headers = PassportSigner(keypair, DIRECTORY_URL).sign_request("GET", SITE_URL)
        verifier = assertion_verifier(keypair, [], calls=calls, require_assertion=False)
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers.as_headers())
        assert result.valid is True
        assert WELL_KNOWN_ASSERTIONS_PATH not in calls

    async def test_assertions_document_is_cached(self, keypair: KeyPair) -> None:
        calls: list[str] = []
        signer = PassportSigner(keypair, DIRECTORY_URL)
        verifier = assertion_verifier(
            keypair, [sign_assertion(keypair, DIRECTORY_URL)], calls=calls
        )
        for _ in range(3):
            headers = signer.sign_request("GET", SITE_URL)
            result = await verifier.verify(
                method="GET", url=SITE_URL, headers=headers.as_headers()
            )
            assert result.valid is True
        assert calls.count(WELL_KNOWN_ASSERTIONS_PATH) == 1
        assert calls.count(WELL_KNOWN_DIRECTORY_PATH) == 1
