"""Airlock Passport core tests: signature base vectors, sign/verify
round-trips, tampering, time windows, malformed headers, directory cache.

Wire-format vectors follow draft-meunier-webbotauth-httpsig-protocol-00
and draft-meunier-webbotauth-httpsig-directory-00 (plus the RFC 8037 A.3
thumbprint test vector).
"""

from __future__ import annotations

import base64
import json
from hashlib import sha256

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from airlock.crypto.keys import KeyPair
from airlock.passport.base import (
    DIRECTORY_MEDIA_TYPE,
    ParsedComponent,
    SfParam,
    SfValue,
    build_signature_base,
    canonicalize_authority,
    parse_signature_agent,
    parse_signature_header,
    parse_signature_input,
    reconstruct_signature_base,
    serialize_sf_string,
    serialize_signature_params,
)
from airlock.passport.directory import (
    build_directory,
    jwk_thumbprint,
    jwk_to_did,
    key_to_jwk,
)
from airlock.passport.signer import PassportSigner
from airlock.passport.verifier import PassportVerifier
from airlock.schemas.passport import PassportJWK, SignatureParams

SEED = b"passport_test_seed_0000000000000"
DIRECTORY_URL = "https://directory.test"
SITE_URL = "https://example.com/some/path?q=1"


@pytest.fixture
def keypair() -> KeyPair:
    return KeyPair.from_seed(SEED)


def make_signer(keypair: KeyPair, **kwargs: object) -> PassportSigner:
    return PassportSigner(keypair, DIRECTORY_URL, **kwargs)  # type: ignore[arg-type]


def make_verifier(
    directory_json: str,
    *,
    calls: list[str] | None = None,
    status_code: int = 200,
    **kwargs: object,
) -> PassportVerifier:
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(str(request.url))
        return httpx.Response(
            status_code,
            content=directory_json,
            headers={"content-type": DIRECTORY_MEDIA_TYPE},
        )

    kwargs.setdefault("require_https", False)
    return PassportVerifier(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]


def directory_json_for(*keypairs: KeyPair) -> str:
    return build_directory([kp.verify_key for kp in keypairs]).model_dump_json(
        exclude_none=True
    )


# ---------------------------------------------------------------------------
# RFC 7638 thumbprints (keyid derivation)
# ---------------------------------------------------------------------------


class TestThumbprint:
    def test_rfc8037_appendix_a3_vector(self) -> None:
        jwk = PassportJWK(
            kty="OKP", crv="Ed25519", x="11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        )
        assert jwk_thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

    def test_draft_example_key_vector(self) -> None:
        # x from the directory draft / Cloudflare docs example; keyid from
        # the httpsig-protocol draft example C.2.1 — the same test key.
        jwk = PassportJWK(
            kty="OKP", crv="Ed25519", x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
        )
        assert jwk_thumbprint(jwk) == "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"

    def test_thumbprint_matches_hand_computed(self, keypair: KeyPair) -> None:
        jwk = key_to_jwk(keypair.verify_key)
        canonical = json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": jwk.x}, separators=(",", ":")
        )
        expected = (
            base64.urlsafe_b64encode(sha256(canonical.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        assert jwk_thumbprint(jwk) == expected

    def test_jwk_did_roundtrip(self, keypair: KeyPair) -> None:
        assert jwk_to_did(key_to_jwk(keypair.verify_key)) == keypair.did


# ---------------------------------------------------------------------------
# Signature base construction (hand-computed from the draft rules)
# ---------------------------------------------------------------------------


class TestSignatureBase:
    def test_base_matches_hand_computed_vector(self, keypair: KeyPair) -> None:
        signer = make_signer(keypair, include_nonce=False)
        created = 1735689600
        headers = signer.sign_request("GET", "https://Example.COM:443/x?y=1", created=created)

        expected_params = (
            '("@authority" "signature-agent")'
            f";created={created}"
            f';keyid="{signer.keyid}"'
            ';alg="ed25519"'
            f";expires={created + 60}"
            ';tag="web-bot-auth"'
        )
        expected_base = (
            '"@authority": example.com\n'
            '"signature-agent": "https://directory.test"\n'
            f'"@signature-params": {expected_params}'
        )

        assert headers.signature_agent == '"https://directory.test"'
        assert headers.signature_input == f"sig1={expected_params}"

        # The signature must verify over exactly the hand-written base.
        sig_b64 = headers.signature.removeprefix("sig1=:").removesuffix(":")
        keypair.verify_key.verify(expected_base.encode(), base64.b64decode(sig_b64))

    def test_nonce_is_included_and_quoted(self, keypair: KeyPair) -> None:
        headers = make_signer(keypair).sign_request("GET", SITE_URL, nonce="abc123==")
        assert ';nonce="abc123=="' in headers.signature_input

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://Example.COM/x", "example.com"),
            ("https://example.com:443/", "example.com"),
            ("http://example.com:80/", "example.com"),
            ("https://example.com:8443/", "example.com:8443"),
            ("http://127.0.0.1:8080/p?q=1", "127.0.0.1:8080"),
            ("https://[2001:db8::1]:8443/", "[2001:db8::1]:8443"),
        ],
    )
    def test_authority_canonicalization(self, url: str, expected: str) -> None:
        assert canonicalize_authority(url) == expected

    def test_authority_requires_host(self) -> None:
        with pytest.raises(ValueError):
            canonicalize_authority("not-a-url")

    def test_sf_string_escaping(self) -> None:
        assert serialize_sf_string('a"b\\c') == '"a\\"b\\\\c"'
        with pytest.raises(ValueError):
            serialize_sf_string("naïve")  # non-ASCII not allowed

    def test_serialize_params_roundtrips_through_parser(self) -> None:
        params = SignatureParams(
            created=100, expires=160, keyid="kid", alg="ed25519", nonce="n", tag="web-bot-auth"
        )
        covered = [
            ParsedComponent(name="@authority"),
            ParsedComponent(name="signature-agent"),
        ]
        serialized = serialize_signature_params(covered, params)
        member = parse_signature_input(f"sig1={serialized}")[0]
        rebuilt = reconstruct_signature_base(
            member,
            method="GET",
            url="https://example.com/",
            headers={"signature-agent": '"https://directory.test"'},
        )
        assert rebuilt.endswith(f'"@signature-params": {serialized}')


# ---------------------------------------------------------------------------
# Sign -> verify round trips
# ---------------------------------------------------------------------------


class TestSignVerifyRoundtrip:
    async def test_valid_roundtrip(self, keypair: KeyPair) -> None:
        headers = make_signer(keypair).sign_request("GET", SITE_URL)
        verifier = make_verifier(directory_json_for(keypair))
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=headers.as_headers()
        )
        assert result.valid is True
        assert result.failure_reason is None
        assert result.agent_did == keypair.did
        assert result.keyid == jwk_thumbprint(key_to_jwk(keypair.verify_key))
        assert result.directory_url == DIRECTORY_URL
        assert result.created is not None and result.expires is not None

    async def test_header_names_are_case_insensitive(self, keypair: KeyPair) -> None:
        headers = {
            k.upper(): v
            for k, v in make_signer(keypair).sign_request("GET", SITE_URL).as_headers().items()
        }
        verifier = make_verifier(directory_json_for(keypair))
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert result.valid is True

    async def test_tampered_authority_fails(self, keypair: KeyPair) -> None:
        headers = make_signer(keypair).sign_request("GET", SITE_URL)
        verifier = make_verifier(directory_json_for(keypair))
        result = await verifier.verify(
            method="GET", url="https://evil.example/some/path?q=1", headers=headers.as_headers()
        )
        assert result.valid is False
        assert result.failure_reason == "signature verification failed"

    async def test_tampered_signature_agent_fails(self, keypair: KeyPair) -> None:
        headers = make_signer(keypair).sign_request("GET", SITE_URL).as_headers()
        headers["Signature-Agent"] = '"https://other-directory.test"'
        verifier = make_verifier(directory_json_for(keypair))
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert result.valid is False
        assert result.failure_reason == "signature verification failed"

    async def test_expired_signature(self, keypair: KeyPair) -> None:
        clock = [1_000_000.0]
        signer = PassportSigner(
            keypair, DIRECTORY_URL, validity_seconds=60, time_source=lambda: clock[0]
        )
        headers = signer.sign_request("GET", SITE_URL)
        clock[0] += 120  # beyond expires + skew
        verifier = make_verifier(
            directory_json_for(keypair), time_source=lambda: clock[0]
        )
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=headers.as_headers()
        )
        assert result.valid is False
        assert result.failure_reason == "signature expired"

    async def test_created_in_future_beyond_skew(self, keypair: KeyPair) -> None:
        clock = [1_000_000.0]
        headers = make_signer(keypair).sign_request(
            "GET", SITE_URL, created=int(clock[0]) + 300
        )
        verifier = make_verifier(
            directory_json_for(keypair), time_source=lambda: clock[0]
        )
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=headers.as_headers()
        )
        assert result.valid is False
        assert result.failure_reason is not None
        assert "created in the future" in result.failure_reason

    async def test_validity_window_too_long(self, keypair: KeyPair) -> None:
        signer = PassportSigner(keypair, DIRECTORY_URL, validity_seconds=100_000)
        headers = signer.sign_request("GET", SITE_URL)
        verifier = make_verifier(directory_json_for(keypair))
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=headers.as_headers()
        )
        assert result.valid is False
        assert result.failure_reason is not None
        assert "validity window too long" in result.failure_reason

    async def test_unknown_keyid(self, keypair: KeyPair) -> None:
        other = KeyPair.from_seed(b"another_seed_0000000000000000000")
        headers = make_signer(keypair).sign_request("GET", SITE_URL)
        verifier = make_verifier(directory_json_for(other))  # directory lacks our key
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=headers.as_headers()
        )
        assert result.valid is False
        assert result.failure_reason is not None
        assert "keyid does not match" in result.failure_reason

    async def test_wrong_tag_is_ignored(self, keypair: KeyPair) -> None:
        headers = make_signer(keypair).sign_request("GET", SITE_URL).as_headers()
        headers["Signature-Input"] = headers["Signature-Input"].replace(
            'tag="web-bot-auth"', 'tag="other-profile"'
        )
        verifier = make_verifier(directory_json_for(keypair))
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert result.valid is False
        assert result.failure_reason is not None
        assert "web-bot-auth" in result.failure_reason

    async def test_https_required_by_default(self, keypair: KeyPair) -> None:
        signer = PassportSigner(keypair, "http://directory.test")
        headers = signer.sign_request("GET", SITE_URL)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=directory_json_for(keypair))

        verifier = PassportVerifier(transport=httpx.MockTransport(handler))  # default: https
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=headers.as_headers()
        )
        assert result.valid is False
        assert result.failure_reason is not None
        assert "HTTPS" in result.failure_reason

    async def test_directory_http_error(self, keypair: KeyPair) -> None:
        headers = make_signer(keypair).sign_request("GET", SITE_URL)
        verifier = make_verifier(directory_json_for(keypair), status_code=500)
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=headers.as_headers()
        )
        assert result.valid is False
        assert result.failure_reason is not None
        assert "could not fetch key directory" in result.failure_reason

    async def test_dictionary_form_signature_agent_verifies(self, keypair: KeyPair) -> None:
        """The verifier accepts the current draft's Dictionary form."""
        agent_header = f'a1={serialize_sf_string(DIRECTORY_URL)}'
        covered = [
            ParsedComponent(name="@authority"),
            ParsedComponent(
                name="signature-agent",
                params=[SfParam(key="key", value=SfValue.of_string("a1"))],
            ),
        ]
        params = SignatureParams(
            created=1_000_000,
            expires=1_000_060,
            keyid=jwk_thumbprint(key_to_jwk(keypair.verify_key)),
            alg="ed25519",
            nonce=None,
            tag="web-bot-auth",
        )
        params_value = serialize_signature_params(covered, params)
        base = build_signature_base(
            [
                ('"@authority"', "example.com"),
                ('"signature-agent";key="a1"', serialize_sf_string(DIRECTORY_URL)),
            ],
            params_value,
        )
        signature = keypair.signing_key.sign(base.encode()).signature
        headers = {
            "Signature-Agent": agent_header,
            "Signature-Input": f"sig1={params_value}",
            "Signature": f"sig1=:{base64.b64encode(signature).decode()}:",
        }
        verifier = make_verifier(
            directory_json_for(keypair), time_source=lambda: 1_000_001.0
        )
        result = await verifier.verify(
            method="GET", url="https://example.com/", headers=headers
        )
        assert result.valid is True
        assert result.agent_did == keypair.did

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda h: h.pop("Signature-Input"),
            lambda h: h.pop("Signature"),
            lambda h: h.pop("Signature-Agent"),
            lambda h: h.__setitem__("Signature-Input", "=== not structured ==="),
            lambda h: h.__setitem__("Signature-Input", "sig1=(@authority)"),
            lambda h: h.__setitem__("Signature", "sig1=:!!!not-base64!!!:"),
            lambda h: h.__setitem__("Signature", 'sig1="not bytes"'),
            lambda h: h.__setitem__("Signature", "other=:AAAA:"),
            lambda h: h.__setitem__("Signature-Agent", "https://unquoted.test"),
            lambda h: h.__setitem__("Signature-Agent", '"has spaces but no url"...trailing'),
        ],
    )
    async def test_malformed_headers_never_raise(
        self, keypair: KeyPair, mutate: object
    ) -> None:
        headers = make_signer(keypair).sign_request("GET", SITE_URL).as_headers()
        mutate(headers)  # type: ignore[operator]
        verifier = make_verifier(directory_json_for(keypair))
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert result.valid is False
        assert result.failure_reason is not None

    async def test_missing_required_param(self, keypair: KeyPair) -> None:
        headers = make_signer(keypair, include_nonce=False).sign_request(
            "GET", SITE_URL
        ).as_headers()
        headers["Signature-Input"] = headers["Signature-Input"].replace(
            ';keyid="', ';kid="'
        )
        verifier = make_verifier(directory_json_for(keypair))
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert result.valid is False
        assert result.failure_reason is not None
        assert "keyid" in result.failure_reason


# ---------------------------------------------------------------------------
# Directory cache TTL
# ---------------------------------------------------------------------------


class TestDirectoryCache:
    async def test_cache_hits_within_ttl_and_refreshes_after(
        self, keypair: KeyPair
    ) -> None:
        clock = [2_000_000.0]
        calls: list[str] = []
        signer = PassportSigner(keypair, DIRECTORY_URL, time_source=lambda: clock[0])
        verifier = make_verifier(
            directory_json_for(keypair),
            calls=calls,
            cache_ttl_seconds=300.0,
            time_source=lambda: clock[0],
        )

        for _ in range(3):
            result = await verifier.verify(
                method="GET",
                url=SITE_URL,
                headers=signer.sign_request("GET", SITE_URL).as_headers(),
            )
            assert result.valid is True
        assert len(calls) == 1  # served from cache within the TTL

        clock[0] += 301.0
        result = await verifier.verify(
            method="GET",
            url=SITE_URL,
            headers=signer.sign_request("GET", SITE_URL).as_headers(),
        )
        assert result.valid is True
        assert len(calls) == 2  # TTL elapsed -> refetched
        assert calls[0].endswith("/.well-known/http-message-signatures-directory")


# ---------------------------------------------------------------------------
# Structured-field parsers (direct)
# ---------------------------------------------------------------------------


class TestParsers:
    def test_parse_signature_header(self) -> None:
        parsed = parse_signature_header("sig1=:AAECAw==:")
        assert parsed == {"sig1": bytes([0, 1, 2, 3])}

    def test_parse_signature_agent_string_form(self) -> None:
        agent = parse_signature_agent('  "https://directory.test"  ')
        assert agent.form == "string"
        assert agent.url == "https://directory.test"

    def test_parse_signature_agent_dictionary_form(self) -> None:
        agent = parse_signature_agent(
            'a1="https://one.test";type=jwks_uri, b2="https://two.test"'
        )
        assert agent.form == "dictionary"
        member = agent.member("a1")
        assert member is not None and member.url == "https://one.test"
        assert member.serialize_value() == '"https://one.test";type=jwks_uri'

    def test_parse_signature_input_rejects_garbage(self) -> None:
        for bad in ("sig1=", "sig1=()trailing)", 'sig1=("@authority",)', "sig1=(1 2)"):
            with pytest.raises(ValueError):
                parse_signature_input(bad)

    def test_duplicate_covered_component_rejected(self, keypair: KeyPair) -> None:
        member = parse_signature_input(
            'sig1=("@authority" "@authority");created=1;expires=2;keyid="k";tag="web-bot-auth"'
        )[0]
        with pytest.raises(ValueError, match="duplicate"):
            reconstruct_signature_base(
                member, method="GET", url="https://example.com/", headers={}
            )


# ---------------------------------------------------------------------------
# Property-based: canonicalization determinism + round-trip
# ---------------------------------------------------------------------------

_LABEL = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=8)
_HOSTS = st.lists(_LABEL, min_size=1, max_size=3).map(".".join)
_PATHS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/",
    max_size=24,
)
_PORTS = st.one_of(st.none(), st.integers(min_value=1, max_value=65535))

_PROPERTY_KP = KeyPair.from_seed(b"hypothesis_property_seed_0000000")


@given(host=_HOSTS, path=_PATHS, port=_PORTS, scheme=st.sampled_from(["http", "https"]))
def test_canonicalization_deterministic_and_roundtrip_verifies(
    host: str, path: str, port: int | None, scheme: str
) -> None:
    """For arbitrary authorities/paths: the signature base is deterministic,
    survives a parse -> canonical re-serialization round trip byte-for-byte,
    and the Ed25519 signature verifies over the reconstruction."""
    netloc = host if port is None else f"{host}:{port}"
    url = f"{scheme}://{netloc}/{path.lstrip('/')}"

    signer = PassportSigner(
        _PROPERTY_KP, DIRECTORY_URL, include_nonce=False, time_source=lambda: 1_000_000.0
    )
    headers_a = signer.sign_request("GET", url)
    headers_b = signer.sign_request("GET", url)
    assert headers_a == headers_b  # deterministic given a fixed clock

    # Mixed-case host canonicalizes identically.
    upper_url = f"{scheme}://{netloc.upper() if port is None else host.upper() + ':' + str(port)}/{path.lstrip('/')}"
    assert canonicalize_authority(url) == canonicalize_authority(upper_url)

    # Verifier-side reconstruction (pure, no HTTP) round-trips and verifies.
    member = parse_signature_input(headers_a.signature_input)[0]
    base = reconstruct_signature_base(
        member,
        method="GET",
        url=url,
        headers={"signature-agent": headers_a.signature_agent},
    )
    assert base.endswith(
        '"@signature-params": ' + headers_a.signature_input.removeprefix("sig1=")
    )
    signature = parse_signature_header(headers_a.signature)["sig1"]
    _PROPERTY_KP.verify_key.verify(base.encode(), signature)

    # Any tampering with the authority breaks verification.
    tampered = reconstruct_signature_base(
        member,
        method="GET",
        url=f"{scheme}://tampered.invalid/{path.lstrip('/')}",
        headers={"signature-agent": headers_a.signature_agent},
    )
    if tampered != base:
        with pytest.raises(BadSignatureError):
            _PROPERTY_KP.verify_key.verify(tampered.encode(), signature)


def test_verify_key_type_sanity(keypair: KeyPair) -> None:
    assert isinstance(keypair.verify_key, VerifyKey)
