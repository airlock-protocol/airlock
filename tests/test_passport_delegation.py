"""EXPERIMENTAL delegation passport tests (F4): minting, header wire
format, verifier chain validation, cascade on parent removal, window
containment, tampering (property-based), interplay with assertions and
replay, the httpx auth helper, wall principal mapping, and the
``airlock passport delegate`` CLI."""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi import FastAPI, Request
from hypothesis import given
from hypothesis import strategies as st
from nacl.exceptions import BadSignatureError

from airlock.crypto.keys import KeyPair
from airlock.passport.assertions import sign_assertion
from airlock.passport.base import DIRECTORY_MEDIA_TYPE
from airlock.passport.delegation import (
    DELEGATION_HEADER,
    DelegatedPassportAuth,
    decode_delegation_header,
    delegation_signing_bytes,
    encode_delegation_header,
    mint_child,
)
from airlock.passport.directory import (
    b64url_decode,
    b64url_encode,
    build_directory,
    jwk_thumbprint,
    key_to_jwk,
)
from airlock.passport.replay import InMemoryNonceCache
from airlock.passport.signer import PassportSigner
from airlock.passport.verifier import PassportVerifier
from airlock.schemas.passport import (
    AssertionsDocument,
    DelegationPayload,
    DelegationStatement,
    SignedAssertion,
)

DIRECTORY_URL = "https://directory.test"
SITE_URL = "https://example.com/some/path?q=1"
NOW = 1_750_000_000


@pytest.fixture
def parent() -> KeyPair:
    return KeyPair.from_seed(b"delegation_parent_seed_000000000")


def resign(parent_kp: KeyPair, payload: DelegationPayload) -> DelegationStatement:
    """Parent-sign an arbitrary payload (for crafting corrupt chains)."""
    signature = parent_kp.signing_key.sign(delegation_signing_bytes(payload)).signature
    return DelegationStatement(payload=payload, sig=b64url_encode(signature))


def make_verifier(
    directory_keys: list[KeyPair],
    *,
    assertions: list[SignedAssertion] | None = None,
    **kwargs: object,
) -> PassportVerifier:
    directory_json = build_directory(
        [kp.verify_key for kp in directory_keys]
    ).model_dump_json(exclude_none=True)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("-assertions"):
            return httpx.Response(
                200,
                content=AssertionsDocument(assertions=assertions or []).model_dump_json(),
                headers={"content-type": "application/json"},
            )
        return httpx.Response(
            200, content=directory_json, headers={"content-type": DIRECTORY_MEDIA_TYPE}
        )

    kwargs.setdefault("require_https", False)
    kwargs.setdefault("allow_delegation", True)
    return PassportVerifier(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]


def delegated_headers(
    child: KeyPair,
    statement: DelegationStatement,
    *,
    url: str = SITE_URL,
    validity_seconds: int = 60,
) -> dict[str, str]:
    signer = PassportSigner(child, DIRECTORY_URL, validity_seconds=validity_seconds)
    headers = signer.sign_request("GET", url).as_headers()
    headers[DELEGATION_HEADER] = encode_delegation_header(statement)
    return headers


# ---------------------------------------------------------------------------
# Minting + wire format
# ---------------------------------------------------------------------------


class TestMintAndWireFormat:
    def test_mint_child_shape(self, parent: KeyPair) -> None:
        child, statement = mint_child(parent, scope="read", validity_seconds=900, now=NOW)
        payload = statement.payload
        assert child.did != parent.did
        assert payload.typ == "airlock-delegation/v1"
        assert payload.parent == jwk_thumbprint(key_to_jwk(parent.verify_key))
        assert payload.child == jwk_thumbprint(key_to_jwk(child.verify_key))
        assert payload.child_jwk.x == key_to_jwk(child.verify_key).x
        assert payload.scope == "read"
        assert (payload.nbf, payload.exp) == (NOW, NOW + 900)

    def test_statement_signature_is_parents(self, parent: KeyPair) -> None:
        _, statement = mint_child(parent, now=NOW)
        parent.verify_key.verify(
            delegation_signing_bytes(statement.payload), b64url_decode(statement.sig)
        )
        other = KeyPair.from_seed(b"delegation_other_seed_0000000000")
        with pytest.raises(BadSignatureError):
            other.verify_key.verify(
                delegation_signing_bytes(statement.payload), b64url_decode(statement.sig)
            )

    def test_header_roundtrip(self, parent: KeyPair) -> None:
        _, statement = mint_child(parent, scope="s", now=NOW)
        encoded = encode_delegation_header(statement)
        payload_bytes, payload, sig = decode_delegation_header(encoded)
        assert payload == statement.payload
        assert delegation_signing_bytes(payload) == payload_bytes

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "onlyonesegment",
            "a.b.c",
            "!!notb64!!.AAAA",
            "eyJub3QiOiAidmFsaWQifQ.AAAA",  # JSON but not a delegation payload
        ],
    )
    def test_malformed_header_raises_valueerror(self, bad: str) -> None:
        with pytest.raises(ValueError):
            decode_delegation_header(bad)

    def test_validity_must_be_positive(self, parent: KeyPair) -> None:
        with pytest.raises(ValueError):
            mint_child(parent, validity_seconds=0)


# ---------------------------------------------------------------------------
# Verifier chain validation
# ---------------------------------------------------------------------------


class TestVerifierDelegation:
    async def test_delegated_child_admitted(self, parent: KeyPair) -> None:
        child, statement = mint_child(parent, scope="read")
        verifier = make_verifier([parent])
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=delegated_headers(child, statement)
        )
        assert result.valid is True
        assert result.delegated is True
        assert result.agent_did == child.did
        assert result.parent_did == parent.did
        assert result.scope == "read"
        assert result.keyid == jwk_thumbprint(key_to_jwk(child.verify_key))

    async def test_off_by_default(self, parent: KeyPair) -> None:
        child, statement = mint_child(parent)
        verifier = make_verifier([parent], allow_delegation=False)
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=delegated_headers(child, statement)
        )
        assert result.valid is False
        assert result.failure_reason == "keyid does not match any key in the directory"

    async def test_missing_header_fails(self, parent: KeyPair) -> None:
        child, _ = mint_child(parent)
        headers = PassportSigner(child, DIRECTORY_URL).sign_request("GET", SITE_URL)
        verifier = make_verifier([parent])
        result = await verifier.verify(
            method="GET", url=SITE_URL, headers=headers.as_headers()
        )
        assert result.valid is False
        assert result.failure_reason == "keyid does not match any key in the directory"

    async def test_parent_absent_cascades_to_child(self, parent: KeyPair) -> None:
        """The cascade property: remove the parent from the directory and
        every outstanding child credential dies with it."""
        child, statement = mint_child(parent)
        headers = delegated_headers(child, statement)

        admitted = await make_verifier([parent]).verify(
            method="GET", url=SITE_URL, headers=headers
        )
        assert admitted.valid is True

        bystander = KeyPair.from_seed(b"delegation_other_seed_0000000000")
        revoked = await make_verifier([bystander]).verify(  # parent no longer served
            method="GET", url=SITE_URL, headers=delegated_headers(child, statement)
        )
        assert revoked.valid is False
        assert revoked.failure_reason == "delegation parent key is not in the directory"

    async def test_statement_expiry(self, parent: KeyPair) -> None:
        child, statement = mint_child(parent, validity_seconds=60, now=NOW)
        clock = [float(NOW + 120)]  # past statement exp + skew
        verifier = make_verifier([parent], time_source=lambda: clock[0])
        signer = PassportSigner(child, DIRECTORY_URL, time_source=lambda: clock[0])
        headers = signer.sign_request("GET", SITE_URL).as_headers()
        headers[DELEGATION_HEADER] = encode_delegation_header(statement)
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert result.valid is False
        assert result.failure_reason == "delegation statement has expired"

    async def test_signature_must_not_outlive_statement(self, parent: KeyPair) -> None:
        child, statement = mint_child(parent, validity_seconds=60)
        headers = delegated_headers(child, statement, validity_seconds=3600)
        result = await make_verifier([parent]).verify(
            method="GET", url=SITE_URL, headers=headers
        )
        assert result.valid is False
        assert result.failure_reason == "signature expires after the delegation window"

    async def test_child_jwk_thumbprint_binding(self, parent: KeyPair) -> None:
        """A parent-signed statement whose child_jwk does not match the
        child thumbprint is rejected — the JWK cannot be swapped."""
        child, statement = mint_child(parent)
        impostor = KeyPair.generate()
        swapped = resign(
            parent,
            statement.payload.model_copy(
                update={"child_jwk": key_to_jwk(impostor.verify_key)}
            ),
        )
        result = await make_verifier([parent]).verify(
            method="GET", url=SITE_URL, headers=delegated_headers(child, swapped)
        )
        assert result.valid is False
        assert result.failure_reason == "delegation child_jwk does not match the child thumbprint"

    async def test_keyid_must_match_child(self, parent: KeyPair) -> None:
        child_a, statement_a = mint_child(parent)
        child_b, _ = mint_child(parent)
        # child B signs, but presents A's statement.
        headers = delegated_headers(child_b, statement_a)
        result = await make_verifier([parent]).verify(
            method="GET", url=SITE_URL, headers=headers
        )
        assert result.valid is False
        assert result.failure_reason == "delegation child does not match the signing keyid"

    async def test_request_signature_must_be_childs(self, parent: KeyPair) -> None:
        """A stolen statement is useless without the child's private key."""
        child, statement = mint_child(parent)
        thief = KeyPair.generate()
        signer = PassportSigner(thief, DIRECTORY_URL)
        headers = signer.sign_request("GET", SITE_URL).as_headers()
        # Claim the child's keyid but sign with the thief's key.
        child_keyid = jwk_thumbprint(key_to_jwk(child.verify_key))
        thief_keyid = jwk_thumbprint(key_to_jwk(thief.verify_key))
        headers["Signature-Input"] = headers["Signature-Input"].replace(
            thief_keyid, child_keyid
        )
        headers[DELEGATION_HEADER] = encode_delegation_header(statement)
        result = await make_verifier([parent]).verify(
            method="GET", url=SITE_URL, headers=headers
        )
        assert result.valid is False
        assert result.failure_reason == "signature verification failed"

    async def test_delegation_with_required_assertion(self, parent: KeyPair) -> None:
        """require_assertion demands the PARENT's possession proof."""
        child, statement = mint_child(parent)
        with_proof = make_verifier(
            [parent],
            assertions=[sign_assertion(parent, DIRECTORY_URL)],
            require_assertion=True,
        )
        result = await with_proof.verify(
            method="GET", url=SITE_URL, headers=delegated_headers(child, statement)
        )
        assert result.valid is True and result.delegated is True

        without_proof = make_verifier([parent], assertions=[], require_assertion=True)
        result = await without_proof.verify(
            method="GET", url=SITE_URL, headers=delegated_headers(child, statement)
        )
        assert result.valid is False
        assert result.failure_reason == "no valid directory assertion for keyid"

    async def test_delegated_replay_is_detected(self, parent: KeyPair) -> None:
        child, statement = mint_child(parent)
        headers = delegated_headers(child, statement)
        verifier = make_verifier([parent], replay_cache=InMemoryNonceCache())
        first = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert first.valid is True
        second = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert second.valid is False
        assert second.failure_reason == "nonce replay detected"

    async def test_non_delegated_result_has_default_fields(self, parent: KeyPair) -> None:
        headers = PassportSigner(parent, DIRECTORY_URL).sign_request("GET", SITE_URL)
        result = await make_verifier([parent]).verify(
            method="GET", url=SITE_URL, headers=headers.as_headers()
        )
        assert result.valid is True
        assert result.delegated is False
        assert result.parent_did is None
        assert result.scope is None


# ---------------------------------------------------------------------------
# Property: any tampering with the statement invalidates the chain
# ---------------------------------------------------------------------------

_PROPERTY_PARENT = KeyPair.from_seed(b"delegation_property_seed_0000000")
_PROPERTY_CHILD, _PROPERTY_STATEMENT = mint_child(
    _PROPERTY_PARENT, scope="prop", validity_seconds=900, now=NOW
)


@given(
    field=st.sampled_from(["parent", "child", "scope", "nbf", "exp"]),
    fuzz=st.integers(min_value=1, max_value=1_000_000),
)
def test_delegation_tampering_property(field: str, fuzz: int) -> None:
    """Mutating any signed statement field breaks the parent signature."""
    import asyncio

    original = _PROPERTY_STATEMENT.payload
    value = getattr(original, field)
    mutated_value = value + fuzz if isinstance(value, int) else f"{value}x{fuzz}"
    tampered = _PROPERTY_STATEMENT.model_copy(
        update={"payload": original.model_copy(update={field: mutated_value})}
    )

    async def scenario() -> None:
        clock = [float(NOW + 5)]
        verifier = make_verifier([_PROPERTY_PARENT], time_source=lambda: clock[0])
        signer = PassportSigner(
            _PROPERTY_CHILD, DIRECTORY_URL, time_source=lambda: clock[0]
        )
        headers = signer.sign_request("GET", SITE_URL).as_headers()
        headers[DELEGATION_HEADER] = encode_delegation_header(tampered)
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert result.valid is False

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# DelegatedPassportAuth + wall principal mapping
# ---------------------------------------------------------------------------


class TestDelegatedAuthAndWall:
    async def test_auth_helper_attaches_all_headers(self, parent: KeyPair) -> None:
        child, statement = mint_child(parent)
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update({k.lower(): v for k, v in request.headers.items()})
            return httpx.Response(200, json={"ok": True})

        auth = DelegatedPassportAuth(child, statement, DIRECTORY_URL)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), auth=auth
        ) as client:
            response = await client.get(SITE_URL)
        assert response.status_code == 200
        assert "signature" in captured and "signature-input" in captured
        assert captured["signature-agent"] == f'"{DIRECTORY_URL}"'
        _, payload, _ = decode_delegation_header(captured["airlock-delegation"])
        assert payload == statement.payload

    async def test_wall_checks_parent_registration_for_children(
        self, parent: KeyPair
    ) -> None:
        from airlock.schemas.passport import (
            PassportStatus,
            PassportVerification,
            ReputationSummary,
        )
        from airlock.sdk.wall import PassportWallMiddleware

        child, statement = mint_child(parent, scope="read")
        status_paths: list[str] = []

        def registry_handler(request: httpx.Request) -> httpx.Response:
            status_paths.append(request.url.path)
            did = request.url.path.removeprefix("/passport/").removesuffix("/status")
            body = PassportStatus(
                did=did,
                registered=True,
                revoked=False,
                reputation=ReputationSummary(found=True, score=0.7),
            )
            return httpx.Response(200, content=body.model_dump_json())

        site = FastAPI()

        @site.get("/")
        async def home(request: Request) -> dict[str, object]:
            passport = request.state.passport
            assert isinstance(passport, PassportVerification)
            return {
                "delegated": passport.delegated,
                "parent_did": passport.parent_did,
                "scope": passport.scope,
            }

        site.add_middleware(
            PassportWallMiddleware,
            verifier=make_verifier([parent]),
            require_registered=True,
            registry_url="http://registry.test",
            registry_transport=httpx.MockTransport(registry_handler),
        )

        auth = DelegatedPassportAuth(child, statement, DIRECTORY_URL)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=site),
            base_url="http://protected.test",
            auth=auth,
        ) as client:
            response = await client.get("/")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["delegated"] is True
        assert body["parent_did"] == parent.did
        assert body["scope"] == "read"
        # The registry was consulted about the PARENT, never the child.
        assert status_paths == [f"/passport/{parent.did}/status"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_delegate_prints_usable_credential(tmp_path: object) -> None:
    from click.testing import CliRunner

    from airlock.cli import cli

    runner = CliRunner()
    key_file = f"{tmp_path}/parent.key"
    parent = KeyPair.from_seed(b"delegation_cli_seed_000000000000")
    with open(key_file, "w", encoding="utf-8") as fh:
        fh.write(parent.signing_key.encode().hex())

    result = runner.invoke(
        cli,
        [
            "passport",
            "delegate",
            "--scope",
            "read",
            "--minutes",
            "5",
            "--key-file",
            key_file,
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["scope"] == "read"
    assert payload["parent_thumbprint"] == jwk_thumbprint(key_to_jwk(parent.verify_key))

    child = KeyPair.from_seed(bytes.fromhex(payload["child_seed_hex"]))
    assert child.did == payload["child_did"]
    _, statement_payload, _ = decode_delegation_header(payload["delegation_header"])
    assert statement_payload.child == jwk_thumbprint(key_to_jwk(child.verify_key))
    assert statement_payload.exp - statement_payload.nbf == 300


def test_cli_delegate_without_key_fails_cleanly(tmp_path: object) -> None:
    from click.testing import CliRunner

    from airlock.cli import cli

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["passport", "delegate", "--key-file", f"{tmp_path}/missing.key"],
    )
    assert result.exit_code == 1
    assert "no passport key" in result.output
