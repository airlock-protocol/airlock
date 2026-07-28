"""Tests for static publication of the passport directory, assertions and CRL."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from airlock.crypto.keys import KeyPair
from airlock.passport.assertions import sign_assertion
from airlock.passport.base import DIRECTORY_MEDIA_TYPE
from airlock.passport.directory import jwk_to_did
from airlock.passport.publish import (
    ASSERTIONS_FILE,
    CRL_FILE,
    DIRECTORY_FILE,
    HEADERS_FILE,
    build_headers_file,
    build_static_artifacts,
    revoked_dids_from_crl,
    select_publishable,
    write_static_artifacts,
)
from airlock.schemas.crl import CRLEntry, SignedCRL
from airlock.schemas.identity import AgentCapability, AgentDID, AgentProfile
from airlock.schemas.passport import AssertionsDocument, SignatureDirectory


def _make_profile(
    keypair: KeyPair,
    *,
    status: str = "active",
    with_assertion: bool = False,
    label: str | None = None,
) -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did=keypair.did, public_key_multibase=keypair.public_key_multibase),
        display_name="Publish Test Agent",
        capabilities=[AgentCapability(name="test", version="1.0", description="t")],
        endpoint_url="https://agent.example.com",
        protocol_versions=["0.1.0"],
        status=status,  # type: ignore[arg-type]
        registered_at=datetime.now(UTC),
        passport_assertion=(
            sign_assertion(keypair, "https://registry.example") if with_assertion else None
        ),
        passport_label=label,
    )


def _make_crl(revoked: list[str]) -> SignedCRL:
    now = datetime.now(UTC)
    return SignedCRL(
        version=1,
        crl_number=1,
        issuer_did="did:key:z6MkIssuer",
        this_update=now,
        next_update=now + timedelta(seconds=60),
        max_cache_age_seconds=300,
        entries=[
            CRLEntry(did=did, status="revoked", reason="compromise", revoked_at=now)
            for did in revoked
        ],
        signature=None,
    )


def _directory_dids(artifacts: dict[str, str]) -> set[str]:
    directory = SignatureDirectory.from_untrusted(json.loads(artifacts[DIRECTORY_FILE]))
    return {jwk_to_did(jwk) for jwk in directory.keys}


def test_select_publishable_drops_inactive_and_revoked() -> None:
    active = KeyPair.generate()
    inactive = KeyPair.generate()
    revoked = KeyPair.generate()
    profiles = [
        _make_profile(active),
        _make_profile(inactive, status="inactive"),
        _make_profile(revoked),
    ]

    selected = select_publishable(profiles, revoked_dids={revoked.did})

    assert [p.did.did for p in selected] == [active.did]


def test_select_publishable_is_deterministically_ordered() -> None:
    keypairs = [KeyPair.generate() for _ in range(5)]
    profiles = [_make_profile(kp) for kp in keypairs]

    first = [p.did.did for p in select_publishable(profiles)]
    second = [p.did.did for p in select_publishable(list(reversed(profiles)))]

    assert first == second == sorted(kp.did for kp in keypairs)


def test_directory_is_a_valid_jwks_of_published_keys() -> None:
    keypairs = [KeyPair.generate() for _ in range(3)]
    artifacts = build_static_artifacts([_make_profile(kp) for kp in keypairs])

    assert _directory_dids(artifacts) == {kp.did for kp in keypairs}


def test_directory_and_crl_agree_on_revoked_agents() -> None:
    """A CRL supplied without an explicit revoked set still filters the directory."""
    live = KeyPair.generate()
    dead = KeyPair.generate()
    crl = _make_crl([dead.did])

    artifacts = build_static_artifacts([_make_profile(live), _make_profile(dead)], crl=crl)

    assert _directory_dids(artifacts) == {live.did}
    assert json.loads(artifacts[CRL_FILE])["crl_number"] == 1


def test_revoked_dids_from_crl_reads_every_entry() -> None:
    dids = [KeyPair.generate().did for _ in range(3)]

    assert revoked_dids_from_crl(_make_crl(dids)) == set(dids)


def test_assertions_document_only_carries_uploaded_proofs() -> None:
    with_proof = KeyPair.generate()
    without_proof = KeyPair.generate()

    artifacts = build_static_artifacts(
        [
            _make_profile(with_proof, with_assertion=True),
            _make_profile(without_proof),
        ]
    )

    document = AssertionsDocument.from_untrusted(json.loads(artifacts[ASSERTIONS_FILE]))
    assert len(document.assertions) == 1


def test_crl_is_omitted_when_not_supplied() -> None:
    artifacts = build_static_artifacts([_make_profile(KeyPair.generate())])

    assert CRL_FILE not in artifacts


def test_headers_file_pins_the_directory_media_type() -> None:
    headers = build_headers_file(300)

    assert f"/{DIRECTORY_FILE}" in headers
    assert f"Content-Type: {DIRECTORY_MEDIA_TYPE}" in headers
    assert "Cache-Control: max-age=300" in headers


def test_write_static_artifacts_creates_the_well_known_tree(tmp_path) -> None:
    artifacts = build_static_artifacts(
        [_make_profile(KeyPair.generate(), with_assertion=True)],
        crl=_make_crl([]),
    )

    written = write_static_artifacts(artifacts, tmp_path)

    for relative in (DIRECTORY_FILE, ASSERTIONS_FILE, CRL_FILE, HEADERS_FILE):
        target = tmp_path / relative
        assert target.is_file()
        assert target.read_text(encoding="utf-8") == artifacts[relative]
    assert len(written) == len(artifacts)
    assert (tmp_path / ".well-known").is_dir()
