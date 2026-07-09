"""Wall middleware tests: PassportWallMiddleware and the require_passport
dependency guarding a toy FastAPI site, with and without registry checks."""

from __future__ import annotations

import httpx
import pytest
from fastapi import Depends, FastAPI, Request

from airlock.crypto.keys import KeyPair
from airlock.passport.base import DIRECTORY_MEDIA_TYPE
from airlock.passport.directory import build_directory
from airlock.passport.httpx_auth import PassportAuth
from airlock.passport.signer import PassportSigner
from airlock.passport.verifier import PassportVerifier
from airlock.schemas.passport import PassportStatus, PassportVerification, ReputationSummary
from airlock.sdk.wall import (
    PassportWallMiddleware,
    register_wall_error_handler,
    require_passport,
)

DIRECTORY_URL = "https://directory.test"
SITE = "http://protected.test"


@pytest.fixture
def keypair() -> KeyPair:
    return KeyPair.from_seed(b"wall_test_seed_00000000000000000")


def directory_transport(kp: KeyPair) -> httpx.MockTransport:
    payload = build_directory([kp.verify_key]).model_dump_json(exclude_none=True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=payload, headers={"content-type": DIRECTORY_MEDIA_TYPE}
        )

    return httpx.MockTransport(handler)


def registry_transport(
    *, registered: bool = True, revoked: bool = False
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        did = request.url.path.removeprefix("/passport/").removesuffix("/status")
        status = PassportStatus(
            did=did,
            registered=registered,
            revoked=revoked,
            reputation=ReputationSummary(found=True, score=0.7, interaction_count=3),
            key_thumbprint=None,
        )
        return httpx.Response(200, content=status.model_dump_json())

    return httpx.MockTransport(handler)


def make_verifier(kp: KeyPair) -> PassportVerifier:
    return PassportVerifier(transport=directory_transport(kp), require_https=False)


def build_middleware_site(kp: KeyPair, **wall_kwargs: object) -> FastAPI:
    site = FastAPI()

    @site.get("/")
    async def home(request: Request) -> dict[str, str]:
        passport = request.state.passport
        assert isinstance(passport, PassportVerification)
        return {"agent_did": passport.agent_did or ""}

    wall_kwargs.setdefault("verifier", make_verifier(kp))
    site.add_middleware(PassportWallMiddleware, **wall_kwargs)  # type: ignore[arg-type]
    return site


def site_client(site: FastAPI, auth: httpx.Auth | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=site), base_url=SITE, auth=auth
    )


def make_auth(kp: KeyPair) -> PassportAuth:
    return PassportAuth(PassportSigner(kp, DIRECTORY_URL))


class TestWallMiddleware:
    async def test_unsigned_request_gets_structured_403(self, keypair: KeyPair) -> None:
        async with site_client(build_middleware_site(keypair)) as client:
            resp = await client.get("/")
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"] == "passport_required"
        assert body["status_code"] == 403
        assert "detail" in body

    async def test_signed_request_passes_and_attaches_state(
        self, keypair: KeyPair
    ) -> None:
        async with site_client(
            build_middleware_site(keypair), auth=make_auth(keypair)
        ) as client:
            resp = await client.get("/")
        assert resp.status_code == 200
        assert resp.json()["agent_did"] == keypair.did

    async def test_bad_signature_rejected(self, keypair: KeyPair) -> None:
        other = KeyPair.from_seed(b"imposter_seed_000000000000000000")
        async with site_client(
            build_middleware_site(keypair), auth=make_auth(other)
        ) as client:
            resp = await client.get("/")
        assert resp.status_code == 403
        assert resp.json()["error"] == "passport_invalid"

    async def test_exempt_paths_bypass_wall(self, keypair: KeyPair) -> None:
        site = build_middleware_site(keypair, exempt_paths=("/health",))

        @site.get("/health")
        async def health() -> dict[str, str]:
            return {"status": "ok"}

        async with site_client(site) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200

    async def test_require_registered_ok(self, keypair: KeyPair) -> None:
        site = build_middleware_site(
            keypair,
            require_registered=True,
            registry_url="http://registry.test",
            registry_transport=registry_transport(registered=True),
        )
        async with site_client(site, auth=make_auth(keypair)) as client:
            resp = await client.get("/")
        assert resp.status_code == 200

    async def test_require_registered_rejects_unregistered(
        self, keypair: KeyPair
    ) -> None:
        site = build_middleware_site(
            keypair,
            require_registered=True,
            registry_url="http://registry.test",
            registry_transport=registry_transport(registered=False),
        )
        async with site_client(site, auth=make_auth(keypair)) as client:
            resp = await client.get("/")
        assert resp.status_code == 403
        assert resp.json()["error"] == "agent_not_registered"

    async def test_require_registered_rejects_revoked(self, keypair: KeyPair) -> None:
        site = build_middleware_site(
            keypair,
            require_registered=True,
            registry_url="http://registry.test",
            registry_transport=registry_transport(registered=True, revoked=True),
        )
        async with site_client(site, auth=make_auth(keypair)) as client:
            resp = await client.get("/")
        assert resp.status_code == 403
        assert resp.json()["error"] == "agent_revoked"

    def test_require_registered_needs_registry_url(self) -> None:
        with pytest.raises(ValueError, match="registry_url"):
            require_passport(require_registered=True)


class TestRequirePassportDependency:
    def build_site(self, kp: KeyPair) -> FastAPI:
        site = FastAPI()
        register_wall_error_handler(site)
        dependency = require_passport(verifier=make_verifier(kp))

        @site.get("/guarded")
        async def guarded(
            passport: PassportVerification = Depends(dependency),
        ) -> dict[str, str]:
            return {"agent_did": passport.agent_did or ""}

        return site

    async def test_dependency_allows_signed(self, keypair: KeyPair) -> None:
        async with site_client(self.build_site(keypair), auth=make_auth(keypair)) as client:
            resp = await client.get("/guarded")
        assert resp.status_code == 200
        assert resp.json()["agent_did"] == keypair.did

    async def test_dependency_rejects_unsigned_with_structured_body(
        self, keypair: KeyPair
    ) -> None:
        async with site_client(self.build_site(keypair)) as client:
            resp = await client.get("/guarded")
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"] == "passport_required"
        assert body["status_code"] == 403
