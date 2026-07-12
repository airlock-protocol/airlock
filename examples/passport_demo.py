"""Airlock Passport end-to-end demo — no Docker, everything local.

Starts two servers on localhost:

1. An Airlock gateway (the registry) with ``passport_enabled=True``, which
   serves the Web Bot Auth key directory at
   ``/.well-known/http-message-signatures-directory``.
2. A toy "protected site" — a FastAPI app wrapped in
   ``PassportWallMiddleware``, standing in for a Cloudflare-style bot wall.

Default flow (Passport v0):

- a plain unsigned request is rejected with a structured 403;
- the agent self-registers its Ed25519 key with the registry;
- the same request, signed with ``PassportAuth``, returns 200 and the
  site echoes the verified agent DID.

``--v02`` runs the hosted-registry hardening flow instead
(draft-singh-webbotauth-hosted-directories-00): per-tenant directory
authorities, tenant-signed possession assertions enforced by the wall,
nonce replay rejection, and an EXPERIMENTAL delegated child credential
that is admitted and then cut off when its parent is revoked.

Run:  python examples/passport_demo.py [--v02]
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import tempfile
import threading
import time

import httpx
import uvicorn
from fastapi import FastAPI, Request

from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair
from airlock.gateway.app import create_app
from airlock.passport.assertions import WELL_KNOWN_ASSERTIONS_PATH, sign_assertion
from airlock.passport.base import WELL_KNOWN_DIRECTORY_PATH
from airlock.passport.delegation import DelegatedPassportAuth, mint_child
from airlock.passport.httpx_auth import PassportAuth
from airlock.passport.registration import (
    directory_url_for_registry,
    fetch_passport_status,
    register_passport,
)
from airlock.passport.replay import InMemoryNonceCache
from airlock.passport.signer import PassportSigner
from airlock.passport.verifier import PassportVerifier
from airlock.sdk.wall import PassportWallMiddleware

TENANT_BASE = "agents.airlock.test"


class ServerThread:
    """Run a uvicorn server on a background thread (cross-platform)."""

    def __init__(self, app: FastAPI, port: int) -> None:
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        deadline = time.monotonic() + 20
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("server did not start within 20s")
            time.sleep(0.05)

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def build_protected_site(registry_url: str) -> FastAPI:
    """A toy third-party site guarded by the Airlock passport wall (v0)."""
    site = FastAPI()

    @site.get("/")
    async def home(request: Request) -> dict[str, str]:
        passport = request.state.passport  # attached by the wall middleware
        return {
            "message": "welcome, verified agent",
            "agent_did": passport.agent_did or "",
            "keyid": passport.keyid or "",
        }

    # PassportWallMiddleware is pure ASGI; FastAPI apps compose via add_middleware.
    site.add_middleware(
        PassportWallMiddleware,
        # Local demo runs over plain HTTP, so relax the HTTPS-only default.
        verifier=PassportVerifier(require_https=False, cache_ttl_seconds=5.0),
        require_registered=True,
        registry_url=registry_url,
    )
    return site


def build_hardened_site(registry_url: str) -> FastAPI:
    """The v0.2 wall: assertions required, replays rejected, delegation on."""
    site = FastAPI()

    @site.get("/")
    async def home(request: Request) -> dict[str, object]:
        passport = request.state.passport
        return {
            "agent_did": passport.agent_did or "",
            "delegated": passport.delegated,
            "parent_did": passport.parent_did or "",
            "scope": passport.scope or "",
        }

    site.add_middleware(
        PassportWallMiddleware,
        verifier=PassportVerifier(
            require_https=False,
            cache_ttl_seconds=1.0,  # short so revocation propagates fast
            require_assertion=True,
            replay_cache=InMemoryNonceCache(),
            allow_delegation=True,
        ),
        require_registered=True,
        registry_url=registry_url,
        registry_cache_ttl_seconds=1.0,
    )
    return site


def run_v0() -> None:
    print("=" * 72)
    print("Airlock Passport demo - Web Bot Auth (RFC 9421) end to end")
    print("=" * 72)

    tmpdir = tempfile.mkdtemp(prefix="airlock-passport-demo-")

    # ------------------------------------------------------------------
    # 1. Start the registry (Airlock gateway with the passport flag on)
    #    and the protected site (toy bot wall).
    # ------------------------------------------------------------------
    gateway_port = free_port()
    registry_url = f"http://127.0.0.1:{gateway_port}"
    gateway_app = create_app(
        AirlockConfig(lancedb_path=f"{tmpdir}/reputation.lance", passport_enabled=True)
    )
    gateway = ServerThread(gateway_app, gateway_port)
    gateway.start()
    print(f"\n[1] Registry running at {registry_url}")
    print(f"    Key directory: {directory_url_for_registry(registry_url)}")

    site_port = free_port()
    site_url = f"http://127.0.0.1:{site_port}"
    site = ServerThread(build_protected_site(registry_url), site_port)
    site.start()
    print(f"    Protected site running at {site_url} (wall: require_registered=True)")

    try:
        # --------------------------------------------------------------
        # 2. Unsigned request → the wall rejects it.
        # --------------------------------------------------------------
        print("\n[2] Plain unsigned request (no passport)...")
        response = httpx.get(site_url + "/")
        print(f"    -> HTTP {response.status_code}: {response.json()}")
        assert response.status_code == 403

        # --------------------------------------------------------------
        # 3. Self-register a passport with the registry.
        # --------------------------------------------------------------
        print("\n[3] Registering a passport key with the registry...")
        keypair = KeyPair.generate()

        result = asyncio.run(
            register_passport(keypair, registry_url, display_name="Demo Passport Agent")
        )
        print(f"    -> registered={result.registered}")
        print(f"       DID: {result.did}")

        status = httpx.get(f"{registry_url}/passport/{keypair.did}/status")
        print(f"       Registry status: {status.json()}")

        # --------------------------------------------------------------
        # 4. Signed request → the wall verifies and lets us through.
        # --------------------------------------------------------------
        print("\n[4] Same request, signed with the passport...")
        signer = PassportSigner(keypair, directory_url=registry_url)
        with httpx.Client(auth=PassportAuth(signer)) as client:
            response = client.get(site_url + "/")
        print(f"    -> HTTP {response.status_code}: {response.json()}")
        assert response.status_code == 200
        assert response.json()["agent_did"] == keypair.did

        print("\n" + "=" * 72)
        print("Success: unsigned traffic blocked (403), passported agent verified")
        print("cryptographically and against the registry, then admitted (200).")
        print("=" * 72)
    finally:
        site.stop()
        gateway.stop()


def run_v02() -> None:
    print("=" * 72)
    print("Airlock Passport v0.2 demo - hosted registry hardening")
    print("(tenant directories / possession assertions / replay / delegation)")
    print("=" * 72)

    tmpdir = tempfile.mkdtemp(prefix="airlock-passport-v02-demo-")

    gateway_port = free_port()
    registry_url = f"http://127.0.0.1:{gateway_port}"
    gateway_app = create_app(
        AirlockConfig(
            lancedb_path=f"{tmpdir}/registry.lance",
            passport_enabled=True,
            passport_tenant_domain_base=TENANT_BASE,
        )
    )
    gateway = ServerThread(gateway_app, gateway_port)
    gateway.start()
    print(f"\n[1] Registry running at {registry_url}")
    print(f"    Tenant domain base: {TENANT_BASE}")

    site_port = free_port()
    site_url = f"http://127.0.0.1:{site_port}"
    site = ServerThread(build_hardened_site(registry_url), site_port)
    site.start()
    print(f"    Hardened site at {site_url}")
    print("    (wall: require_assertion + replay cache + allow_delegation)")

    try:
        # --------------------------------------------------------------
        # 2. Register "Alice" with a tenant-signed possession assertion.
        # --------------------------------------------------------------
        print("\n[2] Registering Alice with a signed directory assertion...")
        alice = KeyPair.generate()
        assertion = sign_assertion(alice, registry_url)
        result = asyncio.run(
            register_passport(alice, registry_url, display_name="Alice", assertion=assertion)
        )
        status = asyncio.run(fetch_passport_status(registry_url, alice.did))
        assert status is not None
        print(f"    -> registered={result.registered}  DID: {result.did}")
        print(f"       tenant label:       {status.passport_label}")
        print(f"       personal directory: {status.tenant_directory_url}")

        # --------------------------------------------------------------
        # 3. Per-tenant directory authority (Host-header routing).
        # --------------------------------------------------------------
        print("\n[3] Tenant directory: one authority per tenant...")
        tenant_host = f"{status.passport_label}.{TENANT_BASE}"
        directory = httpx.get(
            registry_url + WELL_KNOWN_DIRECTORY_PATH, headers={"Host": tenant_host}
        )
        print(f"    GET {WELL_KNOWN_DIRECTORY_PATH} (Host: {tenant_host})")
        print(f"    -> HTTP {directory.status_code}, keys: {len(directory.json()['keys'])}")
        assert directory.status_code == 200 and len(directory.json()["keys"]) == 1

        ghost = httpx.get(
            registry_url + WELL_KNOWN_DIRECTORY_PATH,
            headers={"Host": f"ghost.{TENANT_BASE}"},
        )
        print(f"    Unknown label 'ghost' -> HTTP {ghost.status_code} (structured 404)")
        assert ghost.status_code == 404

        assertions_doc = httpx.get(registry_url + WELL_KNOWN_ASSERTIONS_PATH)
        print(
            f"    Assertions document: {len(assertions_doc.json()['assertions'])} "
            "tenant-signed possession proof(s) published"
        )

        # --------------------------------------------------------------
        # 4. Signed request through the assertion-enforcing wall.
        # --------------------------------------------------------------
        print("\n[4] Alice's signed request (wall verifies key AND assertion)...")
        signer = PassportSigner(alice, directory_url=registry_url)
        with httpx.Client(auth=PassportAuth(signer)) as client:
            response = client.get(site_url + "/")
        print(f"    -> HTTP {response.status_code}: {response.json()}")
        assert response.status_code == 200

        # --------------------------------------------------------------
        # 5. Replay: the identical signed request is rejected.
        # --------------------------------------------------------------
        print("\n[5] Replaying one captured signed request...")
        captured = signer.sign_request("GET", site_url + "/").as_headers()
        first = httpx.get(site_url + "/", headers=captured)
        second = httpx.get(site_url + "/", headers=captured)
        print(f"    first send  -> HTTP {first.status_code}")
        print(f"    replay      -> HTTP {second.status_code}: {second.json()['detail']}")
        assert first.status_code == 200 and second.status_code == 403
        assert "replay" in second.json()["detail"]

        # --------------------------------------------------------------
        # 6. EXPERIMENTAL delegation: visitor pass for a sub-agent.
        # --------------------------------------------------------------
        print("\n[6] Delegation: Alice mints a 15-minute child credential...")
        child, statement = mint_child(alice, scope="fetch", validity_seconds=900)
        child_auth = DelegatedPassportAuth(child, statement, registry_url)
        with httpx.Client(auth=child_auth) as client:
            response = client.get(site_url + "/")
        body = response.json()
        print(f"    child request -> HTTP {response.status_code}: {body}")
        assert response.status_code == 200
        assert body["delegated"] is True and body["parent_did"] == alice.did

        print("\n[7] Revoking Alice at the registry (parent removal)...")
        asyncio.run(gateway_app.state.revocation_store.revoke(alice.did))
        time.sleep(1.3)  # let the wall's 1s directory + status caches lapse
        with httpx.Client(auth=child_auth) as client:
            response = client.get(site_url + "/")
        print(f"    child request -> HTTP {response.status_code}: {response.json()['detail']}")
        assert response.status_code == 403

        print("\n" + "=" * 72)
        print("Success: tenant-scoped directory served, possession assertion")
        print("enforced, replayed signature rejected, delegated child admitted")
        print("and automatically cut off after parent revocation.")
        print("=" * 72)
    finally:
        site.stop()
        gateway.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--v02",
        action="store_true",
        help="run the v0.2 hosted-registry hardening flow "
        "(tenant directories, assertions, replay, delegation)",
    )
    args = parser.parse_args()
    if args.v02:
        run_v02()
    else:
        run_v0()


if __name__ == "__main__":
    main()
