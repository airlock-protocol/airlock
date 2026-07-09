"""Airlock Passport end-to-end demo — no Docker, everything local.

Starts two servers on localhost:

1. An Airlock gateway (the registry) with ``passport_enabled=True``, which
   serves the Web Bot Auth key directory at
   ``/.well-known/http-message-signatures-directory``.
2. A toy "protected site" — a FastAPI app wrapped in
   ``PassportWallMiddleware``, standing in for a Cloudflare-style bot wall.

Then walks through the flow:

- a plain unsigned request is rejected with a structured 403;
- the agent self-registers its Ed25519 key with the registry;
- the same request, signed with ``PassportAuth``, returns 200 and the
  site echoes the verified agent DID.

Run:  python examples/passport_demo.py
"""

from __future__ import annotations

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
from airlock.passport.httpx_auth import PassportAuth
from airlock.passport.registration import directory_url_for_registry, register_passport
from airlock.passport.signer import PassportSigner
from airlock.passport.verifier import PassportVerifier
from airlock.sdk.wall import PassportWallMiddleware


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
    """A toy third-party site guarded by the Airlock passport wall."""
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


def main() -> None:
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
        import asyncio

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


if __name__ == "__main__":
    main()
