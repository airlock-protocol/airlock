"""High-level SDK client for the Airlock trust verification protocol.

Provides a dead-simple interface so developers can verify an AI agent
in 7 lines of code::

    from airlock import AirlockClient

    client = AirlockClient()
    result = client.verify("did:key:z6Mk...")
    if result.verified:
        print(f"Trusted: {result.agent_name}")
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of verifying an agent through the Airlock gateway."""

    verified: bool
    agent_name: str
    trust_score: float
    verdict: str  # "VERIFIED" | "REJECTED" | "DEFERRED"
    seal_token: str | None = None
    session_id: str | None = None
    checks: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class AgentRegistration:
    """Confirmation returned after registering an agent with the gateway."""

    registered: bool
    did: str


class AirlockError(Exception):
    """Base exception for Airlock SDK errors."""


class GatewayUnreachableError(AirlockError):
    """Raised when the gateway cannot be reached."""


class VerificationFailedError(AirlockError):
    """Raised when a verification request fails at the transport level."""


class AirlockClient:
    """Simple SDK client for the Airlock trust verification protocol.

    Args:
        gateway_url: Base URL of a running Airlock gateway.
            Defaults to ``http://localhost:8000``.
        timeout: HTTP request timeout in seconds. Defaults to 30.
        service_token: Optional bearer token for authenticated endpoints.
    """

    def __init__(
        self,
        gateway_url: str = "http://localhost:8000",
        *,
        timeout: float = 30.0,
        service_token: str | None = None,
    ) -> None:
        self._base = gateway_url.rstrip("/")
        self._timeout = timeout
        self._service_token = service_token

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(
        self, did_or_url: str, *, poll_interval: float = 0.5, poll_timeout: float = 30.0
    ) -> VerifyResult:
        """Verify an agent by DID or endpoint URL.

        Resolves the agent, checks reputation, and returns a simple result.
        This is a synchronous convenience wrapper -- use :meth:`averify` in
        async code.

        Args:
            did_or_url: A ``did:key:z6Mk...`` string or an agent endpoint URL.
            poll_interval: Seconds between session-state polls while waiting
                for an async verdict (only applies to full handshake flow).
            poll_timeout: Maximum seconds to wait for a verdict.

        Returns:
            A :class:`VerifyResult` with the verification outcome.

        Raises:
            GatewayUnreachableError: If the gateway is not reachable.
            VerificationFailedError: If the request fails at the transport level.
        """
        return _run_sync(
            self.averify(did_or_url, poll_interval=poll_interval, poll_timeout=poll_timeout)
        )  # type: ignore[no-any-return]  # _run_sync returns Any from asyncio.run

    async def averify(
        self,
        did_or_url: str,
        *,
        poll_interval: float = 0.5,
        poll_timeout: float = 30.0,
    ) -> VerifyResult:
        """Async version of :meth:`verify`."""
        did = self._normalize_did(did_or_url)

        async with self._http_client() as http:
            # Step 1: Resolve the agent profile
            resolve_resp = await self._post(http, "/resolve", {"target_did": did})
            if not resolve_resp.get("found"):
                return VerifyResult(
                    verified=False,
                    agent_name="unknown",
                    trust_score=0.0,
                    verdict="REJECTED",
                )

            profile = resolve_resp.get("profile", {})
            agent_name = profile.get("display_name", "unknown")

            # Step 2: Check reputation score
            rep_resp = await self._get(http, f"/reputation/{did}")
            trust_score = float(rep_resp.get("score", 0.5))

            return VerifyResult(
                verified=trust_score >= 0.5 and rep_resp.get("found", False),
                agent_name=agent_name,
                trust_score=trust_score,
                verdict="VERIFIED"
                if trust_score >= 0.75
                else ("DEFERRED" if trust_score >= 0.5 else "REJECTED"),
                session_id=None,
            )

    def register(
        self,
        name: str,
        capabilities: list[dict[str, str]],
        *,
        endpoint_url: str = "https://localhost",
    ) -> AgentRegistration:
        """Register a new agent with the gateway.

        This is a synchronous convenience wrapper -- use :meth:`aregister` in
        async code.

        Args:
            name: Human-readable display name for the agent.
            capabilities: List of dicts with ``name``, ``version``, and
                ``description`` keys.
            endpoint_url: The agent's callback/service endpoint.

        Returns:
            An :class:`AgentRegistration` confirming success.

        Raises:
            GatewayUnreachableError: If the gateway is not reachable.
            AirlockError: If registration is rejected.
        """
        return _run_sync(self.aregister(name, capabilities, endpoint_url=endpoint_url))  # type: ignore[no-any-return]  # _run_sync returns Any from asyncio.run

    async def aregister(
        self,
        name: str,
        capabilities: list[dict[str, str]],
        *,
        endpoint_url: str = "https://localhost",
    ) -> AgentRegistration:
        """Async version of :meth:`register`."""
        from datetime import UTC, datetime

        from airlock.crypto.keys import KeyPair

        kp = KeyPair.generate()
        agent_did = kp.to_agent_did()

        caps = [
            {
                "name": c.get("name", "default"),
                "version": c.get("version", "1.0.0"),
                "description": c.get("description", ""),
            }
            for c in capabilities
        ]

        body = {
            "did": {"did": agent_did.did, "public_key_multibase": agent_did.public_key_multibase},
            "display_name": name,
            "capabilities": caps,
            "endpoint_url": endpoint_url,
            "protocol_versions": ["0.1.0"],
            "status": "active",
            "registered_at": datetime.now(UTC).isoformat(),
        }

        async with self._http_client() as http:
            resp = await self._post(http, "/register", body)

        return AgentRegistration(
            registered=resp.get("registered", False),
            did=resp.get("did", agent_did.did),
        )

    def health(self) -> dict[str, Any]:
        """Check gateway health. Synchronous convenience wrapper."""
        return _run_sync(self.ahealth())  # type: ignore[no-any-return]  # _run_sync returns Any from asyncio.run

    async def ahealth(self) -> dict[str, Any]:
        """Return gateway health status as a dict."""
        async with self._http_client() as http:
            return await self._get(http, "/health")

    def reputation(self, did: str) -> dict[str, Any]:
        """Look up an agent's trust score. Synchronous convenience wrapper."""
        return _run_sync(self.areputation(did))  # type: ignore[no-any-return]  # _run_sync returns Any from asyncio.run

    async def areputation(self, did: str) -> dict[str, Any]:
        """Return reputation data for an agent DID."""
        async with self._http_client() as http:
            return await self._get(http, f"/reputation/{did}")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _http_client(self) -> httpx.AsyncClient:
        headers: dict[str, str] = {}
        if self._service_token:
            headers["Authorization"] = f"Bearer {self._service_token}"
        return httpx.AsyncClient(
            base_url=self._base,
            timeout=httpx.Timeout(self._timeout),
            headers=headers,
        )

    @staticmethod
    def _normalize_did(did_or_url: str) -> str:
        if did_or_url.startswith("did:key:"):
            return did_or_url
        # Treat as endpoint URL -- not yet supported, return as-is
        return did_or_url

    async def _post(
        self, http: httpx.AsyncClient, path: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            resp = await http.post(path, json=body)
        except httpx.ConnectError as exc:
            raise GatewayUnreachableError(
                f"Cannot reach Airlock gateway at {self._base}: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise AirlockError(f"HTTP error: {exc}") from exc
        if resp.status_code >= 500:
            raise AirlockError(f"Gateway error ({resp.status_code}): {resp.text}")
        if resp.status_code >= 400:
            raise VerificationFailedError(f"Request rejected ({resp.status_code}): {resp.text}")
        result: dict[str, Any] = resp.json()
        return result

    async def _get(self, http: httpx.AsyncClient, path: str) -> dict[str, Any]:
        try:
            resp = await http.get(path)
        except httpx.ConnectError as exc:
            raise GatewayUnreachableError(
                f"Cannot reach Airlock gateway at {self._base}: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise AirlockError(f"HTTP error: {exc}") from exc
        if resp.status_code >= 500:
            raise AirlockError(f"Gateway error ({resp.status_code}): {resp.text}")
        if resp.status_code >= 400:
            raise VerificationFailedError(f"Request rejected ({resp.status_code}): {resp.text}")
        result: dict[str, Any] = resp.json()
        return result


def _run_sync(coro: Any) -> Any:
    """Run an async coroutine synchronously, handling nested event loops."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # We are inside an existing event loop (Jupyter, etc.)
        # Create a new thread to avoid blocking
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)
