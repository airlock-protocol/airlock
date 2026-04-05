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
import logging
import os
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Central registry URL — the default trust verification endpoint.
#
# Every ``AirlockClient()`` and ``airlock verify`` call routes through this
# registry unless explicitly overridden.  The registry holds the global
# trust scores, issuer database, and reputation history.  Self-hosting is
# supported via the ``AIRLOCK_GATEWAY_URL`` env-var or the *gateway_url*
# constructor argument, but the central registry is the recommended default.
# ---------------------------------------------------------------------------
AIRLOCK_REGISTRY_URL = os.environ.get(
    "AIRLOCK_GATEWAY_URL",
    "https://api.airlock.ing",
)


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
        gateway_url: Base URL of an Airlock gateway.  Defaults to the
            central Airlock registry at ``https://api.airlock.ing``.
            Override with ``AIRLOCK_GATEWAY_URL`` env-var or pass explicitly
            to self-host.
        timeout: HTTP request timeout in seconds. Defaults to 30.
        service_token: Optional bearer token for authenticated endpoints.
    """

    def __init__(
        self,
        gateway_url: str = AIRLOCK_REGISTRY_URL,
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
        return _run_sync(  # type: ignore[no-any-return]
            self.averify(did_or_url, poll_interval=poll_interval, poll_timeout=poll_timeout)
        )

    async def averify(
        self,
        did_or_url: str,
        *,
        poll_interval: float = 0.5,
        poll_timeout: float = 30.0,
    ) -> VerifyResult:
        """Async version of :meth:`verify`."""
        from airlock.config import get_config  # noqa: PLC0415

        cfg = get_config()
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
                if trust_score >= cfg.scoring_threshold_high
                else ("DEFERRED" if trust_score >= cfg.scoring_initial else "REJECTED"),
                session_id=None,
            )

    # ------------------------------------------------------------------
    # Full 5-phase verification
    # ------------------------------------------------------------------

    def full_verify(
        self,
        target_did: str,
        *,
        probe_name: str = "airlock-probe",
        poll_interval: float = 0.5,
        poll_timeout: float = 30.0,
    ) -> VerifyResult:
        """Run the complete 5-phase Airlock verification protocol.

        Unlike :meth:`verify` which only checks reputation, this method
        registers a temporary probe agent, sends a signed handshake, and
        polls for the full verdict.  Synchronous convenience wrapper --
        use :meth:`afull_verify` in async code.

        Args:
            target_did: The ``did:key:z6Mk...`` of the agent to verify.
            probe_name: Display name for the ephemeral probe agent.
            poll_interval: Seconds between session-state polls.
            poll_timeout: Maximum seconds to wait for a verdict.

        Returns:
            A :class:`VerifyResult` with the full verification outcome.

        Raises:
            GatewayUnreachableError: If the gateway is not reachable.
            VerificationFailedError: If the handshake is rejected (NACK).
        """
        return _run_sync(  # type: ignore[no-any-return]
            self.afull_verify(
                target_did,
                probe_name=probe_name,
                poll_interval=poll_interval,
                poll_timeout=poll_timeout,
            )
        )

    async def afull_verify(
        self,
        target_did: str,
        *,
        probe_name: str = "airlock-probe",
        poll_interval: float = 0.5,
        poll_timeout: float = 30.0,
    ) -> VerifyResult:
        """Complete 5-phase verification against a target agent DID.

        Unlike :meth:`averify` which only checks reputation, this method
        executes the full protocol: register a probe agent, send a signed
        handshake, and wait for the verdict.

        Phases:
            1. Generate temporary probe + issuer keypairs
            2. Register the probe agent with the gateway
            3. Build a signed handshake request
            4. POST ``/handshake`` and obtain a session ACK
            5. Poll ``GET /session/{session_id}`` until a verdict is issued

        Args:
            target_did: The ``did:key:z6Mk...`` of the agent to verify.
            probe_name: Display name for the ephemeral probe agent.
            poll_interval: Seconds between session-state polls.
            poll_timeout: Maximum seconds to wait for a verdict.

        Returns:
            A :class:`VerifyResult` with the full verification outcome.

        Raises:
            GatewayUnreachableError: If the gateway is not reachable.
            VerificationFailedError: If the handshake is rejected (NACK).
        """
        from airlock.crypto.keys import KeyPair  # noqa: PLC0415
        from airlock.sdk.simple import (  # noqa: PLC0415
            build_signed_handshake,
            ensure_registered_profile,
        )

        # Phase 1: Generate temporary keypairs
        probe_kp = KeyPair.generate()
        issuer_kp = KeyPair.generate()

        async with self._http_client() as http:
            # Phase 2: Register probe agent
            profile = ensure_registered_profile(
                probe_kp,
                display_name=probe_name,
                endpoint_url="http://localhost:0",
                capabilities=[("verify-probe", "0.1.0", "SDK verification probe")],
            )
            try:
                await self._post(http, "/register", profile.model_dump(mode="json"))
            except VerificationFailedError:
                logger.debug("Probe registration returned 4xx (may already exist)")

            # Phase 3: Build signed handshake
            handshake = build_signed_handshake(
                agent_kp=probe_kp,
                issuer_kp=issuer_kp,
                target_did=target_did,
                action="verify_agent",
                description=f"Verification probe for {target_did}",
            )

            # Phase 4: POST /handshake
            try:
                ack_data = await self._post(http, "/handshake", handshake.model_dump(mode="json"))
            except VerificationFailedError as exc:
                # NACK — handshake was rejected at transport level
                return VerifyResult(
                    verified=False,
                    agent_name="unknown",
                    trust_score=0.0,
                    verdict="REJECTED",
                    session_id=None,
                    checks=[{"check": "handshake", "passed": False, "detail": str(exc)}],
                )

            session_id = ack_data.get("session_id", "")
            session_view_token = ack_data.get("session_view_token")

            # Phase 5: Poll GET /session/{session_id} until verdict
            headers: dict[str, str] = {}
            if session_view_token:
                headers["Authorization"] = f"Bearer {session_view_token}"

            result = await self._poll_session(
                http,
                session_id,
                extra_headers=headers,
                interval=poll_interval,
                timeout=poll_timeout,
            )

        return result

    async def _poll_session(
        self,
        http: httpx.AsyncClient,
        session_id: str,
        *,
        extra_headers: dict[str, str] | None = None,
        interval: float = 0.5,
        timeout: float = 30.0,
    ) -> VerifyResult:
        """Poll ``GET /session/{session_id}`` until a terminal state is reached."""
        terminal_states = {"verdict_issued", "sealed", "failed"}
        elapsed = 0.0

        while elapsed < timeout:
            try:
                resp = await http.get(
                    f"/session/{session_id}",
                    headers=extra_headers or {},
                )
                if resp.status_code == 404:
                    # Session not yet visible — retry
                    await asyncio.sleep(interval)
                    elapsed += interval
                    continue
                data: dict[str, Any] = resp.json()
            except httpx.ConnectError as exc:
                raise GatewayUnreachableError(
                    f"Cannot reach Airlock gateway at {self._base}: {exc}"
                ) from exc
            except httpx.HTTPError as exc:
                raise AirlockError(f"HTTP error polling session: {exc}") from exc

            state = data.get("state", "")
            if state in terminal_states:
                verdict_raw = data.get("verdict", "REJECTED") or "REJECTED"
                trust_score = float(data.get("trust_score") or 0.0)
                return VerifyResult(
                    verified=verdict_raw == "VERIFIED",
                    agent_name=data.get("initiator_did", "unknown"),
                    trust_score=trust_score,
                    verdict=verdict_raw,
                    seal_token=data.get("trust_token"),
                    session_id=session_id,
                )

            await asyncio.sleep(interval)
            elapsed += interval

        # Timed out waiting for verdict
        return VerifyResult(
            verified=False,
            agent_name="unknown",
            trust_score=0.0,
            verdict="DEFERRED",
            session_id=session_id,
            checks=[
                {"check": "timeout", "passed": False, "detail": f"No verdict after {timeout}s"}
            ],
        )

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

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
