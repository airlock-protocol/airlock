from __future__ import annotations

from typing import Any

import httpx

from airlock.crypto.keys import KeyPair
from airlock.schemas.challenge import ChallengeResponse
from airlock.schemas.envelope import TransportAck, TransportNack
from airlock.schemas.handshake import HandshakeRequest
from airlock.schemas.identity import AgentProfile
from airlock.schemas.reputation import SignedFeedbackReport
from airlock.schemas.requests import HeartbeatRequest


class AirlockClient:
    """Async httpx wrapper for Airlock gateway endpoints."""

    def __init__(
        self,
        base_url: str,
        agent_keypair: KeyPair,
        *,
        timeout: float = 10.0,
        service_token: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._keypair = agent_keypair
        self._timeout = timeout
        self._service_token = (service_token or "").strip() or None
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout)
        return self._client

    def _service_headers(self) -> dict[str, str]:
        if self._service_token:
            return {"Authorization": f"Bearer {self._service_token}"}
        return {}

    def _parse_ack_or_nack(self, data: dict[str, Any]) -> TransportAck | TransportNack:
        if data.get("status") == "ACCEPTED":
            return TransportAck.model_validate(data)
        return TransportNack.model_validate(data)

    async def resolve(self, target_did: str) -> dict[str, Any]:
        resp = await self._get_client().post("/resolve", json={"target_did": target_did})
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def handshake(
        self,
        request: HandshakeRequest,
        callback_url: str | None = None,
    ) -> TransportAck | TransportNack:
        headers: dict[str, str] = {}
        if callback_url is not None:
            headers["X-Callback-Url"] = callback_url
        resp = await self._get_client().post(
            "/handshake",
            content=request.model_dump_json(),
            headers={"Content-Type": "application/json", **headers},
        )
        resp.raise_for_status()
        return self._parse_ack_or_nack(resp.json())

    async def submit_challenge_response(
        self, response: ChallengeResponse
    ) -> TransportAck | TransportNack:
        resp = await self._get_client().post(
            "/challenge-response",
            content=response.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return self._parse_ack_or_nack(resp.json())

    async def register(self, profile: AgentProfile) -> dict[str, Any]:
        resp = await self._get_client().post(
            "/register",
            content=profile.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def heartbeat(self, body: HeartbeatRequest) -> dict[str, Any]:
        resp = await self._get_client().post(
            "/heartbeat",
            content=body.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def submit_feedback(self, report: SignedFeedbackReport) -> dict[str, Any]:
        resp = await self._get_client().post(
            "/feedback",
            content=report.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def get_reputation(self, did: str) -> dict[str, Any]:
        resp = await self._get_client().get(f"/reputation/{did}")
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def get_session(
        self,
        session_id: str,
        *,
        session_view_token: str | None = None,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if session_view_token:
            headers["Authorization"] = f"Bearer {session_view_token}"
        resp = await self._get_client().get(f"/session/{session_id}", headers=headers)
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def health(self) -> dict[str, Any]:
        resp = await self._get_client().get("/health")
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def live(self) -> dict[str, Any]:
        resp = await self._get_client().get("/live")
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def ready(self) -> dict[str, Any]:
        resp = await self._get_client().get("/ready")
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def metrics(self) -> str:
        resp = await self._get_client().get("/metrics", headers=self._service_headers())
        resp.raise_for_status()
        return resp.text

    async def introspect_trust_token(self, token: str) -> dict[str, Any]:
        resp = await self._get_client().post(
            "/token/introspect",
            json={"token": token},
            headers={"Content-Type": "application/json", **self._service_headers()},
        )
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> AirlockClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
