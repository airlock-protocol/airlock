"""Wall-side Web Bot Auth enforcement for third-party sites.

Two integration styles:

- :class:`PassportWallMiddleware` — pure ASGI middleware. Rejects
  unsigned/invalid requests with a structured 403 and attaches the
  :class:`~airlock.schemas.passport.PassportVerification` to
  ``request.state.passport`` for downstream handlers.
- :func:`require_passport` — a FastAPI dependency factory for per-route
  enforcement. Pair it with :func:`register_wall_error_handler` to get the
  same structured 403 body (without the handler, FastAPI wraps the error
  in its default ``{"detail": ...}`` envelope).

With ``require_registered=True`` the wall additionally checks the agent
against an Airlock registry's ``GET /passport/{did}/status`` endpoint and
rejects unregistered or revoked agents. Registry lookups fail closed: if
the registry is unreachable the request is rejected.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from airlock.passport.replay import NonceCache
from airlock.passport.verifier import PassportVerifier
from airlock.schemas.passport import PassportStatus, PassportVerification, WallErrorBody

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class _PassportGate:
    """Shared verification + registry-check logic for middleware and deps."""

    def __init__(
        self,
        *,
        verifier: PassportVerifier | None,
        require_registered: bool,
        registry_url: str | None,
        registry_timeout: float,
        registry_cache_ttl_seconds: float,
        registry_transport: httpx.AsyncBaseTransport | None,
        replay_cache: NonceCache | None = None,
        require_nonce: bool = False,
    ) -> None:
        if require_registered and not registry_url:
            raise ValueError("require_registered=True needs a registry_url")
        if verifier is not None and (replay_cache is not None or require_nonce):
            raise ValueError(
                "replay_cache/require_nonce apply to the default verifier only; "
                "configure them on your PassportVerifier instead"
            )
        self._verifier = verifier or PassportVerifier(
            replay_cache=replay_cache, require_nonce=require_nonce
        )
        self._require_registered = require_registered
        self._registry_url = (registry_url or "").rstrip("/")
        self._registry_timeout = registry_timeout
        self._registry_cache_ttl = registry_cache_ttl_seconds
        self._registry_transport = registry_transport
        self._registry_client: httpx.AsyncClient | None = None
        self._status_cache: dict[str, tuple[float, WallErrorBody | None]] = {}

    async def evaluate(
        self, method: str, url: str, headers: MutableMapping[str, str] | Any
    ) -> tuple[PassportVerification, WallErrorBody | None]:
        """Verify one request; returns (verification, error-or-None)."""
        result = await self._verifier.verify(method=method, url=url, headers=headers)
        if not result.valid:
            reason = result.failure_reason or "invalid passport signature"
            error = "passport_required" if "missing" in reason else "passport_invalid"
            return result, WallErrorBody(error=error, detail=reason, status_code=403)

        if self._require_registered:
            # For delegated requests the registered principal is the PARENT
            # that minted the child; the registry never sees children.
            principal = result.parent_did if result.delegated else result.agent_did
            if principal is not None:
                registry_error = await self._check_registered(principal)
                if registry_error is not None:
                    return result, registry_error
        return result, None

    async def _check_registered(self, did: str) -> WallErrorBody | None:
        now = time.monotonic()
        cached = self._status_cache.get(did)
        if cached is not None and now - cached[0] < self._registry_cache_ttl:
            return cached[1]

        error: WallErrorBody | None
        try:
            client = self._get_registry_client()
            response = await client.get(f"/passport/{did}/status")
            if response.status_code != 200:
                error = WallErrorBody(
                    error="registry_check_failed",
                    detail=f"registry returned HTTP {response.status_code} for agent status",
                    status_code=403,
                )
            else:
                status = PassportStatus.model_validate(response.json())
                if not status.registered:
                    error = WallErrorBody(
                        error="agent_not_registered",
                        detail=f"agent {did} is not registered with the registry",
                        status_code=403,
                    )
                elif status.revoked:
                    error = WallErrorBody(
                        error="agent_revoked",
                        detail=f"agent {did} has been revoked",
                        status_code=403,
                    )
                else:
                    error = None
        except httpx.HTTPError as exc:
            logger.warning("Registry status check failed for %s: %s", did, exc)
            error = WallErrorBody(
                error="registry_check_failed",
                detail=f"could not reach registry: {exc}",
                status_code=403,
            )
        self._status_cache[did] = (now, error)
        return error

    def _get_registry_client(self) -> httpx.AsyncClient:
        if self._registry_client is None:
            self._registry_client = httpx.AsyncClient(
                base_url=self._registry_url,
                timeout=httpx.Timeout(self._registry_timeout),
                transport=self._registry_transport,
            )
        return self._registry_client


class PassportWallMiddleware:
    """Pure ASGI middleware that enforces web-bot-auth passports.

    Args:
        app: The wrapped ASGI application.
        verifier: A configured :class:`PassportVerifier` (defaults to one
            with production settings — HTTPS-only directories).
        require_registered: Also require the agent to be registered and
            non-revoked at ``registry_url``.
        registry_url: Airlock registry base URL (needed when
            ``require_registered`` is on).
        exempt_paths: Path prefixes that bypass the wall (e.g. ``/health``).
        replay_cache: Optional nonce replay cache for the default verifier
            (rejects re-sent signatures within their validity window).
        require_nonce: Reject signatures without a nonce (default verifier
            only). Both replay options are off by default.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: PassportVerifier | None = None,
        require_registered: bool = False,
        registry_url: str | None = None,
        exempt_paths: tuple[str, ...] = (),
        registry_timeout: float = 10.0,
        registry_cache_ttl_seconds: float = 30.0,
        registry_transport: httpx.AsyncBaseTransport | None = None,
        replay_cache: NonceCache | None = None,
        require_nonce: bool = False,
    ) -> None:
        self.app = app
        self._exempt_paths = exempt_paths
        self._gate = _PassportGate(
            verifier=verifier,
            require_registered=require_registered,
            registry_url=registry_url,
            registry_timeout=registry_timeout,
            registry_cache_ttl_seconds=registry_cache_ttl_seconds,
            registry_transport=registry_transport,
            replay_cache=replay_cache,
            require_nonce=require_nonce,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if any(path.startswith(prefix) for prefix in self._exempt_paths):
            await self.app(scope, receive, send)
            return

        headers = _headers_from_scope(scope)
        url = _url_from_scope(scope, headers)
        result, error = await self._gate.evaluate(scope["method"], url, headers)

        if error is not None:
            response = JSONResponse(status_code=error.status_code, content=error.model_dump())
            await response(scope, receive, send)
            return

        scope.setdefault("state", {})["passport"] = result
        await self.app(scope, receive, send)


def require_passport(
    *,
    verifier: PassportVerifier | None = None,
    require_registered: bool = False,
    registry_url: str | None = None,
    registry_timeout: float = 10.0,
    registry_cache_ttl_seconds: float = 30.0,
    registry_transport: httpx.AsyncBaseTransport | None = None,
    replay_cache: NonceCache | None = None,
    require_nonce: bool = False,
) -> Callable[[Request], Awaitable[PassportVerification]]:
    """Build a FastAPI dependency that enforces a valid passport.

    Returns the :class:`PassportVerification` for valid requests and
    raises :class:`PassportRejectedError` (HTTP 403) otherwise. Reuses a
    verification already attached by :class:`PassportWallMiddleware`.
    ``replay_cache``/``require_nonce`` configure the default verifier's
    replay protection (off by default).
    """
    gate = _PassportGate(
        verifier=verifier,
        require_registered=require_registered,
        registry_url=registry_url,
        registry_timeout=registry_timeout,
        registry_cache_ttl_seconds=registry_cache_ttl_seconds,
        registry_transport=registry_transport,
        replay_cache=replay_cache,
        require_nonce=require_nonce,
    )

    async def dependency(request: Request) -> PassportVerification:
        existing = getattr(request.state, "passport", None)
        if isinstance(existing, PassportVerification) and existing.valid:
            return existing
        result, error = await gate.evaluate(
            request.method, str(request.url), request.headers
        )
        if error is not None:
            raise PassportRejectedError(error)
        return result

    return dependency


class PassportRejectedError(HTTPException):
    """403 raised by :func:`require_passport`; carries the structured body."""

    def __init__(self, body: WallErrorBody) -> None:
        super().__init__(status_code=body.status_code, detail=body.detail)
        self.body = body


def register_wall_error_handler(app: FastAPI) -> None:
    """Emit ``{error, detail, status_code}`` bodies for passport rejections."""

    async def _handler(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, PassportRejectedError)
        return JSONResponse(status_code=exc.body.status_code, content=exc.body.model_dump())

    app.add_exception_handler(PassportRejectedError, _handler)


# ---------------------------------------------------------------------------
# ASGI scope helpers
# ---------------------------------------------------------------------------


def _headers_from_scope(scope: Scope) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", []):
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        if name in headers:
            headers[name] = f"{headers[name]}, {value}"
        else:
            headers[name] = value
    return headers


def _url_from_scope(scope: Scope, headers: dict[str, str]) -> str:
    scheme = scope.get("scheme", "http")
    authority = headers.get("host")
    if not authority:
        server = scope.get("server")
        if server is not None:
            host, port = server
            authority = host if port is None else f"{host}:{port}"
        else:
            authority = "localhost"
    path = scope.get("raw_path", b"").decode("latin-1") or scope.get("path", "/")
    query = scope.get("query_string", b"").decode("latin-1")
    url = f"{scheme}://{authority}{path}"
    return f"{url}?{query}" if query else url
