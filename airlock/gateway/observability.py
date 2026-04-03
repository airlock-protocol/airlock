"""HTTP access logging and Prometheus-friendly request counters."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import Response

from airlock.gateway.metrics import HttpRequestMetrics

access_logger = logging.getLogger("airlock.gateway.access")


def _route_path(request: Request) -> str:
    """Use the matched route template when present (keeps Prometheus cardinality bounded)."""
    route = request.scope.get("route")
    path = getattr(route, "path", None) if route is not None else None
    if isinstance(path, str):
        return path
    return request.url.path.split("?", 1)[0] or "/"


def add_observability_middleware(app: FastAPI) -> None:
    """Register ``http`` middleware for access logs + :class:`HttpRequestMetrics` updates."""

    @app.middleware("http")
    async def _observability_middleware(request: Request, call_next: Any) -> Response:
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = rid
        status_code = 500
        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            metrics: HttpRequestMetrics | None = getattr(request.app.state, "http_metrics", None)
            path = _route_path(request)
            if metrics is not None:
                metrics.record(request.method, path, status_code, duration_ms)
            access_logger.info(
                "http_access",
                extra={
                    "request_id": rid,
                    "http_method": request.method,
                    "http_route": path,
                    "status_code": status_code,
                    "duration_ms": round(duration_ms, 3),
                },
            )
