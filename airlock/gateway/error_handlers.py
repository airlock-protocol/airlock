"""RFC 7807-style Problem Details for HTTP APIs (application/problem+json shape as JSON)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request, status
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse

from airlock.gateway.rate_limit import RateLimitResult

logger = logging.getLogger(__name__)

_PROBLEM_BASE = "https://airlock.ing/problems/"


class RateLimitExceeded(HTTPException):
    """HTTPException enriched with RFC 6585 rate-limit metadata."""

    def __init__(self, detail: str, rl: RateLimitResult) -> None:
        super().__init__(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)
        self.rate_limit_result: RateLimitResult = rl


def _problem_response(
    *,
    request: Request,
    status_code: int,
    type_path: str,
    title: str,
    detail: str | list[Any] | dict[str, Any],
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "type": _PROBLEM_BASE + type_path,
            "title": title,
            "status": status_code,
            "detail": detail,
            "instance": str(request.url.path),
        },
        headers=headers,
    )


def _rate_limit_headers(rl: RateLimitResult) -> dict[str, str]:
    """Build RFC 6585 rate-limit response headers."""
    return {
        "Retry-After": str(rl.retry_after),
        "X-RateLimit-Limit": str(rl.limit),
        "X-RateLimit-Remaining": str(rl.remaining),
        "X-RateLimit-Reset": str(int(rl.reset_at)),
    }


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    title = "HTTP Error"
    if exc.status_code == status.HTTP_404_NOT_FOUND:
        title = "Not Found"
    elif exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
        title = "Too Many Requests"
    elif exc.status_code == status.HTTP_401_UNAUTHORIZED:
        title = "Unauthorized"
    elif exc.status_code == status.HTTP_403_FORBIDDEN:
        title = "Forbidden"
    elif exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
        title = "Service Unavailable"
    detail: str | list[Any] | dict[str, Any]
    if isinstance(exc.detail, str):
        detail = exc.detail
    else:
        detail = exc.detail  # type: ignore[assignment]

    headers: dict[str, str] | None = None
    if isinstance(exc, RateLimitExceeded):
        headers = _rate_limit_headers(exc.rate_limit_result)

    return _problem_response(
        request=request,
        status_code=exc.status_code,
        type_path=f"http-{exc.status_code}",
        title=title,
        detail=detail,
        headers=headers,
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return _problem_response(
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        type_path="validation-error",
        title="Validation Error",
        detail=exc.errors(),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s: %s", request.url.path, exc)
    return _problem_response(
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        type_path="internal-error",
        title="Internal Server Error",
        detail="An unexpected error occurred",
    )


def register_error_handlers(app: Any) -> None:
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
