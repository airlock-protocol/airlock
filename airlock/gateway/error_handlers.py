"""RFC 7807-style Problem Details for HTTP APIs (application/problem+json shape as JSON)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request, status
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

_PROBLEM_BASE = "https://airlock.ing/problems/"


def _problem_response(
    *,
    request: Request,
    status_code: int,
    type_path: str,
    title: str,
    detail: str | list[Any] | dict[str, Any],
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
    )


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
    if isinstance(exc.detail, (str, list, dict)):
        detail = exc.detail
    else:
        detail = str(exc.detail)
    return _problem_response(
        request=request,
        status_code=exc.status_code,
        type_path=f"http-{exc.status_code}",
        title=title,
        detail=detail,
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return _problem_response(
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        type_path="validation-error",
        title="Validation Error",
        detail=list(exc.errors()),
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
