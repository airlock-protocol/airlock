"""httpx integration: sign every outbound request with a passport.

Usage::

    signer = PassportSigner(keypair, "https://api.airlock.ing")
    client = httpx.Client(auth=PassportAuth(signer))          # sync
    aclient = httpx.AsyncClient(auth=PassportAuth(signer))    # async

Signing is pure CPU (no I/O), so a single ``auth_flow`` implementation
serves both the sync and async httpx request flows.
"""

from __future__ import annotations

from collections.abc import Generator

import httpx

from airlock.passport.signer import PassportSigner


class PassportAuth(httpx.Auth):
    """httpx auth hook that attaches web-bot-auth signature headers."""

    requires_request_body = False
    requires_response_body = False

    def __init__(self, signer: PassportSigner) -> None:
        self._signer = signer

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        headers = self._signer.sign_request(request.method, str(request.url))
        request.headers.update(headers.as_headers())
        yield request
