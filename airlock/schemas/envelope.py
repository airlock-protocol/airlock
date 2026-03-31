from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel


class MessageEnvelope(BaseModel):
    protocol_version: str
    timestamp: datetime
    sender_did: str
    nonce: str


class TransportAck(BaseModel):
    status: Literal["ACCEPTED"]
    session_id: str
    timestamp: datetime
    envelope: MessageEnvelope
    # Short-lived JWT when AIRLOCK_SESSION_VIEW_SECRET is set (Authorization: Bearer for /session + WS).
    session_view_token: str | None = None


class TransportNack(BaseModel):
    status: Literal["REJECTED"]
    session_id: str | None = None
    reason: str
    error_code: str
    timestamp: datetime
    envelope: MessageEnvelope


def generate_nonce() -> str:
    return secrets.token_hex(16)


def create_envelope(sender_did: str, protocol_version: str = "0.1.0") -> MessageEnvelope:
    return MessageEnvelope(
        protocol_version=protocol_version,
        timestamp=datetime.now(timezone.utc),
        sender_did=sender_did,
        nonce=generate_nonce(),
    )
