from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings


class AirlockConfig(BaseSettings):
    """Global configuration for the Airlock service."""

    model_config = {"env_prefix": "AIRLOCK_"}

    # development | production — production enables fail-fast validation and stricter defaults.
    env: Literal["development", "production"] = "development"

    host: str = "0.0.0.0"
    port: int = 8000
    session_ttl: int = 180
    heartbeat_ttl: int = 60
    lancedb_path: str = "./data/reputation.lance"
    litellm_model: str = "ollama/llama3"
    litellm_api_base: str = "http://localhost:11434"
    protocol_version: str = "0.1.0"

    # Production: set AIRLOCK_GATEWAY_SEED_HEX to 64 hex chars (32-byte Ed25519 seed).
    gateway_seed_hex: str = ""

    nonce_replay_ttl_seconds: float = 600.0
    rate_limit_per_ip_per_minute: int = Field(default=120, ge=1)
    rate_limit_handshake_per_did_per_minute: int = Field(default=30, ge=1)

    # Comma-separated origins, or "*" for dev (see app factory).
    cors_origins: str = "*"

    # When true, ``airlock.*`` logs are one JSON object per line (useful for Loki/Datadog).
    log_json: bool = False
    log_level: str = "INFO"

    # Default gateway URL for client SDKs (AIRLOCK_GATEWAY_URL overrides in sdk/simple.py).
    default_gateway_url: str = "http://127.0.0.1:8000"

    # Public HTTPS base URL for published agent cards (A2A). Fallback: default_gateway_url.
    public_base_url: str = ""

    # Optional upstream Airlock base URL for delegated POST /resolve (empty = local only).
    # Must be a trusted Airlock-compatible gateway in production (see startup validation).
    default_registry_url: str = ""

    # HS256 trust token issued only on VERIFIED (set secret in production).
    trust_token_secret: str = ""
    trust_token_ttl_seconds: int = Field(default=600, ge=60, le=86_400)

    # Comma-separated issuer DIDs; empty = any issuer (dev). Non-empty = VC issuer must match.
    vc_issuer_allowlist: str = ""

    # Sybil cap: max successful registrations per client IP per rolling hour (0 = disabled).
    register_max_per_ip_per_hour: int = Field(default=0, ge=0)

    # Optional Redis URL for shared nonce replay + rate limits across replicas (empty = in-memory).
    redis_url: str = ""

    # Admin API bearer token; empty disables ``/admin`` routes.
    admin_token: str = ""

    # Bearer token for relying-party / operator endpoints: ``GET /metrics``, ``POST /token/introspect``.
    # Required in production (non-empty). When set in development, those routes require this Bearer.
    service_token: str = ""

    # HS256 secret for short-lived session viewer JWTs (returned on handshake ACK when set).
    # Required in production. When set, ``GET /session`` and WS require ``Authorization: Bearer <token>``.
    session_view_secret: str = ""

    # Intended replica count for this deployment. If > 1, ``AIRLOCK_REDIS_URL`` is required in production.
    expect_replicas: int = Field(default=1, ge=1)

    # Event bus drain timeout during shutdown (seconds).
    event_bus_drain_timeout_seconds: float = Field(default=30.0, ge=1.0, le=600.0)

    @property
    def is_production(self) -> bool:
        return self.env == "production"
