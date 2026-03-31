"""Fail-fast validation for production and high-assurance deployments."""

from __future__ import annotations

from urllib.parse import urlparse

from airlock.config import AirlockConfig


class AirlockStartupError(RuntimeError):
    """Raised when configuration is unsafe for the requested deployment mode."""


def _valid_gateway_seed(hex_str: str) -> bool:
    s = (hex_str or "").strip()
    if len(s) != 64:
        return False
    try:
        return len(bytes.fromhex(s)) == 32
    except ValueError:
        return False


def validate_startup_config(cfg: AirlockConfig) -> None:
    """Raise AirlockStartupError if settings are inconsistent with ``AIRLOCK_ENV=production``."""
    if not cfg.is_production:
        return

    if not _valid_gateway_seed(cfg.gateway_seed_hex):
        raise AirlockStartupError(
            "Production requires AIRLOCK_GATEWAY_SEED_HEX (64 hex chars = 32-byte Ed25519 seed)."
        )

    if (cfg.cors_origins or "").strip() in {"", "*"}:
        raise AirlockStartupError(
            "Production requires explicit AIRLOCK_CORS_ORIGINS (wildcard * is not allowed)."
        )

    if not (cfg.vc_issuer_allowlist or "").strip():
        raise AirlockStartupError(
            "Production requires non-empty AIRLOCK_VC_ISSUER_ALLOWLIST (comma-separated issuer DIDs)."
        )

    if not (cfg.service_token or "").strip():
        raise AirlockStartupError(
            "Production requires AIRLOCK_SERVICE_TOKEN for /metrics and /token/introspect."
        )

    if not (cfg.session_view_secret or "").strip():
        raise AirlockStartupError(
            "Production requires AIRLOCK_SESSION_VIEW_SECRET for session and WebSocket access."
        )

    if cfg.expect_replicas > 1 and not (cfg.redis_url or "").strip():
        raise AirlockStartupError(
            "Production with AIRLOCK_EXPECT_REPLICAS > 1 requires AIRLOCK_REDIS_URL for shared replay and rate limits."
        )

    reg = (cfg.default_registry_url or "").strip()
    if reg:
        parsed = urlparse(reg)
        if parsed.scheme not in ("http", "https"):
            raise AirlockStartupError(
                f"AIRLOCK_DEFAULT_REGISTRY_URL must be http(s), got scheme={parsed.scheme!r}"
            )
        if not parsed.netloc:
            raise AirlockStartupError(
                "AIRLOCK_DEFAULT_REGISTRY_URL must include a host (trusted upstream registry)."
            )
