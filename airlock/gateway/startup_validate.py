"""Fail-fast validation for production and high-assurance deployments."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from airlock.config import AirlockConfig

logger = logging.getLogger(__name__)

_VALID_VC_CAPABILITY_MODES = frozenset({"off", "audit", "warn", "enforce"})


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
    """Raise AirlockStartupError if settings are inconsistent with ``AIRLOCK_ENV=production``.

    Also validates settings that must be correct in ALL environments (dev + production).
    """
    # --- Universal validations (all environments) ---
    if cfg.vc_capability_mode not in _VALID_VC_CAPABILITY_MODES:
        raise AirlockStartupError(
            f"AIRLOCK_VC_CAPABILITY_MODE must be one of {sorted(_VALID_VC_CAPABILITY_MODES)}, "
            f"got {cfg.vc_capability_mode!r}"
        )

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

    if (
        getattr(cfg, "key_rotation_enabled", False)
        and cfg.expect_replicas > 1
        and not (cfg.redis_url or "").strip()
    ):
        raise AirlockStartupError(
            "Multi-replica key rotation requires AIRLOCK_REDIS_URL for a shared "
            "Redis-backed chain registry. Set AIRLOCK_REDIS_URL, reduce "
            "AIRLOCK_EXPECT_REPLICAS to 1, or disable key rotation with "
            "AIRLOCK_KEY_ROTATION_ENABLED=false."
        )

    # Soft warning for Redis Cluster — single-key Lua scripts work, but
    # other subsystems (revocation, rate limiting) are untested on Cluster.
    redis_url = (cfg.redis_url or "").strip()
    if redis_url and _looks_like_cluster(redis_url):
        logger.warning(
            "Redis Cluster detected (URL contains multiple hosts or cluster port). "
            "Airlock's rotation Lua scripts are single-key (Cluster-safe), but "
            "other subsystems (revocation, rate limiting) are untested on Cluster. "
            "Recommend Standard Redis + Sentinel for production. Data volume is "
            "<200MB -- Cluster is unnecessary for Airlock's workload."
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


def _looks_like_cluster(redis_url: str) -> bool:
    """Heuristic to detect Redis Cluster URLs.

    Returns True if the URL contains comma-separated hosts (common in
    Cluster configurations) or uses the ``rediss+cluster://`` scheme.
    """
    lower = redis_url.lower()
    if "cluster" in lower:
        return True
    # Multiple hosts separated by commas (e.g. redis://host1:6379,host2:6380)
    parsed = urlparse(redis_url)
    if parsed.netloc and "," in parsed.netloc:
        return True
    return False
