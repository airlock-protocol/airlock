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
    trust_token_ttl_seconds: int = Field(default=120, ge=60, le=86_400)

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

    # Challenge fallback mode when LLM is unavailable: "ambiguous" (default) or "rule_based".
    challenge_fallback_mode: str = "ambiguous"

    # -----------------------------------------------------------------------
    # Scoring (generic defaults — production overrides via env vars)
    # -----------------------------------------------------------------------
    scoring_initial: float = 0.5
    scoring_half_life_days: float = 30.0
    scoring_verified_delta: float = 0.05
    scoring_rejected_delta: float = -0.15
    scoring_deferred_delta: float = -0.02
    scoring_threshold_high: float = 0.75
    scoring_threshold_blacklist: float = 0.15
    scoring_diminishing_factor: float = 0.1

    # -----------------------------------------------------------------------
    # Trust tier ceilings (overridable via env)
    # -----------------------------------------------------------------------
    scoring_tier_0_ceiling: float = 0.50
    scoring_tier_1_ceiling: float = 0.70
    scoring_tier_2_ceiling: float = 0.90
    scoring_tier_3_ceiling: float = 1.00

    # -----------------------------------------------------------------------
    # Per-tier decay half-lives (days)
    # -----------------------------------------------------------------------
    scoring_decay_half_life_tier_0: float = 30.0
    scoring_decay_half_life_tier_1: float = 90.0
    scoring_decay_half_life_tier_2: float = 180.0
    scoring_decay_half_life_tier_3: float = 365.0

    # Decay floor — agents with N+ successful verifications don't drop below this
    scoring_decay_floor: float = 0.60
    scoring_decay_floor_min_interactions: int = 10

    # -----------------------------------------------------------------------
    # Challenge questions (path to external JSON, empty = use built-in generic set)
    # -----------------------------------------------------------------------
    challenge_questions_path: str = ""

    # -----------------------------------------------------------------------
    # Rule evaluator thresholds (generic defaults)
    # -----------------------------------------------------------------------
    rule_keyword_density_max: float = 0.30
    rule_coherence_min: float = 0.25
    rule_complexity_min_words: int = 25
    rule_cross_domain_max: int = 3
    rule_min_answer_length: int = 20
    rule_min_sentences: int = 2

    # -----------------------------------------------------------------------
    # Proof-of-Work (anti-Sybil)
    # -----------------------------------------------------------------------
    pow_required: bool = False
    pow_difficulty: int = Field(default=20, ge=1, le=32)
    pow_ttl_seconds: int = Field(default=120, ge=30, le=600)
    pow_difficulty_new_did: int = Field(default=22, ge=1, le=32)

    # -----------------------------------------------------------------------
    # Privacy mode
    # -----------------------------------------------------------------------
    privacy_mode_default: str = "any"
    privacy_mode_allow_no_challenge: bool = True

    # -----------------------------------------------------------------------
    # LLM evaluation settings
    # -----------------------------------------------------------------------
    llm_structured_output: bool = True
    llm_dual_evaluation: bool = False
    litellm_model_secondary: str = ""
    litellm_api_base_secondary: str = ""

    # -----------------------------------------------------------------------
    # Answer fingerprinting (bot farm detection)
    # -----------------------------------------------------------------------
    fingerprint_enabled: bool = True
    fingerprint_hamming_threshold: int = Field(default=5, ge=0, le=10)
    fingerprint_window_size: int = Field(default=1000, ge=100, le=100000)
    fingerprint_exact_duplicate_action: str = "fail"
    fingerprint_near_duplicate_action: str = "flag"

    # -----------------------------------------------------------------------
    # CRL (Certificate Revocation List)
    # -----------------------------------------------------------------------
    crl_update_interval_seconds: int = Field(default=60, ge=30, le=600)
    crl_max_cache_age_seconds: int = Field(default=300, ge=60, le=3600)
    crl_emergency_cache_age_seconds: int = Field(default=3600, ge=300, le=86400)
    # Separate CRL signing key (hex-encoded 32-byte Ed25519 seed).
    # Falls back to gateway_seed_hex if empty.
    crl_signing_key_hex: str = ""

    # Event bus drain timeout during shutdown (seconds).
    event_bus_drain_timeout_seconds: float = Field(default=30.0, ge=1.0, le=600.0)

    @property
    def is_production(self) -> bool:
        return self.env == "production"


# ---------------------------------------------------------------------------
# Singleton accessor — avoids re-parsing env vars on every call.
# ---------------------------------------------------------------------------

_config_instance: AirlockConfig | None = None


def get_config() -> AirlockConfig:
    """Return the global AirlockConfig singleton (created on first call)."""
    global _config_instance  # noqa: PLW0603
    if _config_instance is None:
        _config_instance = AirlockConfig()
    return _config_instance


def _reset_config() -> None:
    """Reset the singleton — for use in tests only."""
    global _config_instance  # noqa: PLW0603
    _config_instance = None
