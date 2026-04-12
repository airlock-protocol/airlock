"""FastAPI application factory for the Airlock gateway."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from airlock.audit.trail import AuditStore, AuditTrail
from airlock.config import AirlockConfig
from airlock.engine.event_bus import EventBus
from airlock.engine.orchestrator import VerificationOrchestrator
from airlock.engine.state import SessionManager
from airlock.gateway.crl import CRLGenerator
from airlock.gateway.identity import gateway_keypair_from_config
from airlock.gateway.logging_config import configure_airlock_logging
from airlock.gateway.metrics import HttpRequestMetrics
from airlock.gateway.observability import add_observability_middleware
from airlock.gateway.policy import parse_did_allowlist
from airlock.gateway.rate_limit import DIDRateLimiter, InMemorySlidingWindow, RedisSlidingWindow
from airlock.gateway.replay import InMemoryReplayGuard, RedisReplayGuard
from airlock.gateway.revocation import RedisRevocationStore, RevocationStore
from airlock.gateway.startup_validate import AirlockStartupError, validate_startup_config
from airlock.registry.agent_store import AgentRegistryStore
from airlock.reputation.store import ReputationStore
from airlock.rotation.precommit_store import PreCommitmentStore

logger = logging.getLogger(__name__)


def create_app(config: AirlockConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    All shared state (EventBus, SessionManager, ReputationStore, Orchestrator)
    is attached to app.state so handlers can access it via request.app.state.
    """
    cfg = config or AirlockConfig()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        # ---- startup ----
        try:
            validate_startup_config(cfg)
        except AirlockStartupError as exc:
            logger.error("Startup aborted: %s", exc)
            raise

        # Argon2id fail-fast: production + argon2id enabled requires argon2-cffi
        if cfg.is_production and cfg.pow_algorithm == "argon2id":
            from airlock.pow import argon2_available

            if not argon2_available():
                raise RuntimeError(
                    "pow_algorithm is 'argon2id' but argon2-cffi is not installed. "
                    "Install with: pip install argon2-cffi"
                )

        configure_airlock_logging(log_json=cfg.log_json, log_level=cfg.log_level)
        app.state.started_at_monotonic = time.monotonic()
        app.state.shutting_down = False

        reputation = ReputationStore(db_path=cfg.lancedb_path)
        reputation.open()

        agent_store = AgentRegistryStore(db_path=cfg.lancedb_path)
        agent_store.open()

        session_mgr = SessionManager(default_ttl=cfg.session_ttl)
        await session_mgr.start()

        event_bus = EventBus(maxsize=1000)

        agent_registry: dict[str, Any] = {}
        agent_store.hydrate_mapping(agent_registry)

        heartbeat_store: dict[str, Any] = {}

        airlock_kp = gateway_keypair_from_config(
            cfg.gateway_seed_hex,
            allow_demo_fallback=not cfg.is_production,
        )

        redis_url = (cfg.redis_url or "").strip()
        redis_client = None
        if redis_url:
            from redis.asyncio import Redis as RedisAsync

            redis_client = RedisAsync.from_url(redis_url, decode_responses=True)
            await redis_client.ping()  # type: ignore[misc]  # redis.asyncio.ping() has overloaded return type
            nonce_guard: InMemoryReplayGuard | RedisReplayGuard = RedisReplayGuard(
                redis_client,
                ttl_seconds=cfg.nonce_replay_ttl_seconds,
            )
            rate_limit_ip: RedisSlidingWindow | InMemorySlidingWindow = RedisSlidingWindow(
                redis_client,
                max_events=cfg.rate_limit_per_ip_per_minute,
                window_seconds=60.0,
            )
            _did_backend: RedisSlidingWindow | InMemorySlidingWindow = RedisSlidingWindow(
                redis_client,
                max_events=cfg.rate_limit_handshake_per_did_per_minute,
                window_seconds=60.0,
            )
        else:
            nonce_guard = InMemoryReplayGuard(ttl_seconds=cfg.nonce_replay_ttl_seconds)
            rate_limit_ip = InMemorySlidingWindow(
                max_events=cfg.rate_limit_per_ip_per_minute,
                window_seconds=60.0,
            )
            _did_backend = InMemorySlidingWindow(
                max_events=cfg.rate_limit_handshake_per_did_per_minute,
                window_seconds=60.0,
            )

        did_rate_limiter = DIDRateLimiter(_did_backend)

        vc_allowed = parse_did_allowlist(cfg.vc_issuer_allowlist)
        rate_limit_register_hour: RedisSlidingWindow | InMemorySlidingWindow | None = None
        if cfg.register_max_per_ip_per_hour > 0:
            if redis_client is not None:
                rate_limit_register_hour = RedisSlidingWindow(
                    redis_client,
                    max_events=cfg.register_max_per_ip_per_hour,
                    window_seconds=3600.0,
                )
            else:
                rate_limit_register_hour = InMemorySlidingWindow(
                    max_events=cfg.register_max_per_ip_per_hour,
                    window_seconds=3600.0,
                )

        revocation_store: RevocationStore | RedisRevocationStore
        if redis_client is not None:
            revocation_store = RedisRevocationStore(redis_client)
            await revocation_store.sync_cache()
        else:
            revocation_store = RevocationStore()

        # ---- CRL generator ----
        crl_signing_seed = (cfg.crl_signing_key_hex or "").strip()
        if len(crl_signing_seed) == 64:
            try:
                from nacl.signing import SigningKey as _NaClSigningKey

                crl_signing_key = _NaClSigningKey(bytes.fromhex(crl_signing_seed))
            except (ValueError, Exception):
                crl_signing_key = airlock_kp.signing_key
        else:
            crl_signing_key = airlock_kp.signing_key

        crl_generator = CRLGenerator(
            revocation_store=revocation_store,
            signing_key=crl_signing_key,
            issuer_did=airlock_kp.did,
            update_interval_seconds=cfg.crl_update_interval_seconds,
            max_cache_age_seconds=cfg.crl_max_cache_age_seconds,
        )

        audit_store: AuditStore | None = None
        if cfg.audit_trail_persist:
            from pathlib import Path as _Path

            _Path(cfg.audit_db_path).parent.mkdir(parents=True, exist_ok=True)
            audit_store = AuditStore(cfg.audit_db_path)
            audit_store.open()
            logger.info("Persistent audit trail enabled (path=%s)", cfg.audit_db_path)

        audit_trail = AuditTrail(store=audit_store)

        # Key rotation chain registry (created early so orchestrator can reference it)
        chain_registry: Any = None
        precommit_store: Any = None
        if cfg.key_rotation_enabled:
            if redis_client is not None:
                from airlock.rotation.redis_chain import RedisRotationChainRegistry
                from airlock.rotation.redis_precommit import RedisPreCommitmentStore

                chain_registry = RedisRotationChainRegistry(redis_client)
                await chain_registry.reconcile_index()
                precommit_store = RedisPreCommitmentStore(redis_client)
            else:
                from airlock.rotation.chain import RotationChainRegistry

                _chain_path = (cfg.rotation_chain_store_path or "").strip() or None
                chain_registry = RotationChainRegistry(path=_chain_path)
                _precommit_path = (cfg.precommit_store_path or "").strip() or None
                precommit_store = PreCommitmentStore(path=_precommit_path)
        if precommit_store is None:
            precommit_store = PreCommitmentStore()

        _tok = (cfg.trust_token_secret or "").strip()
        orchestrator = VerificationOrchestrator(
            reputation_store=reputation,
            agent_registry=agent_registry,
            airlock_did=airlock_kp.did,
            litellm_model=cfg.litellm_model,
            litellm_api_base=cfg.litellm_api_base,
            trust_token_secret=_tok or None,
            trust_token_ttl_seconds=cfg.trust_token_ttl_seconds,
            session_mgr=session_mgr,
            vc_allowed_issuers=vc_allowed,
            revocation_store=revocation_store,
            airlock_keypair=airlock_kp,
            chain_registry=chain_registry,
        )
        event_bus.register(orchestrator.handle_event)
        await event_bus.start()

        app.state.config = cfg
        app.state.reputation = reputation
        app.state.agent_store = agent_store
        app.state.session_mgr = session_mgr
        app.state.event_bus = event_bus
        app.state.orchestrator = orchestrator
        app.state.agent_registry = agent_registry
        app.state.heartbeat_store = heartbeat_store
        app.state.revocation_store = revocation_store
        app.state.crl_generator = crl_generator
        app.state.audit_trail = audit_trail
        app.state.airlock_kp = airlock_kp
        app.state.nonce_guard = nonce_guard
        app.state.rate_limit_ip = rate_limit_ip
        app.state.did_rate_limiter = did_rate_limiter
        app.state.rate_limit_register_hour = rate_limit_register_hour
        app.state.http_metrics = HttpRequestMetrics()
        app.state.pow_challenges = {}  # dict[str, Any]
        app.state.redis_client = redis_client

        # Key rotation — assign chain_registry (created above) and precommit store
        app.state.chain_registry = chain_registry
        app.state.precommit_store = precommit_store

        # OAuth 2.1 store
        if cfg.oauth_enabled:
            from airlock.oauth.store import OAuthStore as _OAuthStore

            app.state.oauth_store = _OAuthStore()
        else:
            app.state.oauth_store = None

        # Argon2id bounded verification worker pool
        import asyncio as _asyncio

        app.state.argon2id_semaphore = _asyncio.Semaphore(cfg.pow_argon2id_max_concurrent)

        registry_url = (cfg.default_registry_url or "").strip().rstrip("/")
        if registry_url:
            app.state.registry_http_client = httpx.AsyncClient(
                base_url=registry_url,
                timeout=httpx.Timeout(10.0),
            )
        else:
            app.state.registry_http_client = None

        logger.info(
            "Airlock gateway started (did=%s env=%s redis=%s session_view=%s service_auth=%s)",
            airlock_kp.did,
            cfg.env,
            bool((cfg.redis_url or "").strip()),
            bool((cfg.session_view_secret or "").strip()),
            bool((cfg.service_token or "").strip()),
        )
        yield

        # ---- shutdown ----
        app.state.shutting_down = True
        reg_client = getattr(app.state, "registry_http_client", None)
        if reg_client is not None:
            await reg_client.aclose()
        drain_timeout = float(cfg.event_bus_drain_timeout_seconds)
        await event_bus.drain(timeout=drain_timeout)
        await event_bus.stop()
        await session_mgr.stop()
        if audit_store is not None:
            audit_store.close()
        reputation.close()
        agent_store.close()
        rc = getattr(app.state, "redis_client", None)
        if rc is not None:
            await rc.aclose()
        logger.info("Airlock gateway stopped")

    app = FastAPI(
        title="Agentic Airlock",
        description="Open agent-to-agent trust and identity verification protocol",
        version="0.4.0",
        lifespan=lifespan,
    )

    from airlock.gateway.error_handlers import register_error_handlers

    register_error_handlers(app)

    def _cors_origins() -> list[str]:
        raw = (cfg.cors_origins or "*").strip()
        if raw == "*":
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["*"],
        allow_headers=["*"],
    )

    add_observability_middleware(app)

    from airlock.gateway.routes import register_routes

    register_routes(app)

    from airlock.gateway.a2a_routes import register_a2a_routes

    register_a2a_routes(app)

    if cfg.oauth_enabled:
        from airlock.gateway.oauth_routes import register_oauth_routes

        register_oauth_routes(app)

    if (cfg.admin_token or "").strip():
        from airlock.gateway.admin_routes import router as admin_router

        app.include_router(admin_router)

    return app
