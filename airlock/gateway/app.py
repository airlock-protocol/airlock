from __future__ import annotations

"""FastAPI application factory for the Airlock gateway."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from airlock.config import AirlockConfig
from airlock.engine.event_bus import EventBus
from airlock.engine.orchestrator import VerificationOrchestrator
from airlock.engine.state import SessionManager
from airlock.reputation.store import ReputationStore

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
        reputation = ReputationStore(db_path=cfg.lancedb_path)
        reputation.open()

        session_mgr = SessionManager(default_ttl=cfg.session_ttl)
        await session_mgr.start()

        event_bus = EventBus(maxsize=1000)

        # Agent registry: DID -> AgentProfile (populated via POST /register)
        agent_registry: dict = {}

        # Heartbeat store: DID -> last_seen timestamp (populated via POST /heartbeat)
        heartbeat_store: dict = {}

        # Airlock identity — use a fixed seed for determinism; in production
        # this would be loaded from a secrets manager.
        from airlock.crypto.keys import KeyPair
        airlock_kp = KeyPair.from_seed(b"airlock_gateway_identity_seed_00")

        orchestrator = VerificationOrchestrator(
            reputation_store=reputation,
            agent_registry=agent_registry,
            airlock_did=airlock_kp.did,
            litellm_model=cfg.litellm_model,
            litellm_api_base=cfg.litellm_api_base,
        )
        event_bus.register(orchestrator.handle_event)
        await event_bus.start()

        app.state.config = cfg
        app.state.reputation = reputation
        app.state.session_mgr = session_mgr
        app.state.event_bus = event_bus
        app.state.orchestrator = orchestrator
        app.state.agent_registry = agent_registry
        app.state.heartbeat_store = heartbeat_store
        app.state.airlock_kp = airlock_kp

        logger.info("Airlock gateway started (did=%s)", airlock_kp.did)
        yield

        # ---- shutdown ----
        await event_bus.stop()
        await session_mgr.stop()
        reputation.close()
        logger.info("Airlock gateway stopped")

    app = FastAPI(
        title="Agentic Airlock",
        description="Open agent-to-agent trust and identity verification protocol",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from airlock.gateway.routes import register_routes
    register_routes(app)

    from airlock.gateway.a2a_routes import register_a2a_routes
    register_a2a_routes(app)

    return app
