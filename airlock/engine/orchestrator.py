from __future__ import annotations

"""VerificationOrchestrator: LangGraph state machine for the 5-phase Airlock protocol.

Node map (8 nodes):
  resolve            -> validate_schema
  validate_schema    -> verify_signature  (or failed)
  verify_signature   -> validate_vc       (or failed)
  validate_vc        -> check_reputation  (or failed)
  check_reputation   -> semantic_challenge | issue_verdict (fast-path / blacklist)
  semantic_challenge -> issue_verdict
  issue_verdict      -> seal_session
  seal_session       -> END
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from airlock.crypto.keys import resolve_public_key
from airlock.crypto.signing import verify_model
from airlock.crypto.vc import validate_credential
from airlock.reputation.scoring import routing_decision
from airlock.reputation.store import ReputationStore
from airlock.schemas.challenge import ChallengeRequest, ChallengeResponse
from airlock.schemas.envelope import MessageEnvelope, generate_nonce
from airlock.schemas.events import (
    AnyVerificationEvent,
    ChallengeIssued,
    ChallengeResponseReceived,
    HandshakeReceived,
    ResolveRequested,
    SessionSealed,
    VerdictReady,
    VerificationFailed,
)
from airlock.schemas.handshake import HandshakeRequest
from airlock.schemas.identity import AgentProfile
from airlock.schemas.session import SessionSeal, VerificationSession, VerificationState
from airlock.schemas.verdict import (
    AirlockAttestation,
    CheckResult,
    TrustVerdict,
    VerificationCheck,
)
from airlock.semantic.challenge import (
    ChallengeOutcome,
    evaluate_response,
    generate_challenge,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LangGraph state schema
# ---------------------------------------------------------------------------

class OrchestrationState(TypedDict, total=False):
    """Mutable state threaded through all graph nodes for one session."""

    session: VerificationSession
    handshake: HandshakeRequest
    challenge: ChallengeRequest | None
    challenge_response: ChallengeResponse | None
    check_results: list[CheckResult]
    trust_score: float
    verdict: TrustVerdict | None
    error: str | None
    failed_at: str | None
    # Routing signals (set by nodes, read by conditional edges)
    _sig_valid: bool
    _vc_valid: bool
    _routing: str          # 'fast_path' | 'challenge' | 'blacklist'
    _challenge_outcome: str | None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class VerificationOrchestrator:
    """Event-driven verification orchestrator backed by a LangGraph state machine.

    Usage:
        orchestrator = VerificationOrchestrator(reputation_store, agent_registry,
                                                airlock_keypair, config)
        await orchestrator.handle_event(event)
    """

    def __init__(
        self,
        reputation_store: ReputationStore,
        agent_registry: dict[str, AgentProfile],
        airlock_did: str,
        litellm_model: str = "ollama/llama3",
        litellm_api_base: str | None = None,
        # Callback hooks — set by the gateway to deliver async messages
        on_challenge: Any | None = None,   # async (session_id, ChallengeRequest) -> None
        on_verdict: Any | None = None,     # async (session_id, TrustVerdict, AirlockAttestation) -> None
        on_seal: Any | None = None,        # async (session_id, SessionSeal) -> None
    ) -> None:
        self._reputation = reputation_store
        self._registry = agent_registry
        self._airlock_did = airlock_did
        self._model = litellm_model
        self._api_base = litellm_api_base
        self._on_challenge = on_challenge
        self._on_verdict = on_verdict
        self._on_seal = on_seal

        # Pending challenge responses keyed by session_id
        self._pending_challenges: dict[str, ChallengeRequest] = {}

        self._graph = self._build_graph()

    # ------------------------------------------------------------------
    # Public event dispatcher
    # ------------------------------------------------------------------

    async def handle_event(self, event: AnyVerificationEvent) -> None:
        """Route an incoming event to the appropriate handler."""
        etype = event.event_type

        if etype == "resolve_requested":
            await self._handle_resolve(event)  # type: ignore[arg-type]
        elif etype == "handshake_received":
            await self._handle_handshake(event)  # type: ignore[arg-type]
        elif etype == "challenge_response_received":
            await self._handle_challenge_response(event)  # type: ignore[arg-type]
        elif etype == "verification_failed":
            logger.warning(
                "Verification failed for session %s at %s: %s",
                event.session_id,
                getattr(event, "failed_at", "unknown"),
                getattr(event, "error", ""),
            )
        else:
            logger.debug("Orchestrator ignoring event type: %s", etype)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _handle_resolve(self, event: ResolveRequested) -> None:
        did = event.target_did
        profile = self._registry.get(did)
        if profile:
            logger.info("Resolve: found agent %s", did)
        else:
            logger.info("Resolve: agent %s not in registry", did)

    async def _handle_handshake(self, event: HandshakeReceived) -> None:
        """Run the full verification graph for a new handshake."""
        request = event.request
        session_id = event.session_id

        now = datetime.now(timezone.utc)
        session = VerificationSession(
            session_id=session_id,
            state=VerificationState.HANDSHAKE_RECEIVED,
            initiator_did=request.initiator.did,
            target_did=request.intent.target_did,
            callback_url=event.callback_url,
            created_at=now,
            updated_at=now,
            handshake_request=request,
        )

        initial: OrchestrationState = {
            "session": session,
            "handshake": request,
            "challenge": None,
            "challenge_response": None,
            "check_results": [],
            "trust_score": 0.5,
            "verdict": None,
            "error": None,
            "failed_at": None,
            "_sig_valid": False,
            "_vc_valid": False,
            "_routing": "challenge",
            "_challenge_outcome": None,
        }

        # Run the graph synchronously through all nodes.
        # The graph ends at END after semantic_challenge (challenge path) or
        # after seal_session (fast-path / blacklist).
        final_state = await self._run_graph(initial)

        routing = final_state.get("_routing", "challenge")

        if routing == "challenge" and final_state.get("verdict") is None:
            # Generate the semantic challenge asynchronously (LLM call)
            capabilities = list(request.initiator.__dict__.get("capabilities", []))
            # Fall back to empty list if capabilities not on AgentDID
            challenge = await generate_challenge(
                session_id=session_id,
                capabilities=capabilities,
                airlock_did=self._airlock_did,
                litellm_model=self._model,
                litellm_api_base=self._api_base,
            )
            self._pending_challenges[session_id] = challenge
            if self._on_challenge:
                await self._on_challenge(session_id, challenge)
            return

        # Fast-path or blacklist — verdict already set by the graph
        await self._deliver_verdict(final_state)

    async def _handle_challenge_response(
        self, event: ChallengeResponseReceived
    ) -> None:
        """Resume a paused session with the agent's challenge response."""
        session_id = event.session_id
        challenge = self._pending_challenges.pop(session_id, None)
        if challenge is None:
            logger.warning(
                "No pending challenge for session %s — ignoring response", session_id
            )
            return

        # Evaluate the response
        outcome, justification = await evaluate_response(
            challenge,
            event.response,
            self._model,
            self._api_base,
        )

        verdict_map = {
            ChallengeOutcome.PASS: TrustVerdict.VERIFIED,
            ChallengeOutcome.FAIL: TrustVerdict.REJECTED,
            ChallengeOutcome.AMBIGUOUS: TrustVerdict.DEFERRED,
        }
        verdict = verdict_map[outcome]

        # Fetch the current trust score for attestation
        score_record = self._reputation.get_or_default(
            event.response.envelope.sender_did
            if event.response.envelope.sender_did
            else "unknown"
        )

        check = CheckResult(
            check=VerificationCheck.SEMANTIC,
            passed=(outcome == ChallengeOutcome.PASS),
            detail=justification,
        )

        # Build a minimal final state for delivery
        now = datetime.now(timezone.utc)
        envelope = MessageEnvelope(
            protocol_version="0.1.0",
            timestamp=now,
            sender_did=self._airlock_did,
            nonce=generate_nonce(),
        )
        attestation = AirlockAttestation(
            session_id=session_id,
            verified_did=score_record.agent_did,
            checks_passed=[check],
            trust_score=score_record.score,
            verdict=verdict,
            issued_at=now,
        )
        seal = SessionSeal(
            envelope=envelope,
            session_id=session_id,
            verdict=verdict,
            checks_passed=[check],
            trust_score=score_record.score,
            sealed_at=now,
        )

        # Update reputation
        self._reputation.apply_verdict(score_record.agent_did, verdict)

        if self._on_verdict:
            await self._on_verdict(session_id, verdict, attestation)
        if self._on_seal:
            await self._on_seal(session_id, seal)

        logger.info(
            "Session %s sealed after challenge: %s", session_id, verdict.value
        )

    # ------------------------------------------------------------------
    # Graph execution
    # ------------------------------------------------------------------

    async def _run_graph(self, state: OrchestrationState) -> OrchestrationState:
        """Invoke the LangGraph state machine synchronously (nodes are sync)."""
        result = self._graph.invoke(state)
        return result  # type: ignore[return-value]

    async def _deliver_verdict(self, state: OrchestrationState) -> None:
        """Issue verdict + seal callbacks and update reputation."""
        session = state["session"]
        verdict = state.get("verdict") or TrustVerdict.REJECTED
        trust_score = state.get("trust_score", 0.5)
        checks = state.get("check_results", [])

        now = datetime.now(timezone.utc)
        envelope = MessageEnvelope(
            protocol_version="0.1.0",
            timestamp=now,
            sender_did=self._airlock_did,
            nonce=generate_nonce(),
        )
        attestation = AirlockAttestation(
            session_id=session.session_id,
            verified_did=session.initiator_did,
            checks_passed=checks,
            trust_score=trust_score,
            verdict=verdict,
            issued_at=now,
        )
        seal = SessionSeal(
            envelope=envelope,
            session_id=session.session_id,
            verdict=verdict,
            checks_passed=checks,
            trust_score=trust_score,
            sealed_at=now,
        )

        # Update reputation for terminal verdicts
        if verdict in (TrustVerdict.VERIFIED, TrustVerdict.REJECTED):
            self._reputation.apply_verdict(session.initiator_did, verdict)

        if self._on_verdict:
            await self._on_verdict(session.session_id, verdict, attestation)
        if self._on_seal:
            await self._on_seal(session.session_id, seal)

        logger.info(
            "Session %s sealed: %s (score=%.4f)",
            session.session_id,
            verdict.value,
            trust_score,
        )

    # ------------------------------------------------------------------
    # LangGraph node definitions
    # ------------------------------------------------------------------

    def _node_validate_schema(self, state: OrchestrationState) -> OrchestrationState:
        """Node 1: validate the HandshakeRequest schema (already done by Pydantic on parse)."""
        checks: list[CheckResult] = list(state.get("check_results", []))
        checks.append(
            CheckResult(check=VerificationCheck.SCHEMA, passed=True, detail="Pydantic validation passed")
        )
        state["check_results"] = checks
        state["session"].state = VerificationState.HANDSHAKE_RECEIVED
        return state

    def _node_verify_signature(self, state: OrchestrationState) -> OrchestrationState:
        """Node 2: verify the Ed25519 signature on the HandshakeRequest."""
        checks: list[CheckResult] = list(state.get("check_results", []))
        request = state["handshake"]

        try:
            verify_key = resolve_public_key(request.initiator.did)
            valid = verify_model(request, verify_key)
        except Exception as exc:
            valid = False
            logger.debug("Signature verification error: %s", exc)

        checks.append(
            CheckResult(
                check=VerificationCheck.SIGNATURE,
                passed=valid,
                detail="Ed25519 signature valid" if valid else "Signature verification failed",
            )
        )
        state["check_results"] = checks
        state["_sig_valid"] = valid
        if valid:
            state["session"].state = VerificationState.SIGNATURE_VERIFIED
        else:
            state["error"] = "Invalid signature"
            state["failed_at"] = "verify_signature"
            state["verdict"] = TrustVerdict.REJECTED
            state["session"].state = VerificationState.FAILED
        return state

    def _node_validate_vc(self, state: OrchestrationState) -> OrchestrationState:
        """Node 3: validate the Verifiable Credential attached to the handshake."""
        checks: list[CheckResult] = list(state.get("check_results", []))
        request = state["handshake"]
        vc = request.credential

        try:
            issuer_verify_key = resolve_public_key(vc.issuer)
            valid, reason = validate_credential(vc, issuer_verify_key)
        except Exception as exc:
            valid = False
            reason = str(exc)

        checks.append(
            CheckResult(
                check=VerificationCheck.CREDENTIAL,
                passed=valid,
                detail=reason,
            )
        )
        state["check_results"] = checks
        state["_vc_valid"] = valid
        if valid:
            state["session"].state = VerificationState.CREDENTIAL_VALIDATED
        else:
            state["error"] = f"VC validation failed: {reason}"
            state["failed_at"] = "validate_vc"
            state["verdict"] = TrustVerdict.REJECTED
            state["session"].state = VerificationState.FAILED
        return state

    def _node_check_reputation(self, state: OrchestrationState) -> OrchestrationState:
        """Node 4: look up trust score and decide routing."""
        checks: list[CheckResult] = list(state.get("check_results", []))
        initiator_did = state["session"].initiator_did

        score_record = self._reputation.get_or_default(initiator_did)
        routing = routing_decision(score_record.score)

        checks.append(
            CheckResult(
                check=VerificationCheck.REPUTATION,
                passed=(routing != "blacklist"),
                detail=f"score={score_record.score:.4f} routing={routing}",
            )
        )
        state["check_results"] = checks
        state["trust_score"] = score_record.score
        state["_routing"] = routing

        if routing == "blacklist":
            state["verdict"] = TrustVerdict.REJECTED
            state["error"] = "Agent is blacklisted (trust score below threshold)"
            state["failed_at"] = "check_reputation"
            state["session"].state = VerificationState.FAILED
        elif routing == "fast_path":
            state["verdict"] = TrustVerdict.VERIFIED
            state["session"].state = VerificationState.VERDICT_ISSUED

        return state

    def _node_semantic_challenge(self, state: OrchestrationState) -> OrchestrationState:
        """Node 5: generate a semantic challenge (sync wrapper — actual LLM call is async).

        In the sync graph we use a pre-built placeholder; the real async
        generation happens in _handle_handshake before the graph is invoked
        when routing == 'challenge'.  This node records that a challenge was
        issued and sets the session state.
        """
        # The challenge is already generated and stored in state by the async
        # wrapper in _handle_handshake.  Here we just mark the state.
        state["session"].state = VerificationState.CHALLENGE_ISSUED
        return state

    def _node_issue_verdict(self, state: OrchestrationState) -> OrchestrationState:
        """Node 6: finalise the verdict (fast-path or post-challenge)."""
        if state.get("verdict") is None:
            state["verdict"] = TrustVerdict.VERIFIED
        state["session"].state = VerificationState.VERDICT_ISSUED
        return state

    def _node_seal_session(self, state: OrchestrationState) -> OrchestrationState:
        """Node 7: mark the session as sealed."""
        state["session"].state = VerificationState.SEALED
        return state

    def _node_failed(self, state: OrchestrationState) -> OrchestrationState:
        """Node 8: terminal failure node — ensures REJECTED verdict is set."""
        if state.get("verdict") is None:
            state["verdict"] = TrustVerdict.REJECTED
        state["session"].state = VerificationState.FAILED
        return state

    # ------------------------------------------------------------------
    # Conditional edge functions
    # ------------------------------------------------------------------

    def _route_after_signature(self, state: OrchestrationState) -> str:
        return "validate_vc" if state.get("_sig_valid") else "failed"

    def _route_after_vc(self, state: OrchestrationState) -> str:
        return "check_reputation" if state.get("_vc_valid") else "failed"

    def _route_after_reputation(self, state: OrchestrationState) -> str:
        routing = state.get("_routing", "challenge")
        if routing == "blacklist":
            return "failed"
        elif routing == "fast_path":
            return "issue_verdict"
        else:
            return "semantic_challenge"

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self) -> Any:
        graph: StateGraph = StateGraph(OrchestrationState)

        graph.add_node("validate_schema", self._node_validate_schema)
        graph.add_node("verify_signature", self._node_verify_signature)
        graph.add_node("validate_vc", self._node_validate_vc)
        graph.add_node("check_reputation", self._node_check_reputation)
        graph.add_node("semantic_challenge", self._node_semantic_challenge)
        graph.add_node("issue_verdict", self._node_issue_verdict)
        graph.add_node("seal_session", self._node_seal_session)
        graph.add_node("failed", self._node_failed)

        graph.set_entry_point("validate_schema")

        graph.add_edge("validate_schema", "verify_signature")
        graph.add_conditional_edges(
            "verify_signature",
            self._route_after_signature,
            {"validate_vc": "validate_vc", "failed": "failed"},
        )
        graph.add_conditional_edges(
            "validate_vc",
            self._route_after_vc,
            {"check_reputation": "check_reputation", "failed": "failed"},
        )
        graph.add_conditional_edges(
            "check_reputation",
            self._route_after_reputation,
            {
                "semantic_challenge": "semantic_challenge",
                "issue_verdict": "issue_verdict",
                "failed": "failed",
            },
        )
        # After semantic_challenge the graph ends — the session is resumed
        # asynchronously when the challenge response arrives.
        graph.add_edge("semantic_challenge", END)
        graph.add_edge("issue_verdict", "seal_session")
        graph.add_edge("seal_session", END)
        graph.add_edge("failed", END)

        return graph.compile()
