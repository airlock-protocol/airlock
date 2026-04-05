"""VerificationOrchestrator: LangGraph state machine for the 5-phase Airlock protocol.

Node map (11 nodes):
  resolve                  -> validate_schema
  validate_schema          -> check_revocation
  check_revocation         -> verify_signature          (or failed)
  verify_signature         -> validate_vc               (or failed)
  validate_vc              -> validate_delegation        (or failed)
  validate_delegation      -> cross_ref_capabilities    (or failed)
  cross_ref_capabilities   -> check_reputation          (or failed)
  check_reputation         -> semantic_challenge | issue_verdict (fast-path / blacklist)
  semantic_challenge       -> issue_verdict
  issue_verdict            -> seal_session
  seal_session             -> END
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any, Literal, TypedDict

from langgraph.graph import END, StateGraph

from airlock.crypto.keys import KeyPair, resolve_public_key
from airlock.crypto.signing import sign_attestation, verify_model
from airlock.config import get_config
from airlock.crypto.vc import extract_capabilities, validate_credential
from airlock.engine.state import SessionManager
from airlock.gateway.revocation import RedisRevocationStore, RevocationStore
from airlock.gateway.url_validator import validate_callback_url
from airlock.reputation.scoring import routing_decision
from airlock.reputation.store import ReputationStore
from airlock.schemas.challenge import ChallengeRequest, ChallengeResponse
from airlock.schemas.envelope import MessageEnvelope, generate_nonce
from airlock.schemas.events import (
    AnyVerificationEvent,
    ChallengeResponseReceived,
    HandshakeReceived,
    ResolveRequested,
)
from airlock.schemas.handshake import HandshakeRequest
from airlock.schemas.identity import AgentProfile
from airlock.schemas.session import SessionSeal, VerificationSession, VerificationState
from airlock.schemas.trust_tier import TrustTier
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
from airlock.trust_jwt import mint_verified_trust_token

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
    _routing: str  # 'fast_path' | 'challenge' | 'blacklist'
    _challenge_outcome: str | None
    _tier: int  # TrustTier int value
    _local_only: bool


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
        on_challenge: Any | None = None,  # async (session_id, ChallengeRequest) -> None
        on_verdict: Any
        | None = None,  # async (session_id, TrustVerdict, AirlockAttestation) -> None
        on_seal: Any | None = None,  # async (session_id, SessionSeal) -> None
        trust_token_secret: str | None = None,
        trust_token_ttl_seconds: int = 600,
        session_mgr: SessionManager | None = None,
        vc_allowed_issuers: frozenset[str] | None = None,
        revocation_store: RevocationStore | RedisRevocationStore | None = None,
        airlock_keypair: KeyPair | None = None,
        chain_registry: Any | None = None,
    ) -> None:
        self._reputation = reputation_store
        self._revocation: RevocationStore | RedisRevocationStore | None = revocation_store
        self._chain_registry = chain_registry
        self._registry = agent_registry
        self._airlock_did = airlock_did
        self._airlock_keypair = airlock_keypair
        self._model = litellm_model
        self._api_base = litellm_api_base
        self._on_challenge = on_challenge
        self._on_verdict = on_verdict
        self._on_seal = on_seal
        self._trust_token_secret = trust_token_secret or None
        self._trust_token_ttl_seconds = trust_token_ttl_seconds
        self._session_mgr = session_mgr
        self._vc_allowed_issuers = vc_allowed_issuers

        # Pending challenge responses keyed by session_id
        self._pending_challenges: dict[str, ChallengeRequest] = {}
        self._last_challenge_checks: dict[str, list[CheckResult]] = {}
        self._pending_challenges_lock = asyncio.Lock()
        self._handshake_wait_lock = asyncio.Lock()

        self._graph = self._build_graph()

    def _sign_attestation_if_keypair(self, attestation: AirlockAttestation) -> AirlockAttestation:
        """Sign the attestation with the gateway keypair if available.

        Must be called BEFORE adding the trust_token so the signature
        covers the attestation content without ephemeral fields.
        """
        if self._airlock_keypair is None:
            return attestation
        sig = sign_attestation(attestation, self._airlock_keypair.signing_key)
        return attestation.model_copy(update={"airlock_signature": sig})

    async def _persist_graph_snapshot(self, final_state: OrchestrationState) -> None:
        """Mirror LangGraph session + checks into ``SessionManager`` for HTTP polling."""
        if self._session_mgr is None:
            return
        graph_sess = final_state["session"]
        sid = graph_sess.session_id
        extra: dict[str, Any] = {
            "check_results": list(final_state.get("check_results", [])),
            "state": graph_sess.state,
        }
        ts = final_state.get("trust_score")
        if ts is not None:
            extra["trust_score"] = ts
        vd = final_state.get("verdict")
        if vd is not None:
            extra["verdict"] = vd
        if graph_sess.handshake_request is not None:
            extra["handshake_request"] = graph_sess.handshake_request

        existing = await self._session_mgr.get(sid)
        if existing is not None:
            await self._session_mgr.put(existing.model_copy(update=extra))
        else:
            await self._session_mgr.put(graph_sess.model_copy(update=extra))

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

    async def run_handshake_and_wait(
        self,
        *,
        session_id: str,
        handshake: HandshakeRequest,
        callback_url: str | None = None,
        timeout: float = 120.0,
    ) -> (
        tuple[Literal["verdict"], TrustVerdict, AirlockAttestation]
        | tuple[Literal["challenge"], ChallengeRequest, list[CheckResult]]
    ):
        """Run the handshake pipeline and return a terminal verdict or a pending challenge.

        Used by synchronous HTTP callers (e.g. A2A verify) that must observe
        the same path as an event-driven handshake without publishing duplicate
        events. Serializes concurrent calls so temporary callback hooks stay coherent.
        """
        loop = asyncio.get_running_loop()
        completion: asyncio.Future[
            tuple[Literal["verdict"], TrustVerdict, AirlockAttestation]
            | tuple[Literal["challenge"], ChallengeRequest]
        ] = loop.create_future()

        async def _on_v(sid: str, verdict: TrustVerdict, att: AirlockAttestation) -> None:
            if sid == session_id and not completion.done():
                completion.set_result(("verdict", verdict, att))

        async def _on_ch(sid: str, challenge: ChallengeRequest) -> None:
            if sid == session_id and not completion.done():
                completion.set_result(("challenge", challenge))

        async with self._handshake_wait_lock:
            prev_v, prev_ch = self._on_verdict, self._on_challenge
            self._on_verdict = _on_v
            self._on_challenge = _on_ch
            try:
                await self._handle_handshake(
                    HandshakeReceived(
                        session_id=session_id,
                        timestamp=datetime.now(UTC),
                        request=handshake,
                        callback_url=callback_url,
                    )
                )
                result = await asyncio.wait_for(completion, timeout=timeout)
            finally:
                self._on_verdict = prev_v
                self._on_challenge = prev_ch

        if result[0] == "verdict":
            return ("verdict", result[1], result[2])
        async with self._pending_challenges_lock:
            checks = self._last_challenge_checks.pop(session_id, [])
        return ("challenge", result[1], checks)

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
        # Sanitize callback URL to prevent SSRF
        safe_callback = validate_callback_url(event.callback_url)

        now = datetime.now(UTC)
        session = VerificationSession(
            session_id=session_id,
            state=VerificationState.HANDSHAKE_RECEIVED,
            initiator_did=request.initiator.did,
            target_did=request.intent.target_did,
            callback_url=safe_callback,
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
            "_tier": TrustTier.UNKNOWN,
            "_local_only": getattr(request, "privacy_mode", "any") == "local_only",
        }

        # Run the graph synchronously through all nodes.
        # The graph ends at END after semantic_challenge (challenge path) or
        # after seal_session (fast-path / blacklist).
        final_state = await self._run_graph(initial)

        await self._persist_graph_snapshot(final_state)

        routing = final_state.get("_routing", "challenge")

        if routing == "challenge" and final_state.get("verdict") is None:
            # Generate the semantic challenge asynchronously (LLM call)
            profile = self._registry.get(request.initiator.did)
            capabilities = list(profile.capabilities) if profile is not None else []
            challenge = await generate_challenge(
                session_id=session_id,
                capabilities=capabilities,
                airlock_did=self._airlock_did,
                litellm_model=self._model,
                litellm_api_base=self._api_base,
            )
            async with self._pending_challenges_lock:
                # Sweep expired challenges to prevent unbounded growth
                expired = [
                    sid for sid, ch in self._pending_challenges.items() if now > ch.expires_at
                ]
                for sid in expired:
                    del self._pending_challenges[sid]
                    self._last_challenge_checks.pop(sid, None)
                if len(self._pending_challenges) >= 10_000:
                    logger.warning("Pending challenges at capacity (10000), dropping oldest")
                else:
                    self._pending_challenges[session_id] = challenge
                self._last_challenge_checks[session_id] = list(final_state.get("check_results", []))
            if self._session_mgr is not None:
                cur = await self._session_mgr.get(session_id)
                if cur is not None:
                    ch_extra: dict[str, Any] = {
                        "check_results": list(final_state.get("check_results", [])),
                        "challenge_request": challenge,
                        "state": final_state["session"].state,
                    }
                    chts = final_state.get("trust_score")
                    if chts is not None:
                        ch_extra["trust_score"] = chts
                    await self._session_mgr.put(cur.model_copy(update=ch_extra))
            if self._on_challenge:
                await self._on_challenge(session_id, challenge)
            return

        # Fast-path or blacklist — verdict already set by the graph
        await self._deliver_verdict(final_state)

    async def _handle_challenge_response(self, event: ChallengeResponseReceived) -> None:
        """Resume a paused session with the agent's challenge response."""
        session_id = event.session_id
        async with self._pending_challenges_lock:
            challenge = self._pending_challenges.pop(session_id, None)
        if challenge is None:
            logger.warning("No pending challenge for session %s — ignoring response", session_id)
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
            event.response.envelope.sender_did if event.response.envelope.sender_did else "unknown"
        )

        check = CheckResult(
            check=VerificationCheck.SEMANTIC,
            passed=(outcome == ChallengeOutcome.PASS),
            detail=justification,
        )

        # Build a minimal final state for delivery
        now = datetime.now(UTC)
        envelope = MessageEnvelope(
            protocol_version="0.1.0",
            timestamp=now,
            sender_did=self._airlock_did,
            nonce=generate_nonce(),
        )
        # Resolve privacy_mode from original handshake
        local_only = False
        privacy_mode_str = "any"
        if self._session_mgr is not None:
            cur_session = await self._session_mgr.get(session_id)
            if cur_session is not None:
                hr = getattr(cur_session, "handshake_request", None)
                if hr is not None:
                    pm = getattr(hr, "privacy_mode", "any")
                    privacy_mode_str = str(pm)
                    local_only = privacy_mode_str == "local_only"

        attestation = AirlockAttestation(
            session_id=session_id,
            verified_did=score_record.agent_did,
            checks_passed=[check],
            trust_score=score_record.score,
            tier=score_record.tier,
            verdict=verdict,
            issued_at=now,
            privacy_mode=privacy_mode_str,
        )
        # Sign BEFORE adding trust_token so the signature covers core content
        attestation = self._sign_attestation_if_keypair(attestation)
        if verdict == TrustVerdict.VERIFIED and self._trust_token_secret:
            attestation = attestation.model_copy(
                update={
                    "trust_token": mint_verified_trust_token(
                        subject_did=score_record.agent_did,
                        session_id=session_id,
                        trust_score=score_record.score,
                        issuer_did=self._airlock_did,
                        secret=self._trust_token_secret,
                        ttl_seconds=self._trust_token_ttl_seconds,
                    ),
                }
            )
        seal = SessionSeal(
            envelope=envelope,
            session_id=session_id,
            verdict=verdict,
            checks_passed=[check],
            trust_score=score_record.score,
            sealed_at=now,
        )

        # Update reputation (unless local_only)
        if not local_only:
            self._reputation.apply_verdict(score_record.agent_did, verdict)

        if self._session_mgr is not None:
            cur = await self._session_mgr.get(session_id)
            if cur is not None:
                await self._session_mgr.put(
                    cur.model_copy(
                        update={
                            "challenge_response": event.response,
                            "verdict": verdict,
                            "trust_score": score_record.score,
                            "attestation": attestation,
                            "state": VerificationState.SEALED,
                        }
                    )
                )

        if self._on_verdict:
            await self._on_verdict(session_id, verdict, attestation)
        if self._on_seal:
            await self._on_seal(session_id, seal)

        logger.info("Session %s sealed after challenge: %s", session_id, verdict.value)

    # ------------------------------------------------------------------
    # Graph execution
    # ------------------------------------------------------------------

    async def _run_graph(self, state: OrchestrationState) -> OrchestrationState:
        """Invoke the LangGraph state machine synchronously (nodes are sync)."""
        result: OrchestrationState = self._graph.invoke(state)
        return result

    async def _deliver_verdict(self, state: OrchestrationState) -> None:
        """Issue verdict + seal callbacks and update reputation."""
        session = state["session"]
        verdict = state.get("verdict") or TrustVerdict.REJECTED
        trust_score = state.get("trust_score", 0.5)
        checks = state.get("check_results", [])

        now = datetime.now(UTC)
        envelope = MessageEnvelope(
            protocol_version="0.1.0",
            timestamp=now,
            sender_did=self._airlock_did,
            nonce=generate_nonce(),
        )
        tier = TrustTier(state.get("_tier", TrustTier.UNKNOWN))
        # Resolve privacy_mode for attestation
        handshake = state.get("handshake")
        privacy_mode_str = str(getattr(handshake, "privacy_mode", "any")) if handshake else "any"

        attestation = AirlockAttestation(
            session_id=session.session_id,
            verified_did=session.initiator_did,
            checks_passed=checks,
            trust_score=trust_score,
            tier=tier,
            verdict=verdict,
            issued_at=now,
            privacy_mode=privacy_mode_str,
        )
        # Sign BEFORE adding trust_token so the signature covers core content
        attestation = self._sign_attestation_if_keypair(attestation)
        if verdict == TrustVerdict.VERIFIED and self._trust_token_secret:
            attestation = attestation.model_copy(
                update={
                    "trust_token": mint_verified_trust_token(
                        subject_did=session.initiator_did,
                        session_id=session.session_id,
                        trust_score=trust_score,
                        issuer_did=self._airlock_did,
                        secret=self._trust_token_secret,
                        ttl_seconds=self._trust_token_ttl_seconds,
                    ),
                }
            )
        seal = SessionSeal(
            envelope=envelope,
            session_id=session.session_id,
            verdict=verdict,
            checks_passed=checks,
            trust_score=trust_score,
            sealed_at=now,
        )

        # Update reputation for terminal verdicts (unless local_only).
        # Resolve through rotation chain so mid-session rotation applies
        # to the current DID rather than the (possibly rotated-out) original.
        if verdict in (TrustVerdict.VERIFIED, TrustVerdict.REJECTED):
            if not state.get("_local_only", False):
                reputation_did = session.initiator_did
                chain_reg = getattr(self, "_chain_registry", None)
                if chain_reg is not None:
                    chain = chain_reg.get_chain_by_did(session.initiator_did)
                    if chain is not None:
                        reputation_did = chain.current_did
                self._reputation.apply_verdict(reputation_did, verdict)

        if self._session_mgr is not None:
            prev = await self._session_mgr.get(session.session_id)
            base = prev if prev is not None else session
            await self._session_mgr.put(
                base.model_copy(
                    update={
                        "check_results": checks,
                        "trust_score": trust_score,
                        "verdict": verdict,
                        "attestation": attestation,
                        "state": session.state,
                    }
                )
            )

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
            CheckResult(
                check=VerificationCheck.SCHEMA, passed=True, detail="Pydantic validation passed"
            )
        )
        state["check_results"] = checks
        state["session"].state = VerificationState.HANDSHAKE_RECEIVED
        return state

    def _node_check_revocation(self, state: OrchestrationState) -> OrchestrationState:
        """Node 1b: check if the initiator DID has been revoked."""
        initiator_did = state["session"].initiator_did
        revoked = False
        if self._revocation is not None:
            revoked = self._revocation.is_revoked_sync(initiator_did)

        checks: list[CheckResult] = list(state.get("check_results", []))
        checks.append(
            CheckResult(
                check=VerificationCheck.REVOCATION,
                passed=not revoked,
                detail="Agent is revoked" if revoked else "Agent is not revoked",
            )
        )
        state["check_results"] = checks

        if revoked:
            state["error"] = "Agent DID is revoked"
            state["failed_at"] = "check_revocation"
            state["verdict"] = TrustVerdict.REJECTED
            state["session"].state = VerificationState.FAILED
        return state

    def _route_after_revocation(self, state: OrchestrationState) -> str:
        if state.get("failed_at") == "check_revocation":
            return "failed"
        return "verify_signature"

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
            valid, reason = validate_credential(
                vc,
                issuer_verify_key,
                expected_subject_did=request.initiator.did,
            )
        except Exception as exc:
            valid = False
            reason = str(exc)

        if (
            valid
            and self._vc_allowed_issuers is not None
            and vc.issuer not in self._vc_allowed_issuers
        ):
            valid = False
            reason = "VC issuer not in allowlist (AIRLOCK_VC_ISSUER_ALLOWLIST)"

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

    def _node_validate_delegation(self, state: OrchestrationState) -> OrchestrationState:
        """Node 3b: validate delegation chain if delegator_did is present."""
        checks: list[CheckResult] = list(state.get("check_results", []))
        request = state["handshake"]
        delegator_did = getattr(request, "delegator_did", None)

        if delegator_did is None:
            # Not a delegated handshake — pass through
            checks.append(
                CheckResult(
                    check=VerificationCheck.DELEGATION,
                    passed=True,
                    detail="No delegation (direct handshake)",
                )
            )
            state["check_results"] = checks
            return state

        # Check delegator is not revoked
        if self._revocation is not None and self._revocation.is_revoked_sync(delegator_did):
            checks.append(
                CheckResult(
                    check=VerificationCheck.DELEGATION,
                    passed=False,
                    detail=f"Delegator {delegator_did} is revoked",
                )
            )
            state["check_results"] = checks
            state["error"] = "Delegator DID is revoked"
            state["failed_at"] = "validate_delegation"
            state["verdict"] = TrustVerdict.REJECTED
            state["session"].state = VerificationState.FAILED
            return state

        # Check delegator trust score >= 0.75
        delegator_score = self._reputation.get_or_default(delegator_did)
        if delegator_score.score < 0.75:
            checks.append(
                CheckResult(
                    check=VerificationCheck.DELEGATION,
                    passed=False,
                    detail=f"Delegator trust score {delegator_score.score:.4f} < 0.75",
                )
            )
            state["check_results"] = checks
            state["error"] = "Delegator trust score too low for delegation"
            state["failed_at"] = "validate_delegation"
            state["verdict"] = TrustVerdict.REJECTED
            state["session"].state = VerificationState.FAILED
            return state

        # Validate credential chain
        credential_chain = getattr(request, "credential_chain", None) or []
        delegation = getattr(request, "delegation", None)
        max_depth = delegation.max_depth if delegation else 1

        if len(credential_chain) > max_depth:
            checks.append(
                CheckResult(
                    check=VerificationCheck.DELEGATION,
                    passed=False,
                    detail=f"Credential chain depth {len(credential_chain)} exceeds max_depth {max_depth}",
                )
            )
            state["check_results"] = checks
            state["error"] = "Delegation chain too deep"
            state["failed_at"] = "validate_delegation"
            state["verdict"] = TrustVerdict.REJECTED
            state["session"].state = VerificationState.FAILED
            return state

        # Check expiry
        if delegation and delegation.expires_at:
            from datetime import UTC
            from datetime import datetime as dt

            if dt.now(UTC) > delegation.expires_at:
                checks.append(
                    CheckResult(
                        check=VerificationCheck.DELEGATION,
                        passed=False,
                        detail="Delegation has expired",
                    )
                )
                state["check_results"] = checks
                state["error"] = "Delegation expired"
                state["failed_at"] = "validate_delegation"
                state["verdict"] = TrustVerdict.REJECTED
                state["session"].state = VerificationState.FAILED
                return state

        checks.append(
            CheckResult(
                check=VerificationCheck.DELEGATION,
                passed=True,
                detail=f"Delegation from {delegator_did} validated (chain_depth={len(credential_chain)})",
            )
        )
        state["check_results"] = checks
        return state

    def _route_after_delegation(self, state: OrchestrationState) -> str:
        if state.get("failed_at") == "validate_delegation":
            return "failed"
        return "cross_ref_capabilities"

    def _node_cross_ref_capabilities(self, state: OrchestrationState) -> OrchestrationState:
        """Node 3c: cross-reference VC capabilities with self-declared capabilities.

        Behavior is controlled by ``vc_capability_mode`` config:
          off     — no-op, return state unchanged
          audit   — extract + log VC capabilities, add CheckResult
          warn    — audit + annotate capabilities with trust weights
          enforce — trust-weighted model active, mismatches fail
        """
        cfg = get_config()
        mode = cfg.vc_capability_mode

        if mode == "off":
            return state

        checks: list[CheckResult] = list(state.get("check_results", []))
        request = state["handshake"]
        initiator_did = state["session"].initiator_did

        # Extract capabilities from the VC credential_subject
        vc = request.credential
        extraction = extract_capabilities([vc.credential_subject])

        # --- Three-tier error handling ---

        # Tier 1: Extraction failed (data present but unparseable)
        if extraction.extraction_failed:
            logger.warning(
                "VC capability extraction degraded for %s: %s",
                initiator_did,
                "; ".join(extraction.warnings),
            )
            checks.append(
                CheckResult(
                    check=VerificationCheck.CAPABILITY_CROSS_REF,
                    passed=True,
                    detail=f"extraction_degraded: {'; '.join(extraction.warnings)}",
                    degraded=True,
                )
            )
            state["check_results"] = checks
            return state

        # Tier 2: No capabilities in VC (missing field, not an error)
        if not extraction.capabilities:
            logger.info(
                "VC has no capabilities claim, cross-reference skipped for %s",
                initiator_did,
            )
            checks.append(
                CheckResult(
                    check=VerificationCheck.CAPABILITY_CROSS_REF,
                    passed=True,
                    detail="no_vc_capabilities",
                )
            )
            state["check_results"] = checks
            return state

        # Tier 3: Capabilities extracted — perform cross-reference
        vc_cap_names = {c.name.lower() for c in extraction.capabilities}

        # Get self-declared capabilities from registry
        profile = self._registry.get(initiator_did)
        self_declared_caps = list(profile.capabilities) if profile is not None else []
        self_cap_names = {c.name.lower() for c in self_declared_caps}

        # Compute mismatch: self-declared but not in VC
        self_only = self_cap_names - vc_cap_names
        vc_only = vc_cap_names - self_cap_names

        mismatch_detail_parts: list[str] = []
        if self_only:
            mismatch_detail_parts.append(f"self_declared_only={sorted(self_only)}")
        if vc_only:
            mismatch_detail_parts.append(f"vc_only={sorted(vc_only)}")

        has_mismatch = bool(self_only or vc_only)

        if mode == "audit":
            # Log and record, but do not change behavior
            detail = (
                f"vc_capabilities={sorted(vc_cap_names)}, "
                f"self_declared={sorted(self_cap_names)}"
            )
            if has_mismatch:
                detail += f", mismatch: {'; '.join(mismatch_detail_parts)}"
                logger.info(
                    "Capability cross-ref audit for %s: mismatch found — %s",
                    initiator_did,
                    "; ".join(mismatch_detail_parts),
                )
            else:
                logger.info(
                    "Capability cross-ref audit for %s: capabilities match",
                    initiator_did,
                )
            checks.append(
                CheckResult(
                    check=VerificationCheck.CAPABILITY_CROSS_REF,
                    passed=True,
                    detail=detail,
                )
            )
            state["check_results"] = checks
            return state

        if mode in ("warn", "enforce"):
            # Annotate capabilities with trust weights:
            #   vc_attested=1.0 (in VC), self_declared=0.5 (not in VC)
            # Store annotated info on the state for challenge generation
            if has_mismatch:
                logger.warning(
                    "Capability cross-ref mismatch for %s: %s",
                    initiator_did,
                    "; ".join(mismatch_detail_parts),
                )

            if mode == "enforce" and has_mismatch:
                # In enforce mode, definitive mismatch fails verification
                checks.append(
                    CheckResult(
                        check=VerificationCheck.CAPABILITY_CROSS_REF,
                        passed=False,
                        detail=f"capability_mismatch: {'; '.join(mismatch_detail_parts)}",
                    )
                )
                state["check_results"] = checks
                state["error"] = "Capability cross-reference mismatch in enforce mode"
                state["failed_at"] = "cross_ref_capabilities"
                state["verdict"] = TrustVerdict.REJECTED
                state["session"].state = VerificationState.FAILED
                return state

            # warn mode (or enforce with no mismatch): record pass with annotation
            detail = (
                f"trust_weighted: vc_attested={sorted(vc_cap_names)}, "
                f"self_declared_only={sorted(self_only)}"
            )
            checks.append(
                CheckResult(
                    check=VerificationCheck.CAPABILITY_CROSS_REF,
                    passed=True,
                    detail=detail,
                )
            )
            state["check_results"] = checks
            return state

        # Unknown mode — treat as off (should not reach here due to startup validation)
        return state

    def _route_after_cross_ref(self, state: OrchestrationState) -> str:
        if state.get("failed_at") == "cross_ref_capabilities":
            return "failed"
        return "check_reputation"

    def _node_check_reputation(self, state: OrchestrationState) -> OrchestrationState:
        """Node 4: look up trust score and decide routing.

        When a rotation chain registry is available, resolves the initiator
        DID through the chain so that reputation follows the agent across
        key rotations.
        """
        checks: list[CheckResult] = list(state.get("check_results", []))
        initiator_did = state["session"].initiator_did

        rep_did = initiator_did
        if self._chain_registry is not None:
            chain = self._chain_registry.get_chain_by_did(initiator_did)
            if chain is not None:
                rep_did = chain.current_did

        score_record = self._reputation.get_or_default(rep_did)
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
        state["_tier"] = score_record.tier

        if routing == "blacklist":
            state["verdict"] = TrustVerdict.REJECTED
            state["error"] = "Agent is blacklisted (trust score below threshold)"
            state["failed_at"] = "check_reputation"
            state["session"].state = VerificationState.FAILED
        elif routing == "fast_path":
            state["verdict"] = TrustVerdict.VERIFIED
            state["session"].state = VerificationState.VERDICT_ISSUED

        # Respect privacy_mode: NO_CHALLENGE skips semantic challenge
        privacy = getattr(state["handshake"], "privacy_mode", None)
        if privacy is not None:
            from airlock.schemas.handshake import PrivacyMode

            if privacy == PrivacyMode.NO_CHALLENGE and routing == "challenge":
                state["verdict"] = TrustVerdict.DEFERRED
                state["_routing"] = "issue_verdict"
                state["_local_only"] = True  # Respecting privacy shouldn't erode trust
                state["session"].state = VerificationState.VERDICT_ISSUED
                checks.append(
                    CheckResult(
                        check=VerificationCheck.SEMANTIC,
                        passed=False,
                        detail="Skipped: agent requested privacy_mode=no_challenge",
                    )
                )
                state["check_results"] = checks

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
        return "validate_delegation" if state.get("_vc_valid") else "failed"

    def _route_after_reputation(self, state: OrchestrationState) -> str:
        routing = state.get("_routing", "challenge")
        if routing == "blacklist":
            return "failed"
        elif routing in ("fast_path", "issue_verdict"):
            return "issue_verdict"
        else:
            return "semantic_challenge"

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self) -> Any:
        graph: StateGraph[OrchestrationState] = StateGraph(OrchestrationState)

        graph.add_node("validate_schema", self._node_validate_schema)
        graph.add_node("check_revocation", self._node_check_revocation)
        graph.add_node("verify_signature", self._node_verify_signature)
        graph.add_node("validate_vc", self._node_validate_vc)
        graph.add_node("validate_delegation", self._node_validate_delegation)
        graph.add_node("cross_ref_capabilities", self._node_cross_ref_capabilities)
        graph.add_node("check_reputation", self._node_check_reputation)
        graph.add_node("semantic_challenge", self._node_semantic_challenge)
        graph.add_node("issue_verdict", self._node_issue_verdict)
        graph.add_node("seal_session", self._node_seal_session)
        graph.add_node("failed", self._node_failed)

        graph.set_entry_point("validate_schema")

        graph.add_edge("validate_schema", "check_revocation")
        graph.add_conditional_edges(
            "check_revocation",
            self._route_after_revocation,
            {"verify_signature": "verify_signature", "failed": "failed"},
        )
        graph.add_conditional_edges(
            "verify_signature",
            self._route_after_signature,
            {"validate_vc": "validate_vc", "failed": "failed"},
        )
        graph.add_conditional_edges(
            "validate_vc",
            self._route_after_vc,
            {"validate_delegation": "validate_delegation", "failed": "failed"},
        )
        graph.add_conditional_edges(
            "validate_delegation",
            self._route_after_delegation,
            {"cross_ref_capabilities": "cross_ref_capabilities", "failed": "failed"},
        )
        graph.add_conditional_edges(
            "cross_ref_capabilities",
            self._route_after_cross_ref,
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
