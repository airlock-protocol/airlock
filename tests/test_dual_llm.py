"""Tests for dual-LLM evaluation (Change 6 -- v0.2)."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from airlock.schemas.challenge import ChallengeRequest, ChallengeResponse
from airlock.schemas.envelope import MessageEnvelope, generate_nonce
from airlock.semantic.challenge import (
    ChallengeOutcome,
    evaluate_response_dual,
)


def _make_challenge() -> ChallengeRequest:
    now = datetime.now(UTC)
    return ChallengeRequest(
        envelope=MessageEnvelope(
            protocol_version="0.1.0",
            timestamp=now,
            sender_did="did:key:z6MkGateway",
            nonce=generate_nonce(),
        ),
        session_id="test-session",
        challenge_id="ch-1",
        challenge_type="semantic",
        question="What is Ed25519?",
        context="crypto_security",
        expires_at=now + timedelta(seconds=120),
    )


def _make_response(answer: str = "Ed25519 is an EdDSA signature scheme.") -> ChallengeResponse:
    return ChallengeResponse(
        envelope=MessageEnvelope(
            protocol_version="0.1.0",
            timestamp=datetime.now(UTC),
            sender_did="did:key:z6MkAgent",
            nonce=generate_nonce(),
        ),
        session_id="test-session",
        challenge_id="ch-1",
        answer=answer,
        confidence=0.8,
    )


class TestDualLLMEvaluation:
    @pytest.mark.asyncio
    async def test_both_pass_yields_pass(self) -> None:
        """Both models PASS -> final PASS."""
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new_callable=AsyncMock,
            side_effect=[
                (ChallengeOutcome.PASS, "Model A: good"),
                (ChallengeOutcome.PASS, "Model B: good"),
            ],
        ):
            outcome, just = await evaluate_response_dual(
                _make_challenge(),
                _make_response(),
                "model-a",
                None,
                "model-b",
                None,
            )
            assert outcome == ChallengeOutcome.PASS

    @pytest.mark.asyncio
    async def test_one_fail_yields_fail(self) -> None:
        """One FAIL -> final FAIL (conservative)."""
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new_callable=AsyncMock,
            side_effect=[
                (ChallengeOutcome.PASS, "Model A: good"),
                (ChallengeOutcome.FAIL, "Model B: bad"),
            ],
        ):
            outcome, just = await evaluate_response_dual(
                _make_challenge(),
                _make_response(),
                "model-a",
                None,
                "model-b",
                None,
            )
            assert outcome == ChallengeOutcome.FAIL

    @pytest.mark.asyncio
    async def test_both_fail_yields_fail(self) -> None:
        """Both FAIL -> final FAIL."""
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new_callable=AsyncMock,
            side_effect=[
                (ChallengeOutcome.FAIL, "Model A: bad"),
                (ChallengeOutcome.FAIL, "Model B: bad"),
            ],
        ):
            outcome, just = await evaluate_response_dual(
                _make_challenge(),
                _make_response(),
                "model-a",
                None,
                "model-b",
                None,
            )
            assert outcome == ChallengeOutcome.FAIL

    @pytest.mark.asyncio
    async def test_pass_and_ambiguous_yields_ambiguous(self) -> None:
        """PASS + AMBIGUOUS -> AMBIGUOUS."""
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new_callable=AsyncMock,
            side_effect=[
                (ChallengeOutcome.PASS, "Model A: good"),
                (ChallengeOutcome.AMBIGUOUS, "Model B: unclear"),
            ],
        ):
            outcome, just = await evaluate_response_dual(
                _make_challenge(),
                _make_response(),
                "model-a",
                None,
                "model-b",
                None,
            )
            assert outcome == ChallengeOutcome.AMBIGUOUS

    @pytest.mark.asyncio
    async def test_one_model_error_uses_other(self) -> None:
        """One model errors -> uses other model's result."""
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new_callable=AsyncMock,
            side_effect=[
                (ChallengeOutcome.PASS, "Model A: good"),
                RuntimeError("Model B crashed"),
            ],
        ):
            outcome, just = await evaluate_response_dual(
                _make_challenge(),
                _make_response(),
                "model-a",
                None,
                "model-b",
                None,
            )
            # PASS + AMBIGUOUS(error) -> AMBIGUOUS
            assert outcome == ChallengeOutcome.AMBIGUOUS

    @pytest.mark.asyncio
    async def test_fail_and_ambiguous_yields_fail(self) -> None:
        """FAIL + AMBIGUOUS -> FAIL (FAIL wins over everything)."""
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new_callable=AsyncMock,
            side_effect=[
                (ChallengeOutcome.FAIL, "Model A: bad"),
                (ChallengeOutcome.AMBIGUOUS, "Model B: unclear"),
            ],
        ):
            outcome, just = await evaluate_response_dual(
                _make_challenge(),
                _make_response(),
                "model-a",
                None,
                "model-b",
                None,
            )
            assert outcome == ChallengeOutcome.FAIL

    @pytest.mark.asyncio
    async def test_both_ambiguous_yields_ambiguous(self) -> None:
        """Both AMBIGUOUS -> AMBIGUOUS."""
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new_callable=AsyncMock,
            side_effect=[
                (ChallengeOutcome.AMBIGUOUS, "Model A: unclear"),
                (ChallengeOutcome.AMBIGUOUS, "Model B: unclear"),
            ],
        ):
            outcome, just = await evaluate_response_dual(
                _make_challenge(),
                _make_response(),
                "model-a",
                None,
                "model-b",
                None,
            )
            assert outcome == ChallengeOutcome.AMBIGUOUS

    @pytest.mark.asyncio
    async def test_both_models_error(self) -> None:
        """Both models error -> AMBIGUOUS."""
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new_callable=AsyncMock,
            side_effect=[
                RuntimeError("Model A crashed"),
                RuntimeError("Model B crashed"),
            ],
        ):
            outcome, just = await evaluate_response_dual(
                _make_challenge(),
                _make_response(),
                "model-a",
                None,
                "model-b",
                None,
            )
            assert outcome == ChallengeOutcome.AMBIGUOUS

    @pytest.mark.asyncio
    async def test_justification_includes_both_models(self) -> None:
        """Justification string includes info from both models."""
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new_callable=AsyncMock,
            side_effect=[
                (ChallengeOutcome.PASS, "Model A saw correct Ed25519 usage"),
                (ChallengeOutcome.FAIL, "Model B found evasive answer"),
            ],
        ):
            outcome, just = await evaluate_response_dual(
                _make_challenge(),
                _make_response(),
                "model-a",
                None,
                "model-b",
                None,
            )
            assert outcome == ChallengeOutcome.FAIL
            assert "Model A" in just or "A=" in just
            assert "Model B" in just or "B=" in just
