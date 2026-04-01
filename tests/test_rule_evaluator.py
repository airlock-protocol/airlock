"""Tests for rule-based challenge evaluation fallback."""

from datetime import UTC, datetime, timedelta

from airlock.schemas.challenge import ChallengeRequest, ChallengeResponse
from airlock.schemas.envelope import MessageEnvelope, generate_nonce
from airlock.semantic.challenge import ChallengeOutcome
from airlock.semantic.rule_evaluator import evaluate_rule_based


def _make_envelope() -> MessageEnvelope:
    return MessageEnvelope(
        protocol_version="0.1.0",
        timestamp=datetime.now(UTC),
        sender_did="did:key:test",
        nonce=generate_nonce(),
    )


def _make_challenge(context: str = "General agent verification challenge.") -> ChallengeRequest:
    now = datetime.now(UTC)
    return ChallengeRequest(
        envelope=_make_envelope(),
        session_id="sess-1",
        challenge_id="chal-1",
        challenge_type="semantic",
        question="What is the difference between authentication and authorization?",
        context=context,
        expires_at=now + timedelta(seconds=120),
    )


def _make_response(answer: str) -> ChallengeResponse:
    return ChallengeResponse(
        envelope=_make_envelope(),
        session_id="sess-1",
        challenge_id="chal-1",
        answer=answer,
        confidence=0.9,
    )


class TestRuleEvaluator:
    def test_too_short_answer_fails(self):
        challenge = _make_challenge()
        response = _make_response("short")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "too short" in reason.lower()

    def test_empty_answer_fails(self):
        challenge = _make_challenge()
        response = _make_response("   ")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL

    def test_evasion_i_dont_know(self):
        challenge = _make_challenge()
        response = _make_response("I don't know the answer to that question at all right now")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "evasive" in reason.lower()

    def test_evasion_as_an_ai(self):
        challenge = _make_challenge()
        response = _make_response(
            "As an AI language model I am not able to answer domain questions properly"
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "evasive" in reason.lower()

    def test_evasion_im_not_sure(self):
        challenge = _make_challenge()
        response = _make_response("I'm not sure about the specifics of this topic right now sorry")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "evasive" in reason.lower()

    def test_evasion_i_cannot(self):
        challenge = _make_challenge()
        response = _make_response("I cannot provide a definitive answer to that question right now")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "evasive" in reason.lower()

    def test_domain_keyword_match_crypto(self):
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: crypto."
        )
        response = _make_response(
            "The encryption process uses a hash function and a signature to verify the key exchange protocol"
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.PASS
        assert "domain keywords" in reason.lower()

    def test_domain_keyword_match_payments(self):
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: payments."
        )
        response = _make_response(
            "A payment transaction requires merchant authorization before settlement can proceed"
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.PASS
        assert "domain keywords" in reason.lower()

    def test_complexity_pass(self):
        challenge = _make_challenge()
        long_answer = " ".join(f"word{i}" for i in range(20))
        response = _make_response(long_answer)
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.PASS
        assert "complexity" in reason.lower()

    def test_insufficient_domain_knowledge(self):
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: crypto."
        )
        response = _make_response("The weather today is quite nice and sunny outside")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "insufficient" in reason.lower()
