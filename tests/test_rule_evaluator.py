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


def _make_challenge(
    context: str = "General agent verification challenge.",
    question: str = "What is the difference between authentication and authorization?",
) -> ChallengeRequest:
    now = datetime.now(UTC)
    return ChallengeRequest(
        envelope=_make_envelope(),
        session_id="sess-1",
        challenge_id="chal-1",
        challenge_type="semantic",
        question=question,
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
    def test_too_short_answer_fails(self) -> None:
        challenge = _make_challenge()
        response = _make_response("short")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "too short" in reason.lower()

    def test_empty_answer_fails(self) -> None:
        challenge = _make_challenge()
        response = _make_response("   ")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL

    def test_evasion_i_dont_know(self) -> None:
        challenge = _make_challenge()
        response = _make_response("I don't know the answer to that question at all right now")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "evasive" in reason.lower()

    def test_evasion_as_an_ai(self) -> None:
        challenge = _make_challenge()
        response = _make_response(
            "As an AI language model I am not able to answer domain questions properly"
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "evasive" in reason.lower()

    def test_evasion_im_not_sure(self) -> None:
        challenge = _make_challenge()
        response = _make_response("I'm not sure about the specifics of this topic right now sorry")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "evasive" in reason.lower()

    def test_evasion_i_cannot(self) -> None:
        challenge = _make_challenge()
        response = _make_response("I cannot provide a definitive answer to that question right now")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "evasive" in reason.lower()

    def test_domain_keyword_match_crypto(self) -> None:
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: crypto.",
            question="How does encryption use hash functions in authentication?",
        )
        response = _make_response(
            "The encryption process uses a hash function and a signature "
            "to verify the key exchange. Authentication relies on this "
            "to confirm that the hash matches the expected value."
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.PASS
        assert "domain keywords" in reason.lower()

    def test_domain_keyword_match_payments(self) -> None:
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: payments.",
            question="How does a payment transaction flow through merchant settlement?",
        )
        response = _make_response(
            "A payment transaction requires merchant authorization before "
            "settlement can proceed. The merchant initiates the payment "
            "and waits for the transaction to be confirmed."
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.PASS
        assert "domain keywords" in reason.lower()

    def test_complexity_pass(self) -> None:
        """Complexity heuristic requires 25+ unique words AND 2+ sentences."""
        challenge = _make_challenge(
            question="What is the difference between authentication and authorization?",
        )
        # Build an answer with 30 unique words, 2 sentences, and some
        # question-relevant vocabulary.
        long_answer = (
            "Authentication verifies the identity of a user or system "
            "by checking credentials against a stored record. "
            "Authorization determines what resources and operations "
            "the authenticated entity is allowed to access within "
            "the overall application framework."
        )
        response = _make_response(long_answer)
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.PASS
        assert "complexity" in reason.lower()

    def test_insufficient_domain_knowledge(self) -> None:
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: crypto."
        )
        response = _make_response("The weather today is quite nice and sunny outside")
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "insufficient" in reason.lower()

    # ------------------------------------------------------------------
    # New anti-stuffing tests
    # ------------------------------------------------------------------

    def test_keyword_stuffing_attack_fails(self) -> None:
        """An answer that just sprinkles domain keywords without real
        structure should be caught by the density or coherence checks."""
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: crypto.",
            question="How does encryption use hash functions in authentication?",
        )
        # Keyword soup — mostly domain keywords strung together.
        response = _make_response(
            "encryption hash signature nonce certificate key authentication "
            "encryption hash signature nonce certificate key authentication"
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "keyword density" in reason.lower() or "coherence" in reason.lower()

    def test_cross_domain_keyword_dump_fails(self) -> None:
        """Keywords from 3+ unrelated domains in one answer = stuffing.

        The answer is padded with enough filler to keep density below the
        threshold so that the cross-domain trap fires specifically.
        """
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: crypto.",
            question="What role does a nonce play in preventing replay attacks?",
        )
        # Answer mixes crypto, payments, networking, and database terms
        # with enough natural filler to avoid the density check but still
        # trigger cross-domain detection.
        response = _make_response(
            "The nonce provides replay protection by being unique per "
            "request while the encryption layer adds security. Meanwhile "
            "the merchant requires settlement confirmation through a "
            "separate channel and the dns routing table maps tcp latency "
            "across different zones. Additionally the query planner "
            "optimizes schema lookups via the replication log on the "
            "remote cluster to ensure proper data distribution."
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "cross-domain" in reason.lower()

    def test_genuine_short_correct_answer_passes(self) -> None:
        """A short but legitimate domain answer should still pass."""
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: security.",
            question="What is the difference between authentication and authorization?",
        )
        response = _make_response(
            "Authentication verifies who you are by validating your identity "
            "through credentials. Authorization determines what resources "
            "and permission levels the authenticated user is allowed to access."
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.PASS

    def test_high_density_keyword_answer_fails(self) -> None:
        """An answer where >30% of unique words are domain keywords."""
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: payments.",
            question="How does a payment transaction work?",
        )
        # 7 out of ~10 unique words are domain keywords.
        response = _make_response(
            "transaction payment merchant settlement refund authorization "
            "transfer transaction payment merchant settlement"
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "keyword density" in reason.lower()

    def test_old_complexity_threshold_no_longer_sufficient(self) -> None:
        """15 unique gibberish words no longer pass — need 25 words + 2 sentences."""
        challenge = _make_challenge()
        gibberish = " ".join(f"word{i}" for i in range(20))
        response = _make_response(gibberish)
        outcome, _reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL

    def test_coherence_rejects_random_word_list(self) -> None:
        """A list of unrelated nouns with no function words should fail coherence."""
        challenge = _make_challenge(
            context="This challenge tests your declared expertise in: security.",
            question="How does a firewall protect against unauthorized access?",
        )
        response = _make_response(
            "firewall unauthorized access protection network "
            "perimeter gateway intrusion detection monitoring "
            "packet inspection filtering rules segments zones"
        )
        outcome, reason = evaluate_rule_based(challenge, response)
        assert outcome == ChallengeOutcome.FAIL
        assert "coherence" in reason.lower() or "keyword density" in reason.lower()
