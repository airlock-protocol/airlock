"""Tests for structured LLM evaluation output (Change 5 -- v0.2)."""

import pytest

from airlock.semantic.challenge import (
    ChallengeOutcome,
    LLMEvaluationResult,
    _parse_structured_evaluation,
)


class TestLLMEvaluationResult:
    def test_valid_pass_result(self) -> None:
        result = LLMEvaluationResult(
            verdict="PASS",
            confidence=0.95,
            justification="Demonstrates strong domain knowledge",
            key_evidence=["Correct use of Ed25519", "Proper nonce handling"],
            red_flags=[],
        )
        assert result.verdict == "PASS"
        assert result.confidence == 0.95

    def test_valid_fail_result(self) -> None:
        result = LLMEvaluationResult(
            verdict="FAIL",
            confidence=0.8,
            justification="No domain knowledge demonstrated",
            key_evidence=[],
            red_flags=["Evasive answer", "Keyword stuffing"],
        )
        assert result.verdict == "FAIL"
        assert len(result.red_flags) == 2

    def test_confidence_bounds(self) -> None:
        with pytest.raises(Exception):
            LLMEvaluationResult(
                verdict="PASS",
                confidence=1.5,
                justification="test",
            )

    def test_confidence_lower_bound(self) -> None:
        with pytest.raises(Exception):
            LLMEvaluationResult(
                verdict="PASS",
                confidence=-0.1,
                justification="test",
            )

    def test_schema_export(self) -> None:
        """Model can export JSON schema for LLM response_format."""
        schema = LLMEvaluationResult.model_json_schema()
        assert "verdict" in schema["properties"]
        assert "confidence" in schema["properties"]

    def test_default_factory_lists(self) -> None:
        """key_evidence and red_flags default to empty lists."""
        result = LLMEvaluationResult(
            verdict="AMBIGUOUS",
            confidence=0.5,
            justification="Unclear",
        )
        assert result.key_evidence == []
        assert result.red_flags == []


class TestStructuredParsing:
    def test_parse_valid_json(self) -> None:
        json_str = (
            '{"verdict": "PASS", "confidence": 0.9, "justification": "Good answer",'
            ' "key_evidence": ["fact1"], "red_flags": []}'
        )
        outcome, just = _parse_structured_evaluation(json_str)
        assert outcome == ChallengeOutcome.PASS
        assert "Good answer" in just

    def test_parse_fail_json(self) -> None:
        json_str = (
            '{"verdict": "FAIL", "confidence": 0.85, "justification": "Wrong",'
            ' "key_evidence": [], "red_flags": ["evasive"]}'
        )
        outcome, just = _parse_structured_evaluation(json_str)
        assert outcome == ChallengeOutcome.FAIL

    def test_parse_ambiguous_json(self) -> None:
        json_str = (
            '{"verdict": "AMBIGUOUS", "confidence": 0.4, "justification": "Unclear response",'
            ' "key_evidence": [], "red_flags": ["vague"]}'
        )
        outcome, just = _parse_structured_evaluation(json_str)
        assert outcome == ChallengeOutcome.AMBIGUOUS
        assert "Unclear response" in just

    def test_parse_red_flags_appended(self) -> None:
        json_str = (
            '{"verdict": "FAIL", "confidence": 0.7, "justification": "Bad",'
            ' "key_evidence": [], "red_flags": ["evasive", "keyword stuffing"]}'
        )
        outcome, just = _parse_structured_evaluation(json_str)
        assert outcome == ChallengeOutcome.FAIL
        assert "red_flags:" in just
        assert "evasive" in just
        assert "keyword stuffing" in just

    def test_parse_malformed_falls_back_to_text(self) -> None:
        """Malformed JSON falls back to text parsing."""
        bad_json = "PASS\nGood answer with domain knowledge"
        outcome, just = _parse_structured_evaluation(bad_json)
        # Should fall back to text parser and get PASS
        assert outcome == ChallengeOutcome.PASS

    def test_parse_empty_json(self) -> None:
        outcome, just = _parse_structured_evaluation("")
        # Empty string should fall back and return AMBIGUOUS
        assert outcome == ChallengeOutcome.AMBIGUOUS

    def test_parse_invalid_verdict_falls_back(self) -> None:
        """Invalid JSON with wrong verdict value falls back to text parser."""
        bad_json = '{"verdict": "MAYBE", "confidence": 0.5, "justification": "unsure"}'
        outcome, _just = _parse_structured_evaluation(bad_json)
        # "MAYBE" is not a valid Literal value, so Pydantic validation fails
        # and falls back to text parsing of the raw string
        assert outcome == ChallengeOutcome.AMBIGUOUS
