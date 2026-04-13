from __future__ import annotations

"""Bias detection for agent verification patterns."""

import logging
import statistics
from typing import Any

logger = logging.getLogger(__name__)


class BiasDetector:
    """Detects potential bias in verification outcomes and trust distributions."""

    def analyze_verification_patterns(
        self,
        results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze verification results for potential bias.

        Each result dict should have at least 'outcome' (str) and optionally
        'agent_type' (str) keys.
        """
        if not results:
            return {
                "bias_detected": False,
                "bias_type": None,
                "confidence": 0.0,
                "details": "insufficient data",
            }

        # Group by agent_type
        groups: dict[str, list[dict[str, Any]]] = {}
        for r in results:
            agent_type = str(r.get("agent_type", "unknown"))
            groups.setdefault(agent_type, []).append(r)

        # Compute pass rates per group
        pass_rates: dict[str, float] = {}
        for group_name, group_results in groups.items():
            passed = sum(1 for r in group_results if r.get("outcome") == "verified")
            pass_rates[group_name] = passed / len(group_results) if group_results else 0.0

        # Check for significant disparity
        if len(pass_rates) < 2:
            return {
                "bias_detected": False,
                "bias_type": None,
                "confidence": 0.0,
                "details": "single group, no comparison possible",
                "pass_rates": pass_rates,
            }

        rates = list(pass_rates.values())
        max_disparity = max(rates) - min(rates)

        bias_detected = max_disparity > 0.3
        bias_type = "outcome_disparity" if bias_detected else None
        confidence = min(max_disparity / 0.5, 1.0) if bias_detected else 0.0

        return {
            "bias_detected": bias_detected,
            "bias_type": bias_type,
            "confidence": round(confidence, 3),
            "max_disparity": round(max_disparity, 3),
            "pass_rates": pass_rates,
        }

    def analyze_trust_distribution(
        self,
        scores: list[float],
    ) -> dict[str, Any]:
        """Analyze the distribution of trust scores for fairness."""
        if not scores:
            return {
                "count": 0,
                "mean": 0.0,
                "median": 0.0,
                "std_dev": 0.0,
                "min": 0.0,
                "max": 0.0,
                "skew_warning": False,
            }

        mean = statistics.mean(scores)
        median = statistics.median(scores)
        std_dev = statistics.stdev(scores) if len(scores) >= 2 else 0.0
        min_score = min(scores)
        max_score = max(scores)

        # Flag if distribution is heavily skewed
        skew_warning = abs(mean - median) > 0.15

        return {
            "count": len(scores),
            "mean": round(mean, 4),
            "median": round(median, 4),
            "std_dev": round(std_dev, 4),
            "min": round(min_score, 4),
            "max": round(max_score, 4),
            "skew_warning": skew_warning,
        }
