"""Basic bias detection for AI agent behavior patterns -- FREE-AI Rec #15."""

from __future__ import annotations

import logging
import statistics
from typing import Any

logger = logging.getLogger(__name__)


class BiasDetector:
    """Basic bias detection for AI agent behavior patterns."""

    def analyze_verification_patterns(
        self, verification_results: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Detect statistical bias in verification outcomes.

        Looks for skewed pass/fail rates that could indicate systematic bias
        in the verification process.
        """
        if not verification_results:
            return {
                "bias_detected": False,
                "bias_type": "none",
                "confidence": 0.0,
                "details": "No verification data available",
            }

        total = len(verification_results)
        passed = sum(1 for r in verification_results if r.get("result") == "passed")
        failed = total - passed

        pass_rate = passed / total if total > 0 else 0.0

        # Check for extreme skew (>90% or <10% pass rate with sufficient data)
        if total >= 10 and (pass_rate > 0.9 or pass_rate < 0.1):
            bias_type = "high_pass_rate" if pass_rate > 0.9 else "high_fail_rate"
            return {
                "bias_detected": True,
                "bias_type": bias_type,
                "confidence": min(0.5 + (total / 100), 0.95),
                "details": (
                    f"Verification pass rate is {pass_rate:.1%} "
                    f"across {total} verifications (passed={passed}, failed={failed})"
                ),
            }

        return {
            "bias_detected": False,
            "bias_type": "none",
            "confidence": min(0.5 + (total / 100), 0.95),
            "details": (
                f"Verification pass rate is {pass_rate:.1%} "
                f"across {total} verifications -- within expected range"
            ),
        }

    def analyze_trust_distribution(
        self, trust_scores: list[float]
    ) -> dict[str, Any]:
        """Analyze trust score distribution for anomalies.

        Checks for abnormal clustering, extreme values, or unexpected
        distribution patterns that could indicate bias.
        """
        if not trust_scores:
            return {
                "anomaly_detected": False,
                "distribution_type": "unknown",
                "details": "No trust score data available",
            }

        if len(trust_scores) < 2:
            return {
                "anomaly_detected": False,
                "distribution_type": "insufficient_data",
                "mean": trust_scores[0] if trust_scores else 0.0,
                "details": "Insufficient data for distribution analysis",
            }

        mean = statistics.mean(trust_scores)
        stdev = statistics.stdev(trust_scores)
        median = statistics.median(trust_scores)

        # Detect clustering at extremes
        low_cluster = sum(1 for s in trust_scores if s < 0.2) / len(trust_scores)
        high_cluster = sum(1 for s in trust_scores if s > 0.8) / len(trust_scores)

        anomaly = False
        distribution_type = "normal"
        details_parts: list[str] = []

        if stdev < 0.05 and len(trust_scores) >= 5:
            anomaly = True
            distribution_type = "uniform_cluster"
            details_parts.append(
                f"Scores are unusually clustered (stdev={stdev:.3f})"
            )

        if low_cluster > 0.5:
            anomaly = True
            distribution_type = "low_skew"
            details_parts.append(
                f"{low_cluster:.0%} of scores below 0.2"
            )

        if high_cluster > 0.8:
            anomaly = True
            distribution_type = "high_skew"
            details_parts.append(
                f"{high_cluster:.0%} of scores above 0.8"
            )

        if abs(mean - median) > 0.2:
            anomaly = True
            distribution_type = "skewed"
            details_parts.append(
                f"Mean-median gap of {abs(mean - median):.2f} suggests skew"
            )

        if not details_parts:
            details_parts.append("Distribution appears normal")

        return {
            "anomaly_detected": anomaly,
            "distribution_type": distribution_type,
            "mean": round(mean, 4),
            "stdev": round(stdev, 4),
            "median": round(median, 4),
            "details": "; ".join(details_parts),
        }
