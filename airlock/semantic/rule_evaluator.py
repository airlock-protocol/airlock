"""Rule-based challenge evaluation for when LLM is unavailable."""

import re

from airlock.schemas.challenge import ChallengeRequest, ChallengeResponse
from airlock.semantic.challenge import ChallengeOutcome

_DOMAIN_KEYWORDS = {
    "crypto": {
        "encryption", "signature", "hash", "key", "certificate",
        "nonce", "authentication",
    },
    "payments": {
        "transaction", "settlement", "upi", "payment", "merchant",
        "refund", "authorization",
    },
    "security": {
        "vulnerability", "firewall", "authorization", "authentication",
        "access", "permission",
    },
    "networking": {
        "protocol", "tcp", "http", "dns", "routing", "latency",
        "bandwidth",
    },
    "database": {
        "query", "index", "schema", "normalization", "transaction",
        "replication",
    },
}

_EVASION_PATTERNS = [
    re.compile(r"i don.t know", re.IGNORECASE),
    re.compile(r"as an ai", re.IGNORECASE),
    re.compile(r"i.m not sure", re.IGNORECASE),
    re.compile(r"i cannot", re.IGNORECASE),
]


def evaluate_rule_based(
    challenge: ChallengeRequest,
    response: ChallengeResponse,
) -> tuple[ChallengeOutcome, str]:
    """Evaluate a challenge response using deterministic rules.

    Used as a fallback when the LLM is unavailable and the deployment
    is configured with ``AIRLOCK_CHALLENGE_FALLBACK_MODE=rule_based``.

    Returns ``(ChallengeOutcome, justification)``.
    """
    answer = response.answer.strip()

    # --- too short ---
    if len(answer) < 20:
        return ChallengeOutcome.FAIL, "Answer too short"

    # --- evasion detection ---
    for pattern in _EVASION_PATTERNS:
        if pattern.search(answer):
            return ChallengeOutcome.FAIL, "Evasive answer detected"

    # --- domain keyword matching ---
    context_lower = challenge.context.lower()
    answer_lower = answer.lower()
    answer_words = set(answer_lower.split())

    best_matches = 0
    for domain, keywords in _DOMAIN_KEYWORDS.items():
        if domain in context_lower:
            matches = len(keywords & answer_words)
            best_matches = max(best_matches, matches)

    if best_matches >= 2:
        return (
            ChallengeOutcome.PASS,
            f"Rule-based: {best_matches} domain keywords matched",
        )

    # --- complexity heuristic ---
    unique_words = set(answer_lower.split())
    if len(unique_words) >= 15:
        return ChallengeOutcome.PASS, "Rule-based: sufficient answer complexity"

    return ChallengeOutcome.FAIL, "Rule-based: insufficient domain knowledge"
