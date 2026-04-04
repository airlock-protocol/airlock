"""Rule-based challenge evaluation for when LLM is unavailable.

Hardened against keyword-stuffing attacks with density checks,
n-gram diversity, cross-domain traps, and coherence heuristics.
"""

import logging
import re

from airlock.schemas.challenge import ChallengeRequest, ChallengeResponse
from airlock.semantic.challenge import ChallengeOutcome

logger = logging.getLogger(__name__)

_DOMAIN_KEYWORDS: dict[str, set[str]] = {
    "crypto": {
        "encryption",
        "signature",
        "hash",
        "key",
        "certificate",
        "nonce",
        "authentication",
    },
    "payments": {
        "transaction",
        "settlement",
        "transfer",
        "payment",
        "merchant",
        "refund",
        "authorization",
    },
    "security": {
        "vulnerability",
        "firewall",
        "authorization",
        "authentication",
        "access",
        "permission",
    },
    "networking": {
        "protocol",
        "tcp",
        "http",
        "dns",
        "routing",
        "latency",
        "bandwidth",
    },
    "database": {
        "query",
        "index",
        "schema",
        "normalization",
        "transaction",
        "replication",
    },
}

_ALL_DOMAIN_KEYWORDS: set[str] = set()
for _kw_set in _DOMAIN_KEYWORDS.values():
    _ALL_DOMAIN_KEYWORDS |= _kw_set

# Keywords that belong to exactly one domain.  Used by the cross-domain
# trap so that shared words like "authentication" don't cause false positives.
_EXCLUSIVE_DOMAIN_KEYWORDS: dict[str, set[str]] = {}
for _domain, _kws in _DOMAIN_KEYWORDS.items():
    _other_kws: set[str] = set()
    for _d2, _kws2 in _DOMAIN_KEYWORDS.items():
        if _d2 != _domain:
            _other_kws |= _kws2
    _EXCLUSIVE_DOMAIN_KEYWORDS[_domain] = _kws - _other_kws

_EVASION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"i don.t know", re.IGNORECASE),
    re.compile(r"as an ai", re.IGNORECASE),
    re.compile(r"i.m not sure", re.IGNORECASE),
    re.compile(r"i cannot", re.IGNORECASE),
]

# Sentence-ending punctuation used to count sentences.
_SENTENCE_ENDERS = re.compile(r"[.!?]+")

# Common English function words that form natural connective tissue.
# Their presence in bigrams is a positive coherence signal.
_FUNCTION_WORDS: set[str] = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "has", "have", "had", "do", "does", "did", "will", "would", "shall",
    "should", "may", "might", "can", "could", "must", "of", "in", "to",
    "for", "with", "on", "at", "by", "from", "as", "into", "through",
    "during", "before", "after", "and", "but", "or", "not", "if", "then",
    "that", "this", "these", "those", "it", "its", "which", "who", "whom",
    "what", "when", "where", "how", "than", "both", "each", "every",
    "between", "such", "also", "so", "no", "about", "up", "out", "just",
    "only", "very", "more", "most", "other", "some", "any", "all",
}

# Maximum allowed ratio of domain keywords to total unique words.
_KEYWORD_DENSITY_THRESHOLD: float = 0.30

# Minimum unique word count for the complexity heuristic.
_COMPLEXITY_UNIQUE_WORDS: int = 25

# Minimum sentence count for the complexity heuristic.
_COMPLEXITY_MIN_SENTENCES: int = 2

# How many different domains' keywords may appear before flagging as stuffing.
_CROSS_DOMAIN_LIMIT: int = 3

# Minimum fraction of bigrams that must contain a function word.
_COHERENCE_THRESHOLD: float = 0.25


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _extract_words(text: str) -> list[str]:
    """Lowercase split into alphabetic word tokens."""
    return re.findall(r"[a-z]+", text.lower())


def _count_sentences(text: str) -> int:
    """Count sentences by splitting on sentence-ending punctuation."""
    parts = _SENTENCE_ENDERS.split(text.strip())
    # Filter out empty fragments that result from trailing punctuation.
    return len([p for p in parts if p.strip()])


def _build_ngrams(words: list[str], n: int) -> list[tuple[str, ...]]:
    """Return a list of n-grams from *words*."""
    return [tuple(words[i : i + n]) for i in range(len(words) - n + 1)]


def _extract_question_nouns(question: str) -> set[str]:
    """Extract likely key nouns from the challenge question.

    Uses a simple heuristic: words that are not function words and are
    longer than 2 characters are treated as potential content nouns.
    """
    words = _extract_words(question)
    return {w for w in words if w not in _FUNCTION_WORDS and len(w) > 2}


# ---------------------------------------------------------------------------
# Main evaluator
# ---------------------------------------------------------------------------

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

    answer_words = _extract_words(answer)
    unique_words = set(answer_words)

    # ------------------------------------------------------------------
    # (b) Keyword density check — if domain keywords make up >30% of
    #     unique words the answer is likely keyword-stuffed.
    # ------------------------------------------------------------------
    domain_hits = unique_words & _ALL_DOMAIN_KEYWORDS
    if unique_words:
        density = len(domain_hits) / len(unique_words)
    else:
        density = 0.0

    if density > _KEYWORD_DENSITY_THRESHOLD:
        return (
            ChallengeOutcome.FAIL,
            f"Rule-based: keyword density too high ({density:.0%})",
        )

    # ------------------------------------------------------------------
    # (e) Cross-domain trap — keywords from 3+ domains simultaneously
    #     indicate indiscriminate stuffing.  We only count a domain when
    #     the answer contains at least one keyword *exclusive* to it so
    #     shared words (e.g. "authentication") don't cause false positives.
    # ------------------------------------------------------------------
    domains_hit: list[str] = []
    for domain, exclusive_kws in _EXCLUSIVE_DOMAIN_KEYWORDS.items():
        if exclusive_kws & unique_words:
            domains_hit.append(domain)

    if len(domains_hit) >= _CROSS_DOMAIN_LIMIT:
        return (
            ChallengeOutcome.FAIL,
            f"Rule-based: cross-domain keyword stuffing detected "
            f"({', '.join(sorted(domains_hit))})",
        )

    # ------------------------------------------------------------------
    # (f) Coherence heuristic — at least some bigrams should contain a
    #     function word, indicating natural sentence structure.
    # ------------------------------------------------------------------
    bigrams = _build_ngrams(answer_words, 2)
    if bigrams:
        coherent_count = sum(
            1
            for bg in bigrams
            if bg[0] in _FUNCTION_WORDS or bg[1] in _FUNCTION_WORDS
        )
        coherence = coherent_count / len(bigrams)
        if coherence < _COHERENCE_THRESHOLD:
            return (
                ChallengeOutcome.FAIL,
                f"Rule-based: low coherence ({coherence:.0%})",
            )

    # ------------------------------------------------------------------
    # (a) Question-answer relevance — extract key nouns from the
    #     question and verify the answer addresses at least some.
    # ------------------------------------------------------------------
    question_nouns = _extract_question_nouns(challenge.question)
    if question_nouns:
        overlap = question_nouns & unique_words
        relevance_ratio = len(overlap) / len(question_nouns)
    else:
        relevance_ratio = 1.0  # No nouns to check — skip this gate.

    # --- domain keyword matching (strengthened) ---
    context_lower = challenge.context.lower()

    best_matches = 0
    for domain, keywords in _DOMAIN_KEYWORDS.items():
        if domain in context_lower:
            matches = len(keywords & unique_words)
            best_matches = max(best_matches, matches)

    if best_matches >= 2 and relevance_ratio >= 0.15:
        # ------------------------------------------------------------------
        # (c) N-gram diversity — check that the answer isn't just isolated
        #     keyword drops by requiring varied bigrams and trigrams.
        # ------------------------------------------------------------------
        unique_bigrams = set(bigrams)
        trigrams = _build_ngrams(answer_words, 3)
        unique_trigrams = set(trigrams)

        # Require at least 3 unique bigrams and 2 unique trigrams for
        # answers that pass on keyword matching.
        if len(unique_bigrams) >= 3 and len(unique_trigrams) >= 2:
            return (
                ChallengeOutcome.PASS,
                f"Rule-based: {best_matches} domain keywords matched",
            )

    # ------------------------------------------------------------------
    # (d) Raised complexity threshold — 25 unique words AND at least 2
    #     sentences (containing periods / question marks / exclamation).
    # ------------------------------------------------------------------
    sentence_count = _count_sentences(answer)
    if (
        len(unique_words) >= _COMPLEXITY_UNIQUE_WORDS
        and sentence_count >= _COMPLEXITY_MIN_SENTENCES
        and relevance_ratio >= 0.10
    ):
        return ChallengeOutcome.PASS, "Rule-based: sufficient answer complexity"

    return ChallengeOutcome.FAIL, "Rule-based: insufficient domain knowledge"
