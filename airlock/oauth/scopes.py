from __future__ import annotations

"""OAuth 2.1 scope definitions and validation for Airlock."""

AIRLOCK_SCOPES: dict[str, str] = {
    "verify:read": "Read verification results",
    "trust:write": "Submit trust signals",
    "agent:manage": "Manage agent registration",
    "delegation:exchange": "Perform token exchange",
    "compliance:read": "Read compliance reports",
}


def validate_scopes(requested: str, allowed: str) -> str:
    """Return the intersection of *requested* and *allowed* scope strings.

    Each string is a space-separated list of scope tokens.  Unknown tokens
    (not in :data:`AIRLOCK_SCOPES`) are silently dropped.

    Raises :class:`ValueError` when the resulting scope set is empty.
    """
    allowed_set = set(allowed.replace(",", " ").split())
    requested_set = set(requested.replace(",", " ").split())
    valid = {s for s in requested_set if s in AIRLOCK_SCOPES and s in allowed_set}
    if not valid:
        raise ValueError(
            f"No valid scopes in request. Requested: {requested!r}, allowed: {allowed!r}"
        )
    return " ".join(sorted(valid))


def is_scope_subset(child: str, parent: str) -> bool:
    """Return True when every token in *child* also appears in *parent*."""
    child_set = set(child.replace(",", " ").split())
    parent_set = set(parent.replace(",", " ").split())
    return child_set.issubset(parent_set)
