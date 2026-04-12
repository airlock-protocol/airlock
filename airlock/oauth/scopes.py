from __future__ import annotations

"""OAuth 2.1 scope definitions and validation for the Airlock Protocol."""

import logging

logger = logging.getLogger(__name__)

AIRLOCK_SCOPES: dict[str, str] = {
    "verify:read": "Read verification session status and results",
    "trust:write": "Submit challenge responses and update trust scores",
    "agent:manage": "Register and manage agent profiles",
    "delegation:exchange": "Exchange tokens for delegation chains",
    "compliance:read": "Read audit trail and compliance data",
}


def validate_scopes(scope_string: str, allowed_scopes: str | None = None) -> list[str]:
    """Validate a space-separated scope string and return the list of valid scopes.

    Parameters
    ----------
    scope_string:
        Space-separated scope string from the token request.
    allowed_scopes:
        Comma-separated string of allowed scopes (from config).
        If None, all AIRLOCK_SCOPES are allowed.

    Returns
    -------
    List of validated scope strings.

    Raises
    ------
    ValueError
        If any requested scope is unknown or not in the allowed set.
    """
    if not scope_string or not scope_string.strip():
        return []

    requested = scope_string.strip().split()
    known = set(AIRLOCK_SCOPES.keys())

    if allowed_scopes is not None:
        permitted = {s.strip() for s in allowed_scopes.split(",") if s.strip()}
    else:
        permitted = known

    validated: list[str] = []
    for scope in requested:
        if scope not in known:
            raise ValueError(f"Unknown scope: {scope}")
        if scope not in permitted:
            raise ValueError(f"Scope not permitted: {scope}")
        validated.append(scope)

    return validated


def is_scope_subset(child_scopes: str, parent_scopes: str) -> bool:
    """Check whether child_scopes is a subset of parent_scopes.

    Both are space-separated scope strings.

    Returns True if every scope in child_scopes exists in parent_scopes.
    """
    if not child_scopes or not child_scopes.strip():
        return True
    if not parent_scopes or not parent_scopes.strip():
        return False

    child_set = set(child_scopes.strip().split())
    parent_set = set(parent_scopes.strip().split())
    return child_set.issubset(parent_set)
