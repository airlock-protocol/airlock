"""Tiered CRL freshness assessment for fail-open/fail-closed degradation.

Determines how stale a CRL is and what operational mode the gateway should
use when making trust decisions.

Modes (in order of increasing severity):
  NORMAL       -- CRL is fresh (age < update interval)
  DEGRADED     -- CRL is stale but within max_cache_age (warn on attestations)
  EMERGENCY    -- CRL is very stale (only allow high-trust agents)
  FAIL_CLOSED  -- CRL is unacceptably stale (reject all verifications)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from airlock.config import AirlockConfig
    from airlock.schemas.crl import SignedCRL

logger = logging.getLogger(__name__)


class CRLFreshnessMode(StrEnum):
    """Operational mode based on CRL staleness."""

    NORMAL = "normal"
    DEGRADED = "degraded"
    EMERGENCY = "emergency"
    FAIL_CLOSED = "fail_closed"


def assess_crl_freshness(crl: SignedCRL, config: AirlockConfig) -> CRLFreshnessMode:
    """Determine CRL freshness mode based on age thresholds.

    Parameters
    ----------
    crl:
        The CRL to assess.
    config:
        Gateway configuration containing threshold values.

    Returns
    -------
    CRLFreshnessMode
        The operational mode the gateway should use.

    Thresholds
    ----------
    - NORMAL:      crl_age < crl_update_interval_seconds
    - DEGRADED:    crl_age < crl_max_cache_age_seconds
    - EMERGENCY:   crl_age < crl_emergency_cache_age_seconds
    - FAIL_CLOSED: crl_age >= crl_emergency_cache_age_seconds
    """
    now = datetime.now(UTC)
    crl_age_seconds = (now - crl.this_update).total_seconds()

    if crl_age_seconds < config.crl_update_interval_seconds:
        return CRLFreshnessMode.NORMAL

    if crl_age_seconds < config.crl_max_cache_age_seconds:
        logger.warning(
            "CRL #%d is stale (age=%.0fs, threshold=%ds) — DEGRADED mode",
            crl.crl_number,
            crl_age_seconds,
            config.crl_update_interval_seconds,
        )
        return CRLFreshnessMode.DEGRADED

    if crl_age_seconds < config.crl_emergency_cache_age_seconds:
        logger.warning(
            "CRL #%d is very stale (age=%.0fs, threshold=%ds) — EMERGENCY mode",
            crl.crl_number,
            crl_age_seconds,
            config.crl_max_cache_age_seconds,
        )
        return CRLFreshnessMode.EMERGENCY

    logger.error(
        "CRL #%d exceeds emergency threshold (age=%.0fs, limit=%ds) — FAIL_CLOSED",
        crl.crl_number,
        crl_age_seconds,
        config.crl_emergency_cache_age_seconds,
    )
    return CRLFreshnessMode.FAIL_CLOSED
