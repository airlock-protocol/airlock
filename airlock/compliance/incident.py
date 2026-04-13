from __future__ import annotations

"""Thread-safe incident store with hash-chain integrity."""

import hashlib
import json
import logging
import threading
import uuid
from datetime import UTC, datetime

from airlock.compliance.schemas import IncidentReport, RiskLevel

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def _compute_incident_hash(report: IncidentReport) -> str:
    """Compute SHA-256 hash of an incident report for chain integrity."""
    payload = {
        "incident_id": report.incident_id,
        "agent_did": report.agent_did,
        "severity": report.severity.value,
        "incident_type": report.incident_type,
        "description": report.description,
        "detected_at": report.detected_at.isoformat(),
        "reported_at": report.reported_at.isoformat(),
        "status": report.status,
        "resolution": report.resolution,
        "affected_users": report.affected_users,
        "previous_hash": report.previous_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    return hashlib.sha256(canonical).hexdigest()


class IncidentStore:
    """Thread-safe incident store with hash-chain integrity."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._incidents: list[IncidentReport] = []
        self._index: dict[str, IncidentReport] = {}
        self._last_hash: str = GENESIS_HASH

    def report(
        self,
        agent_did: str,
        severity: RiskLevel,
        incident_type: str,
        description: str,
        affected_users: int = 0,
    ) -> IncidentReport:
        """Create and store a new incident report with hash-chain linking."""
        with self._lock:
            now = datetime.now(UTC)
            incident = IncidentReport(
                incident_id=str(uuid.uuid4()),
                agent_did=agent_did,
                severity=severity,
                incident_type=incident_type,
                description=description,
                detected_at=now,
                reported_at=now,
                affected_users=affected_users,
                previous_hash=self._last_hash,
            )
            incident.incident_hash = _compute_incident_hash(incident)
            self._last_hash = incident.incident_hash

            self._incidents.append(incident)
            self._index[incident.incident_id] = incident
            logger.info(
                "Incident reported: %s (agent=%s, severity=%s)",
                incident.incident_id,
                agent_did,
                severity.value,
            )
            return incident

    def get(self, incident_id: str) -> IncidentReport | None:
        """Retrieve an incident by ID."""
        with self._lock:
            return self._index.get(incident_id)

    def list_all(self) -> list[IncidentReport]:
        """Return all incidents (newest first)."""
        with self._lock:
            return list(reversed(self._incidents))

    def list_by_agent(self, agent_did: str) -> list[IncidentReport]:
        """Return incidents for a specific agent (newest first)."""
        with self._lock:
            return [i for i in reversed(self._incidents) if i.agent_did == agent_did]

    def list_by_severity(self, severity: RiskLevel) -> list[IncidentReport]:
        """Return incidents filtered by severity (newest first)."""
        with self._lock:
            return [i for i in reversed(self._incidents) if i.severity == severity]

    def update_status(
        self,
        incident_id: str,
        status: str,
        resolution: str = "",
    ) -> IncidentReport | None:
        """Update the status and optional resolution of an incident."""
        with self._lock:
            incident = self._index.get(incident_id)
            if incident is None:
                return None
            incident.status = status
            incident.resolution = resolution
            logger.info("Incident %s status updated to %s", incident_id, status)
            return incident

    def count_by_severity(self) -> dict[str, int]:
        """Return a count of incidents grouped by severity."""
        with self._lock:
            counts: dict[str, int] = {}
            for incident in self._incidents:
                key = incident.severity.value
                counts[key] = counts.get(key, 0) + 1
            return counts

    @property
    def last_hash(self) -> str:
        """Return the last hash in the chain."""
        with self._lock:
            return self._last_hash
