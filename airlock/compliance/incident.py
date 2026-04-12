"""Thread-safe incident store with hash-chain integrity -- FREE-AI Rec #13."""

from __future__ import annotations

import hashlib
import json
import logging
import threading

from airlock.compliance.schemas import IncidentReport, RiskLevel

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def _compute_hash(incident: IncidentReport) -> str:
    """Compute SHA-256 of an incident using canonical JSON."""
    payload = {
        "incident_id": incident.incident_id,
        "agent_did": incident.agent_did,
        "severity": incident.severity,
        "incident_type": incident.incident_type,
        "detected_at": incident.detected_at.isoformat(),
        "previous_hash": incident.previous_hash,
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class IncidentStore:
    """Thread-safe incident store with hash-chain integrity."""

    def __init__(self) -> None:
        self._incidents: list[IncidentReport] = []
        self._lock = threading.Lock()
        self._last_hash: str = GENESIS_HASH
        self._index: dict[str, int] = {}  # incident_id -> list index

    def report(self, incident: IncidentReport) -> IncidentReport:
        """Record incident with hash-chain linking."""
        with self._lock:
            incident.previous_hash = self._last_hash
            incident.incident_hash = _compute_hash(incident)
            self._last_hash = incident.incident_hash
            idx = len(self._incidents)
            self._incidents.append(incident)
            self._index[incident.incident_id] = idx
        logger.info(
            "Incident reported: id=%s agent=%s severity=%s",
            incident.incident_id,
            incident.agent_did,
            incident.severity,
        )
        return incident

    def get(self, incident_id: str) -> IncidentReport | None:
        """Look up an incident by ID."""
        with self._lock:
            idx = self._index.get(incident_id)
            if idx is None:
                return None
            return self._incidents[idx]

    def list_all(self, limit: int = 100, offset: int = 0) -> list[IncidentReport]:
        """Return incidents with pagination (newest first)."""
        with self._lock:
            reversed_list = list(reversed(self._incidents))
            return reversed_list[offset : offset + limit]

    def list_by_agent(self, did: str) -> list[IncidentReport]:
        """Return all incidents for a specific agent DID."""
        with self._lock:
            return [i for i in self._incidents if i.agent_did == did]

    def list_by_severity(self, severity: RiskLevel) -> list[IncidentReport]:
        """Return incidents matching a specific severity level."""
        with self._lock:
            return [i for i in self._incidents if i.severity == severity]

    def update_status(
        self, incident_id: str, status: str, resolution: str | None = None
    ) -> bool:
        """Update the status and optional resolution of an incident."""
        with self._lock:
            idx = self._index.get(incident_id)
            if idx is None:
                return False
            incident = self._incidents[idx]
            data = incident.model_dump()
            data["status"] = status
            if resolution is not None:
                data["resolution"] = resolution
            self._incidents[idx] = IncidentReport(**data)
            return True

    def count_by_severity(self) -> dict[str, int]:
        """Return counts grouped by severity level."""
        counts: dict[str, int] = {level.value: 0 for level in RiskLevel}
        with self._lock:
            for incident in self._incidents:
                counts[incident.severity.value] += 1
        return counts

    def count_by_agent(self, did: str) -> int:
        """Return the number of incidents for a specific agent."""
        with self._lock:
            return sum(1 for i in self._incidents if i.agent_did == did)

    def verify_chain(self) -> tuple[bool, str]:
        """Walk the chain and verify every hash link."""
        with self._lock:
            if not self._incidents:
                return True, "ok"
            expected_prev = GENESIS_HASH
            for i, incident in enumerate(self._incidents):
                if incident.previous_hash != expected_prev:
                    return False, f"Incident {i} ({incident.incident_id}): previous_hash mismatch"
                recomputed = _compute_hash(incident)
                if incident.incident_hash != recomputed:
                    return False, f"Incident {i} ({incident.incident_id}): incident_hash mismatch"
                expected_prev = incident.incident_hash
            return True, "ok"

    def __len__(self) -> int:
        with self._lock:
            return len(self._incidents)
