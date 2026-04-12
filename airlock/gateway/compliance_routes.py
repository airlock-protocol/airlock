"""Compliance API routes for the RBI FREE-AI module."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from airlock.compliance.free_ai_mapper import FreeAIMapper
from airlock.compliance.report_generator import ComplianceReportGenerator
from airlock.compliance.risk_classifier import RiskClassifier
from airlock.compliance.schemas import AgentInventoryEntry, IncidentReport

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/inventory")
async def list_inventory(
    request: Request, risk_level: str | None = None
) -> list[dict[str, Any]]:
    """List all agents in the compliance inventory, optionally filtered by risk level."""
    inventory = request.app.state.agent_inventory
    if risk_level is not None:
        entries = inventory.list_by_risk(risk_level)
    else:
        entries = inventory.list_all()
    return [e.model_dump(mode="json") for e in entries]


@router.post("/inventory")
async def register_in_inventory(
    request: Request, body: AgentInventoryEntry
) -> dict[str, Any]:
    """Register an agent in the compliance inventory."""
    if not body.did.startswith("did:key:"):
        return JSONResponse(  # type: ignore[return-value]
            status_code=400,
            content={
                "error": "invalid_did",
                "detail": "DID must start with 'did:key:'",
                "status_code": 400,
            },
        )

    inventory = request.app.state.agent_inventory

    # Auto-classify risk if enabled
    cfg = request.app.state.config
    if cfg.compliance_risk_auto_classify:
        classifier = RiskClassifier()
        classification = classifier.classify(body)
        data = body.model_dump()
        data["risk_level"] = classification.risk_level
        data["last_assessed_at"] = classification.assessed_at
        body = AgentInventoryEntry(**data)

    inventory.register(body)
    return {"registered": True, "did": body.did, "risk_level": body.risk_level.value}


@router.get("/inventory/{did:path}")
async def get_agent_compliance(
    request: Request, did: str
) -> dict[str, Any]:
    """Get compliance details for a specific agent."""
    inventory = request.app.state.agent_inventory
    entry = inventory.get(did)
    if entry is None:
        return JSONResponse(  # type: ignore[return-value]
            status_code=404,
            content={
                "error": "not_found",
                "detail": f"Agent {did} not found in inventory",
                "status_code": 404,
            },
        )
    return entry.model_dump(mode="json")


@router.get("/report")
async def generate_report(
    request: Request, period_days: int = 30
) -> dict[str, Any]:
    """Generate a compliance report for the specified period."""
    inventory = request.app.state.agent_inventory
    incident_store = request.app.state.incident_store
    mapper = FreeAIMapper()
    generator = ComplianceReportGenerator(inventory, incident_store, mapper)

    period_end = datetime.now(UTC)
    period_start = period_end - timedelta(days=period_days)
    report = generator.generate(period_start, period_end)
    return report.model_dump(mode="json")


@router.get("/report/{did:path}")
async def generate_agent_report(
    request: Request, did: str, period_days: int = 30
) -> dict[str, Any]:
    """Generate a compliance report for a specific agent."""
    inventory = request.app.state.agent_inventory
    incident_store = request.app.state.incident_store
    mapper = FreeAIMapper()
    generator = ComplianceReportGenerator(inventory, incident_store, mapper)

    period_end = datetime.now(UTC)
    period_start = period_end - timedelta(days=period_days)
    report = generator.generate_for_agent(did, period_start, period_end)
    return report.model_dump(mode="json")


@router.post("/incident")
async def report_incident(
    request: Request, body: IncidentReport
) -> dict[str, Any]:
    """Report a compliance incident."""
    if not body.agent_did.startswith("did:key:"):
        return JSONResponse(  # type: ignore[return-value]
            status_code=400,
            content={
                "error": "invalid_did",
                "detail": "agent_did must start with 'did:key:'",
                "status_code": 400,
            },
        )
    incident_store = request.app.state.incident_store
    recorded = incident_store.report(body)
    return {
        "recorded": True,
        "incident_id": recorded.incident_id,
        "incident_hash": recorded.incident_hash,
    }


@router.get("/incidents")
async def list_incidents(
    request: Request, limit: int = 100, offset: int = 0
) -> list[dict[str, Any]]:
    """List all compliance incidents with pagination."""
    incident_store = request.app.state.incident_store
    incidents = incident_store.list_all(limit=limit, offset=offset)
    return [i.model_dump(mode="json") for i in incidents]


@router.get("/risk/{did:path}")
async def get_risk_classification(
    request: Request, did: str
) -> dict[str, Any]:
    """Get the risk classification for a specific agent."""
    inventory = request.app.state.agent_inventory
    entry = inventory.get(did)
    if entry is None:
        return JSONResponse(  # type: ignore[return-value]
            status_code=404,
            content={
                "error": "not_found",
                "detail": f"Agent {did} not found in inventory",
                "status_code": 404,
            },
        )
    classifier = RiskClassifier()
    classification = classifier.classify(entry)
    return classification.model_dump(mode="json")


@router.get("/audit-summary")
async def audit_summary(request: Request) -> dict[str, Any]:
    """Get an audit summary of the compliance state."""
    inventory = request.app.state.agent_inventory
    incident_store = request.app.state.incident_store
    mapper = FreeAIMapper()
    generator = ComplianceReportGenerator(inventory, incident_store, mapper)
    return generator.generate_audit_summary()


def register_compliance_routes(app: FastAPI) -> None:
    """Register compliance routes on the FastAPI app."""
    app.include_router(router)
