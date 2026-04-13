from __future__ import annotations

"""FastAPI routes for the compliance module."""

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory
from airlock.compliance.report_generator import ComplianceReportGenerator
from airlock.compliance.risk_classifier import RiskClassifier
from airlock.compliance.schemas import AgentInventoryEntry, RiskLevel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["compliance"])


def _get_inventory(request: Request) -> AgentInventory:
    return request.app.state.agent_inventory  # type: ignore[no-any-return]


def _get_incident_store(request: Request) -> IncidentStore:
    return request.app.state.incident_store  # type: ignore[no-any-return]


@router.get("/inventory")
async def list_inventory(request: Request) -> JSONResponse:
    """List all agents in the compliance inventory."""
    inventory = _get_inventory(request)
    entries = inventory.list_all()
    return JSONResponse(
        content={
            "agents": [e.model_dump(mode="json") for e in entries],
            "total": len(entries),
        }
    )


@router.post("/inventory")
async def register_agent(request: Request) -> JSONResponse:
    """Register an agent in the compliance inventory."""
    body = await request.json()
    inventory = _get_inventory(request)

    entry = AgentInventoryEntry(**body)

    # Auto-classify risk if enabled
    cfg = request.app.state.config
    if cfg.compliance_risk_auto_classify:
        classifier = RiskClassifier()
        classification = classifier.classify(entry)
        entry.risk_level = classification.risk_level

    registered = inventory.register(entry)
    return JSONResponse(
        content=registered.model_dump(mode="json"),
        status_code=201,
    )


@router.get("/inventory/{did:path}")
async def get_agent(did: str, request: Request) -> JSONResponse:
    """Get a specific agent from the compliance inventory."""
    inventory = _get_inventory(request)
    entry = inventory.get(did)
    if entry is None:
        return JSONResponse(
            content={"error": "not_found", "detail": f"Agent {did} not found"},
            status_code=404,
        )
    return JSONResponse(content=entry.model_dump(mode="json"))


@router.get("/report")
async def generate_report(request: Request) -> JSONResponse:
    """Generate a compliance report for the current period."""
    inventory = _get_inventory(request)
    incident_store = _get_incident_store(request)

    generator = ComplianceReportGenerator(inventory, incident_store)
    now = datetime.now(UTC)
    # Default: last 30 days
    period_start = datetime(now.year, now.month, 1, tzinfo=UTC)
    report = generator.generate(period_start, now)
    return JSONResponse(content=report.model_dump(mode="json"))


@router.get("/report/{did:path}")
async def generate_agent_report(did: str, request: Request) -> JSONResponse:
    """Generate a compliance report for a specific agent."""
    inventory = _get_inventory(request)
    incident_store = _get_incident_store(request)

    generator = ComplianceReportGenerator(inventory, incident_store)
    now = datetime.now(UTC)
    period_start = datetime(now.year, now.month, 1, tzinfo=UTC)
    report = generator.generate_for_agent(did, period_start, now)
    if report is None:
        return JSONResponse(
            content={"error": "not_found", "detail": f"Agent {did} not found"},
            status_code=404,
        )
    return JSONResponse(content=report.model_dump(mode="json"))


@router.post("/incident")
async def report_incident(request: Request) -> JSONResponse:
    """Report a compliance incident."""
    body = await request.json()
    incident_store = _get_incident_store(request)

    severity_str = body.get("severity", "medium")
    try:
        severity = RiskLevel(severity_str)
    except ValueError:
        return JSONResponse(
            content={"error": "validation_error", "detail": f"Invalid severity: {severity_str}"},
            status_code=422,
        )

    incident = incident_store.report(
        agent_did=body["agent_did"],
        severity=severity,
        incident_type=body.get("incident_type", "general"),
        description=body.get("description", ""),
        affected_users=body.get("affected_users", 0),
    )
    return JSONResponse(
        content=incident.model_dump(mode="json"),
        status_code=201,
    )


@router.get("/incidents")
async def list_incidents(request: Request) -> JSONResponse:
    """List all compliance incidents."""
    incident_store = _get_incident_store(request)
    incidents = incident_store.list_all()
    return JSONResponse(
        content={
            "incidents": [i.model_dump(mode="json") for i in incidents],
            "total": len(incidents),
        }
    )


@router.get("/risk/{did:path}")
async def classify_risk(did: str, request: Request) -> JSONResponse:
    """Classify the risk level of a specific agent."""
    inventory = _get_inventory(request)
    entry = inventory.get(did)
    if entry is None:
        return JSONResponse(
            content={"error": "not_found", "detail": f"Agent {did} not found"},
            status_code=404,
        )

    classifier = RiskClassifier()
    classification = classifier.classify(entry)
    return JSONResponse(content=classification.model_dump(mode="json"))


@router.get("/audit-summary")
async def audit_summary(request: Request) -> JSONResponse:
    """Get an audit summary of compliance data."""
    inventory = _get_inventory(request)
    incident_store = _get_incident_store(request)

    generator = ComplianceReportGenerator(inventory, incident_store)
    summary = generator.generate_audit_summary()
    return JSONResponse(content=summary)


def register_compliance_routes(app: FastAPI) -> None:
    """Mount the compliance router on the FastAPI app."""
    app.include_router(router)
    logger.info("Compliance routes registered")
