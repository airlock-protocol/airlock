from __future__ import annotations

"""FastAPI routes for the compliance module."""

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from airlock.compliance.evidence_pack import (
    build_evidence_pack,
    default_export_window,
    render_json,
    render_markdown,
)
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


@router.get("/evidence-pack")
async def export_evidence_pack(
    request: Request,
    from_iso: str | None = Query(default=None, alias="from"),
    to_iso: str | None = Query(default=None, alias="to"),
    format: str = Query(default="json"),
) -> Response:
    """Export a signed evidence pack for a time window (admin use, feature-flagged).

    Defaults to the 30 days ending now when ``from``/``to`` are omitted.
    Returns the canonical JSON bundle (``format=json``) or the Markdown
    report (``format=markdown``).
    """
    cfg = request.app.state.config
    if not cfg.evidence_pack_enabled:
        return JSONResponse(
            content={
                "error": "feature_disabled",
                "detail": "Evidence pack export is disabled (set AIRLOCK_EVIDENCE_PACK_ENABLED)",
                "status_code": 404,
            },
            status_code=404,
        )

    if format not in ("json", "markdown"):
        return JSONResponse(
            content={
                "error": "validation_error",
                "detail": f"Invalid format: {format!r} (expected 'json' or 'markdown')",
                "status_code": 422,
            },
            status_code=422,
        )

    default_start, default_end = default_export_window()
    try:
        period_start = (
            datetime.fromisoformat(from_iso) if from_iso is not None else default_start
        )
        period_end = datetime.fromisoformat(to_iso) if to_iso is not None else default_end
    except ValueError:
        return JSONResponse(
            content={
                "error": "validation_error",
                "detail": "Invalid 'from'/'to': expected ISO 8601 datetimes",
                "status_code": 422,
            },
            status_code=422,
        )

    try:
        pack = await build_evidence_pack(
            inventory=_get_inventory(request),
            incident_store=_get_incident_store(request),
            audit_trail=request.app.state.audit_trail,
            keypair=request.app.state.airlock_kp,
            period_start=period_start,
            period_end=period_end,
        )
    except ValueError as exc:
        return JSONResponse(
            content={"error": "validation_error", "detail": str(exc), "status_code": 422},
            status_code=422,
        )

    if format == "markdown":
        return PlainTextResponse(
            content=render_markdown(pack),
            media_type="text/markdown; charset=utf-8",
        )
    return Response(content=render_json(pack), media_type="application/json")


def register_compliance_routes(app: FastAPI) -> None:
    """Mount the compliance router on the FastAPI app."""
    app.include_router(router)
    logger.info("Compliance routes registered")
