from __future__ import annotations

"""Signed, auditor-ready evidence pack composition.

Composes the platform's existing compliance and audit data for a time window
into a single artifact:

- agent inventory snapshot (``airlock.compliance.inventory``)
- risk classifications (``airlock.compliance.risk_classifier``)
- incident log extract (``airlock.compliance.incident``)
- audit-trail extract with hash-chain verification (``airlock.audit.trail``)
- mapping of collected evidence to framework control references
  (``airlock.compliance.regulatory_mapper``)

The pack's canonical JSON bundle is hashed with SHA-256 and the digest is
signed with the gateway's Ed25519 key.  Outputs are a canonical JSON bundle
and a human-readable Markdown report; both embed the signature, the public
key, verification instructions, and the mandatory disclaimer below.
"""

import asyncio
import hashlib
import logging
import uuid
from base64 import b64decode, b64encode
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nacl.exceptions import BadSignatureError
from pydantic import BaseModel, Field

from airlock.audit.trail import GENESIS_HASH, AuditEntry, AuditStore, AuditTrail
from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory
from airlock.compliance.regulatory_mapper import (
    EVIDENCE_AGENT_INVENTORY,
    EVIDENCE_AUDIT_TRAIL,
    EVIDENCE_INCIDENT_LOG,
    EVIDENCE_RISK_CLASSIFICATIONS,
    EVIDENCE_SIGNED_MANIFEST,
    RegulatoryMapper,
)
from airlock.compliance.risk_classifier import RiskClassifier
from airlock.compliance.schemas import AgentInventoryEntry, IncidentReport, RiskClassification
from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair, resolve_public_key
from airlock.crypto.signing import canonicalize

logger = logging.getLogger(__name__)

PACK_FORMAT_VERSION = "0.1.0"

DEFAULT_FRAMEWORK_PROFILES: tuple[str, ...] = ("RBI-FREE-AI", "EU-AI-Act", "ISO-42001")

# Mandatory in every output. Do not remove or weaken.
DISCLAIMER = (
    "This evidence pack is an evidence-collection aid. It compiles operational "
    "records produced by the Airlock platform and maps them to published control "
    "references of the selected frameworks for reviewer convenience. It is not a "
    "certification, an audit opinion, or a determination of regulatory compliance, "
    "and it does not constitute legal advice. A mapping between collected evidence "
    "and a control reference does not assert that the control is satisfied."
)

VERIFICATION_INSTRUCTIONS = (
    "1. Parse the evidence pack JSON and remove the top-level 'manifest' field. "
    "2. Canonicalize the remainder (RFC 8785 style): keys sorted lexicographically, "
    "separators ',' and ':', no insignificant whitespace, UTF-8 encoding, non-ASCII "
    "characters unescaped, integral floats emitted as integers. "
    "3. Compute SHA-256 over the canonical bytes; the hex digest must equal "
    "'manifest.bundle_sha256'. "
    "4. Decode the signer public key from 'manifest.signer_did': strip the "
    "'did:key:z' prefix, base58btc-decode, drop the 2-byte multicodec prefix 0xed01; "
    "the remaining 32 bytes are the Ed25519 public key. "
    "5. Verify the Ed25519 signature (base64 in 'manifest.signature_b64') over the "
    "raw 32-byte SHA-256 digest from step 3. "
    "Reference implementation: airlock.compliance.evidence_pack.verify_evidence_pack."
)

# Upper bound on audit entries pulled into one extract (v0 safeguard).
_AUDIT_EXTRACT_FETCH_LIMIT = 100_000

# Markdown tables are capped for readability; the JSON bundle always holds all rows.
_MARKDOWN_MAX_TABLE_ROWS = 100

# Development fallback signing seed. Byte-for-byte the same as
# ``airlock.gateway.identity._DEMO_GATEWAY_SEED`` so CLI exports match the dev
# gateway identity; duplicated here because core modules must not import from
# ``airlock.gateway``.
_DEV_FALLBACK_SIGNING_SEED = b"airlock_gateway_identity_seed_00"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AuditTrailExtract(BaseModel):
    """Audit-trail entries for the window plus chain-integrity verification."""

    total_entries_in_trail: int
    entries_in_window: int
    chain_verified: bool
    chain_verdict: str
    chain_head_hash: str
    entries: list[AuditEntry] = Field(default_factory=list)


class ControlMapping(BaseModel):
    """One framework control reference and the evidence categories mapped to it."""

    control_id: str
    title: str
    section: str = ""
    evidence_categories: list[str] = Field(default_factory=list)
    evidence_item_counts: dict[str, int] = Field(default_factory=dict)
    evidence_present: bool = False


class FrameworkMapping(BaseModel):
    """Evidence mapping for one framework control profile."""

    profile_id: str
    name: str
    issuer: str
    reference_note: str = ""
    controls: list[ControlMapping] = Field(default_factory=list)


class EvidenceSummary(BaseModel):
    """Counts of collected evidence items."""

    total_agents: int = 0
    agents_by_risk: dict[str, int] = Field(default_factory=dict)
    total_risk_classifications: int = 0
    incidents_in_window: int = 0
    incidents_by_severity: dict[str, int] = Field(default_factory=dict)
    audit_entries_in_window: int = 0
    audit_chain_verified: bool = False


class EvidencePackManifest(BaseModel):
    """Integrity manifest: SHA-256 of the canonical bundle, Ed25519-signed."""

    bundle_sha256: str
    signature_b64: str
    algorithm: str = "Ed25519"
    signed_payload: str = "sha256_digest_of_canonical_bundle"
    signer_did: str
    public_key_multibase: str
    verification_instructions: str = VERIFICATION_INSTRUCTIONS


class EvidencePack(BaseModel):
    """Signed, auditor-ready evidence pack for a reporting window."""

    pack_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pack_format_version: str = PACK_FORMAT_VERSION
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    period_start: datetime
    period_end: datetime
    generated_by: str = ""
    disclaimer: str = DISCLAIMER
    summary: EvidenceSummary
    inventory: list[AgentInventoryEntry] = Field(default_factory=list)
    risk_classifications: list[RiskClassification] = Field(default_factory=list)
    incidents: list[IncidentReport] = Field(default_factory=list)
    audit: AuditTrailExtract
    framework_mappings: list[FrameworkMapping] = Field(default_factory=list)
    manifest: EvidencePackManifest | None = None


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


def _ensure_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime (naive values are treated as UTC)."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


async def build_evidence_pack(
    *,
    inventory: AgentInventory,
    incident_store: IncidentStore,
    audit_trail: AuditTrail,
    keypair: KeyPair,
    period_start: datetime,
    period_end: datetime,
    framework_profiles: Sequence[str] | None = None,
) -> EvidencePack:
    """Compose and sign an evidence pack for ``[period_start, period_end]``.

    The inventory snapshot and risk classifications reflect the state at
    generation time; incidents and audit entries are filtered to the window.
    The audit hash chain is verified in full and the verdict is embedded.
    """
    period_start = _ensure_utc(period_start)
    period_end = _ensure_utc(period_end)
    if period_start > period_end:
        raise ValueError("period_start must not be after period_end")

    profiles = tuple(framework_profiles or DEFAULT_FRAMEWORK_PROFILES)

    # 1. Inventory snapshot + current risk classifications.
    entries = inventory.list_all()
    classifier = RiskClassifier()
    classifications = [classifier.classify(entry) for entry in entries]

    # 2. Incident log extract for the window.
    incidents = [
        incident
        for incident in incident_store.list_all()
        if period_start <= _ensure_utc(incident.detected_at) <= period_end
    ]
    incidents_by_severity: dict[str, int] = {}
    for incident in incidents:
        key = incident.severity.value
        incidents_by_severity[key] = incidents_by_severity.get(key, 0) + 1

    # 3. Audit-trail extract with full-chain integrity verification.
    chain_verified, chain_verdict = await audit_trail.verify_chain()
    newest_first = await audit_trail.get_entries(limit=_AUDIT_EXTRACT_FETCH_LIMIT)
    head_hash = newest_first[0].entry_hash if newest_first else GENESIS_HASH
    window_entries = [
        entry
        for entry in reversed(newest_first)  # oldest first
        if period_start <= _ensure_utc(entry.timestamp) <= period_end
    ]
    audit_extract = AuditTrailExtract(
        total_entries_in_trail=audit_trail.length,
        entries_in_window=len(window_entries),
        chain_verified=chain_verified,
        chain_verdict=chain_verdict,
        chain_head_hash=head_hash,
        entries=window_entries,
    )

    # 4. Map collected evidence to framework control references.
    evidence_counts = {
        EVIDENCE_AGENT_INVENTORY: len(entries),
        EVIDENCE_RISK_CLASSIFICATIONS: len(classifications),
        EVIDENCE_INCIDENT_LOG: len(incidents),
        EVIDENCE_AUDIT_TRAIL: len(window_entries),
        EVIDENCE_SIGNED_MANIFEST: 1,
    }
    mapper = RegulatoryMapper()
    framework_mappings = [
        FrameworkMapping(**mapper.map_evidence_to_framework(profile_id, evidence_counts))
        for profile_id in profiles
    ]

    pack = EvidencePack(
        period_start=period_start,
        period_end=period_end,
        generated_by=keypair.did,
        summary=EvidenceSummary(
            total_agents=len(entries),
            agents_by_risk=inventory.count_by_risk(),
            total_risk_classifications=len(classifications),
            incidents_in_window=len(incidents),
            incidents_by_severity=incidents_by_severity,
            audit_entries_in_window=len(window_entries),
            audit_chain_verified=chain_verified,
        ),
        inventory=entries,
        risk_classifications=classifications,
        incidents=incidents,
        audit=audit_extract,
        framework_mappings=framework_mappings,
    )
    _sign_pack(pack, keypair)
    logger.info(
        "Evidence pack %s built (agents=%d incidents=%d audit_entries=%d chain_ok=%s)",
        pack.pack_id,
        len(entries),
        len(incidents),
        len(window_entries),
        chain_verified,
    )
    return pack


# ---------------------------------------------------------------------------
# Canonicalization, signing, verification
# ---------------------------------------------------------------------------


def canonical_bundle_bytes(pack: EvidencePack | dict[str, Any]) -> bytes:
    """Canonical JSON bytes of the pack, excluding the ``manifest`` field."""
    if isinstance(pack, EvidencePack):
        data = pack.model_dump(mode="json")
    else:
        data = dict(pack)
    data.pop("manifest", None)
    return canonicalize(data)


def _sign_pack(pack: EvidencePack, keypair: KeyPair) -> None:
    """Attach a signed manifest: Ed25519 over the SHA-256 of the canonical bundle."""
    canonical = canonical_bundle_bytes(pack)
    digest = hashlib.sha256(canonical).digest()
    signature = keypair.signing_key.sign(digest).signature
    pack.manifest = EvidencePackManifest(
        bundle_sha256=digest.hex(),
        signature_b64=b64encode(signature).decode("ascii"),
        signer_did=keypair.did,
        public_key_multibase=keypair.public_key_multibase,
    )


def verify_evidence_pack(pack: EvidencePack | dict[str, Any]) -> tuple[bool, str]:
    """Verify a pack's manifest signature. Returns ``(ok, reason)``.

    Accepts either an ``EvidencePack`` instance or the parsed JSON dict of an
    exported bundle.
    """
    if isinstance(pack, EvidencePack):
        manifest_data: dict[str, Any] | None = (
            pack.manifest.model_dump(mode="json") if pack.manifest is not None else None
        )
    else:
        raw = pack.get("manifest")
        manifest_data = dict(raw) if isinstance(raw, dict) else None
    if manifest_data is None:
        return False, "manifest missing"

    canonical = canonical_bundle_bytes(pack)
    digest = hashlib.sha256(canonical).digest()
    if digest.hex() != manifest_data.get("bundle_sha256"):
        return False, "bundle_sha256 mismatch: pack content differs from signed bundle"

    if manifest_data.get("algorithm") != "Ed25519":
        return False, f"unsupported algorithm: {manifest_data.get('algorithm')!r}"

    signer_did = str(manifest_data.get("signer_did", ""))
    try:
        verify_key = resolve_public_key(signer_did)
    except ValueError as exc:
        return False, f"invalid signer DID: {exc}"

    try:
        signature = b64decode(str(manifest_data.get("signature_b64", "")))
        verify_key.verify(digest, signature)
    except (BadSignatureError, ValueError):
        return False, "signature verification failed"
    return True, "ok"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_json(pack: EvidencePack) -> str:
    """Render the full pack (evidence + manifest) as an indented JSON bundle."""
    return pack.model_dump_json(indent=2)


def _cell(value: object) -> str:
    """Escape a value for use inside a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _iso(value: datetime) -> str:
    return _ensure_utc(value).strftime("%Y-%m-%d %H:%M:%S UTC")


def _table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows[:_MARKDOWN_MAX_TABLE_ROWS]:
        lines.append("| " + " | ".join(_cell(col) for col in row) + " |")
    if len(rows) > _MARKDOWN_MAX_TABLE_ROWS:
        remaining = len(rows) - _MARKDOWN_MAX_TABLE_ROWS
        lines.append("")
        lines.append(
            f"*Table truncated for readability: {remaining} further row(s) "
            "are included in the JSON bundle.*"
        )
    return lines


def render_markdown(pack: EvidencePack) -> str:
    """Render the pack as a human-readable Markdown report."""
    md: list[str] = []
    md.append("# Airlock Evidence Pack")
    md.append("")
    md.append(f"> **Important notice.** {pack.disclaimer}")
    md.append("")

    md.append("## 1. Pack identification")
    md.append("")
    md.extend(
        _table(
            ["Field", "Value"],
            [
                ["Pack ID", pack.pack_id],
                ["Format version", pack.pack_format_version],
                ["Generated at", _iso(pack.generated_at)],
                ["Reporting period start", _iso(pack.period_start)],
                ["Reporting period end", _iso(pack.period_end)],
                ["Generated by (signer DID)", pack.generated_by],
            ],
        )
    )
    md.append("")

    md.append("## 2. Summary of collected evidence")
    md.append("")
    summary = pack.summary
    md.extend(
        _table(
            ["Evidence category", "Count"],
            [
                ["Agents in inventory snapshot", summary.total_agents],
                ["Risk classifications", summary.total_risk_classifications],
                ["Incidents in window", summary.incidents_in_window],
                ["Audit-trail entries in window", summary.audit_entries_in_window],
                [
                    "Audit chain integrity",
                    "verified" if summary.audit_chain_verified else "FAILED verification",
                ],
            ],
        )
    )
    md.append("")

    md.append(f"## 3. Agent inventory snapshot ({summary.total_agents} agents)")
    md.append("")
    md.append("Snapshot of the agent inventory at generation time.")
    md.append("")
    if pack.inventory:
        md.extend(
            _table(
                ["DID", "Name", "Type", "Risk level", "Environment", "Status", "Trust score"],
                [
                    [
                        e.did,
                        e.display_name,
                        e.agent_type,
                        e.risk_level.value,
                        e.deployment_environment,
                        e.compliance_status,
                        f"{e.trust_score:.2f} (tier {e.trust_tier})",
                    ]
                    for e in pack.inventory
                ],
            )
        )
    else:
        md.append("No agents were registered in the inventory at generation time.")
    md.append("")

    md.append("## 4. Risk classifications")
    md.append("")
    md.append("Automated classifications current at generation time.")
    md.append("")
    if pack.risk_classifications:
        md.extend(
            _table(
                ["DID", "Risk level", "Risk factors", "Mitigation measures", "Assessed at"],
                [
                    [
                        c.did,
                        c.risk_level.value,
                        "; ".join(c.risk_factors) or "none recorded",
                        "; ".join(c.mitigation_measures) or "none recorded",
                        _iso(c.assessed_at),
                    ]
                    for c in pack.risk_classifications
                ],
            )
        )
    else:
        md.append("No risk classifications (inventory was empty).")
    md.append("")

    md.append(f"## 5. Incident log ({summary.incidents_in_window} in window)")
    md.append("")
    md.append("Incidents detected within the reporting period. Incident records are")
    md.append("hash-chained at write time (each record embeds the previous record's hash).")
    md.append("")
    if pack.incidents:
        md.extend(
            _table(
                ["Incident ID", "Agent DID", "Severity", "Type", "Status", "Detected at"],
                [
                    [
                        i.incident_id,
                        i.agent_did,
                        i.severity.value,
                        i.incident_type,
                        i.status,
                        _iso(i.detected_at),
                    ]
                    for i in pack.incidents
                ],
            )
        )
    else:
        md.append("No incidents were recorded within the reporting period.")
    md.append("")

    audit = pack.audit
    md.append("## 6. Audit-trail extract")
    md.append("")
    chain_status = "PASS" if audit.chain_verified else "FAIL"
    md.extend(
        _table(
            ["Field", "Value"],
            [
                ["Entries in full trail", audit.total_entries_in_trail],
                ["Entries in reporting window", audit.entries_in_window],
                ["Hash-chain verification", f"{chain_status} ({audit.chain_verdict})"],
                ["Chain head hash (SHA-256)", audit.chain_head_hash],
            ],
        )
    )
    md.append("")
    md.append("The audit trail is hash-chained: every entry's SHA-256 hash covers the")
    md.append("previous entry's hash, so altering history breaks verification. The")
    md.append("verification verdict above covers the full trail, not only the window.")
    md.append("")
    if audit.entries:
        md.extend(
            _table(
                ["Timestamp", "Event type", "Actor DID", "Subject DID", "Entry hash"],
                [
                    [
                        _iso(entry.timestamp),
                        entry.event_type,
                        entry.actor_did,
                        entry.subject_did or "-",
                        entry.entry_hash,
                    ]
                    for entry in audit.entries
                ],
            )
        )
    else:
        md.append("No audit entries fall within the reporting period.")
    md.append("")

    md.append("## 7. Framework control mapping")
    md.append("")
    md.append("Collected evidence mapped to published control references. A mapping is")
    md.append("an informational cross-reference only; it does not assert that a control")
    md.append("is satisfied and is not a compliance determination.")
    md.append("")
    for mapping in pack.framework_mappings:
        md.append(f"### {mapping.name} ({mapping.profile_id})")
        md.append("")
        md.append(f"*Source: {mapping.issuer}.*")
        if mapping.reference_note:
            md.append("")
            md.append(f"*Note: {mapping.reference_note}*")
        md.append("")
        md.extend(
            _table(
                ["Control reference", "Title", "Section", "Mapped evidence", "Items collected"],
                [
                    [
                        c.control_id,
                        c.title,
                        c.section,
                        ", ".join(c.evidence_categories),
                        ", ".join(
                            f"{category}: {count}"
                            for category, count in c.evidence_item_counts.items()
                        ),
                    ]
                    for c in mapping.controls
                ],
            )
        )
        md.append("")

    md.append("## 8. Integrity and signature")
    md.append("")
    manifest = pack.manifest
    if manifest is not None:
        md.extend(
            _table(
                ["Field", "Value"],
                [
                    ["Canonical bundle SHA-256", manifest.bundle_sha256],
                    ["Signature algorithm", manifest.algorithm],
                    ["Signed payload", manifest.signed_payload],
                    ["Signature (base64)", manifest.signature_b64],
                    ["Signer DID", manifest.signer_did],
                    ["Public key (multibase)", manifest.public_key_multibase],
                ],
            )
        )
        md.append("")
        md.append("**Verification instructions.** " + manifest.verification_instructions)
    else:
        md.append("This pack has not been signed.")
    md.append("")

    md.append("## 9. Disclaimer")
    md.append("")
    md.append(pack.disclaimer)
    md.append("")
    return "\n".join(md)


# ---------------------------------------------------------------------------
# CLI export (logic lives here; airlock.cli is a thin wrapper)
# ---------------------------------------------------------------------------


def _parse_iso(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid ISO 8601 datetime for {label}: {value!r}") from exc
    return _ensure_utc(parsed)


def _resolve_signing_keypair(config: AirlockConfig) -> KeyPair:
    """Resolve the gateway signing key from config (dev fallback outside production)."""
    seed_hex = (config.gateway_seed_hex or "").strip()
    if len(seed_hex) == 64:
        try:
            seed = bytes.fromhex(seed_hex)
            if len(seed) == 32:
                return KeyPair.from_seed(seed)
        except ValueError:
            pass
    if config.is_production:
        raise ValueError(
            "Invalid or missing AIRLOCK_GATEWAY_SEED_HEX (need 64 hex chars for a "
            "32-byte Ed25519 seed) — required to sign evidence packs in production."
        )
    return KeyPair.from_seed(_DEV_FALLBACK_SIGNING_SEED)


def run_cli_export(
    *,
    from_iso: str,
    to_iso: str,
    fmt: str,
    out_dir: str,
    config: AirlockConfig | None = None,
) -> list[Path]:
    """Build an evidence pack and write it to ``out_dir``. Returns written paths.

    Data sources are resolved from configuration: the audit trail is loaded
    from the persistent SQLite store when ``audit_trail_persist`` is enabled
    and the database exists; the agent inventory and incident store are
    gateway-runtime state, so a standalone CLI export starts them empty (use
    the gateway's ``GET /compliance/evidence-pack`` route to export live
    runtime data).
    """
    if fmt not in ("json", "markdown", "both"):
        raise ValueError(f"Invalid format {fmt!r}: expected 'json', 'markdown' or 'both'")
    period_start = _parse_iso(from_iso, "--from")
    period_end = _parse_iso(to_iso, "--to")
    if period_start > period_end:
        raise ValueError("--from must not be after --to")

    cfg = config or AirlockConfig()
    keypair = _resolve_signing_keypair(cfg)

    audit_store: AuditStore | None = None
    if cfg.audit_trail_persist and Path(cfg.audit_db_path).exists():
        audit_store = AuditStore(cfg.audit_db_path)
        audit_store.open()
    try:
        audit_trail = AuditTrail(store=audit_store)
        pack = asyncio.run(
            build_evidence_pack(
                inventory=AgentInventory(),
                incident_store=IncidentStore(),
                audit_trail=audit_trail,
                keypair=keypair,
                period_start=period_start,
                period_end=period_end,
            )
        )
    finally:
        if audit_store is not None:
            audit_store.close()

    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    stem = (
        f"evidence_pack_{period_start.strftime('%Y%m%d')}"
        f"_{period_end.strftime('%Y%m%d')}_{pack.pack_id[:8]}"
    )
    written: list[Path] = []
    if fmt in ("json", "both"):
        json_path = target / f"{stem}.json"
        json_path.write_text(render_json(pack) + "\n", encoding="utf-8")
        written.append(json_path)
    if fmt in ("markdown", "both"):
        md_path = target / f"{stem}.md"
        md_path.write_text(render_markdown(pack), encoding="utf-8")
        written.append(md_path)
    logger.info("Evidence pack %s exported to %s", pack.pack_id, [str(p) for p in written])
    return written


def default_export_window(now: datetime | None = None) -> tuple[datetime, datetime]:
    """Default reporting window: the 30 days ending now (UTC)."""
    end = _ensure_utc(now) if now is not None else datetime.now(UTC)
    return end - timedelta(days=30), end
