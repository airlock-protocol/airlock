from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

from nacl.signing import VerifyKey

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_message, verify_signature
from airlock.schemas.identity import AgentCapability

if TYPE_CHECKING:
    from airlock.schemas.identity import VerifiableCredential

logger = logging.getLogger(__name__)


def issue_credential(
    issuer_key: KeyPair,
    subject_did: str,
    credential_type: str,
    claims: dict[str, Any],
    validity_days: int = 365,
) -> VerifiableCredential:
    """Issue a signed Verifiable Credential.

    1. Build the VC with issuer DID, subject DID, claims, and expiry
    2. Serialize to canonical JSON (excluding proof)
    3. Sign with issuer's Ed25519 key
    4. Attach CredentialProof with the signature
    5. Return the complete VC
    """
    from airlock.schemas.identity import CredentialProof, VerifiableCredential

    now = datetime.now(UTC)
    expiration = now + timedelta(days=validity_days)
    vc_id = f"{issuer_key.did}#{uuid.uuid4().hex}"
    credential_subject = {"id": subject_did, **claims}

    vc_temp = VerifiableCredential(
        context=["https://www.w3.org/2018/credentials/v1"],  # type: ignore[call-arg]  # alias is @context; populate_by_name=True allows field name
        id=vc_id,
        type=["VerifiableCredential", credential_type],
        issuer=issuer_key.did,
        issuance_date=now,
        expiration_date=expiration,
        credential_subject=credential_subject,
        proof=None,
    )
    vc_dict = vc_temp.model_dump(mode="json", by_alias=True)
    vc_dict.pop("proof", None)

    signature_b64 = sign_message(vc_dict, issuer_key.signing_key)

    proof = CredentialProof(
        type="Ed25519Signature2020",
        created=now,
        verification_method=issuer_key.did,
        proof_purpose="assertionMethod",
        proof_value=signature_b64,
    )

    return VerifiableCredential(
        context=vc_temp.context,  # type: ignore[call-arg]  # alias is @context; populate_by_name=True allows field name
        id=vc_id,
        type=vc_temp.type,
        issuer=issuer_key.did,
        issuance_date=now,
        expiration_date=expiration,
        credential_subject=credential_subject,
        proof=proof,
    )


def validate_credential(
    vc: VerifiableCredential,
    issuer_verify_key: VerifyKey,
    *,
    expected_subject_did: str | None = None,
) -> tuple[bool, str]:
    """Validate a Verifiable Credential.

    Checks:
    1. Not expired (expiration_date > now)
    2. Has a proof attached
    3. Proof signature is valid against issuer's public key
    4. If ``expected_subject_did`` is set, ``credential_subject.id`` must match

    Returns (True, "valid") or (False, "reason for failure").
    """
    if vc.is_expired():
        return False, "credential expired"

    if vc.proof is None:
        return False, "missing proof"

    if expected_subject_did is not None:
        subj_id = (
            vc.credential_subject.get("id") if isinstance(vc.credential_subject, dict) else None
        )
        if subj_id != expected_subject_did:
            return False, "credential subject does not match initiator DID"

    vc_dict = vc.model_dump(mode="json", by_alias=True)
    vc_dict.pop("proof", None)

    if not verify_signature(vc_dict, vc.proof.proof_value, issuer_verify_key):
        return False, "invalid proof signature"

    return True, "valid"


# ---------------------------------------------------------------------------
# VC Capability Extraction
# ---------------------------------------------------------------------------


@dataclass
class CapabilityExtractionResult:
    """Result of extracting capabilities from VC credential subjects.

    Attributes:
        capabilities: Successfully parsed AgentCapability instances.
        warnings: Human-readable warnings encountered during extraction.
        extraction_failed: True when data was present but unparseable.
    """

    capabilities: list[AgentCapability] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    extraction_failed: bool = False


def _parse_single_capability(raw: Any, index: int) -> tuple[AgentCapability | None, str | None]:
    """Parse a single capability dict into an AgentCapability.

    Returns (capability, None) on success or (None, warning_message) on failure.
    """
    if not isinstance(raw, dict):
        return None, f"capability at index {index} is not a dict (got {type(raw).__name__})"

    name = raw.get("name")
    version = raw.get("version")

    if not isinstance(name, str) or not name.strip():
        return None, f"capability at index {index} missing or invalid 'name'"

    if not isinstance(version, str):
        # Tolerate missing version — default to "unknown"
        version = "unknown"

    description = raw.get("description", "")
    if not isinstance(description, str):
        description = str(description)

    return AgentCapability(name=name.strip(), version=version.strip(), description=description.strip()), None


def extract_capabilities(
    credential_subjects: list[dict[str, Any]],
    merge_strategy: Literal["union", "intersection", "first"] = "union",
) -> CapabilityExtractionResult:
    """Extract AgentCapability instances from one or more VC credential subjects.

    Forward-compatible: accepts a list for future multi-VC support.
    For v0.4, callers pass ``[handshake.credential.credential_subject]``.

    Args:
        credential_subjects: List of credential_subject dicts from VCs.
        merge_strategy: How to merge capabilities from multiple subjects.
            - "union": combine all capabilities (default)
            - "intersection": only capabilities present in ALL subjects
            - "first": use only the first subject's capabilities

    Returns:
        CapabilityExtractionResult with parsed capabilities, warnings, and
        extraction_failed flag.
    """
    if not credential_subjects:
        return CapabilityExtractionResult(
            warnings=["no credential subjects provided"],
        )

    all_caps_per_subject: list[list[AgentCapability]] = []
    warnings: list[str] = []
    any_failed = False

    for subj_idx, subject in enumerate(credential_subjects):
        if not isinstance(subject, dict):
            warnings.append(f"credential_subject at index {subj_idx} is not a dict")
            any_failed = True
            continue

        raw_caps = subject.get("capabilities")

        if raw_caps is None:
            # Missing field is not a failure — VC simply has no capabilities claim
            warnings.append(
                f"credential_subject at index {subj_idx} has no 'capabilities' field"
            )
            all_caps_per_subject.append([])
            continue

        if not isinstance(raw_caps, list):
            warnings.append(
                f"credential_subject at index {subj_idx}: 'capabilities' is not a list "
                f"(got {type(raw_caps).__name__})"
            )
            any_failed = True
            continue

        subject_caps: list[AgentCapability] = []
        for cap_idx, raw_cap in enumerate(raw_caps):
            cap, warning = _parse_single_capability(raw_cap, cap_idx)
            if warning:
                warnings.append(f"subject[{subj_idx}].{warning}")
                any_failed = True
            if cap is not None:
                subject_caps.append(cap)

        all_caps_per_subject.append(subject_caps)

        if merge_strategy == "first":
            # Only use the first subject
            break

    # Merge according to strategy
    if not all_caps_per_subject:
        return CapabilityExtractionResult(
            warnings=warnings,
            extraction_failed=any_failed,
        )

    if merge_strategy == "union":
        # Deduplicate by (name, version) — first occurrence wins
        seen: set[tuple[str, str]] = set()
        merged: list[AgentCapability] = []
        for caps in all_caps_per_subject:
            for cap in caps:
                key = (cap.name.lower(), cap.version.lower())
                if key not in seen:
                    seen.add(key)
                    merged.append(cap)
        capabilities = merged

    elif merge_strategy == "intersection":
        if len(all_caps_per_subject) == 1:
            capabilities = all_caps_per_subject[0]
        else:
            # Intersection by (name, version)
            sets = [
                {(c.name.lower(), c.version.lower()) for c in caps}
                for caps in all_caps_per_subject
            ]
            common_keys = sets[0]
            for s in sets[1:]:
                common_keys &= s
            # Preserve the first occurrence for each common key
            capabilities = [
                cap
                for cap in all_caps_per_subject[0]
                if (cap.name.lower(), cap.version.lower()) in common_keys
            ]

    else:  # "first"
        capabilities = all_caps_per_subject[0] if all_caps_per_subject else []

    return CapabilityExtractionResult(
        capabilities=capabilities,
        warnings=warnings,
        extraction_failed=any_failed,
    )
