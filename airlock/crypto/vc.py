from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import TYPE_CHECKING

from nacl.signing import VerifyKey

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_message, verify_signature

if TYPE_CHECKING:
    from airlock.schemas.identity import CredentialProof, VerifiableCredential


def issue_credential(
    issuer_key: KeyPair,
    subject_did: str,
    credential_type: str,
    claims: dict,
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

    now = datetime.now(timezone.utc)
    expiration = now + timedelta(days=validity_days)
    vc_id = f"{issuer_key.did}#{uuid.uuid4().hex}"
    credential_subject = {"id": subject_did, **claims}

    vc_temp = VerifiableCredential(
        context=["https://www.w3.org/2018/credentials/v1"],
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
        context=vc_temp.context,
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
        subj_id = vc.credential_subject.get("id") if isinstance(vc.credential_subject, dict) else None
        if subj_id != expected_subject_did:
            return False, "credential subject does not match initiator DID"

    vc_dict = vc.model_dump(mode="json", by_alias=True)
    vc_dict.pop("proof", None)

    if not verify_signature(vc_dict, vc.proof.proof_value, issuer_verify_key):
        return False, "invalid proof signature"

    return True, "valid"
