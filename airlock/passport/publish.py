"""Static publication of the hosted key directory, assertions and CRL.

Everything a Web Bot Auth verifier fetches from a registry is a
read-only document: the JWKS key directory
(draft-meunier-webbotauth-httpsig-directory-00), the tenant-signed
possession assertions (draft-singh-webbotauth-hosted-directories-00
section 5), and the revocation list. None of them require the gateway
to be running to be served, so this module renders them to files any
static host or CDN can serve.

That split matters operationally. The directory is the surface *other
people's* verifiers depend on — Cloudflare, AWS WAF, Vercel, Akamai —
while registration, feedback and delegation are writes only agents
themselves make. Publishing the read side keeps verification working
while the write side is down, redeploying, or moving hosts. It is the
same shape PKI has always used, where revocation is a static signed
artifact rather than a live query.

The rendered tree is host-agnostic apart from one file: ``_headers`` is
emitted for hosts that read it (Cloudflare Pages, Netlify), because the
directory has its own media type
(``application/http-message-signatures-directory+json``) and a host
that cannot set ``Content-Type`` per path will serve it as something
else. Hosts that ignore ``_headers`` — GitHub Pages among them — cannot
serve a spec-correct directory for that reason.

Per-tenant directory authorities are subdomains (``<label>.<base>``),
which a single static tree cannot express, so only the flat
all-tenants view is rendered here; per-tenant authorities still need
the gateway or one edge function per host.
"""

from __future__ import annotations

import logging
from collections.abc import Collection, Iterable, Mapping
from pathlib import Path

from nacl.signing import VerifyKey

from airlock.crypto.keys import resolve_public_key
from airlock.passport.assertions import WELL_KNOWN_ASSERTIONS_PATH
from airlock.passport.base import DIRECTORY_MEDIA_TYPE, WELL_KNOWN_DIRECTORY_PATH
from airlock.passport.directory import build_directory
from airlock.schemas.crl import SignedCRL
from airlock.schemas.identity import AgentProfile
from airlock.schemas.passport import AssertionsDocument

logger = logging.getLogger(__name__)

# Output paths, relative to the root of the published tree.
DIRECTORY_FILE = WELL_KNOWN_DIRECTORY_PATH.lstrip("/")
ASSERTIONS_FILE = WELL_KNOWN_ASSERTIONS_PATH.lstrip("/")
CRL_FILE = "crl.json"
HEADERS_FILE = "_headers"

JSON_MEDIA_TYPE = "application/json"


def revoked_dids_from_crl(crl: SignedCRL) -> set[str]:
    """Every DID the CRL lists, revoked or suspended alike.

    Used so a published directory and the CRL beside it cannot
    disagree about who is still valid.
    """
    return {entry.did for entry in crl.entries}


def select_publishable(
    profiles: Iterable[AgentProfile],
    revoked_dids: Collection[str] | None = None,
) -> list[AgentProfile]:
    """Active, non-revoked profiles in deterministic DID order.

    Mirrors the gateway's live directory selection so the static copy
    and the served copy agree.
    """
    revoked = set(revoked_dids or ())
    selected = [
        profile
        for profile in profiles
        if profile.status == "active" and profile.did.did not in revoked
    ]
    return sorted(selected, key=lambda profile: profile.did.did)


def build_directory_document(profiles: Iterable[AgentProfile]) -> str:
    """Render the JWKS key directory for ``profiles``.

    Profiles whose DID is not a resolvable Ed25519 key are skipped, as
    they are on the live route.
    """
    keys: list[VerifyKey] = []
    for profile in profiles:
        try:
            keys.append(resolve_public_key(profile.did.did))
        except ValueError:
            logger.debug("Skipping non-Ed25519 DID in directory: %s", profile.did.did)
            continue
    return build_directory(keys).model_dump_json(exclude_none=True)


def build_assertions_document(profiles: Iterable[AgentProfile]) -> str:
    """Render the possession-assertions document for ``profiles``.

    Only agents that uploaded an assertion appear; the registry holds
    no private keys and so can never mint one on their behalf.
    """
    assertions = [
        profile.passport_assertion for profile in profiles if profile.passport_assertion is not None
    ]
    return AssertionsDocument(assertions=assertions).model_dump_json()


def build_headers_file(max_age_seconds: int) -> str:
    """Render a ``_headers`` file pinning media types and cache policy.

    Cloudflare Pages and Netlify read this; hosts that do not will fall
    back to extension-based content sniffing, which cannot produce the
    directory's registered media type.
    """
    blocks = [
        (DIRECTORY_FILE, DIRECTORY_MEDIA_TYPE),
        (ASSERTIONS_FILE, JSON_MEDIA_TYPE),
        (CRL_FILE, JSON_MEDIA_TYPE),
    ]
    lines: list[str] = []
    for path, media_type in blocks:
        lines.append(f"/{path}")
        lines.append(f"  Content-Type: {media_type}")
        lines.append(f"  Cache-Control: max-age={max_age_seconds}")
        lines.append("")
    return "\n".join(lines)


def build_static_artifacts(
    profiles: Iterable[AgentProfile],
    *,
    crl: SignedCRL | None = None,
    revoked_dids: Collection[str] | None = None,
    max_age_seconds: int = 300,
) -> dict[str, str]:
    """Render the full static tree as ``relative path -> file content``.

    When ``crl`` is supplied and ``revoked_dids`` is not, the revoked
    set is taken from the CRL, so the published directory and CRL
    always describe the same registry state.
    """
    if revoked_dids is None and crl is not None:
        revoked_dids = revoked_dids_from_crl(crl)

    publishable = select_publishable(profiles, revoked_dids)

    artifacts = {
        DIRECTORY_FILE: build_directory_document(publishable),
        ASSERTIONS_FILE: build_assertions_document(publishable),
        HEADERS_FILE: build_headers_file(max_age_seconds),
    }
    if crl is not None:
        artifacts[CRL_FILE] = crl.model_dump_json()
    return artifacts


def write_static_artifacts(artifacts: Mapping[str, str], out_dir: str | Path) -> list[Path]:
    """Write rendered artifacts under ``out_dir``, creating parents.

    Returns the written paths in sorted order.
    """
    root = Path(out_dir)
    written: list[Path] = []
    for relative_path in sorted(artifacts):
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(artifacts[relative_path], encoding="utf-8")
        written.append(target)
    logger.info("Published %d static registry artifacts to %s", len(written), root)
    return written
