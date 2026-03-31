"""URL validation to prevent SSRF attacks on callback URLs."""

from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def validate_callback_url(url: str | None) -> str | None:
    """Return the URL if safe, or None if it targets private/internal networks."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            logger.debug("Callback URL rejected: invalid scheme %s", parsed.scheme)
            return None
        hostname = parsed.hostname or ""
        if not hostname or hostname.lower() == "localhost":
            logger.debug("Callback URL rejected: localhost or empty host")
            return None
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                logger.debug("Callback URL rejected: private/internal IP %s", addr)
                return None
        except ValueError:
            pass  # hostname is a domain name — allow
        return url
    except Exception:
        logger.debug("Callback URL rejected: parse error", exc_info=True)
        return None
