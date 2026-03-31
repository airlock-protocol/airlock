from __future__ import annotations

from airlock.crypto.keys import KeyPair

_DEMO_GATEWAY_SEED = b"airlock_gateway_identity_seed_00"


def gateway_keypair_from_config(
    gateway_seed_hex: str,
    *,
    allow_demo_fallback: bool = True,
) -> KeyPair:
    """Load gateway signing identity from AIRLOCK_GATEWAY_SEED_HEX or demo seed (dev/tests only).

    When ``allow_demo_fallback`` is False (production), invalid or missing seed raises ValueError.
    """
    s = (gateway_seed_hex or "").strip()
    if len(s) == 64:
        try:
            seed = bytes.fromhex(s)
            if len(seed) == 32:
                return KeyPair.from_seed(seed)
        except ValueError:
            pass
    if not allow_demo_fallback:
        raise ValueError(
            "Invalid or missing AIRLOCK_GATEWAY_SEED_HEX (need 64 hex chars for a 32-byte seed)."
        )
    return KeyPair.from_seed(_DEMO_GATEWAY_SEED)
