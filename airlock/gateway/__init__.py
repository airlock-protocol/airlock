from __future__ import annotations


def create_app(*args, **kwargs):  # type: ignore[no-untyped-def]
    """Lazy wrapper to avoid circular import between engine and gateway."""
    from airlock.gateway.app import create_app as _create_app

    return _create_app(*args, **kwargs)


__all__ = ["create_app"]
