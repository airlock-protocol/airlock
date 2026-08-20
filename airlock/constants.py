"""Protocol-level constants.

This module must not import from anywhere else in the package. It sits below
every layer so that schemas, engine, and gateway can all read from it without
creating a cycle.
"""

from __future__ import annotations

#: Version of the Airlock wire protocol.
#:
#: Deliberately independent of the distribution version in ``pyproject.toml``.
#: The package version tracks releases of this implementation; this tracks the
#: on-the-wire contract between peers. Bump it only when that contract changes.
PROTOCOL_VERSION = "0.1.0"
