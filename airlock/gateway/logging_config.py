"""Optional JSON log formatting for the ``airlock`` logger tree (no extra deps)."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_LOG_RECORD_SKIP = frozenset(
    {
        "name",
        "msg",
        "args",
        "created",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "exc_info",
        "exc_text",
        "thread",
        "threadName",
        "taskName",
    }
)


class JsonLogFormatter(logging.Formatter):
    """One JSON object per line; includes extra fields from ``logger.info(..., extra={})``."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=UTC).isoformat().replace("+00:00", "Z")
        payload: dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, val in record.__dict__.items():
            if key in _LOG_RECORD_SKIP or key in payload:
                continue
            if key.startswith("_"):
                continue
            try:
                json.dumps(val)
                payload[key] = val
            except (TypeError, ValueError):
                payload[key] = repr(val)
        return json.dumps(payload, ensure_ascii=False)


def configure_airlock_logging(*, log_json: bool, log_level: str = "INFO") -> None:
    """Attach a single handler on the ``airlock`` logger (children propagate to it)."""
    airlock = logging.getLogger("airlock")
    airlock.handlers.clear()
    level = getattr(logging, log_level.upper(), logging.INFO)
    airlock.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    if log_json:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))

    airlock.addHandler(handler)
    airlock.propagate = False
