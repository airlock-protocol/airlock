"""In-process HTTP counters, latency histogram, and Prometheus text exposition."""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Iterator

from fastapi import FastAPI

_BUCKETS_MS = (5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, float("inf"))


def _norm_path(raw: str) -> str:
    if not raw:
        return "/"
    p = raw.split("?", 1)[0]
    return p if p.startswith("/") else f"/{p}"


class HttpRequestMetrics:
    """Thread-safe counters keyed by (method, route_path, status_code)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: dict[tuple[str, str, int], int] = defaultdict(int)
        self._hist: dict[float, int] = defaultdict(int)
        self._dur_sum_ms = 0.0
        self._dur_count = 0

    def record(self, method: str, path: str, status_code: int, duration_ms: float) -> None:
        key = (method.upper(), _norm_path(path), int(status_code))
        with self._lock:
            self._counts[key] += 1
            self._dur_sum_ms += duration_ms
            self._dur_count += 1
            for b in _BUCKETS_MS:
                if duration_ms <= b:
                    self._hist[b] += 1

    def iter_counts(self) -> Iterator[tuple[tuple[str, str, int], int]]:
        with self._lock:
            items = sorted(self._counts.items(), key=lambda x: x[0])
        yield from items

    def _histogram_lines_locked(self) -> list[str]:
        lines = [
            "# HELP airlock_http_request_duration_milliseconds Request duration",
            "# TYPE airlock_http_request_duration_milliseconds histogram",
        ]
        for b in _BUCKETS_MS:
            le = "+Inf" if b == float("inf") else str(int(b))
            lines.append(
                f'airlock_http_request_duration_milliseconds_bucket{{le="{le}"}} '
                f"{self._hist.get(b, 0)}"
            )
        lines.append(f"airlock_http_request_duration_milliseconds_sum {self._dur_sum_ms}")
        lines.append(f"airlock_http_request_duration_milliseconds_count {self._dur_count}")
        return lines

    def prometheus_text(self) -> str:
        lines = [
            "# HELP airlock_http_requests_total Total processed HTTP requests",
            "# TYPE airlock_http_requests_total counter",
        ]
        with self._lock:
            for (method, path, status), n in sorted(self._counts.items(), key=lambda x: x[0]):
                path_esc = path.replace("\\", "\\\\").replace('"', '\\"')
                metric_line = (
                    f'airlock_http_requests_total{{method="{method}",path="{path_esc}",'
                    f'status="{status}"}} {n}'
                )
                lines.append(metric_line)
            lines.extend(self._histogram_lines_locked())
        lines.append("")
        return "\n".join(lines)


class DomainMetrics:
    """Domain-specific counters for Airlock protocol events."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revocations_total = 0
        self._verdicts: dict[str, int] = defaultdict(int)
        self._challenges: dict[str, int] = defaultdict(int)
        self._delegations_total = 0
        self._audit_entries_total = 0

    def inc_revocations(self) -> None:
        with self._lock:
            self._revocations_total += 1

    def inc_verdicts(self, verdict_type: str) -> None:
        with self._lock:
            self._verdicts[verdict_type] += 1

    def inc_challenges(self, outcome: str) -> None:
        with self._lock:
            self._challenges[outcome] += 1

    def inc_delegations(self) -> None:
        with self._lock:
            self._delegations_total += 1

    def inc_audit_entries(self) -> None:
        with self._lock:
            self._audit_entries_total += 1

    def prometheus_domain_text(self) -> str:
        """Return Prometheus-format text for domain-specific counters."""
        lines: list[str] = []

        with self._lock:
            # revocations
            lines.append("# HELP airlock_revocations_total Total agent revocations")
            lines.append("# TYPE airlock_revocations_total counter")
            lines.append(f"airlock_revocations_total {self._revocations_total}")

            # verdicts
            lines.append("# HELP airlock_verdicts_total Total verdicts by type")
            lines.append("# TYPE airlock_verdicts_total counter")
            for vtype, count in sorted(self._verdicts.items()):
                lines.append(f'airlock_verdicts_total{{type="{vtype}"}} {count}')

            # challenges
            lines.append("# HELP airlock_challenges_total Total challenges by outcome")
            lines.append("# TYPE airlock_challenges_total counter")
            for outcome, count in sorted(self._challenges.items()):
                lines.append(f'airlock_challenges_total{{outcome="{outcome}"}} {count}')

            # delegations
            lines.append("# HELP airlock_delegations_total Total delegated resolutions")
            lines.append("# TYPE airlock_delegations_total counter")
            lines.append(f"airlock_delegations_total {self._delegations_total}")

            # audit entries
            lines.append("# HELP airlock_audit_entries_total Total audit trail entries")
            lines.append("# TYPE airlock_audit_entries_total counter")
            lines.append(f"airlock_audit_entries_total {self._audit_entries_total}")

        lines.append("")
        return "\n".join(lines)


def saturation_prometheus_text(app: FastAPI) -> str:
    """Gauges for event bus saturation (best-effort)."""
    eb = getattr(app.state, "event_bus", None)
    if eb is None:
        return ""
    lines = [
        "# HELP airlock_event_bus_queue_depth Current event bus queue depth",
        "# TYPE airlock_event_bus_queue_depth gauge",
        f"airlock_event_bus_queue_depth {eb.qsize}",
        "# HELP airlock_event_bus_dead_letters_total Events dropped (full queue or shutdown)",
        "# TYPE airlock_event_bus_dead_letters_total counter",
        f"airlock_event_bus_dead_letters_total {eb.dead_letter_count}",
        "",
    ]
    return "\n".join(lines)
