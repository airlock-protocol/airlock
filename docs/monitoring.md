# Monitoring and Observability

## Prometheus Metrics

The Airlock gateway exposes Prometheus-format metrics at `GET /metrics` (requires `service_token` Bearer auth in production).

### HTTP Request Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `airlock_http_requests_total` | counter | `method`, `path`, `status` | Total HTTP requests processed |
| `airlock_http_request_duration_milliseconds` | histogram | `le` | Request latency distribution |

### Domain Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `airlock_revocations_total` | counter | -- | Total agent revocations |
| `airlock_verdicts_total` | counter | `type` | Verdicts issued (VERIFIED, REJECTED, DEFERRED) |
| `airlock_challenges_total` | counter | `outcome` | Challenge outcomes (PASS, FAIL, AMBIGUOUS) |
| `airlock_delegations_total` | counter | -- | Delegated resolution requests |
| `airlock_audit_entries_total` | counter | -- | Audit trail entries recorded |

### Infrastructure Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `airlock_event_bus_queue_depth` | gauge | Current event bus queue depth |
| `airlock_event_bus_dead_letters_total` | counter | Events dropped (full queue or shutdown) |

## Configuration

### Environment Variables

- `AIRLOCK_SERVICE_TOKEN` -- Bearer token for `/metrics` endpoint (required in production).
- `AIRLOCK_REDIS_URL` -- Redis URL for shared state across replicas. Enables `RedisRevocationStore`, `RedisReplayGuard`, and `RedisSlidingWindow`.
- `AIRLOCK_CHALLENGE_FALLBACK_MODE` -- Set to `rule_based` for deterministic challenge evaluation when the LLM is unavailable. Default: `ambiguous`.
- `AIRLOCK_LOG_JSON` -- Set to `true` for structured JSON logging (recommended for Loki/Datadog).

## Scrape Configuration (Prometheus)

```yaml
scrape_configs:
  - job_name: "airlock"
    scheme: http
    bearer_token: "<your-service-token>"
    static_configs:
      - targets: ["localhost:8000"]
    metrics_path: /metrics
    scrape_interval: 15s
```

## Alerting Recommendations

- **High rejection rate**: alert when `rate(airlock_verdicts_total{type="REJECTED"}[5m])` exceeds a threshold.
- **LLM fallback active**: monitor `airlock_challenges_total{outcome="AMBIGUOUS"}` for spikes indicating LLM unavailability.
- **Event bus saturation**: alert when `airlock_event_bus_queue_depth` approaches the configured max (default 1000).
- **Dead letters**: alert on any increase in `airlock_event_bus_dead_letters_total`.
