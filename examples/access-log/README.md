# access-log

*Last modified: 2026-06-04*

![access-log](../../docs/assets/access-log.gif)

Structured JSON access log on stdout, ready for Fluent Bit / Vector /
any stdout-tailing log shipper. Demonstrates every commonly-used knob
on the top-level `access_log:` block: status and method filters,
sampling, request and response header capture with the PII redactor,
and the always-on secret redactor.

See [`docs/access-log.md`](../../docs/access-log.md) for the full
field reference and routing options (file output, log shipper
integration patterns).

## Run

```bash
make run CONFIG=examples/access-log/sb.yml
```

In another terminal, drive a mix of statuses + methods:

```bash
curl -s -H 'Host: api.local' http://127.0.0.1:8080/anything | head -c 80
curl -s -H 'Host: api.local' -X POST http://127.0.0.1:8080/anything
curl -s -H 'Host: api.local' http://127.0.0.1:8080/status/500
```

## What you see on the proxy's stdout

One JSON object per response. Optional fields are omitted when their
value is `None`, so a successful proxy hop carries the populated
fields and nothing more:

```json
{
  "timestamp": "2026-08-01T14:56:33.863503+00:00",
  "request_id": "019fbdd3ab8272e2a87d91f409911437",
  "origin": "api.local",
  "method": "GET",
  "path": "/anything",
  "protocol": "HTTP/1.1",
  "host": "api.local",
  "user_agent": "curl/8.18.0",
  "status": 200,
  "response_content_type": "application/json; charset=utf-8",
  "latency_ms": 196.17337500000002,
  "upstream_ttfb_ms": 195.80141700000001,
  "response_filter_ms": 0.060958,
  "bytes_in": 0,
  "bytes_out": 2596,
  "client_ip": "127.0.0.1",
  "trace_id": "a242bdd5b2a948b683f9020924010054",
  "envelope_request_id": "01KYYX7AWCH1C2E5GFP6BCJEGC",
  "session_id": "01KYYX7AWCXXJ74WD2AAZV6EHT",
  "tenant_id": "__default__",
  "principal_kind": "none",
  "key_mode": "none",
  "served_from_cache": false,
  "fallback_triggered": false,
  "retry_count": 0,
  "request_headers": {"user-agent": "curl/8.18.0"},
  "response_headers": {
    "content-length": "2596",
    "content-type": "application/json; charset=utf-8"
  }
}
```

The 500 from `/status/500` adds `error_class: "upstream_5xx"`. It does
not add `upstream_status`: that field only appears when the status the
client sees differs from the one the upstream sent, which is what a
retry chain, a fallback, or a `response_modifier` produces.

## Tuning

| Goal | Knob |
|---|---|
| Error-only logs | drop `200` from `status_codes` |
| Write-only logs | trim `methods` to `["POST", "PUT", "PATCH", "DELETE"]` |
| 5% sample to bound volume | `sample_rate: 0.05` |
| Tighter header capture | drop globs from `capture_headers.request` and list headers by exact name |
| PII redaction over headers | flip `capture_headers.redact_pii: true`; optionally narrow `redact_pii_rules` |
| Capture `authorization` header anyway | list it by exact name in `capture_headers.request` (proxy WARNs at config load) |

## Notes

* The **secret redactor** (bearer tokens, API-key shapes, JWT-shaped
  strings) runs on every line and is not opt-out; the example
  defaults to the safe shape.
* Custom secrets embedded in URLs or other free-form fields are NOT
  PII-redacted today (only captured header values are). Apply
  additional masking at your log shipper for those cases.
* `request_headers` and `response_headers` are omitted entirely
  when no header allowlist match fires.
