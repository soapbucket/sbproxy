# access-log

*Last modified: 2026-06-04*

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
  "timestamp": "2026-06-04T01:23:45Z",
  "request_id": "01H...",
  "origin": "api.local",
  "method": "GET",
  "path": "/anything",
  "status": 200,
  "latency_ms": 12.3,
  "upstream_ttfb_ms": 11.0,
  "bytes_in": 0,
  "bytes_out": 456,
  "client_ip": "127.0.0.1",
  "request_headers": {
    "user-agent": "curl/8.x"
  },
  "response_headers": {
    "content-length": "456",
    "content-type": "application/json"
  }
}
```

The 500 from `/status/500` adds `upstream_status: 500` because the
upstream's status was passed through unchanged. A retry chain or a
`response_modifier` that rewrote the status would surface both
fields with different values.

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
