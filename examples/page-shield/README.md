# Page Shield

*Last modified: 2026-04-27*

Client-side script monitoring via Content Security Policy report intake. The `page_shield` policy stamps a `Content-Security-Policy-Report-Only` (or enforcing) header on every response with the configured directives plus a `report-uri` pointing at the proxy's intake endpoint. Browsers POST violation reports to that endpoint and the proxy logs each report under the `sbproxy::page_shield` tracing target so logpush sinks (or the enterprise connection-monitor) can analyse them. `report-only` mode is the recommended starting point: browsers report violations but do not block them. Watch the event stream until the policy reflects reality, then flip `mode` to `enforce`.

## Run

```bash
sbproxy serve -f sb.yml
```

The example serves a small static HTML page so you can see the CSP header without a real upstream.

## Try it

```bash
# Confirm the CSP header is on every response.
curl -i -H 'Host: app.local' http://127.0.0.1:8080/
# Content-Security-Policy-Report-Only: default-src 'self'; script-src ...;
# report-uri /__sbproxy/csp-report
```

```bash
# Simulate a browser posting a violation report. The intake accepts
# both `application/csp-report` and the newer `application/reports+json`.
curl -i -X POST http://127.0.0.1:8080/__sbproxy/csp-report \
     -H 'content-type: application/csp-report' \
     -d '{"csp-report":{"document-uri":"http://app.local/","violated-directive":"script-src","blocked-uri":"https://evil.example/x.js"}}'
# HTTP/1.1 204 No Content
```

```bash
# Tail the proxy logs to see the structured report event.
sbproxy serve -f sb.yml 2>&1 | grep sbproxy::page_shield
```

## What this exercises

- `page_shield` policy with `mode: report-only`
- `directives` list rendered into the `Content-Security-Policy-Report-Only` header
- Built-in CSP intake at `/__sbproxy/csp-report` that accepts both `application/csp-report` and `application/reports+json`
- Structured violation logging under the `sbproxy::page_shield` tracing target

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
