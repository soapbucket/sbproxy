# DLP catalog

*Last modified: 2026-04-27*

The `dlp` policy scans the request URI and headers for matches against the configured detector set, then either tags the upstream request with a `dlp-detection` header (`action: tag`, default) or rejects with 403 (`action: block`). Detectors come from the built-in regex catalogue (AWS keys, GitHub tokens, Slack tokens, IBANs, etc.) with optional inline `rules:` layered on top. This example ships two origins. `api.local` blocks on AWS, GitHub, Slack, or IBAN matches. `tag.local` enables every default detector (empty `detectors: []`) and adds a custom `internal_ticket` rule that redacts `TICKET-NNNNNN` strings.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Block path: an AWS access key in the query string trips the detector.
curl -i -H 'Host: api.local' \
  'http://127.0.0.1:8080/build?key=AKIAIOSFODNN7EXAMPLE'
# HTTP/1.1 403 Forbidden
# content-type: application/json
#
# {"error":"forbidden","reason":"dlp: detector aws_access matched"}

# Tag path: a Slack token in a header is forwarded but tagged.
curl -i -H 'Host: tag.local' \
  -H 'X-Notes: leaked xoxb-1234567890-abc' http://127.0.0.1:8080/anything
# HTTP/1.1 200 OK
# (httpbin echoes the request back; the upstream view shows the dlp-detection
#  header that the proxy stamped on the request).

# Custom rule (internal_ticket) catches references in headers.
curl -i -H 'Host: tag.local' \
  -H 'X-Ticket: see TICKET-123456 for context' http://127.0.0.1:8080/anything
# HTTP/1.1 200 OK
# X-Notes is rewritten to "[REDACTED:TICKET]" before the upstream sees it.

# Clean request -> no tag, no block.
curl -i -H 'Host: tag.local' http://127.0.0.1:8080/anything
# HTTP/1.1 200 OK   (no dlp-detection header)
```

## What this exercises

- `policies[].type: dlp`
- `action: block` and `action: tag` modes
- Built-in detectors (`aws_access`, `github_token`, `slack_token`, `iban`)
- Empty `detectors: []` to enable every default
- Custom inline `rules:` with `pattern`, `replacement`, `anchor`

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
