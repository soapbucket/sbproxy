# Forwarding headers

*Last modified: 2026-07-09*

![Forwarding headers](../../docs/assets/forwarding-headers.gif)

The proxy injects a standard set of forwarding headers on every upstream request: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `Forwarded` (RFC 7239), and `Via`. Each header has a per-action `disable_*_header` opt-out flag. This example disables `Via` and `X-Forwarded-Port` on `localhost`; everything else stays on. Use these toggles when an upstream rejects the metadata or when you don't want to leak the public-facing scheme/port to a backend.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# The echo service returns the headers it received (keys are lowercase).
# Note that via and x-forwarded-port are missing while the rest of the
# forwarding family is present. The hosted echo runs behind a CDN that
# rewrites x-forwarded-for and friends with its own values, so the exact
# values differ from what the proxy injected; point the config at a
# backend you run yourself to see the raw injected values.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/headers | jq .headers
# {
#   "host": "test.sbproxy.dev",
#   "forwarded": "...",
#   "x-forwarded-for": "...",
#   "x-forwarded-host": "...",
#   "x-forwarded-proto": "https",
#   "x-real-ip": "..."
#   ...
# }

# Verify the absence of the disabled headers explicitly.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/headers | jq '.headers | has("via"), has("x-forwarded-port")'
# false
# false
```

## What this exercises

- `action.disable_via_header`
- `action.disable_forwarded_port_header`
- The full `disable_*_header` opt-out family on the action
- Default forwarding-header injection behaviour

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
