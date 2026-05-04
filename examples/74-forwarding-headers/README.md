# Forwarding headers

*Last modified: 2026-04-27*

The proxy injects a standard set of forwarding headers on every upstream request: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `Forwarded` (RFC 7239), and `Via`. Each header has a per-action `disable_*_header` opt-out flag. This example disables `Via` and `X-Forwarded-Port` on `localhost`; everything else stays on. Use these toggles when an upstream rejects the metadata or when you don't want to leak the public-facing scheme/port to a backend.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# httpbin echoes the headers it received. Note that Via and X-Forwarded-Port
# are missing while the rest of the forwarding family is present.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/headers | jq .headers
# {
#   "Forwarded": "for=127.0.0.1;host=localhost;proto=http",
#   "Host": "httpbin.org",
#   "X-Forwarded-For": "127.0.0.1",
#   "X-Forwarded-Host": "localhost",
#   "X-Forwarded-Proto": "http",
#   "X-Real-Ip": "127.0.0.1"
#   ...
# }

# Verify the absence of the disabled headers explicitly.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/headers | jq '.headers | has("Via"), has("X-Forwarded-Port")'
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
