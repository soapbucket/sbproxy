# Host override

*Last modified: 2026-07-09*

![Host override](../../docs/assets/host-override.gif)

By default the proxy sends the upstream URL's hostname in the upstream `Host` header (so vhost-routed services like Vercel, Cloudflare-fronted origins, S3 website endpoints, and AWS ALBs work out of the box). When the upstream expects a different `Host` than its DNS name (CDN-fronted services, multi-tenant SaaS), set `host_override`. Whenever the proxy rewrites `Host`, it also sets `X-Forwarded-Host` to the client's original `Host` so the upstream can still observe the public name.

This example accepts requests for `api.local` and overrides the upstream `Host` to `test.sbproxy.dev`. That is the only Host the shared test upstream serves (it routes by Host), so the override is exactly what makes the demo work. In production the override is typically a vanity or tenant hostname that differs from the upstream's DNS name.

## Run

```bash
make run CONFIG=examples/host-override/sb.yml
```

## Try it

```bash
# The proxy rewrites Host to test.sbproxy.dev before forwarding. The echo
# service reports the request headers it received (keys are lowercase).
curl -s -H 'Host: api.local' http://127.0.0.1:8080/headers | jq '.headers.host'
# "test.sbproxy.dev"

# The full header map shows the overridden host among the rest.
curl -s -H 'Host: api.local' http://127.0.0.1:8080/headers | jq .headers
# {
#   "host": "test.sbproxy.dev",
#   ...
# }
```

The proxy also injects `X-Forwarded-Host: api.local` alongside the override. The hosted echo runs behind a CDN that replaces `x-forwarded-host` with its own value, so that particular header is not observable through this upstream; point the same config at a backend you run yourself to see it arrive.

## What this exercises

- `action.host_override` to rewrite the upstream `Host` header
- Automatic `X-Forwarded-Host` injection when `Host` is rewritten
- Default behaviour: upstream URL's hostname becomes the upstream `Host`

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
