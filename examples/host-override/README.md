# Host override

*Last modified: 2026-04-27*

By default the proxy sends the upstream URL's hostname in the upstream `Host` header (so vhost-routed services like Vercel, Cloudflare-fronted origins, S3 website endpoints, and AWS ALBs work out of the box). When the upstream expects a different `Host` than its DNS name (CDN-fronted services, multi-tenant SaaS), set `host_override`. Whenever the proxy rewrites `Host`, it also sets `X-Forwarded-Host` to the client's original `Host` so the upstream can still observe the public name.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# The proxy rewrites Host to api.upstream.example before forwarding.
# httpbin echoes back what it sees.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/get | jq .headers
# {
#   "Host": "api.upstream.example",
#   "X-Forwarded-Host": "localhost",
#   ...
# }

# Send a different inbound Host. The override still wins on the upstream,
# but X-Forwarded-Host is updated to match.
curl -s -H 'Host: localhost' -H 'X-Custom: yes' http://127.0.0.1:8080/headers | jq '.headers["Host"], .headers["X-Forwarded-Host"]'
# "api.upstream.example"
# "localhost"
```

## What this exercises

- `action.host_override` to rewrite the upstream `Host` header
- Automatic `X-Forwarded-Host` injection when `Host` is rewritten
- Default behaviour: upstream URL's hostname becomes the upstream `Host`

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
