# Guarded HTTPS reverse-proxy relay

*Last modified: 2026-08-22*

An allow-listed TLS reverse-proxy relay to the host a request already
resolved to (its inbound `Host` header), rather than a URL fixed in config.
It is not an HTTP `CONNECT` proxy and cannot create a raw byte tunnel. Two
origins share one allow-list that permits only `httpbin.org`: a request for
`httpbin.org` relays over TLS to the real `httpbin.org`, and a request for
`example.com` is refused with `403` because that host is not on the list,
even though `example.com` is itself a configured origin.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
curl -s -H 'Host: httpbin.org' http://127.0.0.1:8080/get
# {
#   "args": {},
#   "headers": { ... },
#   "url": "https://httpbin.org/get"
# }

curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: example.com' \
  http://127.0.0.1:8080/get
# 403
```

## What this exercises

- `action.type: https_proxy` with `allowed_hosts`
- An action with no `url:` field: the relay target is the request's own
  resolved host, so the same action config behaves differently depending
  on which origin (and therefore which `Host`) it is attached to
- `sbproxy_action_https_proxy_decisions_total{origin, decision}`
  recording both the `allow` and the `deny` path

## See also

- [docs/configuration.md](../../docs/configuration.md#https_proxy)
- [docs/observability.md](../../docs/observability.md)
