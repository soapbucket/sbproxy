# IP filter

*Last modified: 2026-04-27*

Demonstrates the `ip_filter` policy. Only requests from the loopback range `127.0.0.0/8` and the private LAN range `10.0.0.0/8` are accepted; everything else is rejected with `403` before the upstream `httpbin.org` is contacted. A blacklist entry of `10.0.0.99/32` carves a single IP back out of the allowed range to show how whitelist and blacklist combine. The proxy listens on `127.0.0.1:8080` and routes to the origin via the `ipfilter.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

No setup required. Local curl traffic always lands on `127.0.0.1`, which sits inside the whitelist, so the happy path works out of the box. To see the deny path, narrow the whitelist to a CIDR that excludes your client.

## Try it

```bash
# 200 - request from 127.0.0.1 matches the whitelist
$ curl -i -H 'Host: ipfilter.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json
...
{
  "args": {},
  "headers": {
    "Host": "httpbin.org",
    ...
  },
  "origin": "...",
  "url": "https://httpbin.org/get"
}
```

```bash
# 403 - if you swap the whitelist to a CIDR that excludes 127.0.0.1
$ curl -i -H 'Host: ipfilter.local' http://127.0.0.1:8080/get
HTTP/1.1 403 Forbidden
content-type: text/plain
content-length: 24

forbidden by ip_filter
```

```bash
# Adding 10.0.0.99 to a real client and sending it would also produce 403,
# because the blacklist takes precedence over the whitelist for that single host.
```

## What this exercises

- `ip_filter` policy - CIDR-based whitelist and blacklist evaluation against the client source IP
- `proxy` action - the upstream is only invoked after the policy decides to allow the request
- Listener binding via `proxy.http_bind_port` and Host-header based origin selection

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
