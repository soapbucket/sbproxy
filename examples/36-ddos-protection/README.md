# DDoS protection

*Last modified: 2026-04-27*

Demonstrates the `ddos_protection` policy. The proxy tracks a sliding 1-second window per source IP. When the rate exceeds `request_rate_threshold: 10`, the offending IP is blocked for `block_duration: 10s` and every subsequent request returns `429` with a `Retry-After` header until the block lifts. The whitelist exempts `127.0.0.1` and `10.0.0.0/8` from the check entirely (handy for health checkers and internal load testers). Distinct from `rate_limiting`: rate limiting throttles continuously and per request; DDoS protection trips a hard block once breached and keeps it for a fixed duration. Action is `echo` so each accepted request is reflected back, and the origin is reached on `127.0.0.1:8080` via the `ddos.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Under the threshold - the request is echoed back
$ curl -i -H 'Host: ddos.local' http://127.0.0.1:8080/echo
HTTP/1.1 200 OK
content-type: application/json

{"method":"GET","path":"/echo","headers":{...}}
```

```bash
# Burst past the threshold. First few requests succeed, the rest are blocked.
$ for i in $(seq 1 15); do
    curl -s -o /dev/null -w "%{http_code} " -H 'Host: ddos.local' \
      http://127.0.0.1:8080/echo
  done; echo
200 200 200 200 200 200 200 200 200 200 429 429 429 429 429
```

```bash
# Once blocked, even a single request returns 429 with Retry-After
$ curl -i -H 'Host: ddos.local' http://127.0.0.1:8080/echo
HTTP/1.1 429 Too Many Requests
retry-after: 10
content-type: text/plain

source IP blocked by ddos_protection
```

```bash
# After block_duration has elapsed, the IP is reinstated
$ sleep 11 && curl -i -H 'Host: ddos.local' http://127.0.0.1:8080/echo
HTTP/1.1 200 OK
```

## What this exercises

- `ddos_protection` policy - per-IP burst detection with auto-block
- `detection.request_rate_threshold` and `detection.detection_window` for the trip condition
- `mitigation.block_duration` and `mitigation.auto_block` for the hard-block behaviour
- `whitelist` of IPs and CIDRs that bypass the check
- `echo` action - reflects each accepted request

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
