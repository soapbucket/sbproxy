# Payload limit transform

*Last modified: 2026-04-27*

Demonstrates the `payload_limit` transform. The proxy fetches `https://httpbin.org/bytes/4096`, which returns 4096 random bytes, and clips the response body to `max_size: 256`. With `truncate: true`, oversize bodies are silently clipped to the configured ceiling; with the default `truncate: false`, oversize bodies cause the transform to error and the response fails. Useful as a defensive cap on responses from untrusted or unstable upstreams. The origin is reached on `127.0.0.1:8080` via the `cap.local` Host header.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Original upstream returns 4096 bytes
$ curl -s -o /dev/null -w '%{size_download}\n' https://httpbin.org/bytes/4096
4096
```

```bash
# Proxied response is clipped to 256 bytes
$ curl -s -o /dev/null -w '%{size_download}\n' -H 'Host: cap.local' http://127.0.0.1:8080/bytes/4096
256
```

```bash
# Status code remains the upstream's; only the body length changes
$ curl -sI -H 'Host: cap.local' http://127.0.0.1:8080/bytes/4096
HTTP/1.1 200 OK
content-type: application/octet-stream
```

```bash
# Smaller responses pass through untouched
$ curl -s -o /dev/null -w '%{size_download}\n' -H 'Host: cap.local' http://127.0.0.1:8080/bytes/100
100
```

## What this exercises

- `payload_limit` transform - response body cap with `max_size`
- `truncate: true` - oversize bodies clipped instead of failing
- Composition with the `proxy` action so the cap is layered on top of a real upstream

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
