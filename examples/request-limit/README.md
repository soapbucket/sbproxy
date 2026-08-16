# Request limit

*Last modified: 2026-08-16*

![Request limit](../../docs/assets/request-limit.gif)

Demonstrates the `request_limit` policy. Caps the request body at `1024` bytes, the header count at `20`, and the URL length at `256` characters before the `test.sbproxy.dev` upstream is contacted. Anything past those limits is rejected at the edge so the upstream never sees an oversized payload. Listener is `127.0.0.1:8080` and the origin matches the `limit.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Small JSON body fits all limits - 200
$ curl -i -H 'Host: limit.local' \
       -H 'Content-Type: application/json' \
       -d '{"hello":"world"}' http://127.0.0.1:8080/post
HTTP/1.1 200 OK
content-type: application/json

{"method":"POST","url":"/post","headers":{...},"query":{},"timestamp":"..."}
```

```bash
# Body well over 1 KiB - rejected before the upstream sees it
$ curl -i -H 'Host: limit.local' \
       -H 'Content-Type: application/octet-stream' \
       --data-binary "$(head -c 4096 /dev/urandom | base64)" \
       http://127.0.0.1:8080/post
HTTP/1.1 413 Payload Too Large
content-type: application/json

{"error":"request entity too large"}
```

```bash
# URL longer than 256 chars - rejected
$ curl -i -H 'Host: limit.local' \
       "http://127.0.0.1:8080/post?$(python3 -c "print('a'*300)")"
HTTP/1.1 413 Payload Too Large
content-type: application/json

{"error":"request entity too large"}
```

Every `request_limit` violation returns the same generic `413` with
`{"error":"request entity too large"}`, regardless of which specific cap
(body, header count, header size, URL length, query length) tripped. The
policy does compute a specific reason internally (e.g. `"URL length 312
exceeds limit 256"`), but that detail only reaches the `debug`-level proxy
log, never the client response, so do not rely on the status code or body
to tell the caps apart.

## What this exercises

- `request_limit` policy with `max_body_size`, `max_header_count`, and `max_url_length`
- Edge enforcement: oversized requests are dropped before the upstream connection is opened
- Composition with the `proxy` action

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
