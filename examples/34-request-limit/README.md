# Request limit

*Last modified: 2026-04-27*

Demonstrates the `request_limit` policy. Caps the request body at `1024` bytes, the header count at `20`, and the URL length at `256` characters before the `httpbin.org` upstream is contacted. Anything past those limits is rejected at the edge so the upstream never sees an oversized payload. Listener is `127.0.0.1:8080` and the origin matches the `limit.local` Host header.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Small JSON body fits all limits - 200
$ curl -i -H 'Host: limit.local' \
       -H 'Content-Type: application/json' \
       -d '{"hello":"world"}' http://127.0.0.1:8080/post
HTTP/1.1 200 OK
content-type: application/json

{
  "args": {},
  "data": "{\"hello\":\"world\"}",
  "json": {"hello":"world"},
  ...
}
```

```bash
# Body well over 1 KiB - rejected before the upstream sees it
$ curl -i -H 'Host: limit.local' \
       -H 'Content-Type: application/octet-stream' \
       --data-binary "$(head -c 4096 /dev/urandom | base64)" \
       http://127.0.0.1:8080/post
HTTP/1.1 413 Payload Too Large
content-type: text/plain

request body exceeds max_body_size
```

```bash
# URL longer than 256 chars - rejected
$ curl -i -H 'Host: limit.local' \
       "http://127.0.0.1:8080/post?$(head -c 300 /dev/urandom | base64 | tr -d '\n' | cut -c1-300)"
HTTP/1.1 414 URI Too Long
content-type: text/plain

request URL exceeds max_url_length
```

## What this exercises

- `request_limit` policy with `max_body_size`, `max_header_count`, and `max_url_length`
- Edge enforcement: oversized requests are dropped before the upstream connection is opened
- Composition with the `proxy` action

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
