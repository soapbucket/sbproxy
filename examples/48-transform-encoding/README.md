# Encoding transform

*Last modified: 2026-04-27*

Demonstrates the `encoding` transform. A `static` action returns a small JSON document; the transform converts the bytes to standard base64 via `encoding: base64_encode`. A `response_modifier` switches `Content-Type` to `text/plain; charset=utf-8` to match the new payload shape. Other valid `encoding` values are `base64_decode`, `url_encode`, and `url_decode`. The origin is reached on `127.0.0.1:8080` via the `enc.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Upstream body (what the static action emits internally):
# {"message":"encoded by sbproxy","ok":true}

# Raw response is base64
$ curl -i -H 'Host: enc.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: text/plain; charset=utf-8

eyJtZXNzYWdlIjoiZW5jb2RlZCBieSBzYnByb3h5Iiwib2siOnRydWV9
```

```bash
# Pipe through base64 -d to recover the original JSON
$ curl -s -H 'Host: enc.local' http://127.0.0.1:8080/ | base64 -d
{"message":"encoded by sbproxy","ok":true}
```

```bash
# Round-trip through jq after decoding
$ curl -s -H 'Host: enc.local' http://127.0.0.1:8080/ | base64 -d | jq
{
  "message": "encoded by sbproxy",
  "ok": true
}
```

## What this exercises

- `encoding` transform with `encoding: base64_encode`
- `response_modifiers` rewriting `Content-Type` to match the new body shape
- `static` action emitting an inline JSON body so no upstream is needed

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
