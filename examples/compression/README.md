# Compression

*Last modified: 2026-08-16*

![Compression](../../docs/assets/compression.gif)

Enables response compression on `api.local` for brotli, gzip, and zstd. The first algorithm in `algorithms` that the client advertises in `Accept-Encoding` wins. `min_size: 512` keeps the proxy from compressing tiny payloads where the framing overhead exceeds the savings. The upstream is `test.sbproxy.dev`, which produces enough text to make the size delta visible.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Ask for brotli. Response carries Content-Encoding: br; the compressed
# body is streamed chunked, so no Content-Length header comes with it.
curl -sv -H 'Host: api.local' -H 'Accept-Encoding: br' http://127.0.0.1:8080/get -o /dev/null 2>&1 | grep -iE 'content-encoding|content-length'
# < content-encoding: br

# Ask for gzip. Same chunked framing, no Content-Length.
curl -sv -H 'Host: api.local' -H 'Accept-Encoding: gzip' http://127.0.0.1:8080/get -o /dev/null 2>&1 | grep -iE 'content-encoding|content-length'
# < content-encoding: gzip

# zstd works too.
curl -sv -H 'Host: api.local' -H 'Accept-Encoding: zstd' http://127.0.0.1:8080/get -o /dev/null 2>&1 | grep -i content-encoding
# < content-encoding: zstd

# No Accept-Encoding -> uncompressed pass-through, with a real
# Content-Length (the exact byte count tracks the upstream's current body).
curl -sv -H 'Host: api.local' http://127.0.0.1:8080/get -o /dev/null 2>&1 | grep -iE 'content-encoding|content-length'
# < content-length: 2592
```

## What this exercises

- `compression.enabled`
- `compression.algorithms` priority list (br, gzip, zstd)
- `Accept-Encoding` content negotiation
- `min_size` cutoff to skip compression on small bodies

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
