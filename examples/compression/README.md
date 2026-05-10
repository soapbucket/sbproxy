# Compression

*Last modified: 2026-04-27*

Enables response compression on `api.local` for brotli, gzip, and zstd. The first algorithm in `algorithms` that the client advertises in `Accept-Encoding` wins. `min_size: 512` keeps the proxy from compressing tiny payloads where the framing overhead exceeds the savings. The upstream is `httpbin.org`, which produces enough text to make the size delta visible.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Ask for brotli. Response carries Content-Encoding: br.
curl -sv -H 'Host: api.local' -H 'Accept-Encoding: br' http://127.0.0.1:8080/get -o /dev/null 2>&1 | grep -iE 'content-encoding|content-length'
# < content-encoding: br
# < content-length: 213

# Ask for gzip.
curl -sv -H 'Host: api.local' -H 'Accept-Encoding: gzip' http://127.0.0.1:8080/get -o /dev/null 2>&1 | grep -iE 'content-encoding|content-length'
# < content-encoding: gzip
# < content-length: 245

# zstd works too.
curl -sv -H 'Host: api.local' -H 'Accept-Encoding: zstd' http://127.0.0.1:8080/get -o /dev/null 2>&1 | grep -i content-encoding
# < content-encoding: zstd

# No Accept-Encoding -> uncompressed pass-through.
curl -sv -H 'Host: api.local' http://127.0.0.1:8080/get -o /dev/null 2>&1 | grep -iE 'content-encoding|content-length'
# < content-length: 308
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
