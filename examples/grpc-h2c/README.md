# gRPC over HTTP/2 cleartext (h2c)

*Last modified: 2026-08-28*

Proxies plaintext gRPC traffic to an upstream gRPC server. gRPC requires HTTP/2 end-to-end, so the proxy's plain HTTP listener must speak HTTP/2 cleartext (h2c). The `proxy.http2_cleartext: true` flag enables Pingora's h2c preface detection on the listener so that connections that begin with the HTTP/2 connection preface are upgraded to h2 transparently. Connections that begin with a normal HTTP/1.1 request line continue to be served as HTTP/1.1, so a single listener can carry both protocols.

TLS-fronted gRPC on `https_bind_port` does not need this flag. ALPN negotiates h2 during the TLS handshake. The flag is opt-in for the plain HTTP listener so default deployments are not exposed to h2 prior-knowledge clients unintentionally.

This directory boots its own upstream. `fixture.py` is a Python `grpcio` Echo service (`sbproxy_e2e.echo.Echo/Hello`) on `127.0.0.1:50051`. You do not need to supply a tonic or grpc-go server.

## Run

Install the fixture's Python packages once, then start it and the proxy:

```bash
python3 -m pip install grpcio grpcio-tools
python3 fixture.py &
make run CONFIG=examples/grpc-h2c/sb.yml
```

## Try it

Unary passthrough with `grpcurl`. `-proto echo.proto` is enough; the fixture does not enable server reflection. If *your* upstream does, `grpcurl list` works through this proxy too: reflection is a bidirectional-streaming RPC, and plain passthrough forwards those frames untouched.

```bash
grpcurl -plaintext -proto echo.proto -authority grpc.example.com \
    -d '{"message": "hello"}' \
    127.0.0.1:8080 sbproxy_e2e.echo.Echo/Hello
```

The `-authority grpc.example.com` flag tells grpcurl to set the HTTP/2 `:authority` pseudo-header to `grpc.example.com`, which is how the proxy picks the right origin config.

REST transcode on a second origin. `echo.pb` is a checked-in `FileDescriptorSet`; a missing or stale descriptor fails at config load, not on the first request. Unary only.

```bash
curl -sS -H 'Host: grpc-json.example.com' \
    -H 'Content-Type: application/json' \
    -d '{"message":"hello"}' \
    http://127.0.0.1:8080/echo
```

gRPC-Web on a third origin (`grpc_web: true`). Unary and server-streaming only; the translator buffers the request, so client-streaming and bidi gRPC-Web have no path through. Message compression is not supported (`grpc-accept-encoding: identity`). Point a browser client at `http://127.0.0.1:8080` with `Host: grpc-web.example.com`.

An earlier revision of this page reported `grpcurl list` failing with a framing error. That is no longer what the proxy does. Do not treat reflection as broken.

### One composition to avoid

Attaching a body-reading policy to a `grpc` origin (`content_digest`, `request_validator`, `openapi_validation`, `body_threat_protection`, or body-aware `prompt_injection_v2`) stalls every streaming RPC on it. Those policies need the complete request body, so the proxy holds the request until the client half-closes, and a streaming client will not half-close until it has read a response that cannot arrive. Unary calls are unaffected because they half-close immediately. Nothing refuses the combination at config load, and the stall reads like an upstream problem. See [routing.md](../../docs/routing.md#grpc-limits).

## What this exercises

- `proxy.http2_cleartext: true` - enable h2c preface detection on the plain HTTP listener
- `grpc` action - proxy gRPC requests to an upstream gRPC server with HTTP/2 forced upstream
- `grpc_web: true` - browser gRPC-Web translation (unary and server-streaming)
- `transcode` - REST/JSON onto a unary method from a compiled descriptor

## See also

- [docs/grpc.md](../../docs/grpc.md) - dedicated gRPC page
- [docs/routing.md](../../docs/routing.md#grpc-limits) - cardinality, compression, and the body-reading-policy stall
- [docs/configuration.md](../../docs/configuration.md#grpc) - field table
