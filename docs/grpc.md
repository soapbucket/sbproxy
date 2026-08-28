# grpc action

*Last modified: 2026-08-28*

The `grpc` action proxies gRPC to an upstream gRPC server. Plain passthrough is byte-transparent on HTTP/2 and carries every RPC cardinality, unary through bidirectional streaming. Two opt-in translation modes sit on top of that: `grpc_web: true` for browser clients, and `transcode` for REST/JSON routes bound to unary methods. This page covers how to turn the listener on, which knobs do what, and a walkthrough that boots offline. Field table: [configuration.md#grpc](configuration.md#grpc). Limits that bite in production: [routing.md#grpc-limits](routing.md#grpc-limits).

## Listeners

gRPC needs HTTP/2 end to end.

- **TLS.** Set `https_bind_port` and a certificate. ALPN negotiates `h2` during the handshake. You do not set `http2_cleartext`.
- **Cleartext (h2c).** Set `proxy.http2_cleartext: true` on the plain HTTP listener. The listener peeks at the connection preface: `PRI * HTTP/2.0` becomes h2, a normal HTTP/1.1 request line stays HTTP/1.1. Without the flag, the preface is parsed as a malformed HTTP/1.1 request and the connection dies with `FRAME_SIZE_ERROR`.
- **HTTP/3.** The `grpc` action answers `501`. There is no QUIC path for it.

## Config

```yaml
proxy:
  http_bind_port: 8080
  http2_cleartext: true

origins:
  "grpc.example.com":
    action:
      type: grpc
      url: grpc://127.0.0.1:50051
      timeout_secs: 30
```

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | required | Upstream (`grpc://`, `grpcs://`, `http://`, `https://`). |
| `tls` | bool | `false` | Force TLS regardless of URL scheme. |
| `authority` | string | unset | Override the HTTP/2 `:authority` pseudo-header sent upstream. |
| `timeout_secs` | int | `30` | Per-request timeout. |
| `grpc_web` | bool | `false` | Accept browser gRPC-Web (HTTP/1.1, `application/grpc-web+proto` or `application/grpc-web-text`). Unary and server-streaming only. Off keeps the origin as native gRPC. |
| `transcode` | object | unset | REST-to-gRPC. `descriptor_set` is a compiled protobuf `FileDescriptorSet`. `routes[]` each bind `{method, path, grpc_method, body}` to one unary method. `body: "*"` (or omitted) decodes the whole JSON body as the request message. |

A loopback or private upstream also needs `extensions.upstream.allow_private_cidrs`, or the SSRF guard 502s with "upstream resolved to private network". Production configs pointing at a real cluster address do not need that block.

## What actually runs

**Passthrough.** The proxy forces HTTP/2 upstream and forwards length-prefixed frames untouched. Unary, client-streaming, server-streaming, and bidirectional calls all work, including server reflection (`grpcurl list`), which is itself a bidi RPC. An earlier note that `list` 502'd is stale; do not treat reflection as broken.

**`grpc_web: true`.** The origin accepts HTTP/1.1 gRPC-Web and translates to native gRPC upstream. Content types that work: `application/grpc-web+proto` (binary) and `application/grpc-web-text` (base64). CORS preflight is the browser's; set origin CORS as you would for any HTTP/1.1 API. Client-streaming and bidi gRPC-Web have no path through, because the translator buffers the request. Message compression is not supported; the proxy advertises `grpc-accept-encoding: identity`.

**`transcode`.** Unary only. A streaming method behind a transcode route returns only its first response frame. The descriptor is read once at config load; a missing file or a `grpc_method` the descriptor does not name fails compilation, not the first request. Do not paste a `transcode` block you cannot compile: if you do not have a `FileDescriptorSet` on disk, omit the block.

**Body-reading policies.** `content_digest`, `request_validator`, `openapi_validation`, `body_threat_protection`, and body-aware `prompt_injection_v2` on this origin stall every streaming RPC, `list` included. Unary is fine. Nothing refuses the combination at config load.

Runnable: [`examples/grpc-h2c/`](../examples/grpc-h2c/). That directory boots a stdlib-free wait: Python `grpcio` fixture on `:50051`, then `grpcurl` through the proxy, plus one curl of gRPC-Web and one curl of a transcode route.

## See also

- [routing.md](routing.md#protocol-specific-routing) for where `grpc` sits next to WebSocket and GraphQL
- [websocket.md](websocket.md) and [graphql.md](graphql.md) for the sibling protocol pages
