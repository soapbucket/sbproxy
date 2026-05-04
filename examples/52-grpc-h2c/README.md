# gRPC over HTTP/2 cleartext (h2c)

*Last modified: 2026-04-27*

Proxies plaintext gRPC traffic to an upstream gRPC server. gRPC requires HTTP/2 end-to-end, so the proxy's plain HTTP listener must speak HTTP/2 cleartext (h2c). The `proxy.http2_cleartext: true` flag enables Pingora's h2c preface detection on the listener so that connections that begin with the HTTP/2 connection preface are upgraded to h2 transparently. Connections that begin with a normal HTTP/1.1 request line continue to be served as HTTP/1.1, so a single listener can carry both protocols.

TLS-fronted gRPC on `https_bind_port` does not need this flag. ALPN negotiates h2 during the TLS handshake. The flag is opt-in for the plain HTTP listener so default deployments are not exposed to h2 prior-knowledge clients unintentionally.

## Run

```bash
make run CONFIG=examples/52-grpc-h2c/sb.yml
```

You will need a gRPC server listening on `127.0.0.1:50051`. Any service works. Tonic, grpc-go, grpc-java all bind to the same plaintext h2 wire format.

## Try it

```bash
# List services exposed by the proxied gRPC server.
grpcurl -plaintext -authority grpc.example.com 127.0.0.1:8080 list

# Invoke a unary RPC.
grpcurl -plaintext -authority grpc.example.com \
    -d '{"message": "hello"}' \
    127.0.0.1:8080 your.Service/YourMethod
```

The `-authority grpc.example.com` flag tells grpcurl to set the HTTP/2 `:authority` pseudo-header to `grpc.example.com`, which is how the proxy picks the right origin config.

## What this exercises

- `proxy.http2_cleartext: true` - enable h2c preface detection on the plain HTTP listener
- `grpc` action - proxy gRPC requests to an upstream gRPC server with HTTP/2 forced upstream

## See also

- [docs/features.md](../../docs/features.md) - full feature reference, including the listener section
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
