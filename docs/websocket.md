# websocket action
*Last modified: 2026-08-18*

The `websocket` action proxies `ws://`/`wss://` upstreams. It does not parse WebSocket frames. The inbound HTTP `Upgrade` request runs through the same origin pipeline as any other action, host routing, `authentication`, `policies`, request transforms, and once the upstream answers `101 Switching Protocols` the connection becomes a transparent byte pipe in both directions. This page covers the action's config keys, what runs before the upgrade completes, and what does not happen after it. For where `websocket` sits among the other protocol-specific actions, see [routing.md](routing.md#protocol-specific-routing); for the field table in the general configuration reference, see [configuration.md#websocket](configuration.md#websocket).

## Config

```yaml
origins:
  "ws.example.com":
    action:
      type: websocket
      url: wss://ws-backend.internal:8080
      subprotocols: [graphql-ws, graphql-transport-ws]
      max_message_size: 5242880
```

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | required | Backend WebSocket URL (`ws://` or `wss://`). |
| `subprotocols` | list of string | `[]` | Subprotocols this origin is meant to support. Accepted by config; see [Honest limits](#honest-limits) below. |
| `max_message_size` | int | `10485760` (10 MB) | Maximum message payload size in bytes. Accepted by config; see [Honest limits](#honest-limits) below. |
| `host_override` | string | upstream URL's host | `Host` header sent on the upgrade request. Set this when the upstream is vhost-based and expects a different value than the URL's own hostname. |

`host_override` and the standard forwarding-header opt-outs (`disable_forwarded_for_header`, and so on) work the same way here as on every other URL-bearing action: `proxy`, `load_balancer` targets, `grpc`, `graphql`, and `a2a` all accept the same fields with the same meaning.

## Upgrade semantics

Requests to a `websocket` origin are not required to carry `Upgrade: websocket`. The action is a routing choice, "proxy this Host to a `ws://`/`wss://` target", not a protocol gate. A plain HTTP request to the same origin is proxied unchanged to the same upstream address; whatever that upstream does with a non-upgrade request (typically its own `400`, since a real WebSocket server usually only implements the handshake) is what the client sees. sbproxy does not inspect the request for `Upgrade`/`Connection` headers, reject it on the client's behalf, or otherwise treat it specially before handing it to the upstream connection.

When the client does send a proper upgrade request and the upstream answers `101 Switching Protocols`, Pingora forwards bytes transparently in both directions for the lifetime of the connection. sbproxy is not a party to the WebSocket handshake computation (`Sec-WebSocket-Accept` derived from `Sec-WebSocket-Key`); that is entirely the upstream's responsibility, forwarded through unchanged.

## What runs before the upgrade

Everything that would run for a `proxy` action against the same origin runs here too, against the initial `GET` request and its headers:

- Host-based origin routing
- `authentication` (bearer, API key, JWT, basic, mTLS, OIDC, forward auth, whatever the origin configures)
- `policies` (rate limiting, WAF, CEL, and the rest)
- Request transforms and forward rules

These are the same pipeline stages every origin runs, applied here to a request that happens to be asking for an upgrade. A request that fails one of them (missing auth token, rate limit exceeded, WAF match) never reaches the point where the gateway would attempt the upgrade. A runnable demonstration of an auth gate rejecting the upgrade, and passing it once a valid token is presented, is in [`examples/websocket-proxy/`](../examples/websocket-proxy/).

## Honest limits

Two config fields on this action describe controls the gateway does not currently enforce:

- **`max_message_size`** is accepted by config parsing but nothing in the current codebase counts frame payload bytes or closes a connection for exceeding it. A message far larger than the configured value passes through unmodified; the field currently documents intent, not enforced behavior.
- **`subprotocols`** is likewise accepted but not read anywhere the gateway would negotiate or filter on `Sec-WebSocket-Protocol`. Whatever the client and the real upstream negotiate between themselves is what happens; the gateway is not a party to it.

Post-upgrade traffic overall gets no per-frame inspection: no PII redaction, no payload-shape validation, no per-message rate limiting, nothing that reads or acts on individual WebSocket frames. Everything after `101 Switching Protocols` is a transparent tunnel. If you need control over what flows after the upgrade, whether that is enforcing a message-size ceiling, redacting frame content, or applying a subprotocol allowlist, that has to live in the WebSocket backend itself; the gateway's contribution to a WebSocket connection stops at the pre-upgrade pipeline described above.

## Runnable example

[`examples/websocket-proxy/`](../examples/websocket-proxy/) has the handshake demonstrated end to end (a stdlib Python WebSocket client, since curl cannot speak WebSocket framing after the `101`), the auth gate rejecting an unauthorized upgrade, the failure mode for a non-upgrade request landing on a `websocket` origin, and a live check that `max_message_size` does not currently bound frame size.

```bash
python3 examples/websocket-proxy/fixture.py &
sbproxy serve -f examples/websocket-proxy/sb.yml
python3 examples/websocket-proxy/client.py "hello through the gateway"
```

## See also

- [routing.md#protocol-specific-routing](routing.md#protocol-specific-routing) - `websocket` alongside `grpc` and `graphql`
- [configuration.md#websocket](configuration.md#websocket) - field table in the general configuration reference
- The action implementation at `crates/sbproxy-modules/src/action/websocket.rs`
