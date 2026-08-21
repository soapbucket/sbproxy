# websocket action
*Last modified: 2026-08-20*

The `websocket` action proxies `ws://`/`wss://` upstreams. The inbound HTTP `Upgrade` request runs through the same origin pipeline as any other action, host routing, `authentication`, `policies`, request transforms, and once the upstream answers `101 Switching Protocols` the connection becomes a byte pipe in both directions. The gateway does not read frame payloads, but it does parse frame headers on that pipe to enforce `max_message_size`, and it holds `Sec-WebSocket-Protocol` negotiation to the configured `subprotocols` allowlist. This page covers the action's config keys, what runs before the upgrade completes, and what does and does not happen after it. For where `websocket` sits among the other protocol-specific actions, see [routing.md](routing.md#protocol-specific-routing); for the field table in the general configuration reference, see [configuration.md#websocket](configuration.md#websocket).

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
| `subprotocols` | list of string | `[]` | Allowlist for `Sec-WebSocket-Protocol` negotiation. Empty (the default) leaves negotiation entirely to the client and upstream. See [Subprotocol negotiation](#subprotocol-negotiation). |
| `max_message_size` | int | `10485760` (10 MB) | Maximum message payload size in bytes, enforced in both directions on the upgraded tunnel. A message that declares more payload than this closes the connection. See [Message size enforcement](#message-size-enforcement). |
| `host_override` | string | upstream URL's host | `Host` header sent on the upgrade request. Set this when the upstream is vhost-based and expects a different value than the URL's own hostname. |

`host_override` and the standard forwarding-header opt-outs (`disable_forwarded_for_header`, and so on) work the same way here as on every other URL-bearing action: `proxy`, `load_balancer` targets, `grpc`, `graphql`, and `a2a` all accept the same fields with the same meaning.

## Upgrade semantics

Requests to a `websocket` origin are not required to carry `Upgrade: websocket`. The action is a routing choice, "proxy this Host to a `ws://`/`wss://` target", not a protocol gate. A plain HTTP request to the same origin is proxied unchanged to the same upstream address; whatever that upstream does with a non-upgrade request (typically its own `400`, since a real WebSocket server usually only implements the handshake) is what the client sees. sbproxy does not reject a non-upgrade request on the client's behalf or otherwise treat it specially before handing it to the upstream connection; the subprotocol allowlist below applies only to requests that do ask for an upgrade.

When the client does send a proper upgrade request and the upstream answers `101 Switching Protocols`, Pingora forwards bytes in both directions for the lifetime of the connection, with one gateway-side reader on the pipe: a frame-header scanner enforcing `max_message_size` (described below). sbproxy is not a party to the WebSocket handshake computation (`Sec-WebSocket-Accept` derived from `Sec-WebSocket-Key`); that is entirely the upstream's responsibility, forwarded through unchanged.

## What runs before the upgrade

Everything that would run for a `proxy` action against the same origin runs here too, against the initial `GET` request and its headers:

- Host-based origin routing
- `authentication` (bearer, API key, JWT, basic, mTLS, OIDC, forward auth, whatever the origin configures)
- `policies` (rate limiting, WAF, CEL, and the rest)
- Request transforms and forward rules

These are the same pipeline stages every origin runs, applied here to a request that happens to be asking for an upgrade. A request that fails one of them (missing auth token, rate limit exceeded, WAF match) never reaches the point where the gateway would attempt the upgrade. A runnable demonstration of an auth gate rejecting the upgrade, and passing it once a valid token is presented, is in [`examples/websocket-proxy/`](../examples/websocket-proxy/).

## Message size enforcement

`max_message_size` bounds the payload of a single WebSocket message, in both directions, on every upgraded connection through this action. The gateway parses frame headers on the tunnel (it never buffers or reads payload bytes) and sums the declared payload lengths of a fragmented message across its continuation frames. The moment a message's total crosses the cap, before the payload has even finished arriving, the gateway logs the violation and closes the connection.

Points worth knowing before relying on it:

- **The teardown is abrupt.** There is no `1009 Message Too Big` close handshake; the gateway will not forward a message it has refused, so both TCP connections are dropped. Clients see the socket die mid-message.
- **The cap measures wire bytes.** If the client and upstream negotiate `permessage-deflate`, payload lengths on the wire are compressed sizes, and the cap applies to those.
- **Control frames do not count toward a message, and are bounded on their own.** Pings, pongs, and closes interleave freely without affecting the running message total. The gateway holds them to RFC 6455 section 5.5 itself: a control frame declaring more than 125 payload bytes, or arriving without `FIN`, closes the connection. It has to check rather than assume, because a control frame's declared length is skipped rather than accumulated, so an unchecked one would both reach the upstream and desynchronize the gateway's own scanner for the life of the tunnel.
- **The default is enforced too.** An action that never mentions `max_message_size` gets the documented 10 MB ceiling.
- **Every upgraded tunnel is scanned, not just this action's.** A `101` on any origin whose request asked for a WebSocket upgrade gets the frame scanner, including `/v1/realtime` under an `ai_proxy` origin and a `type: proxy` or `type: load_balancer` origin fronting a WebSocket backend. Only a `websocket` action configures the cap, so every other action's tunnel is held to the same 10 MB default. A `101` for some other protocol upgrade is left alone: those bytes are not RFC 6455 frames.

## Subprotocol negotiation

An empty `subprotocols` list (the default) means the gateway stays out of negotiation entirely: whatever `Sec-WebSocket-Protocol` the client and upstream agree on passes through untouched.

A non-empty list is an allowlist, enforced at three points:

1. **The offer is filtered.** The client's `Sec-WebSocket-Protocol` offer is intersected with the configured list, preserving the client's preference order, before the upgrade request goes upstream. The upstream never sees a subprotocol the origin does not allow.
2. **An unservable offer is refused.** A client whose offer contains none of the configured subprotocols gets a `400` before any upstream connection is attempted. A client that offers nothing at all still passes; the allowlist constrains what gets negotiated, it does not require negotiation.
3. **The upstream's selection is checked.** The subprotocol named on the upstream's `101` must be a single token that the client offered and the list allows. Anything else refuses the upgrade with a `502`, since a selection outside the offer is the upstream violating RFC 6455 negotiation.

The gateway never adds subprotocols the client did not offer, and it does not require the upstream to select one.

## Honest limits

Beyond the message-size cap, the control-frame checks, and the subprotocol allowlist, post-upgrade traffic gets no per-frame inspection: no PII redaction, no payload-shape validation, no per-message rate limiting, nothing that reads or acts on frame *content*. The scanner reads frame headers only. If you need content-level control over what flows after the upgrade, that has to live in the WebSocket backend itself; the gateway's contribution stops at the pre-upgrade pipeline plus the enforcement points described above.

One more limit worth naming: an upgraded tunnel that is not a `websocket` action's has no config key of its own for the cap. `/v1/realtime` and a proxied upgrade are scanned, and both are held to the 10 MB default; there is nowhere to raise or lower it for them today.

## Runnable example

[`examples/websocket-proxy/`](../examples/websocket-proxy/) has the handshake demonstrated end to end (a stdlib Python WebSocket client, since curl cannot speak WebSocket framing after the `101`), the auth gate rejecting an unauthorized upgrade, the failure mode for a non-upgrade request landing on a `websocket` origin, and a live check that `max_message_size` closes the connection on an oversized message.

```bash
python3 examples/websocket-proxy/fixture.py &
sbproxy serve -f examples/websocket-proxy/sb.yml
python3 examples/websocket-proxy/client.py "hello through the gateway"
```

## See also

- [routing.md#protocol-specific-routing](routing.md#protocol-specific-routing) - `websocket` alongside `grpc` and `graphql`
- [configuration.md#websocket](configuration.md#websocket) - field table in the general configuration reference
- The action implementation at `crates/sbproxy-modules/src/action/websocket.rs`
