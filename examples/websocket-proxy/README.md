# WebSocket proxy with an auth gate on the upgrade

*Last modified: 2026-08-20*

The `websocket` action proxies `ws://`/`wss://` upstreams. The HTTP `Upgrade` request runs through the same auth, policy, and transform pipeline as any other origin, and once the upstream answers `101 Switching Protocols` the connection becomes a byte pipe in both directions, with frame headers (never payloads) scanned to enforce `max_message_size`. This example puts `bearer` auth on the origin to make the pre-upgrade pipeline concrete: a request without a valid token is rejected before the upgrade completes, and the WebSocket backend never sees it. It also demonstrates the message-size cap closing a connection.

No live public WebSocket endpoint ships with this repo, so `fixture.py` stands in for one: a stdlib-only server that speaks just enough of RFC 6455 to complete the handshake and echo text frames back with `echo: ` prepended.

## Run

```bash
python3 fixture.py &
sbproxy serve -f sb.yml
```

## Try it

**Handshake without a token.** Auth runs before the action does anything WebSocket-specific, so a missing token never reaches the upgrade logic at all.

```bash
$ curl -i -H 'Host: ws.local' \
    -H 'Upgrade: websocket' -H 'Connection: Upgrade' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    -H 'Sec-WebSocket-Version: 13' \
    http://127.0.0.1:8080/
HTTP/1.1 401 Unauthorized
content-type: application/json

{"error":"unauthorized"}
```

**Handshake with a valid token.** `curl --include` shows the `101` and the response headers, then the process hangs: past this point the connection is an open byte pipe, not a request/response exchange, and curl does not speak WebSocket framing. That hang is expected and is itself evidence the tunnel opened; kill it with Ctrl-C or `--max-time`.

```bash
$ curl -i --max-time 2 -H 'Host: ws.local' \
    -H 'Authorization: Bearer svc-token-alpha' \
    -H 'Upgrade: websocket' -H 'Connection: Upgrade' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    -H 'Sec-WebSocket-Version: 13' \
    http://127.0.0.1:8080/
HTTP/1.1 101 Switching Protocols
upgrade: websocket
connection: Upgrade
sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

`sec-websocket-accept` is `base64(sha1(client_key + the RFC 6455 GUID))`, computed by the upstream fixture and forwarded unchanged; the gateway never touches its bytes. The client key above is RFC 6455's own worked example, so this value is one you can hand-verify.

**A real message exchange.** `client.py` is a stdlib-only WebSocket client: it does the handshake, sends one text frame through the gateway, and prints what comes back.

```bash
$ python3 client.py "hello through the gateway"
HTTP/1.1 101 Switching Protocols
upgrade: websocket
connection: Upgrade
sec-websocket-accept: RpYwXFOSo+qTPj4Aqv2yMP+gr0M=

received: echo: hello through the gateway
```

`python3 client.py "hi" --no-token` reproduces the 401 above end to end, including the frame layer never getting used.

**Oversized frame: `max_message_size` closes the connection.** This origin sets `max_message_size: 65536`. Send an 80,000-byte text frame and the gateway refuses it on the frame header, before the payload has even finished arriving: the declared length is over the cap, so the tunnel is torn down and the frame never reaches the fixture.

```bash
$ python3 client.py "$(python3 -c "print('x' * 80000, end='')")" | tail -1
connection closed by the gateway (no frame received)
```

The teardown is abrupt by design. There is no `1009 Message Too Big` close handshake, because the gateway will not forward a message it has refused; the client sees the socket die. The same cap applies to what the upstream sends back: a fixture echo larger than the cap closes the connection in the other direction (which here means a payload within about six bytes of the cap survives the trip in but not the echo out, since the fixture's `echo: ` prefix grows the return message). A comfortably conforming message still round-trips: try `python3 client.py "$(python3 -c "print('x' * 65000, end='')")"` and see the summary line `client.py` prints for anything over 200 bytes received.

**Watch the enforcement land: the counter and the audit record.** The teardown above is more than a dead socket. `sb.yml` opens a metrics-only admin surface on `:9091` and points a file `events:` sink at `websocket-proxy-events.ndjson` (written wherever the proxy was started), selecting `policy_denied`. A websocket enforcement verdict is the proxy refusing traffic on a rule, so it writes the same policy-violation audit record every other refusal writes, and that record bridges onto the event feed as `policy_denied`. After tripping the cap once:

```bash
$ curl -s -u admin:changeme http://127.0.0.1:9091/metrics | grep sbproxy_websocket_teardowns_total
# HELP sbproxy_websocket_teardowns_total WebSocket upgrades refused or tunnels torn down by the gateway, by closed reason, direction, tenant, and origin
# TYPE sbproxy_websocket_teardowns_total counter
sbproxy_websocket_teardowns_total{direction="client_to_upstream",origin="ws.local",reason="message_too_large",tenant="__default__"} 1
```

```bash
$ tail -1 websocket-proxy-events.ndjson | python3 -m json.tool
{
    "event_type": "policy_denied",
    "hostname": "ws.local",
    "tenant_id": "__default__",
    "timestamp": 1787255910424,
    "data": {
        "client_ip": "127.0.0.1",
        "event_type": "websocket_message_too_large",
        "hostname": "ws.local",
        "key_mode": "none",
        "method": "GET",
        "reason": "websocket message exceeds max_message_size: direction=client_to_upstream, observed=80000, limit=65536",
        "request_id": "01a020c0f013760185bdce7068f0d41e",
        "status_code": 0,
        "tenant_id": "__default__",
        "timestamp": "2026-08-20T19:58:30.424050+00:00"
    }
}
```

The outer `event_type` is the feed's routing label; the inner one is the specific verdict, which is what a SIEM rule selects on. `observed` and `limit` are byte counts read from frame headers, so no payload byte is ever captured and the record is safe to ship to a third-party webhook sink. `status_code` is `0` because a torn-down tunnel receives no HTTP status and the record does not invent one. The same record also lands on the `security_audit` log target and, under `audit.sink: chain`, in the hash-chained tamper-evident file.

**Mid-tunnel: the upstream dies after the upgrade.** Once the `101` is on the wire the client is reading WebSocket frames, so an HTTP error body written into that stream would arrive as garbage spliced between frames. Two shapes of death, and they are worth telling apart. A backend that closes cleanly (`fixture.py` killed with a signal, so the kernel sends a FIN) just ends the tunnel: no error, no counter, nothing to alert on, which is correct because nothing went wrong. A backend that *resets* the connection instead, which is what a crashed worker, an OOM kill, or a load balancer yanking the socket looks like, surfaces inside the proxy as an upstream read error while the client side is already a frame stream. That is the case worth watching, and the gateway drops both connections without writing a byte:

```
WARN sbproxy_core::server::proxy_http: mid-tunnel error on an upgraded websocket; closing
  without writing HTTP bytes hostname=ws.local error=Upstream ReadError [...] cause:
  Connection reset by peer (os error 54) mapped_status=502 error_token="connection_terminated"
```

```bash
$ curl -s -u admin:changeme http://127.0.0.1:9091/metrics | grep 'reason="upstream_error"'
sbproxy_websocket_teardowns_total{direction="none",origin="ws.local",reason="upstream_error",tenant="__default__"} 1
```

The `mapped_status` and `error_token` in that line are the same classification the `Proxy-Status` header carries on an ordinary HTTP request, so the failure mode is not lost just because nothing could be written. There is deliberately no `policy_denied` record for this one: a transport failure is not an enforcement verdict, it already reaches the SIEM as a `request_error`, and filing it beside the violations would poison any alert built on them.

The counter's third reason, `subprotocol_violation`, fires when an upstream selects a subprotocol outside a configured `subprotocols` allowlist; that refusal happens before the tunnel opens, so it renders an ordinary `502` and its record carries `status_code: 502`. One thing worth alerting on across all three: `sum by (reason, origin) (rate(sbproxy_websocket_teardowns_total[5m]))`.

**Failure mode: a non-upgrade request to a `websocket` origin.** The action does not check whether the request carries `Upgrade: websocket` before deciding where to send it. `type: websocket` just means "proxy this Host to a `ws://`/`wss://` target." A plain GET with a valid token still passes auth and gets proxied to the same upstream, byte for byte, as a normal HTTP request:

```bash
$ curl -i -H 'Host: ws.local' -H 'Authorization: Bearer svc-token-alpha' \
    http://127.0.0.1:8080/
HTTP/1.1 400 Bad Request
content-type: text/plain

this fixture only speaks the WebSocket upgrade handshake
```

That `400` is `fixture.py`'s own response, not the gateway's. A real WebSocket server would answer a non-upgrade HTTP request however it chooses, the same as any other HTTP server would; sbproxy does not intercept, validate, or reject the request on the client's behalf just because the origin is configured as `type: websocket`.

## What the gateway enforces before the upgrade, and what it does not enforce after

**Before the upgrade completes**, a `websocket` origin gets the same treatment as any other origin: hostname routing, `authentication`, `policies`, and request transforms all run against the initial `GET` request and its headers, exactly as they would for a `proxy` action. The auth gate demonstrated above is one instance of that; rate limiting, WAF, CEL policies, and anything else attachable to an origin apply the same way.

**After the `101` response**, the connection is a byte pipe with exactly one gateway-side reader on it: a frame-header scanner enforcing `max_message_size` in both directions, demonstrated above. Two fields on this action shape what the tunnel allows:

- `max_message_size` (this example sets `65536`) bounds a message's payload, summed across continuation fragments, in either direction. A message declaring more closes the connection without a WebSocket close handshake. The cap measures wire bytes, so with `permessage-deflate` negotiated it applies to compressed sizes.
- `subprotocols`, when non-empty, is an allowlist for `Sec-WebSocket-Protocol` negotiation: the client's offer is filtered to it before going upstream, an offer with no allowed entry is refused with a `400` before any upstream connection, and an upstream selecting outside the negotiated set is refused with a `502`. This example leaves it empty, which means negotiation passes through untouched.

Anything content-level after the handshake, policy enforcement, PII redaction, payload inspection, per-message rate limiting, is out of scope for this action today; the scanner reads frame headers, never payloads. If you need control over frame content after the upgrade, that has to live in the WebSocket backend itself.

## What this exercises

- `websocket` action - proxy an HTTP `Upgrade` request and the connection it opens to a `ws://`/`wss://` upstream
- `authentication: bearer` applied to a `websocket` origin - proof that origin-level policy runs before the upgrade, not after
- The RFC 6455 handshake computation (`Sec-WebSocket-Key` → `Sec-WebSocket-Accept`)
- `max_message_size` enforcement on the upgraded tunnel: an oversized message closes the connection instead of passing through
- The enforcement telemetry: `sbproxy_websocket_teardowns_total` on the admin metrics endpoint and the policy-violation audit record on a file `events:` sink, plus the mid-tunnel teardown that writes no HTTP bytes at all

## See also

- [docs/websocket.md](../../docs/websocket.md) - the dedicated reference for this action: field table, upgrade semantics, message-size enforcement, subprotocol negotiation, and the enforcement telemetry
- [docs/events.md](../../docs/events.md) - the audit channels this record travels on, the `policy_denied` bridge, and how to point the sink at a webhook instead of a file
- [docs/configuration.md#websocket](../../docs/configuration.md#websocket) - field reference in the general configuration guide
- [docs/routing.md#protocol-specific-routing](../../docs/routing.md#protocol-specific-routing) - where `websocket` sits among the other protocol actions
- The action implementation at `crates/sbproxy-modules/src/action/websocket.rs`
