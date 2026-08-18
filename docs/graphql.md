# graphql action
*Last modified: 2026-08-18*

The `graphql` action proxies GraphQL-over-HTTP requests to a single upstream endpoint. With every field at its default it is a transparent proxy: it never parses the request, and anything the client sends reaches the upstream unchanged. Turning on any validation control flips it into fail-closed parsing with a real GraphQL grammar, and this page covers exactly what that buys, where in the pipeline it runs, and the limits that follow from where it runs. For the action's place among the other protocol-specific actions, see [routing.md](routing.md#protocol-specific-routing); for the field table in the general reference, see [configuration.md#graphql](configuration.md#graphql).

## Config

```yaml
origins:
  "graphql.example.com":
    action:
      type: graphql
      url: https://graphql-backend.internal/graphql
      max_depth: 10
      allow_introspection: false
      validate_queries: true
```

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | required | Backend GraphQL endpoint URL (`http://` or `https://`). |
| `max_depth` | int | `0` | Maximum field nesting depth, counted after named-fragment expansion. `0` means unlimited. |
| `allow_introspection` | bool | `true` | When `false`, any operation selecting `__schema` or `__type` is rejected, including nested, aliased, and fragment-carried selections. |
| `validate_queries` | bool | `false` | Parse GraphQL document syntax before proxying. Syntax only; this is not schema-aware validation. |
| `host_override` | string | upstream URL's host | `Host` header sent to the upstream. |

`host_override` and the standard forwarding-header opt-outs work the same way here as on every other URL-bearing action (`proxy`, `websocket`, `grpc`, `a2a`).

Setting any one of `validate_queries: true`, `max_depth` above zero, or `allow_introspection: false` enables parsing. The three compose: one parse of the document feeds all three checks, so there is no cost to enabling them together.

## What validation enforces

On a validated origin, the gateway parses the query with a GraphQL grammar and refuses what it cannot accept with a `400` and a JSON body naming the reason (`{"error": "GraphQL request validation failed", "detail": ...}`):

- Unparseable document syntax.
- Duplicate fragment definitions, and duplicate keys inside the JSON request envelope.
- `__schema` / `__type` selections when `allow_introspection: false`, wherever they hide: nested fields, aliases, inline fragments, and fragment definitions.
- Nesting past `max_depth`, measured with named fragments expanded, so a fragment cannot smuggle depth past the counter.
- Request shapes outside the GraphQL-over-HTTP contract: a validated request must be a `GET` with exactly one percent-encoded `query` parameter and no body, or a `POST` with `Content-Type: application/json` carrying an object or a batch array. Every batch entry needs a string `query` field, and the whole batch is refused when any entry fails. Any other method is refused.
- Persisted-query-only envelopes (Apollo-style `extensions.persistedQuery` with no `query` on the wire). Validation works against the literal request body, so there is no query text to check; clients that send the full text on first use work unchanged.

When the document passes, the exact validated bytes are forwarded, so the upstream serves what the gateway checked.

## Where validation runs, and the two consequences

Validation runs late, after every request modifier has produced the final outbound method, URI, headers, and body. That placement is deliberate: validating the inbound bytes and then letting a modifier rewrite them would let a benign document pass and a forbidden one ship. It has two visible consequences.

**Bodies are capped at 64 KiB.** A validated body has to be buffered and replayed byte-for-byte to the upstream after the check, and the replay buffer is a fixed 64 KiB. A larger body is refused with a bare `413` (`validated GraphQL request body exceeds the 64 KiB replay limit`) before it is parsed, before a route is even resolved. This is the one refusal that is fully independent of the upstream.

**An unreachable upstream answers `502`, not `400`.** The parse runs in the phase that builds the upstream request, which only exists once the upstream connection has been established. If the upstream is down, the connect failure wins and the client sees `502 Bad Gateway`; the validation code never runs for that request. Do not read a `502` on a malformed query as validation being off: with the upstream healthy, the same query gets its `400`. [`examples/graphql-gateway/`](../examples/graphql-gateway/) demonstrates both sides of this with a stopped and a running fixture.

## Honest limits

- **Syntax, not schema.** The gateway does not load your schema, so it cannot reject a query naming fields that do not exist, check argument types, or compute field-level cost. Depth and introspection are structural properties of the document; everything schema-aware stays at the GraphQL server.
- **No response inspection.** The action never parses what comes back: errors, partial data, and anything else the upstream returns pass through it unexamined. Ordinary response transforms and policies configured on the origin still apply; they just are not GraphQL-aware.
- **Subscriptions are out of scope.** This action speaks GraphQL over HTTP (`GET`/`POST`). GraphQL over WebSocket (`graphql-ws` and friends) can be tunneled with a [`websocket` action](websocket.md), which forwards frames transparently with no GraphQL-level inspection.
- **Multipart is refused on validated origins.** A validated `POST` must be `application/json`; the multipart file-upload convention is not a validated transport. Under the default transparent configuration it passes through unchanged.

## Runnable example

[`examples/graphql-gateway/`](../examples/graphql-gateway/) runs the whole surface against a stdlib Python fixture: a passing query, then every refusal (syntax, introspection, depth, batch, persisted-query, oversized body), each with its exact response captured, plus the section on which refusals need the fixture running and why.

```bash
python3 examples/graphql-gateway/fixture.py &
sbproxy serve -f examples/graphql-gateway/sb.yml
curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"query":"{ __schema { types { name } } }"}' \
    http://127.0.0.1:8080/graphql
# HTTP/1.1 400 Bad Request ... "GraphQL introspection is disabled"
```

## See also

- [configuration.md#graphql](configuration.md#graphql) - the field table in the general reference.
- [routing.md#protocol-specific-routing](routing.md#protocol-specific-routing) - `graphql` among the other protocol actions.
- The action implementation at `crates/sbproxy-modules/src/action/graphql.rs`; the validation call sites in `crates/sbproxy-core/src/server/action_dispatch.rs` and `proxy_http.rs`.
