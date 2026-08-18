# GraphQL gateway with fail-closed validation

*Last modified: 2026-08-18*

The `graphql` action proxies to a single GraphQL HTTP endpoint. With every field at its default it stays a transparent proxy and never parses the request body. Setting `validate_queries: true`, `max_depth` above zero, or `allow_introspection: false` (this example sets all three) turns on fail-closed parsing: the gateway parses the query with a real GraphQL grammar and rejects what it does not like with a `400` before the request reaches the upstream. Introspection selections (`__schema`, `__type`), nesting past the configured depth, unparseable syntax, malformed batches, and oversized bodies all get refused this way, on POST bodies and the `GET`-with-`query`-parameter form alike.

No live public GraphQL endpoint ships with this repo, so `fixture.py` stands in for one: a stdlib-only HTTP server that answers every request with a fixed GraphQL-shaped JSON body. It exists only to give the passing-query step something real to return; the module's own parsing (this example's actual subject) runs entirely inside sbproxy, before the fixture ever sees a byte.

## Run

```bash
python3 fixture.py &
sbproxy serve -f sb.yml
```

## Try it

**A query that passes.** Small, no introspection, within the depth limit. Reaches the fixture and gets a real response back.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"query":"{ viewer { login } }"}' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 200 OK
content-type: application/json

{"data": {"viewer": {"login": "octoproxy", "receivedQueryBytes": 20}}}
```

Everything below this line is a refusal. **This is the one step in this walkthrough that needs the fixture up for its passing outcome**; the refusals below are all gateway-side, but as the section at the end explains, most of them still need the fixture reachable to return their documented status instead of a connect failure.

**Malformed syntax.** An unclosed selection set fails to parse.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"query":"{ viewer { login "}' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"error":"GraphQL request validation failed","detail":"invalid GraphQL query: query parse error: Parse error at 1:18\nUnexpected end of input\nExpected }\n"}
```

**Introspection disabled.** `allow_introspection: false` rejects a `__schema` selection, including nested or aliased ones.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"query":"{ __schema { types { name } } }"}' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"error":"GraphQL request validation failed","detail":"GraphQL introspection is disabled"}
```

**Depth exceeded.** `max_depth: 5` on a query that nests six levels deep.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"query":"{ a { b { c { d { e { f } } } } } }"}' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"error":"GraphQL request validation failed","detail":"GraphQL query depth 6 exceeds configured maximum 5"}
```

**Batch rejected.** A batched POST body is a JSON array of query envelopes. One bad entry fails the whole batch; nothing partially executes.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '[{"query":"{ viewer { login } }"},{"notquery":"oops"}]' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"error":"GraphQL request validation failed","detail":"GraphQL batch entry 1: JSON body must contain a string query field"}
```

**Persisted-query-only envelope refused.** Apollo-style automatic persisted queries send `extensions.persistedQuery` with no `query` field on the wire, expecting the server to resolve the hash server-side. Validation here works against the literal request body, so a persisted-query-only envelope has no `query` string to check and is refused the same way a missing field would be anywhere else in this action. Send the full query text on first use (most persisted-query clients do this automatically) if you turn any validation control on.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"error":"GraphQL request validation failed","detail":"JSON body must contain a string query field"}
```

**Oversized body.** A validated request has to be replayed byte-for-byte to the upstream after validation, and the replay buffer is a fixed 64 KiB. A body over that limit is rejected before it is even parsed.

```bash
$ python3 -c "import json; print(json.dumps({'query': '{ viewer { login } } # ' + 'x'*70000}))" > big_query.json
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    --data-binary @big_query.json \
    http://127.0.0.1:8080/graphql
HTTP/1.1 413 Payload Too Large
content-type: application/json

{"error":"validated GraphQL request body exceeds the 64 KiB replay limit"}
```

That one comes back as a bare `413`, not the `{"error":"GraphQL request validation failed",...}` shape the others use, because it is caught earlier, before a route or upstream is even resolved.

## Which refusals need the fixture running

This is the one genuinely non-obvious part of how this action is wired, so it is worth being precise about it instead of waving at "validation happens gateway-side."

- **Oversized body → 413**: fully gateway-side. It is enforced in the same phase that first sees the request, before routing or any upstream connection attempt. Stop `fixture.py` and this refusal still returns `413` unchanged.
- **Malformed syntax, introspection, depth, batch, and persisted-query refusals → 400**: the parsing that produces these runs *after* the proxy has already picked an upstream and opened a connection to it, so it can validate the exact request a modifier chain would have sent. If `fixture.py` is not running, the same malformed query gets a `502 Bad Gateway` (a connect failure) instead of the `400` shown above, because the connection attempt fails before validation code ever runs. Keep the fixture up for every refusal case in this walkthrough except the oversized-body one, or you will see a `502` and wrongly conclude the refusal itself changed.

Both follow from "validate after modifiers, forward byte-for-byte": the proxy needs a resolved upstream connection before it can hand `upstream_request_filter` a fully-built outbound request to validate against, so that connection has to succeed first.

## What this exercises

- `graphql` action - proxy GraphQL requests to an upstream HTTP endpoint
- `validate_queries: true` - parse GraphQL syntax before proxying (not schema-aware)
- `max_depth` - reject queries nested past a configured field depth, following named-fragment expansion
- `allow_introspection: false` - reject `__schema`/`__type` selections, including nested and aliased ones
- Batch request validation - a JSON array of query envelopes, rejected as a whole when any entry fails
- The 64 KiB validated-body replay limit and its `413`
- Fail-closed parsing versus the default transparent-proxy behavior when every field is left unset

## See also

- [docs/configuration.md#graphql](../../docs/configuration.md#graphql) - full field reference
- [docs/routing.md#protocol-specific-routing](../../docs/routing.md#protocol-specific-routing) - where `graphql` sits among the other protocol actions
- The action implementation at `crates/sbproxy-modules/src/action/graphql.rs`
- The validation call site at `crates/sbproxy-core/src/server/action_dispatch.rs` and `crates/sbproxy-core/src/server/proxy_http.rs`
