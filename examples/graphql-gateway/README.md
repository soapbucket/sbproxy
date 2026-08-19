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

Everything below this line is a refusal. **This is the one step in this walkthrough that needs the fixture up**; the refusals below are all gateway-side and come back the same with the fixture stopped, as the section at the end explains.

**Malformed syntax.** An unclosed selection set fails to parse.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"query":"{ viewer { login "}' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"detail":"invalid GraphQL query: query parse error: Parse error at 1:18\nUnexpected end of input\nExpected }\n","error":"GraphQL request validation failed"}
```

**Introspection disabled.** `allow_introspection: false` rejects a `__schema` selection, including nested or aliased ones.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"query":"{ __schema { types { name } } }"}' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"detail":"GraphQL introspection is disabled","error":"GraphQL request validation failed"}
```

**Depth exceeded.** `max_depth: 5` on a query that nests six levels deep.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"query":"{ a { b { c { d { e { f } } } } } }"}' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"detail":"GraphQL query depth 6 exceeds configured maximum 5","error":"GraphQL request validation failed"}
```

**Batch rejected.** A batched POST body is a JSON array of query envelopes. One bad entry fails the whole batch; nothing partially executes.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '[{"query":"{ viewer { login } }"},{"notquery":"oops"}]' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"detail":"GraphQL batch entry 1: JSON body must contain a string query field","error":"GraphQL request validation failed"}
```

**Persisted-query-only envelope refused.** Apollo-style automatic persisted queries send `extensions.persistedQuery` with no `query` field on the wire, expecting the server to resolve the hash server-side. Validation here works against the literal request body, so a persisted-query-only envelope has no `query` string to check and is refused the same way a missing field would be anywhere else in this action. Send the full query text on first use (most persisted-query clients do this automatically) if you turn any validation control on.

```bash
$ curl -i -H 'Host: graphql.local' -H 'Content-Type: application/json' \
    -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}' \
    http://127.0.0.1:8080/graphql
HTTP/1.1 400 Bad Request
content-type: application/json

{"detail":"JSON body must contain a string query field","error":"GraphQL request validation failed"}
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

That one comes back as a bare `413`, not the `{"detail":...,"error":"GraphQL request validation failed"}` shape the others use, because it is caught earlier, before a route or upstream is even resolved.

## Which refusals need the fixture running

None of them. Every refusal in this walkthrough is gateway-side:

- **Oversized body → 413**: enforced in the same phase that first sees the request, before routing or any upstream connection attempt.
- **Malformed syntax, introspection, depth, batch, and persisted-query refusals → 400**: this config has no `request_modifiers`, so the inbound request is already the final request and the gateway validates it in the request phase, before any connect. Stop `fixture.py` and each refusal still comes back exactly as shown above; only a query that *passes* validation then needs the fixture, and gets a `502 Bad Gateway` connect failure without it.

One caveat worth knowing when you add `request_modifiers` to a validated `graphql` origin: the document a modifier produces is the one the contract holds, so validation moves to the post-modifier seam, which runs on an established upstream connection. On such a route, an invalid query against a down upstream surfaces as the connect failure's `502` instead of the `400`.

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
