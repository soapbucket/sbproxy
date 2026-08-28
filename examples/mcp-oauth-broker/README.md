# MCP OAuth 2.1 broker and resource server

> **Partially runnable.** The upstream authorization server
> (`idp.example.com`) and the federated MCP server (`test.sbproxy.dev`) are
> RFC 2606 reserved placeholders, so the PKCE round trip and `tools/call`
> cannot complete against them. Everything the gateway serves itself works
> as shipped: the two well-known documents, the JWKS, and the 401 challenge
> on an unauthenticated MCP request. Point the four `upstream_*` URLs at a
> real authorization server to complete the flow.

Runs the OAuth broker and the token verifier in one sbproxy process. The
broker owns the PKCE flow against an upstream authorization server and
mints its own RFC 9068 access tokens; the verifier checks those tokens on
every MCP request, before the catalog, the request body, or any upstream
federation.

Run it:

```bash
export MCP_BROKER_SIGNING_KEY_PEM="$(cat broker-signing-key.pem)"
sbproxy serve -f sb.yml
```

Generate a throwaway key for the variable with:

```bash
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out broker-signing-key.pem
```

The `public_jwk` block in `sb.yml` carries a placeholder public half. Swap
in the `x` and `y` of the key you just generated, or the broker's JWKS will
publish a key that does not match what it signs with and every verifier
will reject every token.

What proves it is working:

- `GET /mcp/oauth/.well-known/oauth-authorization-server` returns RFC 8414
  metadata whose `issuer` is `https://mcp.example.com/mcp/oauth` and whose
  `jwks_uri` is the route below.
- `GET /mcp/oauth/.well-known/jwks.json` returns a non-empty `keys` array
  carrying `kid: broker-2026-08`. An empty array means `public_jwk` is
  missing, and startup refuses that combination rather than serving it.
- A `tools/call` with no `Authorization` header returns `401` with a
  `WWW-Authenticate` challenge, and increments
  `sbproxy_mcp_gateway_decisions_total{surface="resource_server",decision="unauthenticated"}`.
- A token carrying only `mcp.read` gets a JSON-RPC `invalid_params` on
  `tools/call` naming `mcp.call`, and increments the same family at
  `surface="scope",decision="refused"`.

What this example does not show:

- **Multiple replicas.** The colocated broker holds sessions, device codes,
  and PAR entries in the process that started them, and `oauth.broker` has
  no key to point them at a shared store. Run this form on one replica; see
  [`docs/mcp-oauth-gateway.md`](../../docs/mcp-oauth-gateway.md) for the
  standalone embedding that takes a Redis-backed store.
- **The device-code consent page.** `device_code_enabled` is off here. Turn
  it on and read the consent-page contract in
  [`docs/mcp-oauth-gateway.md`](../../docs/mcp-oauth-gateway.md) first: the
  POST needs a same-origin `Origin` and the single-use `form_token` the GET
  renders, and your session cookie has to be `SameSite=Lax` or stricter.

See [`docs/mcp.md`](../../docs/mcp.md) for the config reference and
[`examples/mcp-oauth-discovery`](../mcp-oauth-discovery/) for the
discovery-only shape with no broker.
