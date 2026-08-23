# MCP OAuth gateway
*Last modified: 2026-08-22*

`sbproxy-mcp-gateway` provides the OAuth 2.1 broker and protected-resource
authentication used by the live `action: {type: mcp}` request path. The
same crate also exposes an axum router and resource-server provider for
standalone MCP deployments. See [mcp.md](mcp.md)'s "OAuth auth discovery
(RFC 9728)" section for the integrated configuration.

## What it implements

An axum router covering the OAuth 2.1 broker side of the MCP
Authorization spec:

- `/authorize`, `/callback`, `/token`, `/register`: the PKCE
  authorization-code flow plus RFC 7591 dynamic client registration.
- `/device_authorization`, `/verify`: RFC 8628 device-code grant for
  headless clients (CLI tools, SSH-only hosts).
- `/par`: RFC 9126 Pushed Authorization Requests.
- `/revoke`, `/introspect`: RFC 7009 / RFC 7662, proxied to the
  upstream Authorization Server.
- `/.well-known/oauth-authorization-server`, `/.well-known/jwks.json`:
  RFC 8414 discovery and the broker's own signing keys, when
  configured.
- RFC 9449 DPoP proof verification, RFC 8705 mTLS-bound tokens, RFC
  8707 resource indicators, RFC 8693 token exchange, and Client ID
  Metadata Documents (the `parecki` CIMD draft) for clients that are
  themselves an `https://` URL rather than a pre-registered string.

The broker never validates a caller's credentials itself in the sense
of being the identity source: it sits in front of a real upstream
Authorization Server (Okta, Auth0, Keycloak, your own IdP) and adds the
PKCE/DPoP/CIMD/DCR machinery that server may not speak natively, while
keeping the client's original `state` and the upstream's session
completely separate (the broker mints its own opaque `state` for the
upstream hop, so a leaked upstream `state` cannot be replayed against
the client-facing side).

## Storage: in-process by default, Redis for multiple replicas

Every piece of state this crate holds (PKCE-adjacent session rows,
DPoP replay jtis, device codes, PAR entries, the CIMD → DCR translation
cache) is written against `sbproxy_storage::EphemeralKv` /
`PersistentKv`. A single-replica deployment needs nothing external:
`LocalStore` (this crate) is the bounded in-process default and expires
unrelated stale entries during normal reads and writes. Point multiple
replicas at the same session state by constructing
`sbproxy_storage::RedisStore` instead and passing it to the same
constructors; nothing else in the broker's wiring changes. DPoP replay
protection is atomic for callers sharing one in-process cache. A
multi-replica store must provide an atomic consume-or-insert operation
before it can give the same cross-replica guarantee.

## Quickstart

```bash
CARGO_TARGET_DIR=target-infra-cluster \
  MCP_GATEWAY_BASE_URL=http://127.0.0.1:8089 \
  cargo run -p sbproxy-mcp-gateway --example standalone_broker
```

This starts two routers: the broker on `:8089` and a small
resource-server demo on `:8090`. See
[`examples/standalone_broker.rs`](../crates/sbproxy-mcp-gateway/examples/standalone_broker.rs)
for the full source; the interesting part is short:

```rust
let app = router_full_with_par(
    config,
    session_store,
    None,               // as_metadata: upstream AS metadata cache
    Some(cimd_cache),
    None,               // cimd_to_dcr: only needed for upstreams that lack CIMD support
    Some(dpop_replay),
    Some(dpop_nonce),
    Some(device_code_store),
    Some(par_store),
);
```

The plain `router(config, session_store)` constructor wires bounded
in-process collaborators for the features enabled by the config.
`router_full_with_par` remains available when a deployment supplies
shared or custom stores. A minimal config includes the broker's public
origin and its registered upstream callback:

```rust
McpGatewayConfig {
    base_path: "/mcp/oauth".to_string(),
    external_base_url: "https://mcp.example.com".to_string(),
    upstream_redirect_uri: "https://mcp.example.com/mcp/oauth/callback".to_string(),
    upstream_authorization_server_url: "https://idp.example.com/oauth/authorize".to_string(),
    upstream_token_endpoint_url: "https://idp.example.com/oauth/token".to_string(),
    resource_uri: "https://mcp.example.com".to_string(),
    allowed_redirect_uris: vec!["https://client.example.com/callback".to_string()],
    ..McpGatewayConfig::default()
}
```

Run `sbproxy_mcp_gateway::config::validate_startup(&config)` before
binding a listener. It rejects a missing canonical public origin when
DPoP is enabled and rejects replay retention shorter than twice the
allowed clock skew. `MCP_GATEWAY_BASE_URL` remains a legacy override
for standalone deployments.

## Resource-server provider

[`resource_server`](../crates/sbproxy-mcp-gateway/src/resource_server.rs)
verifies the Bearer/DPoP tokens this broker issues. The live MCP action
uses it before catalog lookup or upstream dispatch, and a standalone
server can call it from its own request handling. It shares the exact
DPoP-verification code the broker uses to mint `cnf.jkt`-bound tokens
(`dpop::parse_and_verify`, `dpop::jwk_thumbprint`), so a proof accepted
on the issuance side and one accepted on the verification side can
never drift from each other.

It covers JWKS-mode verification: signature, issuer, and audience via
`jsonwebtoken`, plus RFC 8707 resource binding (the token's `resource`
claim, or failing that its `aud` claim, must contain the configured
`resource_uri`). A signed `cnf.jkt` token always requires a matching
RFC 9449 proof, including `ath`, and a signed `cnf.x5t#S256` token
always requires a directly verified TLS certificate identity. The
provider also checks the process-local revocation denylist before JWKS
verification. RFC 7662 introspection-mode verification is **not** ported:
it would depend on an introspection auth provider that is itself a
separate, not-yet-ported piece of the same disposition plan this crate
came from (`oauth_introspection`, tracked as an independent ticket).
JWKS mode is the spec-recommended default and needs nothing from that
sibling ticket, so it is what ships here.

```rust
let provider = McpResourceServerProvider::new(McpResourceServerConfig {
    resource_uri: "https://mcp.example.com".to_string(),
    authorization_servers: vec!["https://idp.example.com".to_string()],
    jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
    audience: AudienceConfig::Single("https://mcp.example.com".to_string()),
    dpop_enforce_binding: true,
    ..
})?;

match provider.authenticate(auth_header, dpop_header, "GET", &request_url).await {
    Ok(verified) => { /* verified.sub, verified.claims */ }
    Err(err) => {
        // 401 with provider.www_authenticate_header(&err)
    }
}
```

`provider.metadata_document_json()` serves the RFC 9728
protected-resource document; mount it, unauthenticated, at
`provider.config().metadata_path` (defaults to
`/.well-known/oauth-protected-resource`).

## When to use which

| Your MCP server is... | Use |
|---|---|
| Proxied through `sbproxy` with `action: {type: mcp}` | The action's nested `oauth.broker` and `oauth.resource_server` blocks ([mcp.md](mcp.md)). Broker routes, RFC 9728 metadata, RFC 8707 resource binding, DPoP, mTLS certificate binding, and revocation checks run in the live request pipeline. |
| Not proxied through `sbproxy` at all | This crate's `resource_server` module, called directly from your server's own request handling. |
| The token issuer (any MCP server needing PKCE/DPoP/CIMD/DCR in front of an upstream AS) | This crate's broker (`router`, `router_full_with_par`). Both halves work together regardless of which resource-server option the caller picked. |

## Metrics

Every family below carries the sanctioned `sbproxy_mcp_gateway_`
prefix and registers into the process's default Prometheus registry
(`prometheus::default_registry()`), the same one `sbproxy` itself
exposes at `/metrics`. A standalone deployment of this crate should
expose its own `/metrics` route the same way
[`examples/standalone_broker.rs`](../crates/sbproxy-mcp-gateway/examples/standalone_broker.rs)
does (`prometheus::TextEncoder` over `prometheus::gather()`).

| Metric | Type | Labels | What it means |
|---|---|---|---|
| `sbproxy_mcp_gateway_authorize_requests_total` | counter | `outcome` (`redirected`, `rejected`, `error`) | `/authorize` decisions. |
| `sbproxy_mcp_gateway_token_requests_total` | counter | `outcome` (`issued`, `rejected`, `upstream_error`) | `/token` decisions. |
| `sbproxy_mcp_gateway_dpop_proofs_total` | counter | `outcome` (`verified`, `rejected`, `nonce_required`) | RFC 9449 proof verification at `/token`. |
| `sbproxy_mcp_gateway_revocation_introspection_requests_total` | counter | `endpoint` (`revoke`, `introspect`), `outcome` (`ok`, `error`) | `/revoke` and `/introspect` decisions. |
| `sbproxy_mcp_gateway_sessions_active` | gauge | none | In-flight authorization sessions. Only meaningful when the deployment updates it explicitly (`InMemorySessionStore` does not expose a count without an O(n) walk; a caller that wants this gauge live calls `metrics::SESSIONS_ACTIVE.set(...)` from its own periodic sweep). |

The outcome labels are deliberately coarse: recovering the specific
OAuth `error` string would mean buffering and JSON-parsing every
response body in the `tower` middleware that records these metrics, on
every request, including the overwhelming majority with nothing
interesting to extract. The per-request detail lives in the structured
decision logs below.

`dashboards/grafana/sbproxy-mcp-oauth-gateway.json` is the shipped
Grafana dashboard for this crate's metrics.

## Structured logging (decision events)

Every `/authorize`, `/token`, `/revoke`, and `/introspect` request
emits one `tracing::info!` line at `target: "mcp_gateway::decision"`
naming the decision:

```text
event="mcp_oauth_authorize_decision" outcome="rejected" status=400
event="mcp_oauth_token_decision" outcome="allowed" status=200
event="mcp_oauth_revoke_decision" outcome="allowed" status=200
event="mcp_oauth_introspect_decision" outcome="allowed" status=200
```

DPoP verification gets its own, more detailed line at `/token`, since
that is the one path with enough internal branching (proof-missing,
nonce-required, replay, signature-invalid) to warrant naming the
specific reason:

```text
event="mcp_oauth_dpop_decision" outcome="rejected" reason="<why>"
```

Route these into your SIEM or log pipeline the same way this
workspace's other decision events are: structured fields, no secret
material (tokens and proofs are never logged; RFC 8707 URLs that could
carry a credential in a query string are redacted via
`sbproxy_security::url_redact::redacted_url` before they reach a log
line).

## Admin status surface

`GET {base_path}/admin/status` (unauthenticated, mounted
unconditionally) returns which optional collaborators are wired up:

```json
{
  "base_path": "/mcp/oauth",
  "features": {
    "as_metadata_cache": false,
    "cimd": true,
    "cimd_to_dcr_translation": false,
    "dpop_replay_cache": true,
    "dpop_nonce_issuer": true,
    "device_code_grant": true,
    "pushed_authorization_requests": true,
    "revocation": false,
    "introspection": false,
    "token_exchange": false,
    "broker_signing_key": false
  }
}
```

The same endpoint is available from the integrated MCP action and the
standalone axum router. It is a small JSON surface an operator or
script can poll without a Prometheus query client.

## Adversarial coverage

`tests/prompt_injection_corpus.rs` drives
[`tests/corpora/prompt_injection.json`](../crates/sbproxy-mcp-gateway/tests/corpora/prompt_injection.json)
against the broker: 26 entries across six threat categories (tool
description injection, tool-result injection, scope escalation,
confused-deputy forwarding, replay, and cross-tenant session
collision), each asserting one of `blocked`, `sanitized`, or
`allowed_with_caveat`. `tests/e2e_auth_gateway.rs` pairs the broker
with an in-process mock Authorization Server and drives the full PKCE
happy path plus the OAuth-2.1-mandated rejections (implicit grant,
missing PKCE, password grant) over real HTTP. `tests/token_redirect_guard.rs`
proves the hardened outbound client used by every credential-bearing
call refuses to follow a cross-host redirect, so a compromised upstream
cannot bounce a bearer token to an attacker-controlled origin.
