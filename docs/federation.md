# OpenID Federation

*Last modified: 2026-08-27*

[`sbproxy-federation`](../crates/sbproxy-federation) is a standalone
crate implementing enough of
[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
for an sbproxy deployment to prove its own identity to a federated
peer, and to verify a peer's identity by walking that peer's trust
chain up to an anchor you configure. It ships as a library plus a
small axum surface (a well-known route and an admin-status route),
not as a `type:` you configure under `authentication:` on an origin
today; see [Honest limits](#honest-limits) for exactly what that
means.

If you need request-time bearer-token verification instead (a caller
presents a JWT and you check it against an issuer's JWKS),
[cap.md](cap.md) and [auth-oidc.md](auth-oidc.md) are the wired-in
providers. This crate answers a different question, whether a whole
entity is who it claims to be and some authority you trust vouches for
it, which is the trust-establishment step a federation of
independently-operated gateways or agent registries needs before any
per-request token exchange makes sense.

## What it implements

- **Entity Statements** (§3): the signed JWT claim set carrying an
  entity's keys, metadata, authority hints, and trust marks.
  `sign_entity_statement` / `verify_entity_statement` produce and
  consume the compact-JWS form, with the mandatory
  `typ = "entity-statement+jwt"` header and asymmetric-algorithm-only
  enforcement (ES256/ES384/RS256/RS384/RS512/PS256/PS384/PS512/EdDSA;
  HS* is rejected at sign time).
- **RFC 7638 JWK thumbprints**: `jwk_thumbprint_sha256` derives a
  stable `kid` from a JWK's canonical members, for an operator who
  does not pre-assign one.
- **The well-known issuer** (§9): `WellKnownIssuer` signs a
  self-signed Entity Configuration on demand and caches the compact
  JWS in memory until shortly before its `exp`, so concurrent
  requests to `/.well-known/openid-federation` do not each pay a
  fresh signature.
- **The trust-chain resolver** (§9.2): `TrustAnchorStore` holds your
  pinned anchors; `TrustChainResolver::resolve` validates a
  leaf-to-anchor chain of statements, checking every signature and
  every `iss`/`sub` linkage, rejecting cycles, and enforcing a depth
  cap.
- **The HTTP fetcher + chain composer**: `ReqwestFederationFetcher`
  (HTTPS-only, governed egress, see
  [Where the fetcher may dial](#where-the-fetcher-may-dial)) and
  `compose_trust_chain` walk a leaf's `authority_hints` up to a
  configured anchor and hand the assembled chain to the resolver.
- **Trust marks** (§7): `sign_trust_mark` / `verify_trust_mark`
  produce and consume the separate `trust-mark+jwt` compact JWS a
  trust-mark issuer signs about an entity.
- **Metadata-policy operators** (§6.1): `apply_field_policy` /
  `apply_block_policy` / `compose_policies` implement all seven
  operators (`value`, `add`, `default`, `one_of`, `subset_of`,
  `superset_of`, `essential`) a superior can impose on a
  subordinate's published metadata.

## Where the fetcher may dial

A federation peer URL is not written by you. It arrives in an
`authority_hints` array or a `federation_fetch_endpoint` metadata field
signed by some other entity in the chain, and the fetcher is asked to GET
it. So the fetch runs under the same governed egress machinery every other
outbound call in this proxy uses, in two layers.

The first layer is unconditional and has no configuration. Before any
connect, the peer host is resolved and the fetch is refused outright if
any answer is a loopback, RFC 1918, link-local, CGNAT, or otherwise
special-use address. The dial is then pinned to exactly the addresses that
check resolved, so a name that answers publicly at check time and privately
at connect time is refused rather than followed. The refusal says
`destination refused` and names no address, port, or reason: the peer URL
can itself be the thing a probe is asking about.

The second layer is the operator's allowlist, under the top-level
`egress:` section:

```yaml
egress:
  federation:
    mode: deny_by_default
    hosts: ["anchor.example", "intermediate.example"]
```

That arms the `federation` egress purpose: host, scheme, and port are
checked against the list, every redirect hop is re-authorized against it
before any second connect, the chain is bounded, and each refusal is
counted on `sbproxy_egress_refused_total{purpose="federation"}`, logged,
and stamped into `GET /api/egress`.

What is left when you do not write that block: any *public* address is
reachable. A federation deployment discovers its peers through the trust
chain rather than listing them in advance, which is why the allowlist is
opt-in rather than required. Write it once the anchors are known.

## Storage: in-memory only

`TrustAnchorStore` is a plain `HashMap`; `WellKnownIssuer`'s cache is
a plain `RwLock<Option<...>>`. This crate has no Postgres, sqlx, or
Redis dependency, and no file it writes to. An operator supplies the
anchor list and the signing key at process startup; both live only in
that process's memory and are re-supplied from your own config source
on every restart.

## Quickstart

```rust,ignore
use std::sync::Arc;
use std::time::Duration;
use jsonwebtoken::Algorithm;
use sbproxy_federation::{
    router, EntityMetadata, FederationEntityMetadata, FederationKeySet,
    FederationServerConfig, SigningKeyConfig, WellKnownIssuer,
};

let config = FederationServerConfig {
    entity_id: "https://gateway.acme.example".to_string(),
    signing_key: SigningKeyConfig {
        pem: std::fs::read("federation-signing-key.pem")?,
        algorithm: Algorithm::ES256,
        kid: "2026-08".to_string(),
    },
    published_jwks: FederationKeySet::empty(), // push your public JWK(s)
    metadata: EntityMetadata {
        federation_entity: Some(FederationEntityMetadata {
            organization_name: Some("Acme Corp".to_string()),
            ..Default::default()
        }),
        other: Default::default(),
    },
    authority_hints: vec!["https://trust-anchor.example".to_string()],
    trust_marks: vec![],
    metadata_policy: None,
    lifetime: Duration::from_secs(24 * 3600),
    refresh_margin: Duration::from_secs(2 * 3600 + 24 * 60),
};

let issuer = Arc::new(WellKnownIssuer::new(config)?);
let app = router(issuer); // mounts the well-known + admin-status routes
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run `cargo run -p sbproxy-federation --example standalone_federation_server`
for a complete, self-contained demo: it mints a throwaway keypair,
serves the routes above, and resolves a one-step trust chain against
itself so you can see a decision-event log line and a metric tick
before making a single HTTP request. See
[the example's own doc comment](../crates/sbproxy-federation/examples/standalone_federation_server.rs)
for the exact `curl` commands.

## Metrics

Every family carries the `sbproxy_federation_` prefix and registers
into the process-wide Prometheus registry, so a host that already
scrapes `/metrics` picks these up the moment it mounts this crate's
router (or the `entity_configuration_handler` directly).

| Metric | Type | Labels | What it means |
|---|---|---|---|
| `sbproxy_federation_entity_statement_verifications_total` | counter | `outcome` (`verified`, `rejected`) | Every `verify_entity_statement` call, whether driven directly or from inside `TrustChainResolver::resolve`. |
| `sbproxy_federation_trust_mark_verifications_total` | counter | `outcome` (`verified`, `rejected`) | Every `verify_trust_mark` call. |
| `sbproxy_federation_trust_chain_resolutions_total` | counter | `outcome` (`resolved`, `rejected`) | Every `TrustChainResolver::resolve` call, whether driven directly or through `compose_trust_chain`'s HTTP walk. |
| `sbproxy_federation_well_known_serves_total` | counter | `outcome` (`served`, `unavailable`) | Every `GET /.well-known/openid-federation` the handler answered. |
| `sbproxy_federation_well_known_cache_remaining_seconds` | gauge | none | Remaining lifetime of the entity configuration most recently served, sampled at request time. Pinned near zero across many samples means `refresh_margin` is too close to `lifetime` for your request rate. |

[dashboards/grafana/sbproxy-federation.json](../dashboards/grafana/sbproxy-federation.json)
draws all five; see [dashboards/README.md](../dashboards/README.md).

## Decision events

Every verification and every trust-chain resolution emits a
structured `tracing` event at `target: "sbproxy_federation::decision"`
with `event` set to one of:

- `federation_entity_statement_decision`, fields `outcome`, `iss`,
  `sub`, `self_signed` on success or `error` on rejection.
- `federation_trust_mark_decision`, fields `outcome`, `iss`, `sub`,
  `id` on success or `error` on rejection.
- `federation_trust_chain_decision`, fields `outcome`,
  `leaf_entity_id`, and either `trust_anchor_id` plus `chain_len` on
  success or `error` on rejection.

None of these ever log a private key or a raw JWS signature; `iss` /
`sub` / `id` are the entity and trust-mark URLs the spec already
treats as public. This is this workspace's usual "evidence is
structured logs" shape: grep for the `event` field rather than parsing
prose.

## Admin status

`GET /admin/status` (mounted by `router`) returns the entity id,
signing algorithm and `kid`, key/authority-hint/trust-mark counts,
whether a `metadata_policy` is configured, the configured lifetime and
refresh margin, and how many seconds remain on the cached document.
Unauthenticated by design, matching the well-known route itself:
everything in the response is already public in the entity
configuration this process serves.

## Honest limits

- **Not a config-driven `authentication:` provider.** Unlike
  [cap.md](cap.md) or [auth-oidc.md](auth-oidc.md), there is no
  `type: federation` you can set on an origin today. This crate is a
  library plus a small standalone axum surface a host process embeds;
  wiring a trust-chain-verified peer identity into the inbound
  request pipeline is a separate integration this port does not do.
- **No live trust-mark revocation check.** `verify_trust_mark`
  verifies the mark's signature (the offline half of §7). The
  `/.well-known/federation-trust-mark-status` live revocation check
  is an HTTP call a consumer must make separately; this crate does
  not make it for you.
- **No persistence across restarts.** The trust-anchor store and the
  well-known cache are in-process memory only, by design (see
  [Storage](#storage-in-memory-only)); an operator that wants anchors
  to survive a restart re-supplies them from their own config source
  at startup.
- **First-match anchor and first-match `authority_hints` path.**
  `TrustAnchorStore` picks the anchor matching the chain's tail;
  `compose_trust_chain` tries `authority_hints` entries in order and
  returns the first chain that anchors. Neither picks "closest" or
  "highest-preference" when several paths exist.
