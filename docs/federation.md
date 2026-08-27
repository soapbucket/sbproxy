# OpenID Federation

*Last modified: 2026-08-27*

[`sbproxy-federation`](../crates/sbproxy-federation) implements enough of
[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
for an sbproxy deployment to prove its own identity to a federated
peer, and to verify a peer's identity by walking that peer's trust
chain up to an anchor you configure.

Both halves are configuration. `proxy.federation:` in `sb.yml` makes
the proxy serve its own signed entity configuration on the listener you
already run, and `proxy.federation.peer_trust:` makes it verify a
caller's claimed entity against anchors you pin, on the request path,
before authentication. See
[Configuring `proxy.federation`](#configuring-proxyfederation). The
crate is also embeddable as a library plus a small axum surface for a
host process that wants the same machinery outside sbproxy. What it is
still not is a `type:` under `authentication:` on an origin; see
[Honest limits](#honest-limits) for what that costs you.

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

## Configuring `proxy.federation`

[`examples/openid-federation`](../examples/openid-federation) is a
complete `sb.yml` carrying both halves of what follows, with a README
that walks the served statement and the peer-trust refusal end to end.

The identity half. This is all it takes for the proxy to publish its own
entity configuration at `/.well-known/openid-federation` on the listener
it already serves:

```yaml
proxy:
  federation:
    enabled: true
    entity_id: https://gateway.acme.example
    signing_key:
      pem_file: /etc/sbproxy/federation-signing-key.pem
      algorithm: ES256
      kid: fed-2026q3
    published_jwks:
      keys:
        - kty: EC
          crv: P-256
          kid: fed-2026q3
          alg: ES256
          use: sig
          x: DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4
          y: bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc
    lifetime_secs: 86400
    refresh_margin_secs: 7800
    authority_hints:
      - https://trust-anchor.example
```

| Key | Required | What it is |
|---|---|---|
| `enabled` | yes | `false` (the default) leaves the well-known route unmounted. |
| `entity_id` | yes | This entity's HTTPS URL, published as both `iss` and `sub`. Config load refuses a non-`https://` value. |
| `signing_key.pem_file` | yes | Path to the private key, read once when the pipeline is built. |
| `signing_key.algorithm` | yes | One of `ES256`, `ES384`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `EdDSA`. Symmetric algorithms are refused. |
| `signing_key.kid` | yes | Stamped into the protected JWS header. It must name a key in `published_jwks`, and startup refuses the mismatch rather than serving a document every peer rejects. |
| `published_jwks` | yes | The `{"keys": [...]}` object embedded in the statement. Must be non-empty. |
| `lifetime_secs` | no, 3600 | How long each signed statement is good for. |
| `refresh_margin_secs` | no, 300 | How far before expiry the cached statement is re-signed. Must be strictly less than `lifetime_secs`. |
| `authority_hints` | no, empty | This entity's superiors. **Publish at least one unless this proxy is itself a trust anchor**: OpenID Federation 1.0 s3 requires it, and a peer's chain composer walks it, so an empty array is a statement nobody can chain to anything. Each entry must be an `https://` URL. |
| `peer_trust` | no | Inbound peer verification, below. |

### Verifying a peer

The trust half. A caller names the entity it claims to be in a header;
the proxy fetches that entity's configuration, walks its
`authority_hints` up to an anchor you pinned, validates every signature
and linkage in the chain, applies the metadata policy the chain's
superiors imposed, checks any trust marks you require, and admits or
refuses the request before authentication runs.

```yaml
proxy:
  federation:
    enabled: true
    # ... the identity block above ...
    peer_trust:
      required: false
      header: x-federation-entity-id
      trust_anchors:
        - entity_id: https://trust-anchor.example
          jwks:
            keys:
              - kty: EC
                crv: P-256
                kid: anchor-2026
                alg: ES256
                use: sig
                x: DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4
                y: bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc
      required_trust_marks:
        - https://trust-anchor.example/mark/certified
      max_chain_depth: 5
      cache_ttl_secs: 600
```

| Key | Required | What it is |
|---|---|---|
| `required` | no, `false` | `true` refuses a request that names no peer at all. `false` still refuses one whose named peer fails to verify: an unverifiable claim is worse than no claim. Setting it needs `authority_hints`, so a proxy cannot demand a chain from every caller while publishing one nobody can chain. |
| `header` | no, `x-federation-entity-id` | Request header the peer names itself in. Matched case-insensitively. |
| `trust_anchors` | yes | Pinned anchors, each with its `entity_id` and its published `jwks`. These keys are the pin: every chain is verified against them, and they come from your config rather than from the network. At least one is required. |
| `required_trust_marks` | no, empty | Trust-mark ids a verified peer must additionally carry, each signed by the anchor the chain terminated at. |
| `max_chain_depth` | no, 5 | Maximum statements in an accepted chain, and the fetch budget the composer walks with. |
| `cache_ttl_secs` | no, 600 | How long a peer decision is reused before the chain is walked again. Refusals are cached too, so an unverified caller cannot make this proxy generate outbound traffic per request. |

On a verified peer the proxy rewrites `header` to the entity id the
chain proved, so an upstream reading it reads what was verified rather
than what the caller wrote. On no claim with `required: false` the
header is removed outright. A refusal answers 403.

**What this cannot see.** The header is a claim, not a credential. This
answers "is the entity that name refers to vouched for by an anchor I
pinned", which is the trust-establishment question OpenID Federation
exists to answer. It does not answer "is this caller that entity".
Binding a connection to an entity is mutual TLS or a signed request, and
the [`authentication:`](configuration.md) providers do that. Run one of
them alongside this, or what you have is an allowlist keyed on an
unauthenticated header.

Every fetch this makes runs under the two egress layers described in
[Where the fetcher may dial](#where-the-fetcher-may-dial). A deployment
that configures no `peer_trust` block makes no federation fetch at all,
so `egress.federation` reports armed with zero sightings, and that is
the correct reading rather than a broken control.

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
into the process-wide Prometheus registry. sbproxy's own request path
serves the well-known route through this crate's handler body, so the
two well-known families are live on the shipped binary; a host embedding
the crate picks all five up the moment it mounts the router (or the
`entity_configuration_handler` directly).

| Metric | Type | Labels | What it means |
|---|---|---|---|
| `sbproxy_federation_entity_statement_verifications_total` | counter | `outcome` (`verified`, `rejected`) | Every `verify_entity_statement` call, whether driven directly or from inside `TrustChainResolver::resolve`. |
| `sbproxy_federation_trust_mark_verifications_total` | counter | `outcome` (`verified`, `rejected`) | Every `verify_trust_mark` call. |
| `sbproxy_federation_trust_chain_resolutions_total` | counter | `outcome` (`resolved`, `rejected`) | Every `TrustChainResolver::resolve` call, whether driven directly or through `compose_trust_chain`'s HTTP walk. |
| `sbproxy_federation_well_known_serves_total` | counter | `outcome` (`served`, `unavailable`) | Every `GET /.well-known/openid-federation` the handler answered. |
| `sbproxy_federation_well_known_cache_remaining_seconds` | gauge | none | Remaining lifetime of the entity configuration most recently served, sampled at request time. Pinned near zero across many samples means `refresh_margin` is too close to `lifetime` for your request rate. |
| `sbproxy_federation_peer_decisions_total` | counter | `outcome` (`trusted`, `refused`) | The admission decision the proxy made about a caller's claimed entity. Empty until `proxy.federation.peer_trust` is configured. |

The first three rows are written from inside the verification calls, so
on an sbproxy deployment they move only when `peer_trust` is configured:
a proxy that publishes its own statement and verifies nobody leaves them
empty, and that is the correct reading. The two well-known rows move on
every request to `/.well-known/openid-federation`.

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

Those three are the crate's own verification steps. The proxy's
admission decision on top of them is a fourth event at the same target:

- `federation_peer_decision`, field `outcome` (`trusted` or `refused`).
  On `trusted` it also carries `entity_id`, the value the chain proved,
  and `trust_anchor_id`, the pinned anchor it reached. On `refused` it
  carries `reason` (`no_peer_named`, `metadata_policy`, `trust_mark`,
  or the chain-walk failure) and, for the policy and trust-mark
  reasons, the `entity_type` or `trust_mark` at fault.

  This is the event that corresponds to the 403, and it fires once per
  request, including on a cache hit where none of the three above run.
  The refusal deliberately does not echo the entity id the caller
  supplied: that string is attacker-chosen on an unauthenticated
  request, and `reason` says what the walk found without it.

None of these ever log a private key or a raw JWS signature; `iss` /
`sub` / `id` are the entity and trust-mark URLs the spec already
treats as public. This is this workspace's usual "evidence is
structured logs" shape: grep for the `event` field rather than parsing
prose.

## Admin status

On sbproxy, this surface is `GET /admin/federation` on the proxy's own
authenticated admin API, documented in
[admin-api-reference.md](admin-api-reference.md#get-adminfederation). It
carries the identity fields below plus the peer-trust configuration and
how many peer decisions are currently cached. A console page for it is
separate scope, under the admin console work; the JSON route is the
operator surface today.

For a host embedding the crate, `GET /admin/status` (mounted by `router`) returns the entity id,
signing algorithm and `kid`, key/authority-hint/trust-mark counts,
whether a `metadata_policy` is configured, the configured lifetime and
refresh margin, and how many seconds remain on the cached document.
Unauthenticated by design, matching the well-known route itself:
everything in the response is already public in the entity
configuration this process serves.

## Honest limits

- **Not a config-driven `authentication:` provider, and not an
  authentication provider at all.** There is no `type: federation` you
  set on an origin, and `proxy.federation.peer_trust` is not a
  substitute for one: it is proxy-wide rather than per-origin, it runs
  before the auth phase rather than inside it, and it verifies the
  entity a header names rather than binding the connection to that
  entity. Pair it with [cap.md](cap.md), mutual TLS, or
  [auth-oidc.md](auth-oidc.md) for the binding. What it does do is what
  the two sections above describe: publish this entity's configuration
  from the normal listener, and refuse a caller whose claimed entity no
  pinned anchor vouches for.
- **No subordinate-statement endpoint.** This proxy publishes its own
  entity configuration and consumes other entities' chains. It does not
  serve `/fetch`, so it cannot act as an intermediate that issues
  subordinate statements about anyone else.
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
