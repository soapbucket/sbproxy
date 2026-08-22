# CoMP marketplace bridge

*Last modified: 2026-08-22*

[`sbproxy-licensing`](../crates/sbproxy-licensing) is a standalone
crate implementing the IAB Content Authorization Marketplace Protocol
(CoMP) v1.0: a publisher-facing manifest of licensable content tiers,
a signed price quote, and a redeem endpoint that turns a buyer's
signed acceptance and payment proof into a license token. It ships as
a library plus a small axum surface (three well-known routes and an
admin-status route), not as a `type:` you configure under `origins:`
on an sbproxy proxy today; see [Honest limits](#honest-limits) for
exactly what that means.

If you already run [rsl.md](rsl.md)'s `/licenses.xml` and
[ai-crawl-control.md](ai-crawl-control.md)'s pay-per-crawl challenge,
this crate answers a different question: how a buyer who wants a
*standing* license (not a per-request micropayment) discovers your
tiers, gets a price, and redeems it once, rather than re-negotiating
on every crawl.

## What it implements

- **The manifest** (`GET /.well-known/iab-comp/manifest.json`):
  publisher metadata, a list of content tiers (each with pricing, an
  acquisition flow, and a route glob), and pointers at your
  `robots.txt`, `llms.txt`, and RSL catalog. Cached 5 minutes
  (`public, max-age=300`).
- **The quote** (`POST /.well-known/iab-comp/quote`): validates the
  requested tier and volume, computes the price, and returns an
  Ed25519-signed quote good for one hour
  ([`COMP_QUOTE_VALIDITY_SECS`](../crates/sbproxy-licensing/src/comp/marketplace.rs)).
  Quote signatures use this crate's own `comp-<rotation_id>` kid
  namespace ([`keys::KeyManager`](../crates/sbproxy-licensing/src/keys.rs)),
  so a quote signature can never be replayed as a license token.
- **The redeem** (`POST /.well-known/iab-comp/redeem`): verifies the
  buyer's Ed25519 signature over the request, checks the quote hasn't
  been revoked or (within this process's lifetime) expired, checks
  the payment proof shape for the declared rail, and mints a license
  token. `no-store` on both quote and redeem responses; both are
  per-buyer credentials.

## The OLP bridge: same wire format, no extra dependency

Redeem's whole job is "a buyer paid, hand them a license token." Two
protocols already exist for that OSS-side and this crate reuses
neither's *code*, only its *wire format*:

- [cap.md](cap.md) documents the CAP verifier
  (`sbproxy-modules::auth::cap`), which checks a bearer capability
  token; there is no OSS CAP issuer to bridge into.
- The RSL 1.0 Open Licensing Protocol (OLP) glossary entry in
  [glossary.md](glossary.md) documents the OSS OLP issuer:
  `sbproxy-modules::olp` plus the proxy's own
  `/.well-known/olp/{token,key,introspect,revoke}` routes already
  mint, verify, publish JWKS for, introspect (RFC 7662), and revoke
  (RFC 7009) OLP license tokens, config-driven per origin via
  `origins.<host>.olp`.

[`comp::olp_bridge::OlpBridgeSigner`](../crates/sbproxy-licensing/src/comp/olp_bridge.rs)
mints tokens in *exactly* that OSS wire format (compact JWS,
`alg=EdDSA`, `typ="olp-license+jws"`, the same claim names) without
depending on `sbproxy-modules` to do it (a leaf protocol crate has no
business pulling in the WAF, transform, and callback machinery that
lives there; see the module doc for the full boundary argument).
Configure the bridge with the *same* signing key you already put in
`origins.<host>.olp.signing_key`, and a token this crate mints on
redeem verifies against that origin's own
`POST /.well-known/olp/introspect` and is honored by anything else in
your deployment that already trusts OLP license tokens. One claim is
deliberately not reproduced: the WOR-808 `cnf.jwk` Encrypted Media
Standard content-key binding, since a marketplace buyer hasn't gone
through the origin's own EMS key-seed configuration.

## Storage: in-memory by default, Redis optional

[`revocation::InMemoryRevocation`](../crates/sbproxy-licensing/src/revocation.rs)
is a plain `Mutex<HashMap<String, u64>>`; the redeem-time
quote-expiry ledger is the same shape, private to
`CompMarketplace`. This crate has no Postgres, ClickHouse, or NATS
dependency. [`revocation::RedisRevocation`] is an already-optional
adapter over the workspace's `sbproxy-storage::EphemeralKv` trait for
deployments that need a denylist to survive a restart or replicate
across hosts; it composes with any `EphemeralKv` backend rather than
opening its own `redis::Client`.

The quote-expiry ledger is same-process only and is a defense in
depth on top of revocation, not a replacement for it: a quote_id this
process's ledger never saw (an older quote redeemed after a restart)
is not rejected on expiry grounds alone, since a no-external-store
deployment genuinely cannot know its real expiry. An operator whose
threat model needs restart-survival for quote expiry reaches for
`RedisRevocation` and revokes proactively.

## Quickstart

```rust,ignore
use std::sync::Arc;
use sbproxy_licensing::comp::{CompMarketplace, InMemoryBuyerKeyRegistry, OlpBridgeSigner};
use sbproxy_licensing::keys::{KeyManager, MasterKey};
use sbproxy_licensing::revocation::InMemoryRevocation;

let keys = KeyManager::new(MasterKey::from_hex(&std::env::var("COMP_MASTER_KEY_HEX")?)?);
keys.set_active("2026-08")?;

let olp_bridge = Arc::new(OlpBridgeSigner::from_hex_seed(
    &std::env::var("OLP_SIGNING_KEY")?, // same value as origins.<host>.olp.signing_key
    "2026-08",                          // same value as origins.<host>.olp.key_id
    "https://publisher.example.com",    // same value as origins.<host>.olp.issuer
    "ai-input",                         // same value as origins.<host>.olp.default_scope
    24 * 3600,
)?);

let manifest = Arc::new(/* build your CompManifest */);
let revocation = Arc::new(InMemoryRevocation::new());
let buyer_keys = Arc::new(InMemoryBuyerKeyRegistry::new());
// buyer_keys.insert(kid, verifying_key) per onboarded buyer

let marketplace = Arc::new(CompMarketplace::new(keys.clone(), manifest, revocation, olp_bridge, buyer_keys));
let app = sbproxy_licensing::router(marketplace, keys); // mounts the well-known + admin-status routes
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run `cargo run -p sbproxy-licensing --example standalone_marketplace`
for a complete, self-contained demo: it quotes a tier, redeems it into
a bridged OLP token, and serves the routes above so you can repeat the
flow yourself over HTTP. See
[the example's own doc comment](../crates/sbproxy-licensing/examples/standalone_marketplace.rs)
for the exact `curl` commands.

## Metrics

Every family carries the `sbproxy_comp_marketplace_` prefix and
registers into the process-wide Prometheus registry, so a host that
already scrapes `/metrics` picks these up the moment it mounts this
crate's router.

| Metric | Type | Labels | What it means |
|---|---|---|---|
| `sbproxy_comp_marketplace_manifest_serves_total` | counter | `outcome` (`ok`, `error`) | Every `GET /.well-known/iab-comp/manifest.json` the handler answered. |
| `sbproxy_comp_marketplace_quote_requests_total` | counter | `outcome` (`ok`, `rejected`) | Every `POST /.well-known/iab-comp/quote` call. |
| `sbproxy_comp_marketplace_redeem_requests_total` | counter | `outcome` (`ok`, `rejected`) | Every `POST /.well-known/iab-comp/redeem` call. |

[dashboards/grafana/sbproxy-comp-marketplace.json](../dashboards/grafana/sbproxy-comp-marketplace.json)
draws all three plus a redeem rejection-rate stat; see
[dashboards/README.md](../dashboards/README.md).

## Structured logging (decision events)

Every quote and redeem call emits a structured `tracing::info!` event
(module target `sbproxy_licensing::comp::router`) with `event` set to
`comp_quote_decision` or `comp_redeem_decision`, `outcome` set to
`quoted` / `rejected` or `minted` / `rejected`, and either the
resulting `quote_id` / `license` / `agent_id` on success or a `reason`
string (the `LicensingError`'s `Display` output) on rejection. None of
these ever log a buyer's private key or the raw license token; grep
for the `event` field rather than parsing prose.

## Admin status

`GET /admin/status` (mounted by [`router`](../crates/sbproxy-licensing/src/lib.rs))
returns the manifest's publisher domain and tier count, the active
CoMP signing kid, and how many CoMP kids are currently trusted for
verification. Unauthenticated by design, matching the manifest route
itself: everything in the response is already public in the manifest
this process serves.

## Honest limits

- **Not a config-driven `origins:` surface.** Unlike
  [cap.md](cap.md) or the OLP block documented in
  [glossary.md](glossary.md), there is no `type: comp` you set on an
  sbproxy origin today. This crate is a library plus a small
  standalone axum surface a host process embeds; a publisher runs it
  either as its own process in front of (or alongside) their sbproxy
  deployment, or mounts `sbproxy_licensing::router` into their own
  axum app.
- **Redeem always picks the first OLP-authorized tier.** `quote_id`
  does not yet carry a durable pointer back to the exact tier it was
  quoted against; a manifest with more than one `Olp`-authorized tier
  redeems against whichever comes first in `CompManifest::tiers`.
  Fixing this needs a quote-to-tier store, tracked as separate scope.
- **Payment-proof verification is shape-only.** `redeem` checks that
  a proof's required fields are non-empty for its declared rail
  (`x402`, `mpp`, `stripe`); it does not call an x402 facilitator,
  resolve an MPP receipt, or look up a Stripe `payment_intent`. Real
  per-rail verification is separate scope against this workspace's
  existing payment rails (see [payments.md](payments.md)) rather than
  reimplemented here.
- **No CAP or OLP issuer here.** See [the module doc](../crates/sbproxy-licensing/src/lib.rs)
  for why: OLP issuance already ships OSS-side and is materially more
  complete than what this crate's enterprise source carried (mint,
  verify, JWKS, RFC 7662 introspection, RFC 7009 revocation, three
  revocation backends), and CAP issuance's collaborators (an
  `AgentVerifier`, a per-tenant `PolicyStore`) have no OSS-shaped
  equivalent to plug into.
