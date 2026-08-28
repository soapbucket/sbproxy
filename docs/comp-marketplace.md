# CoMP marketplace bridge

*Last modified: 2026-08-28*

The CoMP marketplace bridge implements the IAB Content Authorization
Marketplace Protocol v1.0: a publisher-facing manifest of licensable
content tiers, a signed price quote, and a redeem endpoint that turns a
buyer's signed acceptance and payment proof into a license token.

Set `origins.<host>.comp` and the proxy serves all three endpoints on
that origin. The same code also ships as a library
([`sbproxy-licensing`](../crates/sbproxy-licensing)) with its own axum
router, for a publisher who wants to run the marketplace as its own
process; see [Running it standalone](#running-it-standalone).

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

## Configuration

```yaml
origins:
  "api.example.com":
    action: { type: proxy, url: "https://upstream.example.com" }

    # Required. The bridge has no issuer of its own: it mints with this
    # key, under this kid, so the token it hands a buyer verifies
    # against this same origin's /.well-known/olp/introspect.
    olp:
      enabled: true
      signing_key: "${OLP_SIGNING_KEY}"
      key_id: 2026-q3
      issuer: https://api.example.com
      default_scope: ai-input
      default_ttl_secs: 86400

    comp:
      enabled: true

      # HKDF input for the quote-signing key. Takes the same reference
      # forms as every other secret in the config: file:, vault://,
      # secret://, and a whole-value ${VAR}. At least 32 bytes resolved.
      master_key: "${COMP_MASTER_KEY}"
      # Rotate by bumping this label. A new comp-<rotation_id> kid is
      # derived and published; the previous one keeps verifying until
      # the process restarts.
      rotation_id: 2026-q3-001

      publisher:
        name: Example Publishing Co.
        contact: licensing@example.com

      tiers:
        - id: tier_ai_inference
          name: AI inference
          description: Per-request inference access.
          license: urn:rsl:pay-per-inference:default
          shape: json-envelope        # html | json-envelope | bulk-archive
          authorization: olp          # public | cap | olp
          route_glob: "/api/v1/inference/**"
          pricing:
            model: per_request        # free | per_request | flat_rate
            currency: USD
            amount_micros: 2500

      # The onboarding boundary. A redeem is refused unless its signing
      # kid resolves here, so an empty list refuses every redeem.
      buyer_keys:
        - kid: buyer-acme-001
          public_key: "hs4tRbkr8h8L5rG3xVoOEZUJ8Rk0aG3hFXhtQmiFf9E"
```

`examples/comp-marketplace/` is a runnable version of the same thing.

| Key | Type | Default | Behavior |
|---|---|---|---|
| `enabled` | bool | `false` | Master toggle. When false the three well-known paths fall through to the origin's normal pipeline. |
| `master_key` | secret ref | required | HKDF input for the quote-signing key. At least 32 bytes resolved; refused shorter. |
| `rotation_id` | string | required | Label the active `comp-<rotation_id>` kid derives under. |
| `publisher.name` | string | required | Publisher name the manifest advertises. |
| `publisher.contact` | string | required | Licensing contact a buyer can reach a human at. |
| `publisher.verified_at` | RFC 3339 | unset | Marketplace verification timestamp. Advisory; nothing checks it. |
| `tiers[]` | list | required | At least one, and at least one with `authorization: olp`, since that is the only kind `redeem` can mint for. |
| `buyer_keys[]` | list | required | `kid` plus a base64url-without-padding Ed25519 public key, 32 bytes decoded. |
| `manifest_hash` | string | computed | `sha256:<hex>` over the manifest with the field cleared. Set it only when an out-of-band process owns the value. |
| `allow_unknown_quotes` | bool | `false` | See [What the default refuses](#what-the-default-refuses). |

The publisher domain and the three endpoint URLs are not configurable:
they are this origin's hostname, because that is where the endpoints
actually answer, and a second configurable value could only ever
disagree with it.

Every refusal below fires at config load, so `sbproxy validate` catches
them on a machine that holds none of the secrets: a `comp:` block with
no enabled `olp:` block, an empty `master_key` or `rotation_id`, an
empty `tiers` list, a duplicate tier id, an `authorization` /
`shape` / `pricing.model` outside its vocabulary, a `per_request` tier
with no `amount_micros` or a `flat_rate` tier with no `amount`, a
currency that is not three letters, an empty `buyer_keys` list, a
duplicate kid, and a `public_key` that is not 32 base64url bytes.

## What the default refuses

The bridge keeps its issued-quote ledger in memory, matching the
no-external-store rule this feature ships under. A reload or a restart
therefore forgets every quote it signed.

By default a redeem naming a `quote_id` this process never issued is
refused with `403 {"error":"unknown_quote"}`. That costs a buyer holding
a quote from before a restart one extra round trip: it asks for a new
quote and redeems that. What it buys is the thing the refusal is there
for. Without it, an onboarded buyer key plus a fabricated `quote_id`, a
fabricated `accepted_quote_hash`, and a shape-valid payment proof mints
a license token per call, forever, and the publisher's reconciliation
shows no quote for the revenue.

`allow_unknown_quotes: true` restores the older behavior. A deployment
that sets it should also be running a shared revocation denylist, since
that check is then the only durable one left.

Two more refusals bound the request in time, both on the buyer's own
`accepted_at`:

- More than five minutes ahead of the bridge's clock is refused. The
  allowance is deliberate, so a buyer whose clock runs a minute fast is
  not refused; anything past it is refused rather than clamped.
- Older than a whole quote validity window plus that allowance is
  refused: no quote this bridge would still honor existed when the
  acceptance was signed.
- A timestamp the bridge cannot parse is refused rather than read as
  "now". Treating an unreadable value as the current time turns a
  bounded window into no window at all.

## Running it standalone

The same three endpoints, plus a `GET /admin/status`, mount as an axum
router for a publisher who runs the marketplace as its own process:

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
// buyer_keys.insert_base64url(kid, public_key)? per onboarded buyer

let marketplace = Arc::new(CompMarketplace::new(keys, manifest, revocation, olp_bridge, buyer_keys));
let app = sbproxy_licensing::router(marketplace); // well-known + admin-status routes
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
registers into the process-wide Prometheus registry, so `/metrics` on a
proxy with a `comp:` block carries them. Every writer is in
`comp/serve.rs`, which is the one body both the proxy request path and
the standalone router call, so the counters move on either surface.

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
(module target `sbproxy_licensing::comp::serve`) with `event` set to
`comp_quote_decision` or `comp_redeem_decision`, `outcome` set to
`quoted` / `rejected` or `minted` / `rejected`, and either the
resulting `quote_id` / `license` / `agent_id` on success or a `reason`
string (the `LicensingError`'s `Display` output) on rejection. Grep for
the `event` field rather than parsing prose.

No license token appears in any of them, and none can be added by
accident: `CompRedeemResponse`'s `Debug` prints `[REDACTED]` in place
of `license_token`, so a `?response` in a tracing macro, a `dbg!`, or a
panic message cannot leak the bearer credential either. Every
buyer-supplied string that does reach a log line (`tier_id`,
`quote_id`, and the rendered rejection reason) goes through the same
control-character-stripping sanitizer the federation peer decision
uses, so a newline in a POST body cannot forge a log record.

## Admin status

On a proxy, `GET /admin/licensing` under the admin API lists every
origin with a bridge configured: the publisher name and domain, the
tier count and how many of those are OLP-redeemable, the active CoMP
signing kid (`null` until a rotation is activated, which is when every
quote request fails closed), how many kids still verify, the published
manifest hash, and the three endpoint URLs. Behind the operator-auth
gate: the manifest half is already public, but which origins have a
bridge at all is operational state. No key material and no minted token
appears in the response. See
[admin-api-reference.md](admin-api-reference.md#get-adminlicensing).

A console page for it is deferred to the admin console epic; the route
is the surface today.

Standalone hosts get `GET /admin/status` from
[`router`](../crates/sbproxy-licensing/src/lib.rs) instead, with the
same fields for the single marketplace that process serves.
Unauthenticated by design there, matching the manifest route itself.

## Honest limits

- **The quote ledger does not survive a restart.** It is in memory, by
  design: no Postgres, no ClickHouse, no NATS. With the default a buyer
  holding a quote from before a reload is refused and pays one extra
  round trip for a fresh one; with `allow_unknown_quotes: true` it is
  admitted, and so is a fabricated id. See
  [What the default refuses](#what-the-default-refuses). There is no
  third option today that keeps both properties; one would need a
  durable quote store, which is separate scope.
- **Revocation is in-memory by default too.** A `quote_id` revoked on
  one replica is not revoked on the others until a deployment composes
  [`RedisRevocation`](../crates/sbproxy-licensing/src/revocation.rs)
  over the workspace `EphemeralKv`. That is a library seam rather than
  a config key today.
- **Quote and redeem signatures are not JCS.** The bytes both
  signatures cover are `serde_json::to_vec` of the Rust struct, so the
  field order is the struct's declaration order rather than the sorted
  key order [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) defines.
  A non-Rust CoMP client has to reproduce that order byte for byte to
  sign or verify; the canonical form is whatever
  `canonical_quote_signing_input` and `canonical_redeem_signing_input`
  in
  [`comp/marketplace.rs`](../crates/sbproxy-licensing/src/comp/marketplace.rs)
  emit. Moving to JCS is a wire break and is separate scope.
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
