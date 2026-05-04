# ADR: User ID propagation (Wave 8 / T3.1)

*Last modified: 2026-04-28*

## Status

Accepted. Builds on `adr-event-envelope.md` (T5.1).

## Context

The proxy already accepts `user` as a budget scope, but nothing today fills the upstream signal that scope keys on. Per-user analytics, per-user budgets, and the portal's Users view all need a consistent end-user identifier landed at the edge.

The challenge is precedence: callers can supply the ID directly, our auth providers can resolve it from a token's subject claim, and trusted upstream proxies (zero-trust gateways, identity-aware proxies) can forward it. We need a single deterministic precedence so ops can audit who was charged for what.

## Decision

### Resolution precedence

For each request, the proxy resolves `user_id` from the first source that yields a non-empty value, in this order:

1. **Explicit header**: `X-Sb-User-Id`. Lowest-friction caller-supplied ID, used when the SDK already knows the subject.
2. **JWT `sub` claim**: when JWT auth is enabled on the origin and the token carries `sub`, that value resolves to `user_id`. Implemented via the existing `jwt` auth provider, which already extracts `sub`; this ADR just plumbs it through to `RequestEvent`.
3. **Forward-auth trust header**: when `forward_auth` is enabled and the upstream auth gateway returns a header (default `X-Authenticated-User`, configurable), that value resolves to `user_id`. Trust the upstream only when forward-auth is in the chain; never read this header from clients directly.

Resolution writes to `RequestEvent.user_id`. Once resolved, `req.user_id` is exposed read-only to CEL/Lua/JS/WASM and used as the `user` budget scope key.

### Cardinality cap

`user_id` is uncontrolled input. A misconfigured client could mint a fresh ID per request and DDoS the per-user storage shard. Defenses:

- **Length**: 256 chars. Drop and increment `sbproxy_user_dropped_total{reason="length"}` when over.
- **Per-workspace cardinality cap**: configurable, default `1_000_000` distinct user IDs per workspace per 24 h, tracked via HyperLogLog. When the cap is hit, new user IDs are dropped (request still serves; `user_id` is unset on the event), and we emit `sbproxy_user_cardinality_capped_total{workspace_id}`. T3.4 enforces this on the enterprise side; OSS uses an in-memory HLL with the same default.
- **PII handling**: we treat `user_id` as opaque. Nothing in the proxy decodes, hashes, or interprets it. The recommendation in operator docs (T3.5) is to send a hash/pseudonym rather than an email, and the redaction hook from T1 can be extended to user IDs in a future ADR if customer demand warrants.

### Cardinality safety in metrics

Same rule as properties and sessions: `user_id` does not enter Prometheus labels. We expose `sbproxy_user_count_distinct` (HLL) for ops; per-user metrics are always served from the event store, never from `/metrics`.

### Budget integration

The existing `BudgetScope::User` variant is unblocked. The budget engine's per-scope counter map keys on the resolved `user_id`. When `user_id` is unset (anonymous), the scope falls back to `BudgetScope::Workspace` so cost is still tracked, just not per-user.

Configuration shape:

```yaml
budgets:
  user:
    daily_usd_cap: 5.00          # per-user daily spending cap
    over_cap_action: log         # block | log | downgrade
```

This is unchanged from existing budget config; the new wire here is the resolution path that fills the scope key.

### Auth provider integration

`sbproxy-modules` JWT and `forward_auth` providers gain a `resolved_user` output that the request pipeline reads after auth runs. We do not change the auth interface for OSS plugins; the plumbing is internal to the modules crate.

## Consequences

- Deterministic resolution: ops can answer "where did this `user_id` come from" by checking which source filled it (we attach `RequestEvent.user_id_source ∈ {header, jwt, forward_auth, anonymous}` for diagnostic queries).
- Per-user budgets and per-user analytics light up without a separate config knob; both are downstream consumers of `RequestEvent.user_id`.
- Forward-auth's trust boundary is explicit. Reading the trust header from a client request directly is a misconfiguration, not a feature.
- Cardinality cap is the load-bearing safeguard against a runaway client. Operators see `sbproxy_user_cardinality_capped_total` ramp before storage gets hot.

## References

- `docs/PORTAL.md` sec 6.3.
- `docs/adr-event-envelope.md`.
- Existing JWT auth provider: `crates/sbproxy-modules/src/auth/jwt.rs`.
- Existing forward-auth provider: `crates/sbproxy-modules/src/auth/forward_auth.rs`.
