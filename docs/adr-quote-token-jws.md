# ADR: Signed quote-token JWS for replay protection

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-billing-hot-path-vs-async.md` (layering rule), `adr-http-ledger-protocol.md` (the wire protocol that carries the redeem call), `adr-schema-versioning.md` (schema rules), `adr-billing-rail-x402-mpp-mapping.md` (the rail-mapping ADR), `adr-multi-rail-402-challenge.md` (the 402 body that carries the token), and `adr-db-migration-policy.md` (governs the `quote_tokens` table migration).

## Context

The single-rail 402 implements replay protection via the `Crawler-Payment` token: each token is a UUID seeded into the in-memory ledger or a signed identifier the HTTP ledger validates. The token is opaque to the agent; the ledger is the authority on whether it has been spent.

A richer model carries a *quote* in the 402 response: "for this exact route, this exact shape, this exact rail, the price is X micros, until time T." The agent uses the quote to decide whether to pay; the quote needs to be cryptographically bound to the resource it offers, otherwise an agent can pay against a stale quote, retry against a different resource, or reuse a quote across multiple rails.

A signed quote token makes that binding explicit:

- The token's claims encode the offered route, shape, price, rail, and TTL.
- The signature lets the redeem path prove the agent paid for what was offered (not something they made up).
- A nonce in the token plus a single-use ledger table makes the token unredeemable twice.

This ADR fixes the JWS shape, the signing-key story, the verification path, the replay-protection storage, and the multi-rail nonce semantics.

## Decision

### Token shape

The quote token is a JSON Web Signature (RFC 7515) compact-serialised, with Ed25519 (`EdDSA`) as the signing algorithm. The protected header:

```json
{
  "alg": "EdDSA",
  "typ": "sbproxy-quote+jws",
  "kid": "<key id from the signing-key registry>"
}
```

The payload claims:

```json
{
  "iss": "https://api.example.com",
  "sub": "<agent_id>",
  "aud": "ledger",
  "iat": 1730462400,
  "exp": 1730462700,
  "nonce": "01J5Q3Y9...",
  "route": "/articles/foo",
  "shape": "markdown",
  "price": { "amount_micros": 5000, "currency": "USD" },
  "rail": "x402",
  "facilitator": "https://facilitator-base.x402.org",
  "quote_id": "01J5Q3Y9..."
}
```

| Claim | Type | Notes |
|---|---|---|
| `iss` | URL | The proxy's external base URL. Used by the verifier to locate the public key. |
| `sub` | string | The agent identity from the agent-class taxonomy. `unknown` and `anonymous` sentinels are valid. |
| `aud` | string | Always `"ledger"` for now. Reserved for future split (e.g. `"facilitator"` if facilitators ever verify quotes themselves). |
| `iat` | unix seconds | Issued-at. The verifier rejects tokens with `iat` more than 5 minutes in the future (clock skew tolerance). |
| `exp` | unix seconds | Expiration. The verifier rejects tokens with `exp <= now`. Default is `iat + 300` (5 minutes); operator-configurable per route up to a hard ceiling of 1 hour. |
| `nonce` | ULID string | Single-use replay guard. The ledger marks the nonce spent on first redeem. |
| `route` | path string | The route the quote was issued against. Must match the path the agent is retrying against; mismatch is a verifier rejection. |
| `shape` | enum string | Content shape from `adr-metric-cardinality.md` (`html`, `markdown`, `json`, `pdf`, `other`). Must match the shape the agent's `Accept` resolves to on retry. |
| `price` | object | `{ amount_micros, currency }`. The price the quote was offered at. Must equal the price the redeem path resolves at retry-time; a config edit between issue and redeem invalidates the quote. |
| `rail` | enum string | The rail this quote is bound to (`x402`, `mpp`). One token per rail entry. |
| `facilitator` | URL, optional | Set only when `rail = x402`. Pins which facilitator the agent committed to; the rail re-verifies the EIP-3009 receipt against this URL. |
| `quote_id` | ULID string | Stable identifier for the quote (separate from `nonce`). Lets operators correlate "quote issued" / "quote redeemed" / "quote expired" lifecycle events in the audit log. |

The compact JWS form is base64url-encoded as `<header>.<payload>.<signature>` and embedded in the 402 body as the `quote_token` field.

### Signing key

JWS signing uses an Ed25519 key pair distinct from the ledger HMAC key:

- The HMAC key is symmetric and lives only on the proxy host's secret mount. It signs the bilateral proxy-to-ledger channel. It stays exactly as it is.
- The quote-token key is asymmetric (Ed25519). The private half lives on the proxy host's secret mount alongside the HMAC key. The public half is published at a stable URL (`<base_url>/.well-known/sbproxy/quote-keys.json`, JWKS format) so the LedgerClient (which lives in-process on the proxy) and any external verifier (an agent SDK that wants to inspect a quote before paying) can both verify the signature.

We picked Ed25519 over HMAC for two reasons:

1. **Asymmetric verification.** The agent SDK and the proxy can both verify the same token without sharing a secret. Symmetric HMAC would force the agent to be a trust-domain peer of the proxy, which is not the relationship.
2. **Standard signature shape.** Ed25519 produces 64-byte signatures; HMAC-SHA256 produces 32. The compact-JWS overhead difference is small but Ed25519 is the standard choice in the JWS ecosystem (RFC 8037), so any agent SDK that already speaks JWS handles it natively.

Key lifecycle:

- The key file is loaded at startup from `SBPROXY_QUOTE_KEY_FILE` (per-line `<kid>=<base64-private-key>`). One active key, optionally one previous key in a rotation window.
- Rotation: a new key is added with a new `kid`. The proxy signs new tokens with the new key for 24 hours while still accepting redemptions of tokens signed by the previous key. After 24 hours plus the maximum quote TTL (default 1 hour), the old key is removed.
- Verification: the JWKS endpoint serves both keys during the rotation window. The verifier picks the key matching the JWS header's `kid`.

The 24-hour rotation window is calibrated to be longer than the quote TTL ceiling so no in-flight quote is invalidated by rotation. Operators can shorten it but not below `quote_ttl + 5min` (a safety check at config-load).

### Verification path

The agent presents the JWS in the redeem request as part of the retry payload. The proxy's `ai_crawl_control` policy passes the token to `LedgerClient::redeem`, which forwards it to the local ledger service. The ledger service performs the verification:

1. **Parse.** Decode the compact JWS, extract the header and the unverified claims. Reject malformed tokens with `ledger.bad_request`.
2. **Key lookup.** Find the public key matching `header.kid`. If not present, reject with `ledger.signature_invalid`.
3. **Signature.** Verify the Ed25519 signature with `subtle::ConstantTimeEq` semantics. Reject mismatch with `ledger.signature_invalid`.
4. **`exp` check.** Reject if `exp <= now` with `ledger.token_expired` (a new closed code in this ADR; an amendment to `adr-schema-versioning.md` registers it).
5. **`iat` skew check.** Reject if `iat > now + 300` (5-minute future skew tolerance) with `ledger.timestamp_skewed`.
6. **`route` match.** Reject if the claim's `route` does not equal the redeem call's resolved `path` with `ledger.bad_request`.
7. **`shape` match.** Reject if the claim's `shape` does not equal the redeem call's `content_shape` with `ledger.bad_request`. (The proxy resolves `content_shape` from the request `Accept` before calling redeem.)
8. **`price` match.** Reject if the claim's `price` does not equal the redeem call's `(amount_micros, currency)` with `ledger.bad_request`. A config edit between issue and redeem (e.g. operator changes the price) invalidates the quote and forces the agent back to a new 402.
9. **`rail` match.** Reject if the claim's `rail` does not equal the rail the agent's retry is using (the agent indicates rail in the retry request body or via a follow-up header). Mismatch is `ledger.bad_request`.
10. **Nonce single-use check.** Look up `nonce` in the `quote_tokens` table. If present (status `redeemed`), reject with `ledger.token_already_spent`. If absent, insert a row with status `redeemed` atomically with the wallet debit, in the same transaction.
11. **Wallet debit.** Standard redeem path. Returns `RedeemResult` with the redemption id, which the rail layer carries forward.

The verification is in the local ledger service, not in the proxy. The proxy only emits the token (when constructing the 402) and forwards it to the ledger (during redeem). Verification logic does not bloat the proxy's hot-path code; it lives where the wallet does.

### Replay protection: the `quote_tokens` table

Per `adr-db-migration-policy.md`, this ADR ships a new Postgres table backed by the same `refinery` migration tooling. Migration filename: `20260501_001_quote_tokens.sql`.

```sql
CREATE TABLE quote_tokens (
    workspace_id  TEXT NOT NULL,
    nonce         TEXT NOT NULL,         -- ULID, primary identifier for replay protection
    quote_id      TEXT NOT NULL,         -- ULID, stable correlation across the lifecycle
    agent_id      TEXT NOT NULL,
    route         TEXT NOT NULL,
    shape         TEXT NOT NULL,
    rail          TEXT NOT NULL,
    amount_micros BIGINT NOT NULL,
    currency      CHAR(3) NOT NULL,
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    redeemed_at   TIMESTAMPTZ,           -- NULL until redeemed
    redemption_id TEXT,                  -- FK-style link to redeemed_tokens.id
    PRIMARY KEY (workspace_id, nonce)
);

CREATE INDEX quote_tokens_expires_idx ON quote_tokens (expires_at)
    WHERE redeemed_at IS NULL;
CREATE INDEX quote_tokens_quote_id_idx ON quote_tokens (workspace_id, quote_id);
```

Behaviour:

- **Issue.** When the proxy emits a 402 with quote tokens, it inserts one row per rail entry into `quote_tokens` with `redeemed_at = NULL`. The insert is asynchronous so the 402 response does not block on Postgres; the audit-log buffer absorbs the write. (Trade-off below.)
- **Redeem.** The redeem path runs an atomic `UPDATE quote_tokens SET redeemed_at = now(), redemption_id = $1 WHERE workspace_id = $2 AND nonce = $3 AND redeemed_at IS NULL RETURNING ...`. Zero rows updated means either the nonce does not exist or it was already redeemed; either way the redeem is rejected.
- **Sweep.** A nightly worker deletes rows where `expires_at < now() - interval '7 days'`. The 7-day grace window covers post-hoc audit / dispute lookups. Operators can extend with a per-deployment override.

The asynchronous-insert trade-off means a small race exists: an agent that retries faster than the Postgres write can land could in principle redeem a token whose `quote_tokens` row has not yet been inserted. The race is harmless because the redeem path's `UPDATE` returns zero rows (nonce not present), which the ledger interprets as "unknown nonce" and rejects with `ledger.bad_request`. The agent gets a 402 with a fresh quote; no double-charge, no security gap. The only cost is one extra round-trip on a fast-retry edge case, which is acceptable for the alternative of synchronous Postgres writes on every 402 response.

If operators run multiple proxies behind a load balancer, the `quote_tokens` table is the shared replay-protection store. Per-proxy in-memory nonce caches are not allowed because they would let a fast agent redeem the same nonce against two different proxies before the row reaches Postgres.

### TTL policy

Default TTL is 5 minutes (`exp = iat + 300`). Operator-configurable per route in the policy:

```yaml
policies:
  - type: ai_crawl_control
    quote_token:
      default_ttl_seconds: 300
      max_ttl_seconds: 3600          # hard ceiling, refused at config load if exceeded
    tiers:
      - route_pattern: /premium/*
        quote_ttl_seconds: 60        # short-lived for high-value content
      - route_pattern: /preview/*
        quote_ttl_seconds: 1800      # 30 minutes for cheap previews
```

The hard ceiling (1 hour) is non-overridable. Longer TTLs defeat the replay-protection model: a 24-hour quote is a 24-hour window for an attacker who steals the token to re-use it (subject to nonce single-use, but the wider the window, the more time to construct a downstream attack). The 1-hour ceiling balances agent convenience against attack surface.

The verifier rejects tokens whose effective TTL exceeds the ceiling, even if the issuer was misconfigured to emit them. This is a defence-in-depth check; the issuer should never produce a too-long token.

### Per-shape ties

The `shape` claim binds the quote to the content shape the agent asked for. The resolver picks a tier based on `Accept` and emits the matched shape into the quote. On redeem, the proxy re-resolves `Accept` (in case the agent's retry uses a different `Accept`) and compares against the quote's `shape`. Mismatch is a server bug or a misbehaving agent; either way the redeem fails and the audit trail captures the divergence.

The closed `shape` enum (`html`, `markdown`, `json`, `pdf`, `other`) matches the cardinality budget for `content_shape` in `adr-metric-cardinality.md`. Adding a shape goes through `adr-schema-versioning.md` (closed enum amendment, deprecation window).

### Multi-rail tokens

A single 402 response can advertise multiple rails. Each rail entry carries its own quote token with its own `nonce`. The agent picks one rail and redeems that rail's token; the others expire on TTL and the nightly sweep removes them.

The tokens for a single 402 response share `quote_id` (the operator-correlation field) but have distinct `nonce` values. So an audit query like "show me all the rails offered for quote_id X" works, but each `nonce` is independently single-use. An agent that tries to redeem two tokens from the same 402 response (presumably a misbehaving or compromised agent) succeeds on the first and fails on the second with `ledger.bad_request` (the second rail's `rail` claim does not match what the agent retried with, or the wallet rejects double-debit).

The wallet-side debit happens once per redeem, against the price in the redeemed token. If a 402 offers x402 at $0.001 USD and MPP at $0.001 USD and the agent redeems the x402 token, the wallet sees one $0.001 debit. The MPP token's nonce stays unspent and expires on TTL. Per-rail price differences would land in this slot without changing the protocol.

## Consequences

- The redeem path is now cryptographically bound to the offer. An agent cannot pay against a stale or forged offer; the proxy verifies the same claims it issued.
- Asymmetric signatures let the agent SDK verify quotes before paying, which is the right pattern for a paying customer who wants to know the offer is authentic. The HMAC stays exactly where it is; this ADR adds a sibling key, not a replacement.
- The `quote_tokens` table is a new Postgres write. The asynchronous-insert pattern keeps the 402 response off the Postgres critical path; the cost is the rare race window where a fast agent retries before the insert lands. The race is harmless.
- The 1-hour TTL ceiling is a meaningful defence-in-depth. Operators who want longer windows must justify why; the ADR amendment process gates relaxation.
- Closed enum on `shape` and `rail` plus the `adr-schema-versioning.md` deprecation rules mean adding a new shape (e.g. `audio`) or a new rail (e.g. Lightning) is a documented, gated process. The escape hatch is intentional friction.
- The multi-rail per-token nonce model means the agent must commit to one rail at redemption time. They cannot redeem two tokens from the same 402 to game the rail selection; the second redeem fails on the wallet side regardless.
- Key rotation is a 24-hour process; the rotation window plus the quote TTL ceiling means no in-flight quote is invalidated by rotation. Operators who need faster rotation are doing something wrong (a leaked private key is a security incident, not a rotation event).

## Alternatives considered

**HMAC-signed tokens instead of Ed25519 JWS.** Considered. Rejected because the agent cannot verify HMAC without the shared secret; the asymmetric model is the right shape for agent-side verification. HMAC also rules out third-party verifiers (e.g. a wallet UI that wants to show "this offer is authentic"). The 32-byte saving is not worth the topology constraint.

**Reuse the ledger HMAC key for the JWS.** Rejected. Two different trust relationships should not share a key. The HMAC is bilateral (proxy-to-ledger, both sides have the key); the JWS is asymmetric (proxy issues, anyone verifies). Sharing the key collapses the topology and creates rotation entanglement.

**No nonce; rely on `(quote_id, exp)` for replay protection.** Considered. Rejected because `quote_id` is a correlation field, not a nonce. Two tokens with different `quote_id` could share the same `(route, shape, price, rail)`; the nonce is what makes each token unique. The `nonce` plus `quote_tokens` table is the right idiomatic shape (RFC 7519 § 4.1.7).

**Synchronous insert into `quote_tokens` on 402 issue.** Rejected. Adds Postgres latency to every 402 response, which is a fast-path concern for high-volume crawl deployments. The async-insert race is harmless (verifier rejects unknown nonce as `bad_request`), so we pay the consistency cost on the rare retry-faster-than-write case rather than on every 402.



**Token TTL of 24 hours by default.** Rejected. The 5-minute default is calibrated against agent retry behaviour; an agent that takes longer than 5 minutes to pay has typically encountered a problem (rail outage, balance issue) that re-quoting will surface anyway. The 1-hour ceiling is the maximum the ADR allows.

**Embed the full price ledger row in the token (avoid per-redeem price match).** Rejected. The token would carry too much state; price changes between issue and redeem are a feature (the agent should be re-quoted), not a bug. The price-match check is the right enforcement.

## References

- `adr-billing-hot-path-vs-async.md` (the layering rule; the verifier lives in the local ledger service, not the proxy).
- `adr-http-ledger-protocol.md` (the redeem path that carries the JWS to the verifier; new error code `ledger.token_expired` is added under a closed-enum amendment).
- `adr-schema-versioning.md` (the closed-enum rules for `shape` and `rail`).
- `adr-db-migration-policy.md` (the migration tooling for the `quote_tokens` table).
- Companion ADRs: `adr-billing-rail-x402-mpp-mapping.md` and `adr-multi-rail-402-challenge.md`.
- RFC 7515: JSON Web Signature.
- RFC 7519: JSON Web Token (claim conventions for `iss`, `sub`, `aud`, `iat`, `exp`, `nonce`).
- RFC 8037: CFRG Elliptic Curve Diffie-Hellman (Ed25519 in JWS).
- ULID spec for the nonce and `quote_id` shapes: <https://github.com/ulid/spec>.
