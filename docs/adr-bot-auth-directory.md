# ADR: Web Bot Auth directory cache (Wave 1 / A1.3)

*Last modified: 2026-04-30*

## Status

Accepted. Consumed by G1.7 (dynamic Web Bot Auth directory refresh in `sbproxy-modules/auth/bot_auth.rs`), Q1.4 (e2e regression for refresh, TTL, self-signature, HTTPS-only, negative caching), and Q1.7 (conformance test against `draft-meunier-web-bot-auth-architecture-05` and `draft-meunier-http-message-signatures-directory-05`).

## Context

Today `bot_auth` (`crates/sbproxy-modules/src/auth/bot_auth.rs`) carries a *static* directory of agent public keys, configured inline in `sb.yml`. That works for an OSS demo but operators have to redeploy the proxy whenever a vendor rotates a key. The Web Bot Auth drafts define a hosted directory at `/.well-known/http-message-signatures-directory` in JWKS form, which agents reference via the `Signature-Agent` request header.

Wave 1 G1.7 extends `bot_auth` to fetch and refresh that directory at runtime. The mechanics are straightforward but every operational corner case (cache TTL, negative caching, what happens when the directory becomes unreachable, what to trust about a directory's own signature, plain-HTTP attack surface) is independently load-bearing. Picking the policy now means G1.7 ships a reviewed implementation, not a series of follow-up incidents.

The drafts referenced:

- `draft-meunier-web-bot-auth-architecture-05`: the overall protocol shape.
- `draft-meunier-http-message-signatures-directory-05`: the JWKS-flavoured directory format and `Signature-Agent` header semantics.
- `draft-rescorla-anonymous-webbotauth-00`: the anonymous variant we honour at the resolver layer (G1.4).

## Decision

Define cache semantics, signature trust rules, transport rules, and `Signature-Agent` resolution. Configure each via `sb.yml` with conservative defaults that match the draft guidance.

### Directory shape

The directory is fetched as `application/http-message-signatures-directory+json`, JWKS-shaped:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64url-key",
      "kid": "thumbprint",
      "alg": "EdDSA",
      "use": "sig",
      "agent": "openai-gptbot",
      "valid_from": "2026-04-01T00:00:00Z",
      "valid_until": "2026-07-01T00:00:00Z"
    }
  ]
}
```

The `agent` extension field is read but not required; absent it, the cache stores the key under `kid` only. `valid_from` / `valid_until` are honoured: keys outside their validity window are loaded but flagged as not-yet-valid or expired and not used for verification.

### Configuration

Per-origin, in `sb.yml`:

```yaml
authentication:
  type: bot_auth
  directory:
    url: https://bot-auth.openai.example/.well-known/http-message-signatures-directory
    refresh_interval: 24h           # JWKS TTL, default 24 h
    negative_cache_ttl: 5m          # default 5 m
    stale_grace: 24h                # serve stale this long past TTL on fetch failure
    require_self_signature: true    # default true
    pin:
      sha256_thumbprints:           # optional cert-pin on the directory's TLS leaf
        - "abc123..."
    signature_agents:
      allow:                        # exact-match allowlist for `Signature-Agent` URLs
        - https://bot-auth.openai.example
        - https://bot-auth.anthropic.example
```

`refresh_interval`, `negative_cache_ttl`, and `stale_grace` accept duration strings (`24h`, `30m`, `5m`). `require_self_signature`, `pin.sha256_thumbprints`, and `signature_agents.allow` carry conservative defaults; an operator can relax them but a relaxation is visible in the diff.

### JWKS TTL

Default 24 h, configurable via `directory.refresh_interval`. The proxy refreshes the directory on the first request after the TTL expires (lazy refresh) *and* in the background on a fixed timer (eager refresh). Eager refresh runs a 1-minute random jitter to avoid synchronized refresh storms across a fleet.

The fetcher honours `Cache-Control: max-age` from the directory response *only* when it is shorter than the configured `refresh_interval`. A directory cannot extend its own cache beyond the operator's policy.

### Negative caching

When a directory fetch fails (network error, 5xx, signature verification failure), we cache the failure for `negative_cache_ttl` (default 5 minutes) before retrying. Negative caching prevents a tight loop hammering a broken directory under load. A 4xx that is not retryable (404, 403) caches for the same window; a 401 / 403 also surfaces a `tracing::error!` because it likely means a config drift on the operator's side.

The cache key is the directory URL. Per-key negative caching is not needed: the failure is at the directory level, not the individual key level.

### Stale-while-fail

When a fetch fails *and* a previously-fetched directory exists in the cache *and* the cached copy is within `stale_grace` of its expiry (default 24 h past `refresh_interval`), the proxy continues to verify signatures against the stale copy. Counters:

- `sbproxy_bot_auth_directory_stale_serves_total{directory_url}` increments on each verification served from a stale copy.
- `sbproxy_bot_auth_directory_fetch_failures_total{directory_url, reason}` increments on the underlying fetch failure (`reason ∈ {network, http_5xx, http_4xx, signature_invalid, parse_error}`).

After `stale_grace` is exceeded the directory is evicted. Verifications then fall through to `BotAuthVerdict::UnknownAgent` (or `Missing` when the request had no signature at all). This is the *fail-closed* end state: an indefinitely-unreachable directory means the proxy treats requests as unverified. The current `bot_auth` policy already maps `UnknownAgent` to deny; this ADR does not change that.

Operators alert on `sbproxy_bot_auth_directory_fetch_failures_total > 0` for more than two consecutive refresh windows. The `stale_grace` window gives them time to act before the fall-through hits production.

### Directory self-signature

The directory itself MUST be signed. Default policy (`require_self_signature: true`):

The directory body is signed by one of the keys in the directory body. The signature appears in a `Signature` header on the directory response (RFC 9421 message signature), with `keyid` referring to a key inside the JWKS. The proxy verifies the signature *before* admitting any key into the cache. A directory that does not self-sign is rejected (`signature_invalid`); the reject is negative-cached for `negative_cache_ttl`.

Self-signature is what bridges the trust gap: the operator running the proxy did not pre-share a key with the directory, but they did pre-share a *URL* and a transport check. The self-signature lets the directory bootstrap its own trust on first fetch, with the TLS certificate as the root.

When `require_self_signature: false`, the proxy still attempts verification but admits the directory on signature-verify failure with a `tracing::warn!`. This relaxation exists for the early days of the draft when not all directories have implemented self-signing yet; it should not be the default in production.

Rotation: a new key entering the directory is signed by an *existing* key (not the new one). The operator publishes the new key in the directory body, the directory is re-signed by the still-valid prior key, the proxy fetches and admits the new key, and only then can the directory transition to signing with the new key. Standard JWKS rollover.

### HTTPS enforcement

The directory URL must be `https://`. `http://` is rejected at config-load time with a hard error. The TLS connection uses the system trust roots; operators can pin via `directory.pin.sha256_thumbprints` (SHA-256 of the leaf certificate's DER). Pinning is off by default because most directory operators are on Let's Encrypt with rotating certs and pinning is a footgun unless the operator knows what they are doing.

We enforce TLS 1.2 minimum, prefer TLS 1.3, and reject any cipher in the `LOW`/`MEDIUM` OpenSSL classes. This matches the rest of the proxy's outbound TLS profile (`sbproxy-tls`).

### `Signature-Agent` resolution

A request signed under Web Bot Auth carries:

- `Signature-Input`: the RFC 9421 signature input header (already handled by `MessageSignatureVerifier`).
- `Signature`: the actual signature.
- `Signature-Agent`: a URL pointing at the directory the proxy should consult.

Resolution rules:

1. **Allowlist check.** If `signature_agents.allow` is set, the request's `Signature-Agent` URL must exact-match one of the allowed entries. No prefix match, no wildcard. Mismatch maps to `BotAuthVerdict::UnknownAgent`. Allowlist absent means "accept any URL", which is appropriate for a hub deployment but is *not* the default in `sb.yml` for a single-origin deployment; the example template ships with the empty `allow: []` and a comment to populate it.
2. **HTTPS check.** Reject `http://` `Signature-Agent` values, even if the static config's directory URL is HTTPS. A request that wants the proxy to talk to a plaintext directory is rejected outright.
3. **Cache lookup.** If the URL has a fresh cache entry (within TTL or within `stale_grace` after a fetch failure), use it.
4. **Fetch on miss or staleness.** Fetch the directory inline at the request path. Fetch deadline is 2 s; on deadline expiry we serve from stale (if available) or fall through to `UnknownAgent`. Inline fetch is rate-limited at the (request-path, directory-URL) tuple to one in-flight request per cache key (a lock on the cache slot). Concurrent requests targeting the same fresh-on-fetch entry coalesce on a single fetch.
5. **Verify.** Use the `keyid` from `Signature-Input` to look up the key in the directory. Verify the request signature with that key.

When no `Signature-Agent` header is present, the resolver falls back to the statically-configured directory in `directory.url`. Static configuration remains the OSS-friendly default for operators who want to enumerate their accepted agents inline.

### Failure modes and counters

| Mode | Verdict | Counter |
|---|---|---|
| Fresh cache hit, signature valid | `Verified` | `sbproxy_bot_auth_verifications_total{result="verified"}` |
| Cache miss, fetch ok, signature valid | `Verified` | `sbproxy_bot_auth_directory_fetches_total{result="ok"}` |
| Cache miss, fetch fail, stale available | `Verified` (using stale) | `sbproxy_bot_auth_directory_stale_serves_total` |
| Cache miss, fetch fail, no stale | `UnknownAgent` | `sbproxy_bot_auth_directory_fetch_failures_total` |
| Self-signature fails | (directory rejected) | `sbproxy_bot_auth_directory_fetch_failures_total{reason="signature_invalid"}` |
| `Signature-Agent` HTTPS check fails | `UnknownAgent` | `sbproxy_bot_auth_signature_agent_rejected_total{reason="not_https"}` |
| `Signature-Agent` allowlist mismatch | `UnknownAgent` | `sbproxy_bot_auth_signature_agent_rejected_total{reason="not_allowlisted"}` |
| Inline fetch deadline exceeded | (stale or `UnknownAgent`) | `sbproxy_bot_auth_directory_fetch_deadline_exceeded_total` |

All counters honour the cardinality budget in `adr-metric-cardinality.md`. `directory_url` is high-cardinality in principle (one per agent operator) but bounded by the allowlist plus the static config URL; the `CardinalityLimiter` workspace cap (200) handles the unbounded-allowlist case.

### Concurrency and fetch coalescing

A `tokio::sync::OnceCell` per cache entry guards the fetch. The first request to find a stale or missing entry initiates the fetch; concurrent requests for the same entry await the same future. This prevents a thundering-herd refresh when 1k requests hit a just-expired entry simultaneously.

### Crate placement

The directory cache, fetcher, and self-signature verifier live in a new `sbproxy-modules::auth::bot_auth_directory` submodule. The existing `BotAuthProvider` gains a `Directory` trait dependency that the static-config path satisfies via a `StaticDirectory` impl and the dynamic path satisfies via `HostedDirectory`. The verdict surface (`BotAuthVerdict` in `bot_auth.rs`) is unchanged.

JWKS parsing, signature verification, and the timer for eager refresh are implemented in pure Rust (no `openssl` dependency); `ring` and `ed25519-dalek` already cover the algorithms in scope.

### What this ADR does NOT decide

- The KYA (Skyfire) token verification path. Owned by a future ADR (Wave 5 identity-and-fingerprinting).
- The reverse-DNS verification interplay. Owned by `adr-agent-class-taxonomy.md` and G1.5 implementation; the bot-auth path is one input to the resolver, rDNS is another.
- Anonymous Web Bot Auth rate-limiting. Owned by a Wave 5 ADR; the resolver routes anonymous-signed requests to `agent_id="anonymous"` (per the taxonomy ADR), and the rate limit is a separate concern.

## Consequences

- Operators get key rotation without redeploys. A vendor publishes a new key, the directory re-signs with the prior key, and the proxy picks up the change on next refresh.
- The directory cannot extend its own cache window past the operator's policy. A compromised or runaway directory is bounded by `refresh_interval`.
- A failing directory does not cascade: stale-while-fail keeps verifications working for `stale_grace` (default 24 h), giving operators a workday window to react.
- Self-signature verification is the single trust check on the directory body; without it, an MITM with a forged TLS cert (or an untrusted CA) could inject keys. With it, the attacker also needs the directory's signing key.
- HTTPS enforcement on both the static URL and inbound `Signature-Agent` headers eliminates the "downgrade the protocol" attack class.
- The `signature_agents.allow` allowlist gives single-origin deployments a tight default. A request can name any directory it likes, but the proxy refuses to fetch from one the operator has not approved.
- Inline fetch is rate-limited and deadline-bound, so a slow directory cannot slow inbound requests beyond the 2 s deadline before the fall-through path runs.
- Counter granularity (`directory_url`, `reason`) is bounded by the allowlist; operators retain the ability to alert on per-directory health without breaking the cardinality budget.

## Alternatives considered

**No negative caching.** Rejected. Under any directory failure the request rate is unbounded, the directory operator's load goes up, and the proxy becomes a scrape amplifier. 5 minutes of negative caching is a small price for breaking that loop.

**No self-signature requirement.** Rejected as a default. Without self-signature, the only authenticity check is TLS, and the trust boundary becomes "anyone with a cert from any public CA can serve a directory." Self-signature with the directory's own key adds a second factor that survives CA compromise.

**Aggressive 1-hour TTL.** Rejected. Most key rotations are scheduled events (vendor publishes a 90-day rotation calendar). A 24 h TTL is enough to pick up rotations within the same business day while keeping background fetch traffic to an unobjectionable level (around 24 fetches per directory per day, with jitter).

**Allow plaintext `Signature-Agent` URLs in dev mode.** Rejected. The same argument as in `adr-http-ledger-protocol.md`: the cost of one misconfigured production deployment outweighs the convenience of skipping local TLS setup. Developer examples ship with self-signed certs.

**Eager-only refresh, no inline fetch on miss.** Considered. Eager-only is simpler and avoids the 2 s deadline corner case, but it punts the cold-start problem (a fresh proxy with no cache) to "wait one refresh window before any signed request can verify." The hybrid (lazy + eager) is the right default; deadline-bound inline fetch is a manageable operational corner.

## References

- `docs/AIGOVERNANCE-BUILD.md` §4.1 (Wave 1 architect task A1.3, sbproxy-rust task G1.7, qa tasks Q1.4 and Q1.7).
- `docs/AIGOVERNANCE.md` §3.1 (agent discovery and fingerprinting), §4.1 (identity and signing standards).
- `crates/sbproxy-modules/src/auth/bot_auth.rs` (existing static-directory implementation).
- `crates/sbproxy-modules/src/auth/jwks.rs` (existing JWKS parser, reused here).
- IETF drafts: `draft-meunier-web-bot-auth-architecture-05`, `draft-meunier-http-message-signatures-directory-05`, `draft-rescorla-anonymous-webbotauth-00`.
- RFC 9421 (HTTP Message Signatures).
- Companion ADRs: `adr-agent-class-taxonomy.md` (`expected_keyids` bridges static catalog to directory), `adr-metric-cardinality.md` (counter labels here respect the budget there).
