# ADR: Skyfire KYA token format and verification

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-bot-auth-directory.md`, `adr-agent-class-taxonomy.md`, `adr-admin-action-audit.md`, `adr-schema-versioning.md`, and `adr-multi-rail-402-challenge.md`.

## Context

Skyfire (backed by a16z and Coinbase Ventures) publishes KYA (Know Your Agent) tokens that act as agent-side identity credentials. Unlike Web Bot Auth, which requires the agent to cryptographically sign every individual request, KYA is a session-level or hourly-level identity assertion: the agent presents a signed token once, and the gateway verifies it to establish durable identity for the session.

Akamai and TollBit already verify KYA tokens in production. For SBproxy to claim parity with Akamai in the agent-identity column, this ADR ships a KYA verifier.

Three design questions shape this ADR:

1. What is the token format and which claims are normative for the verifier?
2. Where does KYA fit in the existing four-step agent_class resolver chain from `adr-agent-class-taxonomy.md`?
3. How does KYAPay - the payment side of the Skyfire protocol - interact with the multi-rail 402 challenge?

## Decision

### Token format

KYA tokens are JWS-signed JWTs in compact serialization (RFC 7519 + RFC 7515). The protected header carries `alg`, `typ`, and `kid`. Skyfire's production issuer signs with ES256 (ECDSA P-256 + SHA-256). The gateway must accept ES256 and RS256; all other algorithms are rejected at decode time. The `kid` references the signing key in the issuer's JWKS.

Standard claims (all required):

| Claim | Type | Notes |
|---|---|---|
| `iss` | URL | Must match an entry in the operator's issuer allowlist before any JWKS fetch. |
| `sub` | string | The agent's stable identifier in Skyfire's namespace (e.g. `agent:skyfire.io:openai-gptbot-prod`). Mapped to `agent_id` at verdict time. |
| `aud` | string or array | Must include this gateway's hostname or the literal `"*"`. |
| `iat` | unix seconds | Skew tolerance plus or minus 2s per the clock-sync requirement. |
| `exp` | unix seconds | Reject when `exp <= now`. |
| `jti` | string | Unique token identifier for replay detection via the KYA denylist. |

KYA-specific claims (unregistered per RFC 7519 section 4.3):

| Claim | Type | Notes |
|---|---|---|
| `agent_id` | string | Skyfire's internal agent identifier. Distinct from the SBproxy `agent_id` in the agent-class taxonomy; mapped at verdict time. |
| `agent_class` | string | Skyfire's classification: one of `"crawler"`, `"assistant"`, `"llm-agent"`, `"headless"`. Advisory; does not override the resolver result. |
| `vendor` | string | Human-readable vendor name (e.g. `"OpenAI"`, `"Anthropic"`). |
| `kya_version` | string | KYA spec version. Current: `"1.0"`. Unknown versions are logged but not rejected per `adr-schema-versioning.md` Rule 1. |
| `kyab_balance` | object | Optional. Schema: `{ "amount": u64, "currency": "USD", "expires_at": "<RFC 3339>" }`. The gateway reads this field but does not act on it directly (see KYAPay section below). |

### Worked example: token shape

```
Header: { "alg": "ES256", "typ": "JWT", "kid": "skyfire-prod-2026-q2" }

Payload:
{
  "iss": "https://api.skyfire.io",
  "sub": "agent:skyfire.io:openai-gptbot-prod",
  "aud": ["news.example.com"],
  "iat": 1746834000,
  "exp": 1746837600,
  "jti": "01JVKPZN3G8HXWQ4Y7D",
  "agent_id": "oai-gptbot-v1",
  "agent_class": "crawler",
  "vendor": "OpenAI",
  "kya_version": "1.0"
}
```

The `exp - iat` window is 3600 seconds. The gateway caches the verified result for `min(exp - now, kya_cache_ttl)`.

### Verification flow

The verifier lives in `sbproxy-modules/auth/kya.rs`. It mirrors the structural pattern from `bot_auth_directory.rs`: JWKS fetch, cache, and self-signature verification logic are reused.

1. **Extract token.** KYA tokens arrive in the `X-Skyfire-KYA` request header. A missing header produces `KyaVerdict::Missing`.
2. **Decode header without verification.** Extract `kid` and `alg`. Reject immediately if `alg` is not `ES256` or `RS256`.
3. **Allowlist check.** The `iss` claim must match an entry in the operator's issuer allowlist before any JWKS fetch.
4. **JWKS cache lookup.** Cache key is the issuer URL. TTL is clamped to [5min, 24h]. Lazy refresh on cache miss plus eager background refresh with 1-minute random jitter. Negative caching on fetch failure: 5-minute TTL before retry.
5. **Verify signature.** Look up the key by `kid`. Verify the JWT signature. Reject on mismatch.
6. **Verify standard claims.** Check `exp >= now`, `iat <= now + 2s`, `aud` contains this gateway's hostname or `"*"`.
7. **Denylist check.** Fetch the issuer's denylist at `iss + "/.well-known/kya-denylist.json"`. Reject if `jti` appears.
8. **Emit verdict.** `KyaVerdict::Verified { agent_id, vendor, agent_class, kya_version, sub }`.

Inline JWKS fetch deadline: 2 seconds. Concurrent requests for the same issuer coalesce on a single fetch via a `tokio::sync::OnceCell` per cache entry.

### Worked example: verification in practice

Agent presents `X-Skyfire-KYA: <token>` on `GET /articles/breaking-news`:

1. `alg=ES256` accepted.
2. `iss = "https://api.skyfire.io"` in allowlist.
3. JWKS cache hit. Key `skyfire-prod-2026-q2` found. Signature verifies.
4. `exp = 1746837600 > now = 1746835000`. `iat = 1746834000 <= now + 2`. `aud` includes `"news.example.com"`.
5. `jti = "01JVKPZN3G8HXWQ4Y7D"` not in denylist.
6. Verdict: `KyaVerdict::Verified { agent_id: "oai-gptbot-v1", vendor: "OpenAI", ... }`.
7. Resolver maps `vendor = "OpenAI"` + `agent_class = "crawler"` to `AgentClass::id = "openai-gptbot"` via the taxonomy catalog.

### Where KYA fits next to Web Bot Auth

Web Bot Auth and KYA are complementary, not alternative.

- **Web Bot Auth** - the agent signs each request with HTTP Message Signatures (RFC 9421). Per-request key possession proof.
- **KYA** - the agent presents a Skyfire-issued token once per session or hour. Session-level issuer-mediated identity attestation.

When both are present, the resolver applies them in this order:

1. Web Bot Auth keyid lookup (step 1, highest confidence).
2. KYA token verification (new step 1.5).
3. Reverse-DNS verification (step 2).
4. User-Agent regex match (step 3).
5. Anonymous Web Bot Auth (step 4).
6. Fallback sentinels `unknown` / `human`.

KYA sits at step 1.5 because bot-auth is cryptographically stronger. On conflict - bot_auth keyid resolves to `openai-gptbot` but KYA `agent_id` claims a different vendor - the bot-auth verdict wins. The conflict is logged at `tracing::warn!` with both verdicts. Rationale: per-request key possession proof cannot be forged by presenting a stolen session token; the stronger evidence wins.

The `agent_id_source` field on `RequestContext` gains the new value `kya`. Existing consumers must handle this per `adr-schema-versioning.md` Rule 3 (closed-enum amendment).

### Token refresh and revocation

Refresh is the agent's responsibility. The gateway does not issue KYA tokens.

**Gateway-side caching.** Cache key is `(iss, jti)`. TTL is `min(exp - now, kya_cache_ttl)` where `kya_cache_ttl` defaults to 1 hour. This avoids re-verifying the same token on every request within its lifetime.

**Revocation.** KYA uses a JWT denylist at `iss + "/.well-known/kya-denylist.json"` - a JSON array of revoked `jti` values. The gateway fetches and caches it with the same TTL and negative-caching parameters as the JWKS. A `jti` in the denylist produces `KyaVerdict::Revoked`. The denylist is stored as a `HashSet<String>` in memory; at 64 bytes per `jti`, a 100k-entry denylist is 6 MB.

### Trust anchor management

**Single-tenant configuration in `sb.yml`:**

```yaml
authentication:
  type: kya
  issuers:
    - url: https://api.skyfire.io
      jwks_refresh_interval: 1h
      negative_cache_ttl: 5m
      stale_grace: 24h
      audience_check: hostname
  cache_ttl: 1h
  fail_open: false
```

Default issuer is `https://api.skyfire.io`. Operators add partner issuers as additional list entries.

**Multi-tenant deployments.** Per-tenant trust anchors are configured in the per-tenant config store, hot-reloadable via SIGHUP, and every change emits an `AdminAuditEvent` with `target_kind = "KyaTrustAnchor"` per `adr-admin-action-audit.md`.

### Failure modes and verdicts

| Mode | Verdict | Counter |
|---|---|---|
| No `X-Skyfire-KYA` header | `KyaVerdict::Missing` | (no counter; handled by origin policy) |
| `alg` not in allowed set | `KyaVerdict::Invalid { reason: "unsupported_alg" }` | `sbproxy_kya_verifications_total{result="invalid_alg"}` |
| `iss` not in allowlist | `KyaVerdict::Invalid { reason: "untrusted_issuer" }` | `sbproxy_kya_verifications_total{result="untrusted_issuer"}` |
| JWKS unavailable past stale_grace | `KyaVerdict::DirectoryUnavailable` | `sbproxy_kya_directory_fetch_failures_total{reason}` |
| Signature invalid | `KyaVerdict::Invalid { reason: "signature_invalid" }` | `sbproxy_kya_verifications_total{result="sig_invalid"}` |
| `exp <= now` | `KyaVerdict::Expired` | `sbproxy_kya_verifications_total{result="expired"}` |
| `aud` mismatch | `KyaVerdict::Invalid { reason: "audience_mismatch" }` | `sbproxy_kya_verifications_total{result="aud_mismatch"}` |
| `jti` in denylist | `KyaVerdict::Revoked` | `sbproxy_kya_verifications_total{result="revoked"}` |
| All checks pass | `KyaVerdict::Verified { ... }` | `sbproxy_kya_verifications_total{result="verified"}` |

`KyaVerdict::DirectoryUnavailable` mirrors `BotAuthVerdict::DirectoryUnavailable`. The origin policy controls fail-open vs fail-closed. Default is fail-closed (`fail_open: false`).

### Worked example: fail-open vs fail-closed

Skyfire's JWKS endpoint is down and the cache has expired past `stale_grace`:

- `fail_open: false` (default): request denied 401. Counter: `sbproxy_kya_directory_fetch_failures_total{reason="stale_grace_exceeded"}`.
- `fail_open: true`: request proceeds with `KyaVerdict::DirectoryUnavailable`. Resolver falls through to rDNS or UA. Operators who set `fail_open: true` should alert on `sbproxy_kya_directory_fetch_failures_total`.

### Audit envelope

Each KYA verification result emits an audit event per `adr-admin-action-audit.md`:

- `target_kind = "KyaVerification"` (new closed-enum variant; closed-enum amendment required)
- `action = "KyaVerify"` (new `AuditAction` variant; closed-enum amendment required)
- `after = { verdict, agent_id, vendor, jti, iss }`
- `subject` = the gateway's own service identity

Sampling: 1 event per N verifications, N defaults to 100, configurable via `audit.kya_sample_rate`. Full verification stream goes to ClickHouse via async ingest. At 10k rps and sample rate 1/100 the audit pipeline sees approximately 100 events/second.

### KYAPay and the multi-rail 402 challenge

KYAPay is the integrated payment side of Skyfire. An agent holding a KYA token with a `kyab_balance` claim has a pre-funded Skyfire balance.

**Position: KYAPay is not a fourth rail today.** Three reasons:

1. KYAPay settlement requires Skyfire as a centralized intermediary in the payment path. The proxy keeps rail calls async and out of the hot path.
2. The KYAPay settlement API (as of 2026-05) has not reached the production stability of x402 v2 (Linux Foundation GA) and MPP (Stripe + Tempo GA on `2026-03-04.preview`).
3. The `kyab_balance` claim is advisory.

The KYA verifier exposes `kyab_balance` in `KyaVerdict::Verified` so scripting (CEL/Lua/JS/WASM) can read `request.kya.kyab_balance.amount` and make policy decisions. That is a scripting-layer opt-in, not a protocol-layer rail.

Future follow-up: evaluate KYAPay as a fourth `rails[]` entry. The 402 schema accommodates a new `kind` value via the closed-enum amendment path.

## Consequences

- SBproxy gains parity with Akamai and TollBit on KYA token verification.
- The resolver chain gains step 1.5. Operators without KYA issuers configured see no behavior change.
- Bot-auth wins over KYA on conflict. Per-request cryptographic proof outweighs session-level issuer attestation.
- KYAPay deferral leaves the 402 challenge pipeline unchanged.
- Three new closed-enum variants require ADR amendment entries on ship: `AuditAction::KyaVerify`, `AuditTarget::KyaVerification`, `AgentIdSource::Kya`.

## Alternatives considered

**KYA as step 1, overriding bot-auth on conflict.** Rejected. Bot-auth provides stronger per-request cryptographic proof. A stolen session token should not be able to override a per-request key possession check.

**Merge JWKS cache with the bot-auth-directory cache.** Considered. TTL parameters, negative-caching semantics, self-signature requirements, and denylist behavior are different enough that a shared cache adds obscuring branches. Two separate cache implementations with a shared fetch utility is cleaner.

**KYAPay as a rail today.** Rejected. API stability, hot-path dependency, and the async-rail rule block it.

## References

1. `docs/adr-bot-auth-directory.md` - directory cache and `BotAuthVerdict::DirectoryUnavailable` pattern mirrored here.
2. `docs/adr-agent-class-taxonomy.md` - `AgentIdSource` enum and resolver chain extended here.
3. `docs/adr-admin-action-audit.md` - audit envelope and sampling.
4. `docs/adr-schema-versioning.md` - closed-enum amendment rules.
5. `docs/adr-multi-rail-402-challenge.md` - 402 body that KYAPay may extend later.
6. `crates/sbproxy-modules/src/auth/bot_auth.rs` - `BotAuthVerdict` pattern mirrored by `KyaVerdict`.
7. Skyfire: `https://skyfire.xyz`.
8. RFC 7515 (JWS), RFC 7519 (JWT).
9. `draft-meunier-web-bot-auth-architecture-05` - the complementary per-request protocol.
