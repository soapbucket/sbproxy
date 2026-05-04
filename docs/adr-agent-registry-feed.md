# ADR: Agent registry feed and reputation scoring

*Last modified: 2026-05-03*

## Status

Accepted. Implements the hosted-feed shape reserved by `adr-agent-class-taxonomy.md`. Mirrors the publisher / subscriber pattern of the WAF feed. Consumed by the agent_class resolver, the per-agent metric label set, the DCR endpoint (`adr-agent-dcr.md`), and publisher dashboards.

## Context

`adr-agent-class-taxonomy.md` defines `AgentClass` and pins a sketch for a hosted, signed JSON feed. The embedded default catalog plus inline `sb.yml` overrides works air-gapped and during outages, but cannot keep up with the reality of a constantly-shifting agent landscape:

- Vendors rebrand bots and rotate user-agent strings on a quarterly cadence.
- Web Bot Auth `keyid` thumbprints land in vendor-published JWK directories on no schedule we control.
- Reputation signals (the crawl-to-refer ratio, robots-compliance score) are observation-derived; they need a feed loop, not a rebuild loop.
- Operators want to mute or down-weight a specific agent within minutes of a bad actor surfacing, without waiting for the next sbproxy release.

The `waf-feed` crate already solves the same publisher / subscriber shape for OWASP CRS rules: signed JSON bundles, hot-reload on the subscriber, HTTP poll plus optional Redis Streams push. Mirroring that shape costs us nothing and lets operators reason about one feed pattern, not two.

The reputation surface is new. It rolls up two signals beyond the static taxonomy:

1. **Crawl-to-refer ratio**: how many requests does this agent crawl for every one referral it sends back to the publisher. Cloudflare's published bot data already tracks this; the hosted publisher measures it on its own observation pipeline.
2. **Robots-compliance score**: did the agent honour `robots.txt` and `Content-Signal` directives in the observation window.

This ADR pins the wire format, the signing model with key rotation, the refresh / hot-reload protocol, and the subscriber's verification contract. It does not pin the publisher-side ingestion pipeline that sources the underlying signals.

## Decision

Define a signed JSON feed published from `https://feed.sbproxy.dev/agents/v1.json` (operator-configurable). The feed mirrors `waf-feed`'s top-level shape: typed bundle, detached signature, key-id discriminator. Subscribers refresh every 5 minutes by default, hot-reload the in-memory catalog atomically, and apply a dual-key acceptance window during signature key rotation.

### Endpoint and configuration

| Setting | Default | Source |
|---|---|---|
| Feed URL | `https://feed.sbproxy.dev/agents/v1.json` | `agent_registry.feed_url` in `sb.yml`; env `SBPROXY_AGENT_FEED_URL` overrides |
| Public key directory | `https://feed.sbproxy.dev/agents/keys.json` | `agent_registry.keys_url`; resolves the active and grace-window keys |
| Refresh interval | 300 s | `agent_registry.refresh_interval_seconds` |
| Hard expiry honour | `expires_at` from feed body | non-overridable |
| Stale-but-still-valid | 24 h after `expires_at` (warn) | `agent_registry.stale_grace_seconds` |
| HTTPS-only | yes | enforced at config-load time |
| Certificate pin | optional SHA-256 of the SPKI | `agent_registry.spki_pin_sha256` |

The feed URL is HTTPS-only. Plain HTTP at config load is a hard error, mirroring `adr-http-ledger-protocol.md` § "Endpoints".

### Top-level feed shape

```json
{
  "format_version": 1,
  "generated_at": "2026-05-01T12:00:00Z",
  "expires_at":   "2026-05-08T12:00:00Z",
  "issuer":       "feed.sbproxy.dev",
  "entries": [
    {
      "agent_id":  "openai-gptbot",
      "vendor":    "OpenAI",
      "purpose":   "training",
      "expected_user_agents": [
        "(?i)\\bGPTBot/\\d"
      ],
      "expected_reverse_dns_suffixes": [
        ".gptbot.openai.com"
      ],
      "expected_keyids": [
        "ed25519:ABCDEF0123..."
      ],
      "reputation_score":         87,
      "crawl_to_refer_ratio":     0.0042,
      "robots_compliance_score":  98,
      "flags": ["throttled"],
      "deprecated": false,
      "aliases":    [],
      "contact_url": "https://platform.openai.com/docs/gptbot"
    }
  ],
  "signature": {
    "alg": "ed25519",
    "kid": "sb-feed-2026-q2",
    "value": "base64..."
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `format_version` | u32 | Per `adr-schema-versioning.md`, integer-versioned. Initial cut ships `1`. New optional fields do not bump; type changes or removals do. |
| `generated_at` | RFC 3339 UTC ms | Set by the publisher at signing time. |
| `expires_at` | RFC 3339 UTC ms | Hard ceiling. Subscribers refuse the feed past this point unless the operator opts into stale-grace. |
| `issuer` | string | Hostname of the publisher. Logged for diagnostics. |
| `entries[]` | array of entry objects | See entry shape below. |
| `signature` | object | Detached signature over the canonicalised body. See § Signing. |

### Entry shape

Every field except where marked optional is required. The schema is a strict superset of `AgentClass` from `adr-agent-class-taxonomy.md`; consumers materialise an `AgentClass` from each entry plus the reputation triple.

| Field | Type | Notes |
|---|---|---|
| `agent_id` | string, kebab-case | Stable identifier. Same set as the static catalog; new IDs from the feed extend the in-memory catalog. Sentinels `human`, `unknown`, `anonymous` are reserved and MUST NOT appear. |
| `vendor` | string | Display name. |
| `purpose` | enum | `training`, `search`, `assistant`, `research`, `archival`, `unknown`. |
| `expected_user_agents[]` | array of regex strings | Anchored, case-insensitive. Subscribers compile once at hot-reload. |
| `expected_reverse_dns_suffixes[]` | array of strings, optional | Empty array means the rDNS check is not applicable. |
| `expected_keyids[]` | array of strings, optional | Web Bot Auth JWK thumbprints. Empty means the agent does not sign yet. Format `<alg>:<thumbprint>` for forward compat with non-Ed25519 algorithms. |
| `reputation_score` | u8 in 0-100 | Composite score; the publisher derives from compliance + crawl-to-refer + abuse reports. 0 means "do not trust", 100 means "trusted vendor in good standing". Used as a policy input, not a metric label. |
| `crawl_to_refer_ratio` | f32, optional | Decimal ratio over the trailing 30 days. `null` when the publisher has insufficient data. |
| `robots_compliance_score` | u8 in 0-100 | Operator-declared in defaults; measured by the publisher pipeline when available. |
| `flags[]` | array of strings | Closed set. Initial values: `throttled` (operator-imposed cap suggested), `deprecated` (vendor renamed the bot), `incident` (active abuse report under investigation), `unverified` (no rDNS or Web Bot Auth hit yet). New flags require an ADR amendment. |
| `deprecated` | bool, default false | Convenience mirror of the `deprecated` flag. Resolver still matches the entry; dashboards mark stale. |
| `aliases[]` | array of strings, optional | Historical agent IDs that resolve to this entry. |
| `contact_url` | string, HTTPS, optional | Vendor's published abuse / documentation URL. |

### Crawl-to-refer signal

`crawl_to_refer_ratio` is the per-agent ratio of inbound crawl requests to outbound referrals observed in the trailing 30-day window. The publisher observation pipeline computes it as:

```
crawl_to_refer_ratio = referrals_30d / max(crawls_30d, 1)
```

Smaller is worse: a bot that crawls 1,000 pages per referral is far less reciprocal than a bot at 1:1. Publishers consume this on the dashboard and operators can drive policy decisions from it (e.g. raise the price for agents below `0.001`).

Until measurement data is available, entries either omit the field (`null`) or carry seed values from public sources (Cloudflare's published bot data).

### Signing

Detached Ed25519 signature over the canonicalised JSON body with `signature` removed. The canonicalisation is JCS (RFC 8785) so the publisher and the verifier agree on byte-for-byte input regardless of key ordering.

```
signing_input  = JCS-canonical-JSON({ feed body without "signature" })
signature.value = base64(Ed25519-sign(signing_key, signing_input))
```

Why Ed25519 instead of HMAC (which `waf-feed` uses): the agent registry feed is public and shared by every deployment. HMAC requires the same secret on every subscriber, which would force the publisher to leak a master key. Ed25519's public-key model lets every subscriber verify against a published public key without holding any secret material. The `waf-feed` crate runs per-tenant and each tenant has its own HMAC; this feed runs single-tenant from the hosted publisher.

The `signature.alg` field is required and currently fixed at `ed25519`. New algorithms require an ADR amendment; the field reserves the option without committing to a future algorithm today.

### Key rotation: dual-key window

Per `adr-schema-versioning.md` and the established 30-day grace-window pattern in the workspace:

- The publisher rotates the active signing key every 90 days.
- During rotation, both the old and the new key are accepted by subscribers for a 30-day overlap.
- Subscribers fetch the public-key directory at `https://feed.sbproxy.dev/agents/keys.json` on every feed refresh; cached for the same 5-minute interval.

Public key directory shape:

```json
{
  "format_version": 1,
  "generated_at": "2026-05-01T00:00:00Z",
  "active":  { "kid": "sb-feed-2026-q2", "alg": "ed25519", "public_key": "base64...", "valid_from": "2026-04-01T00:00:00Z", "valid_until": "2026-07-31T23:59:59Z" },
  "grace": [
    { "kid": "sb-feed-2026-q1", "alg": "ed25519", "public_key": "base64...", "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-05-01T00:00:00Z" }
  ],
  "revoked": [
    { "kid": "sb-feed-2025-q4", "revoked_at": "2026-04-01T00:00:00Z", "reason": "scheduled_rotation" }
  ]
}
```

Subscribers verify the directory itself with a long-lived bootstrap public key compiled into the binary (one per release line, rotated at major releases). The bootstrap key signs the directory; the directory's per-period keys sign individual feed bodies. Two-tier signing means a compromised feed key does not compromise the directory.

A subscriber rejects:

- A feed signed with a `kid` not present in `active` or `grace`.
- A feed signed with a `kid` listed in `revoked`.
- A feed whose `signature.alg` is not the directory entry's `alg`.

Revocation is immediate on the publisher side. Subscribers pick up revocation on their next refresh (worst case 5 minutes; emergency operators can SIGHUP). A revoked-key feed already in memory is NOT discarded by the subscriber on revocation alone, because the subscriber cannot tell whether the revocation itself is forged; the revocation just blocks new fetches signed with that key. The active-key swap is what flushes stale data.

### Refresh, hot-reload, and atomic swap

The subscriber runs a background task on the configured refresh interval. Each tick:

1. `GET <feed_url>` with `If-None-Match: <last_etag>` and `If-Modified-Since: <last_modified>`. The publisher SHOULD return 304 when the body has not changed.
2. On 200, parse the body. Reject if `format_version > 1` (unless minor superset, see `adr-schema-versioning.md` Rule 1).
3. Verify the signature against the cached public-key directory. If the `kid` is not in `active` or `grace`, refresh the directory once and retry. If still unknown, drop the response and emit `sbproxy_agent_feed_signature_invalid_total{reason="unknown_kid"}`.
4. Check `expires_at > now`. If expired but within `stale_grace_seconds`, accept and emit `sbproxy_agent_feed_stale{}` gauge = 1.
5. Build a new in-memory catalog map keyed by `agent_id`.
6. Atomically swap the catalog pointer behind an `ArcSwap<Catalog>` (same pattern `waf-feed` uses for its rule set). Existing in-flight requests holding the old `Arc` finish with the old catalog; new requests pick up the new one.
7. Emit `sbproxy_agent_feed_reloaded_total{result="success|failure"}` counter.

The atomic swap means there is no "the catalog is being rebuilt" window. Hot-reload is non-blocking and safe under concurrent reads.

`expires_at` is a hard ceiling. Past `expires_at + stale_grace_seconds`, the subscriber unloads the catalog (`Arc::new(Catalog::empty_with_static_overrides())`) and emits `sbproxy_agent_feed_unloaded{reason="expired"}`. The agent_class resolver falls back to its embedded default catalog; this is the air-gapped floor `adr-agent-class-taxonomy.md` describes.

### Subscriber surface

The subscriber exposes:

```rust
pub trait AgentRegistry: Send + Sync {
    fn lookup(&self, agent_id: &str) -> Option<Arc<AgentClass>>;
    fn lookup_by_user_agent(&self, ua: &str) -> Option<Arc<AgentClass>>;
    fn snapshot(&self) -> Arc<Catalog>;
}
```

The `AgentClass` type is re-exported from `sbproxy-classifiers::agent_class`. The resolver accepts an `Option<Arc<dyn AgentRegistry>>` and falls back to the static catalog when None, which is the air-gapped deployment path.

### Sentinels are not in the feed

`human`, `unknown`, and `anonymous` are emitted by the resolver, never published. The feed is the source of truth for *known* agents. The resolver order in `adr-agent-class-taxonomy.md` is unchanged; the feed populates the lookup table, the resolver consumes it.

### Failure modes and metrics

| Metric | Type | Labels |
|---|---|---|
| `sbproxy_agent_feed_reloaded_total` | counter | `result` |
| `sbproxy_agent_feed_signature_invalid_total` | counter | `reason` |
| `sbproxy_agent_feed_stale` | gauge | (none) |
| `sbproxy_agent_feed_unloaded` | counter | `reason` |
| `sbproxy_agent_feed_entries` | gauge | (none) |
| `sbproxy_agent_feed_age_seconds` | gauge | (none) |

These feed Grafana dashboards and the SLO catalog in `adr-slo-alert-taxonomy.md`. A failing feed (signature invalid for two consecutive refreshes, or `age_seconds > 24h`) pages on `SLO-AGENT-FEED-STALE`.

### What this ADR does NOT decide

- The publisher-side observation pipeline that sources `crawl_to_refer_ratio` and `robots_compliance_score`.
- The reputation-score weighting formula. The field shape is locked; the formula can evolve without breaking the wire format.
- Per-tenant reputation overrides (operator says "I trust this agent more than the global score").
- Customer-mirrored feeds (operators republishing the feed inside their VPC); operators can self-host the publisher with the same shape.

## Consequences

- One feed shape covers static catalog overrides and dynamic reputation. Operators learn one schema.
- Dual-key 30-day window matches the rest of the workspace's rotation pattern. Operators do not need a separate playbook for agent-feed rotation.
- Atomic `ArcSwap` hot-reload means no request path ever sees a partially-populated catalog. The hot-reload guarantee is independent of the refresh interval.
- The bootstrap-key two-tier model means we can rotate feed signing keys without re-signing the binary. Bootstrap keys rotate on major-release boundaries only.
- Sentinels (`human`, `unknown`, `anonymous`) stay out of the feed. The resolver remains the single source of truth for "no concrete entry caught this request".
- Public-key model (Ed25519) is correct for a single-publisher, many-subscriber feed. We deliberately diverge from `waf-feed`'s HMAC; the two-feed split is the right call.
- The 5-minute refresh window plus hard `expires_at` means the worst-case lag between a publisher revocation and a subscriber un-load is bounded.

## Alternatives considered

**HMAC like `waf-feed`.** Rejected. HMAC requires a shared secret on every subscriber. The agent registry feed is single-publisher, many-subscriber, public; the `waf-feed` crate is per-tenant and HMAC is correct there. Mixing the two patterns would force us to ship a master HMAC key on every deployment.

**JWS instead of detached Ed25519 + JCS.** Considered. JWS gives us serialisation conventions for free. Rejected because the JWS spec admits multiple signing modes and we would need to pin one anyway; the explicit `{alg, kid, value}` triple plus JCS is shorter to specify and shorter to verify.

**Single key, no rotation window.** Rejected. A key compromise without a rotation plan is a multi-day outage. The 30-day dual-key window matches `adr-agent-class-taxonomy.md`'s reservation and the rest of the workspace.

**Push-only via Redis Streams (mirror `waf-feed`'s push path).** Considered. Rejected because the agent registry has many more subscribers than `waf-feed` (every deployment, not per-tenant). A Redis fan-out at that scale is a separate operational concern; HTTP poll plus `If-None-Match` solves it. A Redis push channel for tenants who want sub-minute latency may land later; the wire format stays the same.

**Embed reputation history (last 30 days of daily ratios) inside each entry.** Rejected. The feed is meant to be small (under 100 KiB at steady state). History belongs in the analytics surface, not the policy substrate. The trailing window is a single rolling number.

## References

- `adr-agent-class-taxonomy.md`: the static side of this taxonomy, the reserved sentinels, the feed-shape sketch.
- `adr-schema-versioning.md`: integer versioning, the dual-emit / dual-read window, the breaking-change checklist.
- `adr-http-ledger-protocol.md`: HTTPS-only enforcement at config load; the precedent for hard-fail on plain HTTP.
- `adr-admin-action-audit.md`: every approval / revocation in the publisher tooling emits an `AdminAuditEvent`; the registry feed is the consumer of those approvals.
- `adr-slo-alert-taxonomy.md`: the `SLO-AGENT-FEED-STALE` alert.
- `adr-agent-dcr.md`: the registration intake whose approvals populate this feed.
- JCS: RFC 8785. Ed25519: RFC 8032.
- Cloudflare published bot data.
