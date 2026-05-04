# ADR: Agent-class taxonomy

*Last modified: 2026-05-03*

## Status

Accepted. Foundational substrate for the agent_class resolver, the reverse-DNS verifier, per-agent metric labels, the HTTP ledger payload, and the hosted registry feed.

## Context

`ai_crawl_control` today identifies AI agents by case-insensitive User-Agent substring (`crawler_user_agents: ["GPTBot", "ClaudeBot", ...]`). That is enough to fire a 402 challenge but it is not enough to:

- attach a stable, low-cardinality `agent_id` label to metrics,
- decide whether reverse-DNS verification is even applicable to a given UA,
- carry agent identity into the HTTP ledger payload so revenue rolls up per vendor,
- power the per-agent crawl-to-refer ratio publishers care about,
- distinguish a bot that respects robots.txt from a bot that does not (publisher-facing reputation signal).

Each downstream consumer needs the same pieces of information about an agent: who runs it, what it claims to be doing, where to complain, and how trustworthy it is. Without one canonical taxonomy, every consumer would synthesize its own table of vendor strings. The HTTP ledger ADR blocks on this one because the redeem payload carries an `agent_id`, and that ID has to come from somewhere.

The OSS deliverable is the schema, a static config-driven table covering ten well-known vendors, and the data type. A hosted, signed feed ships updates without redeploys. This ADR fixes the schema so both can ship against the same shape.

## Decision

Define an `AgentClass` record. Ship a static catalog inline in `sb.yml` and reserve a hosted-feed format.

### Schema

The `AgentClass` record, encoded in YAML alongside the rest of `sb.yml`:

```yaml
agent_classes:
  - id: openai-gptbot
    vendor: OpenAI
    purpose: training
    contact_url: https://platform.openai.com/docs/gptbot
    expected_user_agent_pattern: "(?i)\\bGPTBot/\\d"
    expected_reverse_dns_suffixes:
      - .gptbot.openai.com
    expected_keyids: []
    robots_compliance_score: 0.95
    crawl_to_refer_ratio: null
    aliases: []
    deprecated: false
```

Field set, all required unless noted:

| Field | Type | Notes |
|---|---|---|
| `id` | string, kebab-case `vendor-bot` | Stable identifier. Used as the `agent_id` metric label and ledger payload field. Must match `^[a-z][a-z0-9-]{1,62}$`. |
| `vendor` | string | Display name of the operator (`OpenAI`, `Anthropic`, `Perplexity`, `Google`, `Microsoft`, `DuckDuckGo`, `Apple`, `Common Crawl`). Used for the `agent_vendor` metric label. |
| `purpose` | enum | One of `training`, `search`, `assistant`, `research`, `archival`, `unknown`. Becomes the `agent_purpose` audit-log field; not a metric label. |
| `contact_url` | string, HTTPS URL, optional | Operator's published contact / documentation URL. Surfaced in audit log and dashboards so abuse triage can find the right form. |
| `expected_user_agent_pattern` | regex string | Anchored regex (case-insensitive). Matched against the `User-Agent` header during resolution. The resolver compiles this once at config load. |
| `expected_reverse_dns_suffixes` | list of strings, optional | Suffixes accepted by the forward-confirmed reverse-DNS check. `.gptbot.openai.com`, `.googlebot.com`, `.search.msn.com`, etc. Empty list means "no rDNS check applies"; presence elevates the verification verdict. |
| `expected_keyids` | list of strings, optional | Web Bot Auth `keyid` values (JWK thumbprints) the agent is expected to sign with. Empty list means "agent does not sign yet". Used by the resolver's bot-auth path. |
| `robots_compliance_score` | f32 in `[0.0, 1.0]`, optional | Operator-declared or community-attested score for robots.txt and `Content-Signal` compliance. Sourced from the publisher community (see Cloudflare's published bot data). Used as a policy input, not a metric label. |
| `crawl_to_refer_ratio` | f32, optional | Latest measured crawl-to-refer ratio for this agent (from observation, not declaration). Filled by the hosted feed; left `null` in static configs. |
| `aliases` | list of strings, optional | Alternate UA substrings or historical IDs that resolve to this entry. Used for migration when a vendor renames a bot. |
| `deprecated` | bool, default false | When true, the resolver still matches the entry (so historical queries keep working), but new metric series use the alias's replacement and operator dashboards mark the row stale. |

### Reserved IDs

Two reserved values that the resolver always emits when no concrete entry matches:

- `unknown` (`agent_id == "unknown"`, `agent_vendor == "unknown"`, `purpose == "unknown"`): the request looks like an automated agent (UA matched a generic crawler heuristic, or was anonymous Web Bot Auth without a known keyid) but no taxonomy entry caught it. This is the fall-through bucket.
- `anonymous` (`agent_id == "anonymous"`): the request authenticated via anonymous Web Bot Auth (`draft-rescorla-anonymous-webbotauth-00`). Distinct from `unknown` because the request is provably an agent under a rate-limiting protocol, just not an identified one.

Both reserved values are stable across releases. Operators can rely on dashboards keying on them.

Human traffic resolves to `agent_id == "human"` with the same fields zeroed. The resolver returns `human` when no automated-agent signal is present (no UA match, no signature, no rDNS hit). Three sentinel values total: `human`, `anonymous`, `unknown`.

### Default catalog

Eight well-known vendors ship in `sbproxy-classifiers/data/agent_classes_default.yaml`, embedded into the binary at build time so the OSS distribution works out of the box:

| `id` | `vendor` | `purpose` | rDNS suffix |
|---|---|---|---|
| `openai-gptbot` | OpenAI | training | `.gptbot.openai.com` |
| `openai-chatgpt-user` | OpenAI | assistant | `.chatgpt.openai.com` |
| `anthropic-claudebot` | Anthropic | training | (none published as of 2026-04) |
| `perplexity-perplexitybot` | Perplexity | search | `.perplexity.ai` |
| `google-googlebot` | Google | search | `.googlebot.com`, `.google.com` |
| `google-extended` | Google | training | (UA only; no rDNS) |
| `microsoft-bingbot` | Microsoft | search | `.search.msn.com` |
| `duckduckgo-duckduckbot` | DuckDuckGo | search | `.duckduckgo.com` |
| `apple-applebot` | Apple | search | `.applebot.apple.com` |
| `commoncrawl-ccbot` | Common Crawl | archival | (UA only; rDNS not enforced) |

Operators can extend or override entries inline in their own `sb.yml`. An entry with the same `id` overrides the default; a new `id` appends.

### Static config vs hosted feed

**Static (default):** the catalog is YAML, embedded in the binary plus optional inline overrides in `sb.yml`. YAML, not TOML, because every other surface in the project (`sb.yml`, examples, k8s CRDs) is YAML; mixing TOML for one substrate file taxes operators for no benefit. The static catalog refreshes only on binary upgrade or `sb.yml` reload (SIGHUP).

**Hosted feed:** a signed JSON document fetched from a configurable endpoint, mirroring the existing `waf-feed` pattern. The shape on the wire matches the YAML catalog exactly so operators can `curl` the feed and diff it against their static overrides.

Hosted feed contract sketch (full spec in `adr-agent-registry-feed.md`):

```json
{
  "version": 17,
  "issued_at": "2026-04-30T12:00:00Z",
  "expires_at": "2026-05-07T12:00:00Z",
  "signing_key_id": "sb-feed-2026-q2",
  "agent_classes": [
    { "id": "openai-gptbot", "vendor": "OpenAI", "...": "..." }
  ],
  "signature": "ed25519:base64..."
}
```

Refresh cadence reservation: 24 h pull with a 7 d grace TTL. Signing-key rotation cadence: assumed 90 d. HTTPS-only, certificate-pinned to the registry origin. The signing key is published at the same well-known URL alongside a key-history list so operators can verify a feed signed by a freshly rotated key.

### Resolver order (reference)

For each request, the agent_class resolver picks the first match:

1. Web Bot Auth verified `keyid` matches an `expected_keyids` entry. Highest confidence.
2. Reverse-DNS forward-confirmed against an `expected_reverse_dns_suffixes` entry. Strong confidence.
3. `User-Agent` regex match against `expected_user_agent_pattern`. UA-only signal; treat as advisory unless the policy explicitly trusts UAs.
4. Anonymous Web Bot Auth signature with no matching `keyid`: emit `anonymous`.
5. Generic crawler UA heuristic: emit `unknown`.
6. None of the above: emit `human`.

The resolver records which signal matched and surfaces it as `agent_id_source ∈ {bot_auth, rdns, user_agent, anonymous_bot_auth, fallback}` for diagnostic queries. (Same shape as the user-id resolver in `adr-user-id.md`.)

### Crate placement

The `AgentClass` struct, the embedded default catalog, and the YAML loader live in `sbproxy-classifiers::agent_class`. Resolver logic lives in `sbproxy-modules::policy::agent_class`; reverse-DNS verification in `sbproxy-security::agent_verify`. Both consumers import the type from `sbproxy-classifiers`.

### What this ADR does NOT decide

- The signature algorithm and key-rotation policy for the hosted feed.
- Crawl-to-refer measurement methodology.
- Robots-compliance score sourcing (operator-declared vs community-attested vs measured); the catalog seeds plausible defaults.
- The exact Web Bot Auth keyids per vendor, since most are not yet published.

## Consequences

- One canonical record consumed by metrics labels, the HTTP ledger payload, the bot-auth resolver, and the reverse-DNS verifier. No drift between consumers.
- `agent_id` is bounded to the union of the catalog plus three sentinels (`human`, `unknown`, `anonymous`). That bound is what makes the per-metric cardinality budget feasible.
- Operators can override entries without forking the binary. Adding a private bot for an internal tool is a YAML edit.
- The hosted-feed shape is fixed, so the implementation is straightforward.
- Vendor renames are handled via `aliases` and `deprecated`; we do not orphan historical metrics when a bot rebrands.
- Adding a new vendor to the embedded default catalog is a code change (PR, review, release). That is intentional. The hosted feed is the dynamic path; the embedded catalog is the air-gapped, no-network-required floor.

## Alternatives considered

**TOML for the catalog file.** Rejected. The project's config is uniformly YAML; TOML would force operators to learn a second format for one file, and the agent-class catalog is not richer than YAML can express. TOML's static-config strengths (commentable, key-ordered) do not outweigh the operator cost.

**Inline taxonomy in `ai_crawl_control` only.** Rejected. The taxonomy is consumed by metrics, ledger, audit log, bot-auth, reverse-DNS, and content-shape pricing. A type that lives in one policy module would be re-imported by five sibling modules; better to declare it once in `sbproxy-classifiers`.

**Skip the embedded default catalog and require operators to populate.** Rejected. The story is "deploy a single binary, get a usable AI Governance Gateway." A blank catalog forces every new operator to research vendor metadata before their first 402 challenge fires. The 8-vendor default is the right floor.

**Numeric `purpose` codes.** Rejected. Strings (`training`, `search`, `assistant`) are self-documenting in dashboards and ClickHouse queries; the cardinality is bounded enough that the wire-size cost of strings does not matter.

## References

- `crates/sbproxy-modules/src/policy/ai_crawl.rs` - the UA-substring matcher.
- Cloudflare published crawler list and Content-Signal extensions.
- Hosted-feed ADR: `adr-agent-registry-feed.md`.
