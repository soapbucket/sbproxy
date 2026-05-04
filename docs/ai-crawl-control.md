# AI Crawl Control + Pay Per Crawl
*Last modified: 2026-05-03*

The `ai_crawl_control` policy implements the "Pay Per Crawl" pattern: AI crawlers that arrive without a valid `Crawler-Payment` token receive `402 Payment Required` along with a JSON challenge body. A crawler that wants the content reads the challenge, posts a payment to your billing system, and retries with the issued token in the `Crawler-Payment` header. Each token redeems exactly once.

The OSS implementation ships an in-memory ledger seeded from config and an HTTPS-only HTTP ledger client for production. The enterprise build extends the same `Ledger` trait with managed adapters so the proxy can authorise tokens against Stripe, x402, MPP, and Lightning rails.

## Request flow

```
crawler GET /article
        User-Agent: GPTBot/1.0
proxy   <- 402 Payment Required
        Crawler-Payment: realm="ai-crawl" currency="USD" price="0.001"
        Content-Type: application/json
        body: {"error":"payment_required","price":"0.001","currency":"USD","target":"blog.example.com/article","header":"crawler-payment"}

crawler GET /article (after paying out-of-band)
        User-Agent: GPTBot/1.0
        crawler-payment: tok_a89be2...
proxy   <- 200 OK
        body: <article>

crawler GET /article (replay attempt)
        User-Agent: GPTBot/1.0
        crawler-payment: tok_a89be2...
proxy   <- 402 (single-use ledger; token already spent)
```

## Configuration

```yaml
policies:
  - type: ai_crawl_control
    price: 0.001
    currency: USD
    header: crawler-payment           # default
    crawler_user_agents:              # case-insensitive substring match
      - GPTBot
      - ChatGPT-User
      - ClaudeBot
      - anthropic-ai
      - Google-Extended
      - PerplexityBot
      - CCBot
    valid_tokens:                      # in-memory ledger
      - tok_a89be2f1
      - tok_b7cf012e
      - tok_c34f9a82
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `price` | float | unset | Price emitted in the challenge body and the `price=` parameter of the challenge header. Used as the fallback when no tier matches. |
| `currency` | string | `USD` | ISO-4217 code surfaced in the challenge header and body. |
| `header` | string | `crawler-payment` | Header the crawler reads from the 402 response and writes to its retry. |
| `crawler_user_agents` | list | covers GPTBot, ChatGPT-User, ClaudeBot, anthropic-ai, Google-Extended, PerplexityBot, CCBot, FacebookBot | Case-insensitive substring matches against the request User-Agent. Empty list treats every GET / HEAD as a crawler. |
| `valid_tokens` | list | `[]` | Seeds the in-memory ledger. Each token redeems once, then leaves the set. |
| `tiers` | list | `[]` | Pricing tiers. First match wins. See "Tiered pricing" below. |
| `ledger` | block | unset | HTTP ledger client config. See "HTTP ledger" below. Mutually exclusive with `valid_tokens`. |

Only `GET` and `HEAD` requests are subject to charging today. `POST`, `PUT`, `PATCH`, and `DELETE` pass through without charge.

## Tiered pricing

A flat per-site price is the right starting point but not the right long-term shape. Different routes carry different commercial value, and the same article in three formats (HTML, Markdown, PDF) is worth three different prices to a training crawler. The `tiers:` field lets you price by route pattern and content shape without forking the policy.

```yaml
policies:
  - type: ai_crawl_control
    price: 0.0005                      # fallback when no tier matches
    currency: USD
    tiers:
      - route_pattern: /premium/*
        price:
          amount_micros: 5000          # $0.005 per crawl
          currency: USD
        free_preview_bytes: 1024       # cooperative crawlers get 1 KiB free
        paywall_position: hard
      - route_pattern: /articles/*
        price:
          amount_micros: 1000          # $0.001 per crawl
          currency: USD
        content_shape: markdown        # Markdown form only
        free_preview_bytes: 4096
        paywall_position: soft
      - route_pattern: /articles/*
        price:
          amount_micros: 500           # $0.0005 per crawl
          currency: USD
        content_shape: html
      - route_pattern: /docs/*
        price:
          amount_micros: 250
          currency: USD
```

| Field | Type | Description |
|---|---|---|
| `route_pattern` | string | Path matcher. Supports literal paths (`/about`) and a `*` suffix wildcard (`/articles/*`). First match wins; later tiers act as fallbacks. |
| `price.amount_micros` | u64 | Price in micros (1e-6 of one unit of `currency`). 1000 micros = $0.001. Floats never enter the wire format. |
| `price.currency` | string | ISO-4217 code. Must match the policy-level `currency` for now. |
| `content_shape` | enum | One of `html`, `markdown`, `json`, `pdf`, `other`. Advisory; surfaced in metrics and the redeem payload but not yet used as a tier filter. |
| `free_preview_bytes` | u64, optional | Byte budget the crawler may read without paying. Surfaced in the challenge body so cooperative crawlers can decide up front whether the preview alone meets their need. |
| `paywall_position` | enum, optional | Hint to the crawler about where the paywall sits: `hard` (no content without payment), `soft` (preview, then paywall), `metered` (N free per period). |

The first tier whose `route_pattern` matches wins. When no tier matches, the policy falls back to the top-level `price` and `currency`. An empty `tiers` list keeps the original flat-price behaviour.

### Per-shape pricing

`content_shape` is advisory: configurations may set the field on a tier so metrics and the redeem payload carry the shape, but the policy does not yet match against it. The wire format is stable, so configurations that set `content_shape` today will keep working when the resolver lands.

## HTTP ledger

The OSS in-memory ledger (`valid_tokens:`) is fine for tests, fixed-token issuance, or one-off content gates. Production deployments with multiple proxy replicas need a network-callable ledger so one token spends across all nodes. The HTTP ledger client speaks the JSON-over-HTTPS protocol pinned in [adr-http-ledger-protocol.md](adr-http-ledger-protocol.md).

```yaml
policies:
  - type: ai_crawl_control
    price: 0.001
    currency: USD
    ledger:
      endpoint: "https://ledger.internal"
      key_id: "sb-ledger-2026-q2"
      key_file: "${SBPROXY_LEDGER_HMAC_KEY_FILE}"
      workspace_id: "default"
      agent_id: "openai-gptbot"        # forwarded into the redeem payload
      agent_vendor: "OpenAI"
      per_attempt_timeout_ms: 5000
      total_timeout_ms: 30000
      max_attempts: 5                  # hard-capped at 5 by the ADR
      breaker:
        failure_threshold: 10
        success_threshold: 1
        open_duration_ms: 5000
```

The client refuses to construct against a non-HTTPS endpoint at config-load time. Plain HTTP is a hard error because the request envelope carries an HMAC over the body, and TLS is the only thing keeping the body itself confidential.

### Request envelope

Every redeem call carries the eight-line canonical envelope from the protocol ADR:

```json
{
  "v": 1,
  "request_id": "01HZX...",
  "timestamp": "2026-04-30T12:34:56.789Z",
  "nonce": "8f4a...32-hex...",
  "agent_id": "openai-gptbot",
  "agent_vendor": "OpenAI",
  "workspace_id": "default",
  "payload": {
    "token": "tok_abc...",
    "host": "blog.example.com",
    "path": "/articles/foo",
    "amount_micros": 1000,
    "currency": "USD",
    "content_shape": "markdown"
  }
}
```

The signature is HMAC-SHA256 over the canonical signing string (eight `\n`-separated fields, last one being the SHA-256 of the request body). The signature lands in the `X-Sb-Ledger-Signature: v1=<hex>` header. The `v1=` prefix reserves room for future MAC migrations without breaking peers.

### Idempotency

Every attempt carries an `Idempotency-Key` header (a fresh ULID per logical operation). Retries reuse the same key; the ledger short-circuits the second attempt with the cached response. A different body under the same key returns 409 `ledger.idempotency_conflict`, which protects against accidental key reuse across operations.

`Idempotency-Key` is distinct from the envelope's `request_id`: the request id identifies the inbound 402 from the agent, while the idempotency key identifies a single conversation with the ledger about that request.

### Retry and circuit breaker

Exponential backoff with full jitter, max 5 attempts, per-attempt deadline 5 s, total deadline 30 s. The base schedule is 0 ms, 250 ms, 500 ms, 1 s, 2 s, each with `[0, base)` jitter added. Retries fire only on:

- network errors (DNS, TCP RST, TLS handshake, read timeout)
- HTTP 429 (with `Retry-After` honoured)
- HTTP 502 / 503 / 504
- error envelopes with `retryable: true`

Hard failures (`ledger.token_already_spent`, `ledger.signature_invalid`, `ledger.bad_request`) translate directly to a 402 to the crawler. There is no point retrying a token the ledger already rejected as spent.

The circuit breaker opens after 10 consecutive failures over a 30 s window, half-opens after 5 s with one probe, and closes on probe success. While the breaker is open, the client returns a synthetic `ledger.unavailable` error without making the network call. The policy treats that as "ledger is down" and applies the configured `on_ledger_failure` action (default fail-closed).

A 503 response with `Retry-After` propagates straight to the crawler: the 402 response carries `Retry-After` so the crawler knows when to come back. This is the one case where the policy emits `Retry-After` on a 402.

### Failure modes

| Ledger response | Policy action |
|---|---|
| 200 success, redeemed | Pass the request through. |
| 200 success, not redeemed | 402 with the challenge body. The token was valid format but the ledger refused (out of balance, expired). |
| 409 `token_already_spent` | 402, no retry. |
| 4xx other | 402, no retry, log at WARN. |
| 5xx, transient envelope, breaker open | Apply `on_ledger_failure` (default fail-closed -> 503). |

## Agent classes and per-vendor pricing

An `agent_class` taxonomy lets metrics, audit logs, and ledger payloads attribute revenue per vendor. The agent class is resolved at request time via three signals (in order of confidence):

1. Verified Web Bot Auth `keyid` matches an `expected_keyids` entry. Highest confidence.
2. Forward-confirmed reverse-DNS suffix matches an `expected_reverse_dns_suffixes` entry. Strong confidence.
3. User-Agent regex match. Advisory unless the policy explicitly trusts UAs.

Three reserved sentinels round out the resolver:

- `human` is emitted when no automated-agent signal is present.
- `unknown` is the fall-through bucket for an automated UA without a registry match.
- `anonymous` is emitted for anonymous Web Bot Auth requests with no known `keyid`.

Operators see all three values in metrics and dashboards; alerting on a sustained climb in `unknown` is the normal way to spot a new crawler that needs a registry entry.

### Per-vendor pricing example

```yaml
agent_classes:
  - id: openai-gptbot
    vendor: OpenAI
    purpose: training
    expected_user_agent_pattern: "(?i)\\bGPTBot/\\d"
    expected_reverse_dns_suffixes: [".gptbot.openai.com"]
  - id: anthropic-claudebot
    vendor: Anthropic
    purpose: training
    expected_user_agent_pattern: "(?i)\\bClaudeBot/\\d"
  - id: commoncrawl-ccbot
    vendor: Common Crawl
    purpose: archival
    expected_user_agent_pattern: "(?i)\\bCCBot/\\d"

policies:
  - type: ai_crawl_control
    currency: USD
    tiers:
      # Training crawlers pay full price.
      - route_pattern: /articles/*
        agent_id: openai-gptbot
        price: { amount_micros: 2000, currency: USD }
      - route_pattern: /articles/*
        agent_id: anthropic-claudebot
        price: { amount_micros: 2000, currency: USD }
      # Archival crawlers get a discount.
      - route_pattern: /articles/*
        agent_id: commoncrawl-ccbot
        price: { amount_micros: 500, currency: USD }
      # Sentinel buckets price differently for diagnostics.
      - route_pattern: /articles/*
        agent_id: anonymous
        price: { amount_micros: 1000, currency: USD }
      - route_pattern: /articles/*
        agent_id: unknown
        price: { amount_micros: 1500, currency: USD }
```

`agent_id` on a tier matches against the resolver's verdict. The first tier whose route pattern AND agent id both match wins. A tier without `agent_id` matches every agent.

The eight default agent classes (`openai-gptbot`, `openai-chatgpt-user`, `anthropic-claudebot`, `perplexity-perplexitybot`, `google-googlebot`, `google-extended`, `microsoft-bingbot`, `duckduckgo-duckduckbot`, `apple-applebot`, `commoncrawl-ccbot`) ship embedded in the binary. Operators extend or override entries inline in `sb.yml`. See [adr-agent-class-taxonomy.md](adr-agent-class-taxonomy.md) for the full schema and resolver rules.

## Observability

Every redeem fires a metric and a structured-log line. The label set:

| Label | Source | Cardinality cap |
|---|---|---|
| `agent_id` | Agent-class resolver. Bounded to registry plus `human`, `unknown`, `anonymous` sentinels. | 200 |
| `agent_class` | Closed enum from the taxonomy. | 8 |
| `agent_vendor` | Free-form vendor name from the taxonomy. | 20 |
| `payment_rail` | Closed enum: `none`, `x402`, `mpp_card`, `mpp_stablecoin`, `stripe_fiat`, `lightning`. | 6 |
| `content_shape` | Closed enum: `html`, `markdown`, `json`, `pdf`, `other`. | 5 |

Cardinality budgets are enforced by `sbproxy-observe::cardinality::CardinalityLimiter`; over-cap label values demote to `__other__` and increment `sbproxy_label_demotion_total`. The full per-metric budget table lives in [adr-metric-cardinality.md](adr-metric-cardinality.md).

### Metrics

| Metric | Type | Notes |
|---|---|---|
| `sbproxy_ledger_redeem_total{result, agent_id, agent_vendor, payment_rail}` | counter | Per-redeem outcome. `result` is one of `success`, `denied`, `error`. |
| `sbproxy_ledger_redeem_duration_seconds_bucket` | histogram | Tail-latency of the ledger round-trip. Carries trace exemplars. |
| `sbproxy_ledger_circuit_breaker_state{endpoint}` | gauge | 0 closed, 1 half-open, 2 open. |
| `sbproxy_ledger_circuit_breaker_transitions_total{endpoint, from, to}` | counter | Breaker flap counter. |
| `sbproxy_requests_total{agent_id, agent_class, agent_vendor, payment_rail, content_shape}` | counter | Per-request outcome. |

The per-agent dashboard (`deploy/dashboards/per-agent.json`) groups every panel by `agent_class` plus `agent_vendor`, so operators see one row per vendor and one row each for the sentinels. The audit-log dashboard (`deploy/dashboards/audit-log.json`) shows admin actions on `ai_crawl_control` tier edits.

### Tracing

The HTTP ledger client emits one outbound span per attempt, named `sbproxy.ledger.redeem` per [adr-observability.md](adr-observability.md). The span carries `sbproxy.ledger.idempotency_key` so operators correlating across the proxy and the ledger can grep both sides for the same key. W3C TraceContext propagates on the outbound request; if the ledger emits OTel spans, the trace stitches end-to-end without manual correlation.

Exemplars on `sbproxy_ledger_redeem_duration_seconds_bucket` let Grafana jump from "this latency outlier" straight to the matching trace in Tempo.

## Limitations

- Detection is User-Agent based by default. Crawlers that lie about their UA bypass the check unless reverse-DNS or Web Bot Auth signals catch them; layer this with bot-detection or WAF policies for defence in depth.
- The OSS in-memory ledger is single-process. Multi-replica deployments without an HTTP ledger need sticky session affinity to one replica.
- `content_shape` is advisory. The field flows through metrics and the redeem payload but is not yet used as a tier filter.
- Per-agent pricing requires the agent-class resolver to be enabled; the resolver runs unconditionally by default, but operators who explicitly disable it fall back to UA-only matching and lose the per-vendor distinction.

## See also

- [configuration.md](configuration.md#ai_crawl_control) - schema reference.
- [ai-gateway.md](ai-gateway.md) - how this policy interacts with `ai_proxy` upstreams.
- [adr-http-ledger-protocol.md](adr-http-ledger-protocol.md) - HTTP ledger wire format.
- [adr-agent-class-taxonomy.md](adr-agent-class-taxonomy.md) - agent classes, sentinels, hosted feed.
- [adr-metric-cardinality.md](adr-metric-cardinality.md) - per-label cardinality budgets.
- [observability.md](observability.md) - metrics, logs, traces, dashboards.
- `examples/95-ai-crawl-control/` - runnable example.
