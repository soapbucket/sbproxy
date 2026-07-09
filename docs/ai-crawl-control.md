# AI Crawl Control + Pay Per Crawl
*Last modified: 2026-07-09*

![GPTBot receiving a 402 challenge, then the article after presenting a Crawler-Payment token](assets/ai-crawl-control.gif)

Each token redeems exactly once ([config](../examples/ai-crawl-control/)).

The `ai_crawl_control` policy implements the "Pay Per Crawl" pattern: AI crawlers that arrive without a valid `Crawler-Payment` token receive `402 Payment Required` along with a JSON challenge body. A crawler that wants the content reads the challenge, posts a payment to your billing system, and retries with the issued token in the `Crawler-Payment` header. Each token redeems exactly once.

The OSS implementation ships an in-memory ledger seeded from config and an HTTPS-only HTTP ledger client for production. The enterprise build extends the same `Ledger` trait with managed adapters so the proxy can authorise tokens against Stripe, x402, MPP, and Lightning rails.

## OSS scope: challenge body only

The OSS proxy emits two challenge shapes:

1. **Single-rail (default).** A 402 with the `Crawler-Payment` header and a flat JSON body describing the price. This is the path legacy crawlers see.
2. **Multi-rail (opt-in).** When the agent sends `Accept-Payment:` or one of the multi-rail `Accept` MIME types (`application/sbproxy-multi-rail+json`, `application/x402+json`, `application/mpp+json`), the OSS proxy emits a 402 with `Content-Type: application/sbproxy-multi-rail+json` and a body that lists one entry per rail the operator declared (x402, MPP, Lightning), each with its own quote-token JWS.

The multi-rail body is the wire-format contract. The OSS build can negotiate it, advertise rails, mint per-rail quote tokens, and respond 406 when the agent's preference set has no overlap with the operator's offered rails.

What the OSS build cannot do is settle a payment on x402, MPP, Stripe, or Lightning. Settlement code lives in the enterprise build behind the `stripe`, `x402`, `mpp`, `lightning-cln`, `lightning-lnd`, and `lightning-phoenixd` cargo features. With an OSS-only build, the rails advertised in the multi-rail body are honoured by the in-memory or HTTP ledger; the enterprise BillingRail registrations are what actually authorise a real-money settlement.

### Stripe rail: partially implemented

The Stripe rail is experimental and not advertised as a supported rail yet. On the `stripe_fiat` rail the build emits a placeholder payment intent (`pi_pending_<quote_id>`), not a real Stripe `pi_*`, so no charge is created; the issued token is honoured only by the local in-memory or HTTP ledger. Real Stripe capture is an enterprise concern behind the `stripe` cargo feature and is still being finished. Treat Stripe support as a work in progress until this note is removed, and do not rely on it for production billing.

This is the same framing the rail-Lightning example uses: see `examples/rail-lightning/README.md`. For the wire-shape contract on its own, see [`402-challenge.md`](402-challenge.md).

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

![a crawler hitting a charged article URL and getting 402 while the free preview path returns 200](assets/ai-crawl-tiered.gif)

Tiers price full HTML, Markdown feeds, and previews differently ([config](../examples/ai-crawl-tiered/)).

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
        paywall_position: top_of_page
      - route_pattern: /articles/*
        price:
          amount_micros: 1000          # $0.001 per crawl
          currency: USD
        content_shape: markdown        # Markdown form only
        free_preview_bytes: 4096
        paywall_position: inline
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
| `paywall_position` | enum, optional | Hint to the crawler about where the paywall sits in the rendered response: `top_of_page` (paywall replaces the entire body; any free preview is a separate excerpt), `inline` (free preview served inline, paywall follows in the same body), `bottom_of_page` (paywall after the full or near-full preview; discouraged for high-value content). |

The first tier whose `route_pattern` matches wins. When no tier matches, the policy falls back to the top-level `price` and `currency`. An empty `tiers` list keeps the original flat-price behaviour.

### Per-shape pricing

`content_shape` is advisory: configurations may set the field on a tier so metrics and the redeem payload carry the shape, but the policy does not yet match against it. The wire format is stable, so configurations that set `content_shape` today will keep working when the resolver lands.

## HTTP ledger

The OSS in-memory ledger (`valid_tokens:`) is fine for tests, fixed-token issuance, or one-off content gates. Production deployments with multiple proxy replicas need a network-callable ledger so one token spends across all nodes. The HTTP ledger client speaks a JSON-over-HTTPS protocol with HMAC-SHA256 envelope signatures over a fixed eight-line canonical form.

```yaml
policies:
  - type: ai_crawl_control
    price: 0.001
    currency: USD
    ledger:
      url: "https://ledger.internal"   # required; plain http:// is rejected
      key_id: "sb-ledger-2026-q2"
      secret_ref:
        env: SBPROXY_LEDGER_HMAC_KEY   # env var holding the hex-encoded HMAC key
      workspace_id: "default"          # default: "default"
      idempotency_key_header: "Idempotency-Key"   # default
      timeout_ms: 5000                 # per-attempt timeout; default 5000
      retry:
        max_attempts: 5                # 1..=5; hard-clamped by the client
        initial_backoff_ms: 250        # default 250
        max_backoff_ms: 5000           # default 5000
      breaker:
        failure_threshold: 10          # consecutive failures that open; default 10
        success_threshold: 1           # half-open successes to close; default 1
        open_duration_ms: 5000         # default 5000
```

The HMAC key resolves through `secret_ref`, which takes either `env: <VAR>` (an environment variable holding the hex-encoded key) or `secret: <name>` (a logical secret resolved through the secrets layer). For dev configs and tests only, an inline `key_hex:` is honoured when `secret_ref` is absent; it should not appear in a production `sb.yml`. The agent identity fields on the redeem payload come from the request-time agent-class resolver, not from ledger config.

The client refuses to construct against a non-HTTPS `url` at config-load time. Plain HTTP is a hard error because the request envelope carries an HMAC over the body, and TLS is the only thing keeping the body itself confidential.

### Request envelope

Every redeem call carries the eight-line canonical envelope:

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

The circuit breaker opens after 10 consecutive failures, half-opens after 5 s with one probe, and closes on probe success. While the breaker is open, the client returns a synthetic `ledger.unavailable` error without making the network call. The policy treats that as "ledger is down" and fails closed: the crawler gets a 503 with a `ledger_unavailable` JSON body and a `Retry-After` header. There is no `on_ledger_failure` knob; fail-closed is the fixed behaviour, because failing open would hand out the content the paywall exists to price.

A ledger `Retry-After` propagates straight to the crawler on that 503 (defaulting to 5 seconds when the ledger did not send one), so the crawler knows when to come back.

### Failure modes

| Ledger response | Policy action |
|---|---|
| 200 success, redeemed | Pass the request through. |
| 200 success, not redeemed | 402 with the challenge body. The token was valid format but the ledger refused (out of balance, expired). |
| 409 `token_already_spent` | 402, no retry. |
| 4xx other | 402, no retry, log at WARN. |
| 5xx, transient envelope, breaker open | Fail closed: 503 with a `ledger_unavailable` body and `Retry-After`. Not configurable. |

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
  catalog: inline
  entries:
    - id: openai-gptbot
      vendor: OpenAI
      purpose: training
      expected_user_agent_pattern: "(?i)\\bGPTBot/\\d"
      expected_reverse_dns_suffixes: [".gptbot.openai.com"]
      expected_keyids: ["openai-2026-01"]
    - id: anthropic-claudebot
      vendor: Anthropic
      purpose: training
      expected_user_agent_pattern: "(?i)\\bClaudeBot/\\d"
      expected_keyids: ["anthropic-2026-01"]
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

`agent_id` on a tier matches against the resolver's verdict. The first tier whose route pattern AND agent id both match wins. A tier without `agent_id` matches every agent. `expected_keyids` lets a verified Web Bot Auth signature classify the request even when the User-Agent string is missing or spoofed.

The default agent classes ship embedded in the binary. Use `catalog: inline` when you want `sb.yml` to provide a complete catalog with your own `expected_keyids`; use `catalog: builtin` or omit the block to keep the embedded catalog.

## Observability

Every redeem fires a metric and a structured-log line. The label set:

| Label | Source | Cardinality cap |
|---|---|---|
| `agent_id` | Agent-class resolver. Bounded to registry plus `human`, `unknown`, `anonymous` sentinels. | 200 |
| `agent_class` | Closed enum from the taxonomy. | 8 |
| `agent_vendor` | Free-form vendor name from the taxonomy. | 20 |
| `payment_rail` | Closed enum: `none`, `x402`, `mpp_card`, `mpp_stablecoin`, `stripe_fiat`, `lightning`. | 6 |
| `content_shape` | Closed enum: `html`, `markdown`, `json`, `pdf`, `other`. | 5 |

Cardinality budgets are enforced by `sbproxy-observe::cardinality::CardinalityLimiter`; over-cap label values demote to `__other__` and increment `sbproxy_label_cardinality_overflow_total`.

### Metrics

| Metric | Type | Notes |
|---|---|---|
| `sbproxy_ledger_redeem_duration_seconds{host, outcome}` | histogram | Latency of the ledger round-trip, one observation per redeem. `outcome` is `success`, `transient_failure`, or `hard_failure`; count redeems from the histogram's `_count` series. Carries trace exemplars. There is no separate `sbproxy_ledger_redeem_total` counter. |
| `sbproxy_circuit_breaker_transitions_total{origin, from_state, to_state}` | counter | Breaker flap counter, shared with every other circuit breaker in the proxy. There is no ledger-specific breaker-state gauge. |
| `sbproxy_requests_total{hostname, method, status, agent_id, agent_class, agent_vendor, payment_rail, content_shape}` | counter | Per-request outcome. |

The per-agent dashboard (`deploy/dashboards/per-agent.json`) groups every panel by `agent_class` plus `agent_vendor`, so operators see one row per vendor and one row each for the sentinels. The audit-log dashboard (`deploy/dashboards/audit-log.json`) shows admin actions on `ai_crawl_control` tier edits.

### Tracing

Per-attempt ledger spans are design-stage: the intended shape is one outbound span per attempt named `sbproxy.ledger.redeem`, carrying `sbproxy.ledger.idempotency_key` and W3C TraceContext on the outbound request so the trace stitches end-to-end with a ledger that emits OTel spans. The HTTP ledger client does not emit those spans or inject `traceparent` today.

What ships now: exemplars on `sbproxy_ledger_redeem_duration_seconds_bucket` carry the active trace id, so Grafana can jump from "this latency outlier" straight to the matching trace in Tempo.

## Limitations

- Detection is User-Agent based by default. Crawlers that lie about their UA bypass the check unless reverse-DNS or Web Bot Auth signals catch them; layer this with bot-detection or WAF policies for defence in depth.
- The OSS in-memory ledger is single-process. Multi-replica deployments without an HTTP ledger need sticky session affinity to one replica.
- `content_shape` is advisory. The field flows through metrics and the redeem payload but is not yet used as a tier filter.
- Per-agent pricing requires the agent-class resolver to be enabled; the resolver runs unconditionally by default, but operators who explicitly disable it fall back to UA-only matching and lose the per-vendor distinction.

## See also

- [configuration.md](configuration.md#ai_crawl_control) - schema reference.
- [ai-gateway.md](ai-gateway.md) - how this policy interacts with `ai_proxy` upstreams.
- [observability.md](observability.md) - metrics, logs, traces, dashboards.
- `examples/ai-crawl-control/` - runnable example.
