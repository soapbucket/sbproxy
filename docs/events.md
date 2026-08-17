# SBproxy events

*Last modified: 2026-08-16*

SBproxy hands a SIEM three different things, and this page is the map of how they fit together: typed proxy events (the `events:` block, a closed set of twelve), decision-audit records (`observability.log.decision_audit`, eighteen pipeline decisions normalized to OCSF), and four audit channels that write to their own tracing targets (`security_audit`, `config_audit`, `key_audit`, and the admin action ring). Two of those four, `security_audit` and `config_audit`, can additionally be hash-chained and Ed25519-signed for tamper evidence.

If you only read one section, read [How the four audit channels relate to the event stream](#how-the-four-audit-channels-relate-to-the-event-stream). It is the piece that is easy to miss: `events:` is a delivery mechanism, not a source of truth, and most of what it delivers is a typed copy of a record another channel already produced.

## The typed proxy events

`ProxyEvent::event_type` is a closed enum. Variants serialize to snake_case JSON, and those are the names `events.types:` accepts.

| Name | When | Has an emitter |
|------|------|------|
| `request_started` | A new request entered the pipeline. | Yes |
| `request_completed` | The request finished without an error. | Yes |
| `request_error` | The request terminated with an error. | Yes |
| `auth_denied` | Authentication rejected the request. | Yes |
| `policy_denied` | A policy (rate limit, IP filter, WAF, request limit) blocked the request, or an HTTP framing violation was refused. | Yes |
| `egress_refused` | An outbound dial (AI provider, MCP OAuth token exchange, model artifact fetch, telemetry sink, ...) was refused by egress authorization. | Yes |
| `provider_selected` | An AI request failed over to a different provider. | Yes, on the transition only |
| `budget_exceeded` | An AI spend or quota budget was exhausted and the request was blocked. | Yes, on the deny only |
| `guardrail_triggered` | An AI guardrail blocked a request or a response. | Yes, on the block only |
| `config_reloaded` | The proxy configuration changed, or a reload was refused. | Yes |
| `cache_hit` | A response was served from the response cache. | No |
| `cache_miss` | The cache lookup found no usable entry. | No |

Ten of the twelve publish today. The other two, `cache_hit` and `cache_miss`, are declared on purpose and will not be wired: both fire on every cacheable request, and putting an NDJSON line on a configured webhook per cache lookup is a cost nobody asked to pay. The forensic question either answers, "did this response come from cache," already has a home: the `cache.admit` and `cache.key` decision-audit events (below) and the access log's `cache_status` column. If you write `events.types: [cache_hit]`, the proxy still boots, because refusing a name here would also block pre-configuring a type a later release wires. It just tells you at startup that nothing will ever arrive.

### The boot warning, so a quiet sink is a fact, not a guess

An empty `events:` sink and a broken one look identical from the outside: neither delivers anything. So at boot, the proxy checks every name in `events.types:` (or, when `types:` is absent, every name that means "all twelve") against the emitters that actually exist, and warns once, by name, for anything that will never fire:

```
WARN events.types selects event types that nothing publishes yet; the configured sink will not
     see these until their emitters ship events=cache_hit,cache_miss
```

This is the same shape `observability.log.decision_audit` has used for a while, extended to this channel. Read [observability.md](observability.md) for that side; the short version is in the next section.

### Verdict-level, not per-request

Three of the ten wired events are worth being explicit about, because "wired" does not mean "fires on every request that touches the feature":

- **`provider_selected`** fires on a provider failover or advance, never on the provider chosen for an ordinary first attempt. The data carries `from_provider`, `to_provider`, and the reason (`http_503`, `transport`, `content_policy`, `managed_cold_fallback`). A deployment with healthy providers and no failovers sees none of these, which is correct: routing choice by itself is not a security-relevant event, a transition off the configured plan is.
- **`budget_exceeded`** fires once per request that actually crosses a configured cap and gets blocked, at the same site that already builds the 402 response body. It does not fire for a request that stays under budget, and it does not fire on a soft-landing downgrade, only on a hard block. The data carries `scope` (the limit's scope label), `reason`, `max_tokens`, `max_cost_usd`, and `window_secs`.
- **`guardrail_triggered`** fires once per guardrail evaluation stage (input, RAG-augmented input, or output) that ends in a block, never per streamed chunk and never on an allow. The data carries `stage`, `guardrail` (which one blocked), and `flagged_count` (how many others flagged without blocking).

## Decision-audit: the other eighteen

Eleven of the twelve typed proxy events map onto request lifecycle and infrastructure facts. The gateway's actual security decisions, "did the WAF block this," "did the AI guardrail block this," "did this MCP tool dispatch succeed," live on a separate, wider channel: `DecisionEvent`, configured under `proxy.observability.log.decision_audit` and documented in full in [observability.md](observability.md#decision-audit-records) and the generated [decision-records.md](decision-records.md).

The short version, because this page is where the two channels need to be told apart:

- **Eighteen named decision points.** `auth`, `policy`, `rate_limit`, `waf`, `cache.key`, `cache.admit`, `route.decide`, `ai.guardrail.input`, `ai.guardrail.output`, `ai.tool_call`, `ai.stream.event`, `ai.close`, `ai.failure`, `transform`, `action`, `log.custom_field`, `mcp.tool`, `payment.lifecycle`.
- **Six coverage states**, because "wired or not" turned out to be the wrong question for at least four of these:
  - *Emitted*: publishes its own record. As of this sweep that is `auth`, `cache.key`, `cache.admit`, `route.decide`, `ai.guardrail.input`, `ai.guardrail.output`, `ai.tool_call`, `ai.close`, `ai.failure`, and `mcp.tool`.
  - *SupersededByPolicy*: `waf` and `rate_limit` compile to policy modules, so their decisions already publish as `policy` records carrying a `policy_id`. A second emitter under their own label would double-record one decision.
  - *ConfigDependent*: `policy` always reaches the bus, but arrives as the legacy `policy_verdict_event` shape until `policy_record_format: decision` moves it onto this feed.
  - *DurableElsewhere*: `payment.lifecycle` is recorded by the settlement store, which is non-lossy by design. This queue drops records under load (a sound trade for a security decision, the wrong one for money), so publishing the same event here would offer a second, weaker answer beside an authoritative one.
  - *NeverPublishes*: `ai.stream.event` fires once per streamed chunk. Enabling it is refused at config load, not warned about, because there is no configuration under which it will ever emit.
  - *Unwired*: `transform`, `action`, and `log.custom_field` accept configuration and publish nothing, on purpose for now. Transforms rewrite response bodies with no deny/allow semantics to record. Most of what `action` would report already has its own event under a more specific label. `log.custom_field` is operator-authored telemetry that belongs in the access log it was configured into, not a second copy on this bus.

`ai.close` and `ai.failure` are new to the *Emitted* set as of this sweep. `ai.failure` fires at the one funnel every provider-response failure classification already ran through, carrying `selected_provider` and a closed failure kind (`rate_limited`, `content_filter`, `upstream_5xx`, `provider_error`) under `unmapped`. `ai.close` fires once a streamed response finishes, carrying the terminal `finish_reason`, and is the intentional counterweight to `ai.stream.event`'s refusal: without it, the per-chunk feed that gets refused on volume grounds would have no summary anywhere in SIEM-land either.

`ai.close` carries one honest caveat the others do not. It publishes only for a request whose AI extension chain (JS, Lua, or WASM bundle hooks on `ai.*` events) is non-empty for that generation, because that is the only place the stream's finish-reason aggregate exists today. A deployment with zero AI extension bundles configured never builds that chain, so `ai.close` publishes nothing there even with `decision_audit` enabled and the boot warning silent (the warning cannot see a gap that is config-shaped rather than code-shaped). If you rely on `ai.close`, confirm you have at least one AI extension hook registered, linked or bundle. This is a narrower guarantee than the funnel-per-event shape the other *Emitted* events carry, and it is called out here rather than left for you to discover against a quiet feed.

`mcp.tool` here covers a successful (or gateway-declined) tool dispatch attribution. It does not cover an MCP request refused before dispatch on RBAC, quota, or a lethal-trifecta session check (tool access, private data, and external communication in one session): those denials are carried by the MCP governance evidence channel, a separate, purpose-built record for exactly that shape of decision, rather than by any channel this page documents.

## Event shape

```rust,no_run
pub struct ProxyEvent {
    pub event_type: EventType,
    pub hostname: String,
    pub tenant_id: String,         // empty when no tenant resolved
    pub timestamp: u64,            // Unix epoch milliseconds
    pub data: serde_json::Value,   // event-specific payload
}
```

`data` is built by whichever channel produced the underlying fact, not invented at the bridge:

- `auth_denied` and `policy_denied` carry the `security_audit` entry: timestamp, event type, reason, hostname, client IP, request id, method, status code, tenant id, credential provider and mode, and the public key id.
- `config_reloaded` carries the `config_audit` entry: source, origin delta, actor, the before and after revisions, and, on a rejection, a `rejection_reason`. That field is bounded to 512 bytes and has the local config path scrubbed out of it, but it is not scrubbed of config content in general: a compile or validation error routinely echoes the fragment it is complaining about (an invalid expression, an unrecognized key, a hostname), because naming the fragment is how the error explains itself. Point a rejection-reason sink at somewhere you already trust with your config's shape.
- `egress_refused` carries the four fields `record_egress_refused` already puts on its Prometheus series: `purpose`, `reason`, `tenant`, `origin`, all closed, bounded labels.
- `provider_selected`, `budget_exceeded`, and `guardrail_triggered` carry the fields listed under [Verdict-level, not per-request](#verdict-level-not-per-request) above.
- `request_completed` and `request_error` carry the full request envelope: latency, status, provider, model, token counts, and cost.

None of those payloads carries a credential, and that is a property under test rather than a convention. `api_key_id` is the public id or a derived `sk_<hex>` fingerprint and never the secret. `prompt_fingerprint` is salted and non-reversible. No field holds prompt text, a header value, or a resolved config value. A field added to any of these records fails a test until somebody has confirmed it can be sent to a third party, because with a webhook sink these bytes leave your network.

## The `events:` block

```yaml
events:
  sink: webhook                             # none | file | webhook
  url: https://siem.example.com/sbproxy     # webhook only
  signing_secret: secret://local/siem-hmac  # webhook only, optional
  types:                                    # empty or absent means all
    - policy_denied
    - auth_denied
    - egress_refused
  queue_capacity: 4096
```

| Key | Meaning |
|-----|---------|
| `sink` | `none` (the default) publishes nothing and costs one atomic load per event site. `file` appends NDJSON. `webhook` POSTs batches. |
| `path` | Output file for `sink: file`. Parent directories are created at boot. Required by `file`, refused otherwise. |
| `url` | Destination for `sink: webhook`. Must be `http://` or `https://`. Required by `webhook`, refused otherwise. |
| `signing_secret` | HMAC-SHA256 key for the webhook signature. Takes a secret reference and nothing else; see below. |
| `types` | Which event types to deliver. Empty or absent means all twelve. An unrecognized name is refused at compile time with the accepted list; a recognized but unwired name compiles and warns at boot (see above). |
| `queue_capacity` | Depth of the hand-off queue. Defaults to 4096. Zero is refused. |

A worked example for an AI-heavy deployment that wants the abuse and cost signals in one place:

```yaml
events:
  sink: file
  path: /var/log/sbproxy/ai-events.ndjson
  types:
    - budget_exceeded
    - guardrail_triggered
    - provider_selected
    - egress_refused
```

The file form is a line per event, the same shape a `jq` filter or a Vector source expects:

```yaml
events:
  sink: file
  path: /var/log/sbproxy/events.ndjson
  types:
    - policy_denied
```

### The webhook contract

One POST per batch, up to 256 events, `Content-Type: application/json`:

```json
{
  "source": "sbproxy",
  "version": "1.11.0",
  "events": [
    {
      "event_type": "policy_denied",
      "hostname": "api.example.com",
      "tenant_id": "acme",
      "timestamp": 1754697600000,
      "data": { "reason": "rate limit exceeded", "status_code": 429 }
    }
  ]
}
```

Headers: `X-Sbproxy-Event: proxy_events`, `X-Sbproxy-Event-Count`, `X-Sbproxy-Timestamp` (Unix seconds), and, when `signing_secret` is set, `X-Sbproxy-Signature: v1=<hex>`. The signature is HMAC-SHA256 over `<timestamp>.<body>`, the same construction the alert webhook uses, so a receiver that already verifies one verifies the other with the same code.

Any 2xx is success. Anything else drops the batch and counts it.

The URL goes through the SSRF guard at boot and again before every batch, so a collector hostname that starts resolving to a private address stops being posted to rather than becoming an internal probe.

### Authenticating the webhook

`signing_secret` accepts a secret reference and there is no plaintext field beside it. Every scheme the rest of the config takes works here: `${VAR}`, `file:`, `secret://`, `vault://`, `awssm://`, `gcpsm://`, `azurekv://`, `k8ssecret://`. References resolve at boot, and one that cannot be resolved stops the proxy from starting rather than posting the literal reference text to your collector.

```yaml
proxy:
  secrets:
    backends:
      - type: local
        name: local

events:
  sink: webhook
  url: https://siem.example.com/sbproxy
  signing_secret: secret://local/siem-hmac
```

## Fail-closed semantics

SBproxy names three request-time postures rather than a binary "fail open or closed," and the full matrix, with every subsystem that honors it, lives in [degradation.md](degradation.md). Summarized here because it decides what a missing or errored record means:

| Posture | The request | What is left behind |
|---|---|---|
| `closed` | Refused | The refusal itself is the record. |
| `degraded` | Admitted | An explicit record that the guarantee was not made. |
| `open` | Admitted | Nothing. |

The rule of thumb, stated once in [a2a-gateway.md](a2a-gateway.md): fail closed for anything enforcing a security boundary, fail open only where refusing would turn a non-security failure into an outage.

Two decision events illustrate both ends on the same request. `cache.key` fails closed on an engine fault: the decision could not be made, so the outcome is `error` and the record says so. `cache.admit` fails open on the same class of fault: an admission decision that could not be made still lets the response through, and the event records `outcome=allow` on the family plus a separate `sbproxy_decision_event_fail_open_total` counter, because a fail-open is a different operational fact than an error and wants a different alert. Neither state is silent. That is the property to check when a SIEM rule assumes "no record means nothing happened": for anything on the decision-audit or typed-event feed, no record can also mean the feed dropped it (see Backpressure, below) or, for `cache.admit`-shaped events, that the decision fired open rather than closed. The fail-open counter is what tells those two apart.

## OTel field-name conventions used here

There is no single schema file to point at; the convention is consistent rather than centralized. Every structured emission in this codebase, whether it is a `tracing::warn!` line, a decision-audit record, or one of these typed events, follows the same shape: a discriminator field named `event` carrying a stable string, plus a closed set of named fields beside it. Circuit-breaker transitions log `event = "circuit_breaker_transition"`; a SIGTERM mid-startup logs `event = "shutdown_signal_received"`; a policy decision logs under its own `cache.admit`-style dotted label. Grep for `event = "` across the tracing call sites in `sbproxy-core` and `sbproxy-observe` and the pattern is the same everywhere: name the fact, then attach the fields a rule would select on.

Two vocabularies get reused deliberately rather than invented per feature:

- **The OCSF envelope**, for decision-audit. Every record is API Activity (6003) with the Security Control profile: `class_uid`, `metadata.correlation_uid` (the request id), `cloud.org.name` (tenant), `api.service.name` (the origin id, never the request `Host`), `disposition_id` / `is_alert`, and per-event structured detail under `unmapped`, OCSF's sanctioned home for attributes the class does not define. [observability.md](observability.md) and [decision-records.md](decision-records.md) have the full field-by-field reference.
- **The OTel GenAI and error vocabulary**, for the AI request/response spans this page's events correlate with. `gen_ai.*` attributes follow the OTel GenAI semantic conventions, and a failed span sets `otel.status_code = ERROR` with `error.type` drawn from a closed set: `guardrail_blocked`, `rate_limited`, `content_filter`, `budget_exceeded`, `upstream_5xx`, `timeout`, `provider_error`. `ai.failure`'s decision-audit `verdict` field (`rate_limited`, `content_filter`, `upstream_5xx`, `provider_error`) is drawn from the same closed vocabulary on purpose, so a rule written against the span's `error.type` and a rule written against the decision-audit record agree about what a failure was.

Standard resource attributes (`service.name`, `service.version`, `host.name`, `k8s.pod.name`, and the rest) and the `sbproxy.*` namespace (`sbproxy.request_id`, `sbproxy.tenant_id`, `sbproxy.route`) are documented in full in [observability.md](observability.md#traces).

## Retention is the SIEM's job

Nothing in SBproxy retains an event once it has been handed off. The `events:` queue is bounded and in-memory; a process restart discards whatever was still queued. The two chainable audit channels, `security_audit` and `config_audit` under `audit.sink: chain`, are durable and tamper-evident, but they are not a retention system either: there is no rotation or built-in expiry, each is one append-only file that grows for the life of the deployment, and the documented way to manage its size is to archive by copying, not by trimming a file whose whole value is that nothing in it can be quietly removed.

That is a deliberate division of labor, not a gap. A proxy that buffered, indexed, and aged out its own security event history would be reimplementing the thing you already run a SIEM for, badly, on the request path's memory budget. SBproxy's job is to produce the record, attribute it correctly, and get it off the box with the least possible cost to the request that triggered it. Your SIEM's job is everything after that: indexing, long-term storage, retention policy, and cross-tenant search. Point `events:` and `audit.sink: chain` at storage you control, and let that system own how long a record lives.

One thing this section is not claiming: there is no per-tenant sequence guarantee on either the typed-event feed or decision-audit today. Both are lossy under load by design (see Backpressure, below), and neither carries a sequence number a consumer could use to detect a gap. If your compliance posture needs a provable, gapless per-tenant record, that is a different, narrower guarantee than anything on this page, and it is not implemented here.

## How the four audit channels relate to the event stream

Four channels write structured records, and only some of that traffic ever reaches `events:`:

| Channel | Tamper-evident | Reaches `events:`? |
|---|---|---|
| `security_audit` | Yes, under `audit.sink: chain` | Yes, bridged: `auth_*` and `forward_auth_*` reasons become `auth_denied`; everything else (framing violations, policy labels) becomes `policy_denied`. |
| `config_audit` | Yes, under `audit.sink: chain` | Yes, bridged one to one to `config_reloaded`, for both an accepted and a rejected reload, on every reload path: the admin API, the file watcher, SIGHUP, the config-authority bundle apply, the remote config-source refresh poller, and the Git-backed extension-bundle refresh poller. |
| `key_audit` | No (deliberately not chainable yet; see [audit-log.md](audit-log.md)) | No. Key-plane mutations (create, rotate, block, revoke) stay on the `key_audit` tracing target only. |
| Admin action ring | No | No. Console logins, content-inspection reads, and other admin-console actions stay on the `sbproxy::admin::audit` tracing target and the bounded in-memory ring `GET /api/audit/recent` reads. |

The egress-refusal event follows the same bridge shape as the other two, just from a funnel that does not itself belong to any of the four named channels: `record_egress_refused` (the one function every purpose, AI provider, MCP token exchange, model artifact fetch, webhook and usage-sink delivery, already goes through) already writes a Prometheus series and a `tracing::warn!` line under `target: "sbproxy::egress"`. Since it lives in a leaf crate that cannot depend on the observability crate, the bridge to `EventType::EgressRefused` is a function pointer installed once at boot rather than a direct call, but the effect is the same as the security-audit bridge: one funnel, one typed event, covering every purpose that funnel serves.

The practical read for a SIEM integration: subscribe to `events:` for a typed, filterable copy of denials and config changes, cheap to deliver and safe to lose the occasional record under load. Subscribe to `audit.sink: chain` separately, on `security_audit` and `config_audit`, when you need the tamper-evident original those typed copies were built from. Read `key_audit` and the admin ring directly if you need key-plane or console-action history; neither has a typed-event mirror.

## Backpressure, and the drops it causes

The queue is bounded. When it is full, the newest event is discarded and `sbproxy_events_dropped_total{sink,reason}` ticks. Dropping the newest rather than evicting the oldest loses the tail of a burst instead of events that were already accepted and may already be in flight.

Every other way an event fails to arrive lands on the same counter, so an empty SIEM always has an answer:

| `reason` | What happened |
|-----|-----|
| `queue_full` | A publish site found the queue at capacity. Raise `queue_capacity`, narrow `types`, or find out why the sink is slow. |
| `worker_stopped` | The delivery thread is gone. |
| `serialize_error` | The event would not encode as JSON. |
| `write_error` | The file write or flush failed. |
| `http_error` | The endpoint answered a non-2xx status. |
| `delivery_failed` | The request never got an answer: connection refused, DNS failure, or the five-second timeout. |
| `ssrf_rejected` | The URL resolved to an address the SSRF guard refuses. |

A steady `queue_full` rate against a healthy collector usually means `types:` is too broad. `request_completed` fires once per request; `policy_denied` fires once per denial; `provider_selected`, `budget_exceeded`, and `guardrail_triggered` fire only on the verdict transitions described above, so a high rate on any of those three is itself worth looking at before you widen the queue.

## Shutdown does not flush

Stated plainly so nobody assumes otherwise. On `SIGTERM` or `SIGKILL` the process exits with whatever is still queued still queued: up to `queue_capacity` events, plus the batch the worker was mid-delivery on.

Two things bound the loss. The file sink flushes after every drained batch, so what reached the file is on the file rather than in a userspace buffer. The webhook sink delivers one batch at a time and never buffers across batches.

If you need a record that survives the process and detects tampering, this is the wrong channel. Use `audit.sink: chain`, which appends every `security_audit` or `config_audit` event to a hash-chained, Ed25519-signed file that `sbproxy audit verify` re-derives from genesis.

## What the config refuses

Every one of these is a config that would compile, boot, serve traffic, and deliver nothing, which is the failure an event sink is worst at surfacing: the evidence it works is events arriving, and the evidence it is broken looks identical to a quiet afternoon.

- A `path` with any sink other than `file`, or a `url` or `signing_secret` with any sink other than `webhook`. An ignored key reads as configured.
- `sink: file` with no `path`, or `sink: webhook` with no `url`.
- A `url` that is not `http://` or `https://`.
- `queue_capacity: 0`.
- `types:` or `queue_capacity:` under `sink: none`.
- An event name `types:` does not recognize. The error quotes the name and lists all twelve.
- Any key the block does not define, so a hopeful `retries:` or `batch_size:` fails rather than being dropped.

A recognized but unwired name (`cache_hit`, `cache_miss`) is different from all of the above: it compiles, because the config layer cannot know which names a future release will wire, and it warns once at boot instead. See [The boot warning](#the-boot-warning-so-a-quiet-sink-is-a-fact-not-a-guess).

## Not implemented

Kafka, NATS, and EventBridge are follow-ups. Each needs a client library, a partitioning decision, and a delivery guarantee that a bounded queue and a best-effort POST do not have. Their names are refused today rather than accepted into a sink that would not deliver.

There are no retries. One attempt per batch, and a failure is counted rather than requeued: a retry queue in front of a bounded queue turns a slow endpoint into dropped events plus a stall, and choosing otherwise means choosing how long an event is worth holding.

One `events:` block selects one sink. Two collectors means one sink plus a forwarder.

## Subscribing in process

`EventBus` is a separate mechanism for code that embeds the workspace crates. Each `subscribe` call binds a closure to one event type, and publishers fan out to all bound closures synchronously.

```rust,no_run
use sbproxy_observe::events::{EventBus, EventType, ProxyEvent};

let bus = EventBus::new();

bus.subscribe(EventType::BudgetExceeded, Box::new(|event: &ProxyEvent| {
    eprintln!("budget tripped on {}: {}", event.hostname, event.data);
}));
```

Handlers run on the publisher's thread, so a slow or panicking handler stalls whatever emitted the event. Keep the body short. The `events:` sinks do not go through this bus and are not affected by a handler registered on it.

## See also

- [observability.md](observability.md) - the full decision-audit reference: every event's coverage state, the OCSF field mapping, the boot warning, and OTel traces and metrics.
- [decision-records.md](decision-records.md) - the generated, code-checked contract for exactly what each *Emitted* decision event's `unmapped` object carries. Regenerated from the source of truth; do not hand-edit.
- [degradation.md](degradation.md) - the full fail-open / fail-closed / degraded matrix referenced above.
- [audit-log.md](audit-log.md) - `security_audit` and `config_audit` under `audit.sink: chain`, and why `key_audit` and the admin ring are not chained yet.
- [metrics-stability.md](metrics-stability.md) - `sbproxy_events_dropped_total`, `sbproxy_decision_audit_events_total`, and the rest of the metric families that overlap with these events.
- [ai-usage-ledger.md](ai-usage-ledger.md) - per-request AI usage records, the built-in path for accounting these AI-shaped events summarize rather than duplicate.
- [architecture.md](architecture.md) - the request pipeline these event types map onto.
- [troubleshooting.md](troubleshooting.md) - debugging missed events.
