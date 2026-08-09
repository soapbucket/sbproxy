# SBproxy events

*Last modified: 2026-08-09*

SBproxy has a closed set of eleven typed lifecycle events. The `events:` block sends them out of the process, either appended to a file as NDJSON or POSTed to an HTTP endpoint. That is how you get policy denials into a SIEM without parsing a log sink.

Delivery is off the request path. A publish site tests a bitmask, puts the event on a bounded queue, and returns; a background worker owns the file handle and the HTTP client. A collector that has gone slow or gone away cannot make a request slower, and the price of that is that a full queue drops events and counts them. There is no configuration in which an event sink adds latency to a request.

There is also a separate in-process `EventBus` that embedders can register closures against. That one does run handlers on the publisher's thread and is unaffected by anything here. See [Subscribing in process](#subscribing-in-process).

## Event types

`ProxyEvent::event_type` is the closed enum below. Variants serialize to snake_case JSON, and those are the names `events.types:` accepts.

| Name | When |
|------|------|
| `request_started` | A new request entered the pipeline. |
| `request_completed` | The request finished without an error. |
| `request_error` | The request terminated with an error. |
| `auth_denied` | Authentication rejected the request. |
| `policy_denied` | A policy (rate limit, IP filter, WAF, request limit) blocked the request, or an HTTP framing violation was refused. |
| `cache_hit` | A response was served from the response cache. |
| `cache_miss` | The cache lookup found no usable entry. |
| `provider_selected` | An AI provider was chosen for routing. |
| `budget_exceeded` | An AI spend or quota budget was exhausted. |
| `guardrail_triggered` | An AI guardrail flagged or blocked content. |
| `config_reloaded` | The proxy configuration changed. |

Circuit-breaker activity is a metric (`sbproxy_circuit_breaker_transitions_total`), not an event. See [metrics-stability.md](metrics-stability.md).

## Which of them the shipped binary actually emits

Five. The other six are enum variants an embedder can publish, and configuring a sink for one of those gets you a sink that never fires.

| Event | Emitted from |
|------|------|
| `request_completed` | Every request that terminates normally, once the capture path has minted an envelope request id. |
| `request_error` | Same site, when the request terminated with an error class. |
| `auth_denied` | Every authentication rejection, including forward-auth and digest challenges. |
| `policy_denied` | Every policy block (rate limit, IP filter, WAF, object authorization, A2A, prompt injection) and every HTTP framing violation. |
| `config_reloaded` | A configuration change through the admin API, carrying the revision pair and the origin delta. |

`request_started`, `cache_hit`, `cache_miss`, `provider_selected`, `budget_exceeded`, and `guardrail_triggered` have no emitter in this build. The cache path reports through `sbproxy_cache_*`, and the AI path reports through `sbproxy_ai_*` and the [usage ledger](ai-usage-ledger.md), which is where the gateway's own accounting lives. Point a sink at those six only if your own code publishes them.

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

`data` is the record the emitting channel already built. For `auth_denied` and `policy_denied` it is the `security_audit` entry: timestamp, event type, reason, hostname, client IP, request id, method, status code, tenant id, credential provider and mode, and the public key id. For `config_reloaded` it is the `config_audit` entry: source, origin delta, actor, and the before and after revisions. For `request_completed` and `request_error` it is the full request envelope, including latency, status, provider, model, token counts, and cost.

None of those payloads carries a credential, and that is a property under test rather than a convention. `api_key_id` is the public id or a derived `sk_<hex>` fingerprint and never the secret. `prompt_fingerprint` is salted and non-reversible. No field holds prompt text, a header value, or a resolved config value. A field added to either record fails a test until somebody has confirmed it can be sent to a third party, because with a webhook sink these bytes leave your network.

## The `events:` block

```yaml
events:
  sink: webhook                             # none | file | webhook
  url: https://siem.example.com/sbproxy     # webhook only
  signing_secret: secret://local/siem-hmac  # webhook only, optional
  types:                                    # empty or absent means all
    - policy_denied
    - auth_denied
  queue_capacity: 4096
```

| Key | Meaning |
|-----|---------|
| `sink` | `none` (the default) publishes nothing and costs one atomic load per event site. `file` appends NDJSON. `webhook` POSTs batches. |
| `path` | Output file for `sink: file`. Parent directories are created at boot. Required by `file`, refused otherwise. |
| `url` | Destination for `sink: webhook`. Must be `http://` or `https://`. Required by `webhook`, refused otherwise. |
| `signing_secret` | HMAC-SHA256 key for the webhook signature. Takes a secret reference and nothing else; see below. |
| `types` | Which event types to deliver. Empty or absent means all eleven. An unrecognized name is refused at compile time with the accepted list. |
| `queue_capacity` | Depth of the hand-off queue. Defaults to 4096. Zero is refused. |

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
  "version": "1.10.0",
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

A steady `queue_full` rate against a healthy collector usually means `types:` is too broad. `request_completed` fires once per request; `policy_denied` fires once per denial.

## Shutdown does not flush

Stated plainly so nobody assumes otherwise. On `SIGTERM` or `SIGKILL` the process exits with whatever is still queued still queued: up to `queue_capacity` events, plus the batch the worker was mid-delivery on.

Two things bound the loss. The file sink flushes after every drained batch, so what reached the file is on the file rather than in a userspace buffer. The webhook sink delivers one batch at a time and never buffers across batches.

If you need a record that survives the process and detects tampering, this is the wrong channel. Use `audit.sink: chain`, which appends every security audit event to a hash-chained, Ed25519-signed file that `sbproxy audit verify` re-derives from genesis.

## What the config refuses

Every one of these is a config that would compile, boot, serve traffic, and deliver nothing, which is the failure an event sink is worst at surfacing: the evidence it works is events arriving, and the evidence it is broken looks identical to a quiet afternoon.

- A `path` with any sink other than `file`, or a `url` or `signing_secret` with any sink other than `webhook`. An ignored key reads as configured.
- `sink: file` with no `path`, or `sink: webhook` with no `url`.
- A `url` that is not `http://` or `https://`.
- `queue_capacity: 0`.
- `types:` or `queue_capacity:` under `sink: none`.
- An event name `types:` does not recognize. The error quotes the name and lists all eleven.
- Any key the block does not define, so a hopeful `retries:` or `batch_size:` fails rather than being dropped.

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

- [metrics-stability.md](metrics-stability.md) - `sbproxy_events_dropped_total` and the metrics that overlap with these events.
- [audit-log.md](audit-log.md) - the `security_audit` channel these denials also write to, and the hash-chained form `audit.sink: chain` gives it.
- [ai-usage-ledger.md](ai-usage-ledger.md) - per-request AI usage records, the built-in path for the accounting the AI event types describe.
- [architecture.md](architecture.md) - the request pipeline the event types map onto.
- [troubleshooting.md](troubleshooting.md) - debugging missed events.
