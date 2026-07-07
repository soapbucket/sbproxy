# SBproxy events

*Last modified: 2026-07-06*

SBproxy has a small in-process event bus in `sbproxy-observe`. It defines a closed set of typed lifecycle events and a bus that code-level embedders publish to and register handler closures against. The shipped `sbproxy` binary does not publish to a global bus today; its own request telemetry flows through the `sbproxy_*` Prometheus metrics, the access log, and the request-event sink. The bus is the seam for embedders building on the workspace crates. Nothing crosses the process boundary; OSS has no webhook, file, or Lua sink.

## Event types

`ProxyEvent::event_type` is the closed enum below. Variants serialise to snake_case JSON.

| Name | When |
|------|------|
| `request_started` | A new request entered the pipeline. |
| `request_completed` | The request finished without an error. |
| `request_error` | The request terminated with an error. |
| `auth_denied` | Authentication rejected the request. |
| `policy_denied` | A policy (rate limit, IP filter, WAF, request limit) blocked the request. |
| `cache_hit` | A response was served from the response cache. |
| `cache_miss` | The cache lookup found no usable entry. |
| `provider_selected` | An AI provider was chosen for routing. |
| `budget_exceeded` | An AI spend or quota budget was exhausted. |
| `guardrail_triggered` | An AI guardrail flagged or blocked content. |
| `config_reloaded` | The proxy configuration reloaded successfully. |

`circuit_breaker_*`, `analytics_*`, and `buffer_*` are metrics in OSS, not events. See [metrics-stability.md](metrics-stability.md).

The three AI variants (`provider_selected`, `budget_exceeded`, `guardrail_triggered`) name AI-gateway moments, but the shipped AI path records those through the `sbproxy_ai_*` metrics and the [usage ledger](ai-usage-ledger.md) rather than through this bus. Use the enum variants when your embedding code publishes its own events; use the metrics and ledger when you want the gateway's built-in accounting.

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

`data` is a free-form JSON map; keys vary per event. The event carries a `tenant_id` (empty string in single-tenant deployments) so handlers can filter per tenant without parsing `data`. The bus does not stamp severity, `workspace_id`, or tags; derive those from `data` in your handler.

## Subscribing programmatically

Each `EventBus::subscribe` call binds a closure to one event type. Publishers fan out to all bound closures synchronously, in the order they registered.

```rust,no_run
use sbproxy_observe::events::{EventBus, EventType, ProxyEvent};

let bus = EventBus::new();

bus.subscribe(EventType::BudgetExceeded, Box::new(|event: &ProxyEvent| {
    eprintln!("budget tripped on {}: {}", event.hostname, event.data);
}));

bus.subscribe(EventType::ConfigReloaded, Box::new(|_| {
    metrics::counter!("config_reload_total").increment(1);
}));
```

Handlers run on the publisher's thread, so a slow or panicking handler stalls the request that emitted the event. Keep the body short and offload long work onto a queue you push to from the closure.

## No `events:` YAML block

The OSS bus is a code-level extension point, so there is no `events:` config. Webhook, file, and Lua sinks are tracked under the enterprise roadmap; the YAML block lands with them.

## See also

- [metrics-stability.md](metrics-stability.md) - Prometheus metrics that overlap with these events.
- [ai-usage-ledger.md](ai-usage-ledger.md) - per-request AI usage records, the built-in path for the accounting these AI event types describe.
- [architecture.md](architecture.md) - the request pipeline the event types map onto.
- [troubleshooting.md](troubleshooting.md) - debugging missed events.
