# SBproxy events

*Last modified: 2026-04-27*

SBproxy has a small in-process event bus. The proxy publishes typed events from a few well-known points in the request lifecycle, and code-level embedders register handler closures against them. Nothing crosses the process boundary; OSS has no webhook, file, or Lua sink.

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

## Event shape

```rust
pub struct ProxyEvent {
    pub event_type: EventType,
    pub hostname: String,
    pub timestamp: u64,            // Unix epoch milliseconds
    pub data: serde_json::Value,   // event-specific payload
}
```

`data` is a free-form JSON map; keys vary per event. The bus does not stamp severity, `workspace_id`, or tags. Derive those from `data` in your handler.

## Subscribing programmatically

Each `EventBus::subscribe` call binds a closure to one event type. Publishers fan out to all bound closures synchronously, in the order they registered.

```rust
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
- [architecture.md](architecture.md) - where in the pipeline events publish.
- [troubleshooting.md](troubleshooting.md) - debugging missed events.
