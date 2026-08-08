# Routing Strategies
*Last modified: 2026-08-08*

The `RoutingStrategy` trait is an extension point for custom upstream selection in a `load_balancer` action. It lives in `sbproxy-modules::action::routing`. The trait runs synchronously on the request hot path, receives already-projected request and target state, and returns the index of a chosen eligible target or `None` to use the configured `algorithm`.

The built-in algorithms (`round_robin`, `weighted_random`, `least_connections`, `ip_hash`, `uri_hash`, `header_hash`, `cookie_hash`, and `ring_hash`) remain fallback selectors. When `strategy` names a registered strategy, the production action compiles it once and consults it before `algorithm` on every request. `lb_method: plugin` is an accepted compatibility marker and requires `strategy`; `strategy` is the field that selects and compiles the registered implementation.

Before a strategy runs, the load balancer applies deployment-mode, backup, priority, active-health, circuit-breaker, and outlier-ejection filters. A strategy sees only that eligible slice. If every active target was filtered out, the load balancer uses its existing last-resort fallback rather than asking a strategy to bypass health filters.

## Configuration

```yaml
action:
  type: load_balancer
  algorithm: least_connections
  lb_method: plugin
  strategy: gpu-aware
  strategy_config: {}
  targets:
    - url: https://test.sbproxy.dev/gpu-a
      metadata:
        gpu_utilization: 0.72
    - url: https://test.sbproxy.dev/gpu-b
      metadata:
        gpu_utilization: 0.31
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `strategy` | string | unset | Registered strategy name. When set, the production action compiles and executes it before `algorithm`. Unknown names fail config compilation. |
| `strategy_config` | object | `{}` | Strategy-specific settings. A scalar or array is rejected. |
| `lb_method` | string | unset | Compatibility marker. `plugin` requires `strategy`; it does not replace `algorithm`. |
| `algorithm` | string or object | `round_robin` | Fallback selector when a strategy returns `None`. |
| `targets[].metadata` | object | `{}` | Static JSON signals projected into `TargetState.metadata`. Each target accepts at most 64 entries, and each key is at most 64 bytes. |

Request routing hints are bounded too. `model` comes from `X-Model` or `?model=`, and `adapter` comes from `X-LoRA-Adapter` or `?adapter=`. Empty values and values longer than 256 bytes are ignored. Headers take precedence over query parameters.

## Trait shape

```rust,ignore
pub trait RoutingStrategy: Send + Sync {
    fn select(
        &self,
        request: &RoutingRequest,
        targets: &[TargetState],
    ) -> Option<usize>;

    fn name(&self) -> &str;

    fn record_outcome(
        &self,
        target_url: &str,
        outcome: RoutingOutcome,
    ) {}
}
```

`RoutingRequest` carries the method, full path and query, headers, client IP, hostname, optional `model` and `adapter`, and a free-form metadata map.

`TargetState` carries the configured target index, URL, collapsed health status, active connection count, weight, and configured metadata. The health value incorporates active checks, circuit breakers, and outlier detection before the strategy runs.

The public surface also provides:

- `build_routing_strategy(name, config)` to resolve a registered name and instantiate it.
- `list_routing_strategies()` to enumerate registered names for diagnostics and config validation.

## Registering a strategy

Strategies register at link time via `inventory::submit!`, the same pattern used by the other module registries.

```rust,ignore
use std::sync::Arc;
use sbproxy_modules::action::routing::{
    RoutingRequest, RoutingStrategy, RoutingStrategyRegistration, TargetState,
};

pub struct LeastLoaded;

impl RoutingStrategy for LeastLoaded {
    fn name(&self) -> &str { "least-loaded" }

    fn select(
        &self,
        _request: &RoutingRequest,
        targets: &[TargetState],
    ) -> Option<usize> {
        targets
            .iter()
            .enumerate()
            .filter(|(_, target)| target.healthy)
            .min_by_key(|(_, target)| target.active_connections)
            .map(|(index, _)| index)
    }
}

inventory::submit! {
    RoutingStrategyRegistration {
        name: "least-loaded",
        build: |_config| Ok(Arc::new(LeastLoaded)),
    }
}
```

Once its crate is linked into the proxy binary, referencing `strategy: least-loaded` makes config compilation resolve the implementation to an `Arc<dyn RoutingStrategy>`.

## Production strategies

| Name | Behavior |
|------|----------|
| `first-healthy` | Picks the lowest-index eligible target. |
| `lora` | With an adapter hint, picks the lowest-index eligible target that advertises it or defers. Without a hint, picks the first eligible target. |
| `lora-aware` | Prefers the least-loaded eligible target that advertises the requested adapter, or defers. |
| `gpu-aware` | Picks the eligible target with the lowest valid `metadata.gpu_utilization` in `[0.0, 1.0]`. With no valid signal, it round-robins across eligible targets. |
| `bandit` | Learns a latency-sensitive reward from completed outcomes and explores a random eligible target with probability `epsilon`. |

### GPU-aware signals

`gpu-aware` is a pure consumer of configured metadata. It does not poll GPUs, scrape metrics, or fabricate utilization when a signal is absent or invalid. Operators can update `targets[].metadata.gpu_utilization` through their config generation and hot-reload path. Values below `0.0`, above `1.0`, or not numeric are ignored. If no eligible target has a valid value, the strategy uses its deterministic healthy-target round robin.

### Bandit learning and retention

`bandit` accepts `epsilon` (default `0.1`, clamped to `[0.0, 1.0]`) and `unseen_bonus` (default `0.05`, clamped to zero or greater). Unseen targets score `1.0 + unseen_bonus`, which ensures every eligible arm is sampled before pure exploitation settles on an observed arm. Set `epsilon: 0.0` for deterministic exploitation after those initial samples.

A failed attempt receives reward `0`. A successful attempt receives:

```text
reward = 1 / (1 + latency_seconds)
```

The score for a seen target is its mean recorded reward. The inputs are the observed success status and wall-clock latency of a completed upstream attempt. The strategy does not invent token price, monetary cost, provider cost, or GPU data.

Bandit feedback is process-local and keyed by origin, strategy name, and the ordered target URL list. A compatible hot reload with the same key reuses learned state. Changing the origin, strategy name, target URLs, or target order creates a fresh namespace. A process restart always resets learning. Retention is bounded to 256 namespaces per process and 256 target arms per namespace. The oldest namespace is evicted when the namespace bound is reached, and additional arms beyond the per-namespace bound are not recorded.

## LoRA-aware routing

`strategy: lora-aware` prefers an upstream that already has the requested adapter warm in memory. The request can carry the adapter in `X-LoRA-Adapter` or `?adapter=`. When no eligible upstream advertises that adapter, the strategy returns `None` and the configured `algorithm` selects the target.

Each target advertises its inventory as a JSON array under `metadata.loaded_adapters`:

```yaml
targets:
  - url: https://test.sbproxy.dev/lora-a
    metadata:
      loaded_adapters:
        - alice-tone
        - bob-style
```

A missing key, a non-array value, or non-string elements are treated as an empty inventory. SBproxy does not discover adapter inventories from upstreams. Operators generate this metadata from their source of truth and apply updates through normal config hot reload.

`fallback_below` in `strategy_config` sets the minimum number of eligible warm targets required before `lora-aware` commits to a selection. It defaults to `1`; a configured `0` is normalized to `1`. Among qualifying warm targets, the lowest active connection count wins. Ties select the earlier target in the priority-ordered eligible slice; equal-priority targets retain configuration order.

The strategy returns `None` when:

1. No bounded adapter hint is present.
2. Fewer than `fallback_below` eligible targets advertise the adapter.
3. No eligible target advertises the adapter.

The configured `algorithm` then selects from the same eligible target slice. No strategy selects an unhealthy target or fabricates a lowest-cost target.

```yaml
action:
  type: load_balancer
  algorithm: least_connections
  lb_method: plugin
  strategy: lora-aware
  targets:
    - url: https://test.sbproxy.dev/lora-a
      metadata: { loaded_adapters: [alice-tone, bob-style] }
    - url: https://test.sbproxy.dev/lora-b
      metadata: { loaded_adapters: [carol-voice] }
    - url: https://test.sbproxy.dev/lora-c
      metadata: { loaded_adapters: [alice-tone, dave-formal] }
```

A request for `adapter=alice-tone` selects the less-loaded of the first and third targets. A request for an unknown adapter or no adapter falls through to `least_connections`.

A runnable configuration lives at `examples/lora-aware-routing/sb.yml`.

## Watching a strategy choose

Which target a strategy picked is not visible when every target is the same address, which is the reason a config alone cannot demonstrate any of this. [`examples/routing-strategies/`](../examples/routing-strategies/) ships two upstreams that report their own name and points three origins at the same pair.

```bash
cd examples/routing-strategies
docker compose up -d --wait
```

`gpu-aware` picks the lowest valid `metadata.gpu_utilization`, and keeps picking it, because the value is configuration rather than telemetry it polls:

```bash
for i in 1 2 3 4; do curl -s -H 'Host: gpu.local' http://127.0.0.1:8080/infer; echo; done
```

```
{"target":"replica-b","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
```

The `percent.local` origin carries the same two targets with `72` and `31` in that field, the percent-versus-fraction typo. Both are outside `[0.0, 1.0]`, so the strategy ignores them rather than reading a busy replica as the idle one, and its deterministic round robin runs instead:

```bash
for i in 1 2 3 4; do curl -s -H 'Host: percent.local' http://127.0.0.1:8080/infer; echo; done
```

```
{"target":"replica-a","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
{"target":"replica-a","path":"/infer","adapter_requested":""}
{"target":"replica-b","path":"/infer","adapter_requested":""}
```

`lora-aware` prefers the replica advertising the requested adapter, and returns no selection when none does, at which point the configured `algorithm` picks from the same eligible slice:

```bash
curl -s -H 'Host: lora.local' -H 'X-LoRA-Adapter: alice-tone' http://127.0.0.1:8080/infer; echo
curl -s -H 'Host: lora.local' -H 'X-LoRA-Adapter: nobody-has-this' http://127.0.0.1:8080/infer
```

```
{"target":"replica-a","path":"/infer","adapter_requested":"alice-tone"}
{"target":"replica-a","path":"/infer","adapter_requested":"nobody-has-this"}
```

`docker compose down -v` tears it down.

## Examples in Practice

To see various routing strategies in action, consult these runnable examples:

| Example | What it is | How to use it | Outcome |
|---------|------------|---------------|---------|
| [`load-balancer-deployment`](../examples/load-balancer-deployment/) | Advanced LB topologies. | Configure `upstream` blocks. | Sophisticated load balancing across clusters. |
| [`error-pages`](../examples/error-pages/) | Custom error pages. | Set `error_pages` mapping in config. | Friendly, branded HTML responses on 503s or 404s. |
| [`grpc-h2c`](../examples/grpc-h2c/) | gRPC over cleartext HTTP/2. | Set `protocol: h2c`. | Seamless gRPC proxying without TLS termination overhead. |
| [`headers-and-cors`](../examples/headers-and-cors/) | Manage CORS and HTTP headers. | Use `cors:` and `headers:` blocks. | Secure, standard-compliant browser API access. |
| [`request-limit`](../examples/request-limit/) | Concurrency limits. | Configure `concurrent_requests` cap. | Sheds load dynamically during traffic spikes to protect upstream servers. |
| [`response-cache-per-origin-keys`](../examples/response-cache-per-origin-keys/) | Cache isolation by origin. | Add origin variables to your cache key. | Prevents cache poisoning across multitenant platforms. |
