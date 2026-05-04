# Routing Strategies
*Last modified: 2026-04-27*

The `RoutingStrategy` trait is an opt-in extension point for plugging custom upstream selection logic into a `load_balancer` action. It lives in `sbproxy-modules::action::routing` and is the OSS scaffold that production work in [Fail-6](roadmap.md) (LoRA-aware, GPU-aware, contextual-bandit routing) will build against. The trait runs on the request hot path, so it is synchronous, takes a borrowed slice of already-projected target state, and returns the index of the chosen target or `None` to fall through to the configured `lb_method`.

The existing built-in algorithms (`round_robin`, `weighted`, `least_connections`, `consistent_hash`, `random`, `priority`, ...) are unchanged and are not yet behind this trait. They continue to handle every request the way they always have. Strategies plug in alongside them: when a `RoutingStrategy` returns `None`, the configured built-in `lb_method` runs as the fall-back. The migration of the built-ins to live behind the trait, plus the three concrete production strategies, is tracked separately under Fail-6 in the roadmap.

## Trait shape

```rust,ignore
pub trait RoutingStrategy: Send + Sync {
    fn select(
        &self,
        request: &RoutingRequest,
        targets: &[TargetState],
    ) -> Option<usize>;

    fn name(&self) -> &str;
}
```

`RoutingRequest` carries the request projection a strategy is allowed to see: `method`, `path`, `headers`, `client_ip`, `hostname`, optional `model` and `adapter` (set on the AI-proxy code path), and a free-form `metadata` map for additional signals.

`TargetState` is the projected upstream view: `index` into the load balancer's target slice, `url`, a single `healthy` boolean (collapsing health checks, circuit breakers, and outlier detection), `active_connections`, `weight`, and a `metadata` map sourced from the target config (loaded LoRA adapters, GPU model, region, ...).

The four core methods on the public surface:

- `RoutingStrategy::select` - pick an index into `targets`, or return `None` to defer.
- `RoutingStrategy::name` - stable identifier used for logging and metrics labels.
- `build_routing_strategy(name, config)` - look up a strategy by registered name and instantiate it from a JSON config blob.
- `list_routing_strategies()` - enumerate every registered strategy name (used by `clictl` config validation).

## Registering a strategy from a third-party crate

Strategies register themselves at link time via `inventory::submit!`, the same pattern the auth-plugin registry uses. There is no centralised registration list to edit.

```rust,ignore
use std::sync::Arc;
use sbproxy_modules::action::routing::{
    RoutingStrategy, RoutingStrategyRegistration,
    RoutingRequest, TargetState,
};

pub struct LeastLoadedGpu;

impl RoutingStrategy for LeastLoadedGpu {
    fn name(&self) -> &str { "least-loaded-gpu" }

    fn select(
        &self,
        _req: &RoutingRequest,
        targets: &[TargetState],
    ) -> Option<usize> {
        targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.healthy)
            .min_by_key(|(_, t)| t.active_connections)
            .map(|(idx, _)| idx)
    }
}

inventory::submit! {
    RoutingStrategyRegistration {
        name: "least-loaded-gpu",
        build: |_config| Ok(Arc::new(LeastLoadedGpu)),
    }
}
```

Once the crate is linked into the proxy binary, the strategy is discoverable by name. Configuration consumes it the same way an enterprise auth plugin would: by referencing the registered name in the load-balancer config and letting `build_routing_strategy` resolve it to an `Arc<dyn RoutingStrategy>`.

The OSS tree ships one trivial built-in strategy, `first-healthy` (`AlwaysFirstHealthyStrategy`), purely as a reference implementation for tests and documentation. Production deployments should continue to use the existing `lb_method` algorithms until the Fail-6 follow-up lands the real LoRA-aware, GPU-aware, and contextual-bandit strategies.

## LoRA-aware routing

`strategy: lora-aware` (`LoraAwareStrategy`) is the first concrete production strategy delivered against the trait. It targets the AI-proxy code path: when a request carries an adapter identifier (`?adapter=...` or `X-LoRA-Adapter`), the strategy prefers an upstream that already has that adapter warm in memory, avoiding the cold-load penalty paid when a fresh adapter has to be paged onto a GPU. When no upstream advertises the adapter, the strategy returns `None` and the configured `lb_method` (typically `least_connections`) gets to pick.

### When the strategy fires

- `request.adapter` is `Some(_)`. AI-proxy requests set this; plain HTTP requests do not, and the strategy short-circuits to `None` for them.
- At least `fallback_below` healthy targets advertise the requested adapter. Default is `1`, so any single warm target wins. Operators that want a stronger signal (e.g. only commit when at least two warm replicas exist, so a single slow target cannot be hot-spotted) can raise the threshold.
- Among the warm-and-healthy targets, the one with the lowest `active_connections` wins. Ties break on the lower target index for deterministic replay.

### Metadata contract

Each target advertises its adapter inventory in the `metadata` map under the key `loaded_adapters`. The shape is a JSON array of adapter identifiers:

```yaml
targets:
  - url: https://upstream-0.ai.internal
    metadata:
      loaded_adapters:
        - alice-tone
        - bob-style
```

A missing key, a non-array value, or non-string elements are all treated as "no adapters loaded" rather than producing an error: the strategy is intentionally lenient so a single misconfigured target cannot poison routing for the rest of the pool.

Populating this metadata is operator work. Today the supported path is hand-pinned YAML (per the example above). The live-feed path, where each upstream reports its adapter inventory back to the proxy via either pull (Prometheus-style scrape) or push (sidecar), is the same telemetry plane the GPU-aware sibling card will productionise; both paths land together as part of Fail-6.

### Fall-back semantics

Returning `None` from `select` is the explicit "fall through to `lb_method`" signal. The strategy returns `None` in three situations:

1. `request.adapter` is `None`. No LoRA signal to route on.
2. Fewer than `fallback_below` healthy targets advertise the adapter. The strategy is unwilling to commit at this signal strength.
3. No healthy target advertises the adapter at all. Cold-loading is unavoidable, so the lb_method picks the cheapest cold target by its own metric.

The strategy never picks an unhealthy target, even if it advertises the adapter. Health collapses circuit-breaker, outlier-detection, and active-health-check state into a single boolean before the strategy sees it.

### Typical multi-tier setup

The recommended configuration pairs `lora-aware` with `least_connections` as the fallback:

```yaml
action:
  type: load_balancer
  algorithm: least_connections   # fallback when lora-aware returns None
  lb_method: plugin              # forward-looking: route through the trait
  strategy: lora-aware
  targets:
    - url: https://upstream-0.ai.internal
      metadata: { loaded_adapters: [alice-tone, bob-style] }
    - url: https://upstream-1.ai.internal
      metadata: { loaded_adapters: [carol-voice] }
    - url: https://upstream-2.ai.internal
      metadata: { loaded_adapters: [alice-tone, dave-formal] }
```

A request for `adapter=alice-tone` lands on whichever of upstream-0 / upstream-2 has fewer in-flight requests. A request for `adapter=eve-poetry` (not loaded anywhere) falls through to `least_connections`, which picks whichever upstream is currently quietest, paying the cold-load penalty there. A request with no `adapter` at all also falls through, since the strategy has no signal.

A working example lives at `examples/99-lora-aware-routing/sb.yml`.
