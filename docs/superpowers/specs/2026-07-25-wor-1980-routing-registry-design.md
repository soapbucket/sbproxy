# WOR-1980 Production Routing Registry Design

## Status

Approved for implementation by the existing WOR-1963 through WOR-1968
implementation plan and the instruction to finish Phase 0/1.

## Decision

Wire the existing `sbproxy-modules::action::routing` registry into the
`load_balancer` action it was designed for. Do not add a second copy of the
registry strategies to `sbproxy-ai::Router`, and do not fold them into the
AI router's closed strategy enum.

This choice follows the public trait contract, existing examples, and
`docs/routing-strategies.md`: a registry strategy receives a projected HTTP
request and projected load-balancer targets, may select one eligible target,
and may defer to the configured built-in `algorithm`. The AI provider router
remains the outer provider-selection layer with its existing strategies.
A model or provider fleet that needs registry routing uses a
`load_balancer` action for the replica pool.

## Considered approaches

### 1. Wire the registry into `load_balancer` (selected)

- Preserves the existing `RoutingRequest`, `TargetState`, and fallback
  contracts.
- Makes the checked-in `lb_method: plugin` and `strategy:` examples truthful.
- Reuses live health, breaker, outlier, deployment, priority, and active
  connection state already owned by `LoadBalancerAction`.
- Keeps Phase 1 isolated from the Phase 4 work in `sbproxy-ai::routing`.

### 2. Adapt registry strategies into `sbproxy-ai::Router`

- Would make `ai_proxy.routing.strategy: bandit` work directly.
- Requires translating AI providers and managed replicas into a second target
  model, duplicating health and feedback state.
- Overlaps the Phase 4 outcome, prefix, and token-routing work and leaves the
  documented load-balancer plugin surface inert.

### 3. Fold every registry strategy into the AI routing enum

- Gives one closed implementation path.
- Removes the third-party registry seam and duplicates the strategy
  implementations.
- Creates the largest compatibility and review surface.

## Configuration

The `load_balancer` action accepts:

```yaml
action:
  type: load_balancer
  algorithm: least_connections
  lb_method: plugin
  strategy: bandit
  strategy_config:
    epsilon: 0.05
  targets:
    - url: http://provider-a:8080
      metadata:
        gpu_utilization: 0.42
        loaded_adapters: [support]
    - url: http://provider-b:8080
      metadata:
        gpu_utilization: 0.18
        loaded_adapters: [coding]
```

`strategy` is the opt-in. `lb_method: plugin` is accepted as the explicit
spelling used by existing examples, but omitting it while setting `strategy`
has the same behavior. Omitting `strategy` preserves all existing
load-balancer behavior. `strategy_config` is an object passed to the
registered factory. An unknown strategy, a non-object strategy config, or
`lb_method: plugin` without `strategy` is a config-compile error.

Each target gains a bounded JSON metadata map. The built-in registry
strategies consume only documented keys. Metadata is copied into the
per-request projection, and a runtime update seam allows a model-host or
control-plane owner to replace one target's metadata without rebuilding the
selection algorithm.

`list_routing_strategies` returns sorted, deduplicated registered names so
diagnostics and validation expose the selectable set deterministically.

## Selection flow

1. Apply deployment-mode, backup, priority, active-health, breaker, and
   outlier filtering exactly as today.
2. Project the surviving targets into `TargetState`, including original
   indices, live active-connection counts, weights, and current metadata.
3. Project the inbound method, full path and query, headers, client address,
   hostname, optional model, and optional LoRA adapter into
   `RoutingRequest`.
4. Invoke the configured registry strategy.
5. Map a valid selected slice index back to the original target index.
6. If the strategy returns `None` or an out-of-range index, run the existing
   built-in `algorithm` over the same eligible set.

The core records the selected strategy name in request diagnostics. It does
not claim a registry selection when the strategy deferred; diagnostics name
the built-in fallback in that case.

## Feedback and reload behavior

The trait gains a default no-op outcome callback. Existing and third-party
strategies remain source-compatible. The callback receives the stable target
URL, whether the upstream completed without a transport or 5xx failure, and
the measured attempt latency.

Bandit reward is:

```text
failure reward = 0
success reward = 1 / (1 + latency_seconds)
```

This makes correctness dominant and uses latency to distinguish successful
targets. Generic HTTP load balancing has no trustworthy request-cost signal,
so cost is not fabricated. The design deliberately does not create a second
outcome-aware feedback store in `sbproxy-ai`.

Bandit observations live in a bounded process-local registry keyed by the
origin identity, strategy name, and target pool. Recompiling the same origin
on hot reload reuses the state. A process restart resets it, which is
documented. Namespace count and target count are bounded; overflow evicts the
oldest inactive namespace rather than growing without limit.

Each upstream attempt records exactly one outcome:

- response headers: status below 500 succeeds; 5xx fails;
- connect, TLS, write, or read timeout before a terminal response fails;
- retries record the failed attempt before selecting the next target.

## Error handling and compatibility

- Default configs never construct or call a registry strategy.
- A registry strategy cannot make an unhealthy or policy-filtered target
  eligible because it only sees the filtered projection.
- An invalid returned index is treated as deferral and emits a bounded
  warning/metric rather than panicking.
- Malformed optional model or adapter inputs remain absent; they do not fail
  unrelated HTTP routing.
- Strategy names and result labels use the closed registered set.
- No GPU polling, cloud provisioning, or scheduled GPU work is added.

## Verification

- Unit tests for config parsing, unknown names, deterministic listing,
  projection, fallback, invalid indices, metadata updates, and reload-stable
  bandit state.
- Integration tests proving `first-healthy`, `gpu-aware`, and `lora-aware`
  select through a compiled production action.
- E2E with two mock upstreams proving client traffic uses registry selection
  and a deterministic bandit converges on the faster successful target.
- Documentation and the LoRA-aware example updated to remove all
  forward-looking or inert-surface language.
- Generated schema/catalog checks and the complete Phase 0/1 gate.
