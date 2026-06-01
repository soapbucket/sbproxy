# AI router load-balancing benchmark
*Last modified: 2026-05-31*

The AI router supports several load-balancing strategies (round-robin,
peak-EWMA, least-connections, least-token-usage, prefix-affinity, and
others). This page compares them on a synthetic, skewed workload and
publishes the P50 / P95 / P99 / P99.9 numbers an operator can compare
against when picking a strategy.

## What the bench measures

The harness at `sbproxy-bench/harness/ai_lb_strategy/` drives a
synthetic, skewed workload through the live
`sbproxy_ai::routing::Router` for each declared strategy, then
prints a P50 / P95 / P99 / P99.9 / max comparison table plus a
Jain fairness index and (for `prefix_affinity`) a KV-cache hit
rate.

The bench is in-process, not HTTP-driven. The variable under test
is the LB algorithm; an HTTP backend would have to fake the
KV-cache and provider-latency skews anyway, so the in-process
driver lets the bench measure the router without confounds from
the proxy substrate.

## The workload

Three orthogonal skews, each tunable via CLI:

| Skew | Default | Models the real-world case where ... |
| --- | --- | --- |
| Provider latency heterogeneity | one slow provider out of four at 5x base latency | A vLLM pool has one warm-but-overloaded worker |
| Prompt-prefix Zipf | s = 1.1 over 100 prefixes | Chat traffic where some system prompts repeat |
| Tenant token-burst Zipf | s = 1.0 over 10 tenants | A small fleet with one hot tenant emitting most tokens |

## Simulated latency model

```text
observed_ms = base_ms * provider_factor
            - kv_cache_bonus_ms  if prefix was seen on this provider
                                  in the last 64 requests
            + queue_term_ms       (in-flight count * 5ms)
            + lognormal noise     (mu=0, sigma=0.3)
```

The lognormal noise creates the heavy tail that makes P99 the
right comparison metric. The KV-cache bonus is what lets
`prefix_affinity` show its value in simulation; without it the
strategy is indistinguishable from round-robin.

These assumptions are not validated against a real vLLM pool. A
follow-up bench against a Docker vLLM fixture is tracked under
the bench harness's README.

## Reproducing the run

```bash
cd sbproxy-bench/harness/ai_lb_strategy
SBPROXY_BENCH=1 cargo run --release -- --total-requests 50000
```

The `SBPROXY_BENCH=1` env-var gate is enforced in `main.rs` so an
accidental local invocation cannot saturate a core. CI does not
run this; it is a lab-only artifact.

## What to expect

Under the default skewed workload:

- **`round_robin`** posts the worst P99 because it does not avoid
  the slow provider. Per-provider request distribution is uniform
  (Jain ~1.0) which looks fair but produces the tail.
- **`peak_ewma`** posts the best P99 of the latency-aware strategies.
  Two-of-N sampling avoids the herd-on-one-fast-provider pathology
  that `lowest_latency` falls into.
- **`prefix_affinity`** posts the best P99 when the Zipf parameter
  is at least ~1.0 (default 1.1). The KV-cache hit rate column shows
  why: the same prefix lands on the same provider often enough to
  reuse a warm cache. Lower the prefix-Zipf to 0.0 (uniform) and
  the strategy degenerates toward round-robin's number.
- **`least_token_usage`** posts a fairness Jain index above 0.95
  on the tenant-skewed workload because it spreads the hot tenant's
  tokens evenly across providers.
- **`least_connections`** behaves similarly to `peak_ewma` here
  because the queue term in the latency model is what its in-flight
  signal tracks. In a real vLLM pool the queue term is more
  pronounced and the two diverge.

The README at `sbproxy-bench/harness/ai_lb_strategy/README.md` is
the canonical reference for the flags and the model assumptions.

## Caveats

1. The KV-cache bonus and lognormal-noise sigma are unvalidated
   against production traffic. The doc calls them out so a reader
   can challenge them.
2. The bench writes to `Router::record_latency` with `Relaxed`
   atomic semantics. Two strategies (`lowest_latency`, `peak_ewma`)
   read the same field as ground truth. The most recent write
   wins; under the bench's single-threaded sample loop this is
   deterministic, but under multi-threaded production traffic the
   reads see slightly stale numbers.
3. `prefix_affinity` looks bad with uniform prompts. The default
   prefix-Zipf of 1.1 ships the strategy in its strong configuration;
   operators considering it should match against their own traffic
   shape before turning it on.
4. The bench does not measure cost. Strategies with cost in their
   name (`cost_optimized`, `cascade`) are not in the comparison
   table because P99 is the wrong axis for them.

## Related

- `crates/sbproxy-ai/src/routing.rs` is where the strategies live.
- `BENCHMARK.md` at the repo root covers workspace-level proxy
  overhead numbers; this page is the AI router-specific axis.
- The `sbproxy_ai_lb_decisions_total{strategy, provider}` metric
  emitted by the router lets you reproduce the per-provider
  distribution table on a live deployment.
