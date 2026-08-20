# AI router load-balancing benchmark
*Last modified: 2026-08-19*

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
Jain fairness index and a simulated KV-cache hit rate for each strategy.
Prefix samples are translated into chat-shaped JSON and passed
through the production prefix normalizer. The benchmark records an
accepted selection as an observed holder before the next request, matching
the serving path instead of modeling affinity as a stateless hash.

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
            - kv_cache_bonus_ms  if normalized prefix was seen on this provider
                                  in its last 64 requests
            + queue_term_ms       (in-flight count * 5ms)
            + lognormal noise     (mu=0, sigma=0.3)
```

The lognormal noise creates the heavy tail that makes P99 the
right comparison metric. The KV-cache bonus is what lets
`prefix_affinity` show its value in simulation. On a prefix miss, the live
router picks the provider with the lowest recent token load. After the
simulated request succeeds, the harness records the chosen provider as a
holder. A later matching prefix can then reuse that provider's simulated
cache.

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

### Phase 4 reproducible spot check

The Phase 4 implementation was checked with 5,000 requests and seed
`0x5ba0f0de01234567`. With equal replica latency
(`--slow-provider-multiplier 1`), observed affinity improved both cache reuse
and latency over round-robin:

| Strategy | P50 ms | P99 ms | KV hit rate | Jain fairness |
| --- | ---: | ---: | ---: | ---: |
| `round_robin` | 216.06 | 480.00 | 71.0% | 1.000 |
| `prefix_affinity` | 203.52 | 442.37 | 88.9% | 0.993 |

That run reduced P50 by 5.8%, reduced P99 by 7.8%, and raised simulated cache
hits by 17.9 percentage points. Under the default 5x slow-replica skew,
`prefix_affinity` still raised cache hits from 71.0% to 88.9% and reduced P50
from 251.26 ms to 244.09 ms, while P99 increased from 1707.01 ms to
1727.49 ms because affinity can keep a hot prefix on the slow replica. The
second result is why this page does not claim affinity is universally
tail-optimal.

## What to expect

Under the default skewed workload:

- **`round_robin`** repeatedly visits the slow provider. Per-provider
  request distribution is uniform (Jain ~1.0), which looks fair but
  retains that provider's latency in the tail.
- **`peak_ewma`** posts the best P99 of the latency-aware strategies.
  Two-of-N sampling avoids the herd-on-one-fast-provider pathology
  that `lowest_latency` falls into.
- **`prefix_affinity`** raises the KV-cache hit rate when prefixes repeat.
  The router learns which provider accepted a normalized prefix and sends
  repeats to that live holder. That improves cache reuse and can reduce
  median latency, but it does not guarantee the best P99 when a hot prefix
  is resident on the simulated slow provider. Lower the prefix-Zipf to 0.0
  (uniform) and the strategy trends toward its least-loaded miss path.
- **`least_token_usage`** posts a fairness Jain index above 0.95
  on the tenant-skewed workload because it spreads the hot tenant's
  tokens evenly across providers.
- **`least_connections`** is sensitive to the harness's approximate
  completion and drain model. Treat its row as a synthetic queue-model
  result, not a production capacity claim.

The README at `sbproxy-bench/harness/ai_lb_strategy/README.md` is
the canonical reference for the flags and the model assumptions.

## Caveats

1. The KV-cache bonus and lognormal-noise sigma are unvalidated
   against production traffic. The doc calls them out so a reader
   can challenge them.
2. The bench feeds observations through `Router::record_latency`.
   `lowest_latency` reads the latest relaxed atomic value, while
   `peak_ewma` updates its time-decayed estimator and includes the
   current in-flight count. The single-threaded sample loop advances
   very little wall time relative to the default 10-second half-life,
   so this benchmark emphasizes immediate spike and queue response,
   not long idle recovery.
3. `prefix_affinity` looks bad with uniform prompts. The default
   prefix-Zipf of 1.1 favors repeated prompts; operators considering it
   should match against their own traffic shape before turning it on.
   The reduced run completes much faster than the five-minute production
   prefix TTL, so it measures learned holder reuse rather than expiration.
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
- [ai-gateway.md#routing-strategies](ai-gateway.md#routing-strategies)
  documents every strategy's config and semantics; this page only compares
  the latency-sensitive subset under synthetic load.
- [ai-outcome-aware-routing.md](ai-outcome-aware-routing.md) covers
  `outcome_aware`, the cost-per-success strategy this bench does not touch.
