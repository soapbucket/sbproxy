# ai-lb-strategy-bench

Compares the AI router's load-balancing strategies on a synthetic,
skewed workload, printing P50 / P95 / P99 / P99.9 latency per
strategy plus a Jain fairness index and a KV-cache hit rate for
prefix affinity.

## Why standalone Cargo

The harness pulls `hdrhistogram` and `rand_distr`, which the proxy
itself does not need. An empty `[workspace]` block in `Cargo.toml`
keeps `cargo build --workspace` at the repo root from picking it up
by default. The harness builds in this directory or via an explicit
`-p ai-lb-strategy-bench` from this directory only.

## Why the env-var gate

`main.rs` refuses to run unless `SBPROXY_BENCH=1` is set. The bench
spins through tens of thousands of in-process iterations and will
saturate a core for several seconds; the guard stops a stray
`cargo run` from doing that on a developer laptop.

## Run

```bash
cd sbproxy-bench/harness/ai_lb_strategy
SBPROXY_BENCH=1 cargo run --release -- --total-requests 50000
```

Useful flags:

| Flag | Default | Effect |
| --- | --- | --- |
| `--providers N` | `4` | Pool size. |
| `--total-requests N` | `50000` | Sample count per strategy. |
| `--slow-provider-multiplier X` | `5.0` | Provider 0 latency factor. Setting `1.0` disables the latency skew. |
| `--prefix-zipf-s S` | `1.1` | Prompt-prefix Zipf exponent. `0.0` is uniform (worst case for `prefix_affinity`). |
| `--tenant-zipf-s S` | `1.0` | Tenant Zipf exponent. |
| `--kv-cache-bonus-ms MS` | `80` | Latency bonus when the chosen provider has seen the prefix recently. |
| `--seed N` | fixed | RNG seed; same seed reproduces the same workload across runs. |

## Output

One row per strategy:

```text
strategy                p50_ms     p95_ms     p99_ms   p99.9_ms     max_ms  fairness   kv_hit_%  decide_ns
round_robin             ...        ...        ...      ...         ...       0.999       2.1%        20
prefix_affinity         ...        ...        ...      ...         ...       0.870      48.6%        70
...
```

Below the table the harness prints per-provider request and token
distributions so a reader can see herding visually.

## What "skewed load" means

Three orthogonal skews layered into the workload. All default on.

1. **Provider latency heterogeneity.** One slow provider out of N.
   Exposes the herding pathology in `round_robin` (it keeps stuffing
   the slow one) and rewards `peak_ewma` and `least_connections`.
2. **Prompt-prefix Zipf.** A vocabulary of distinct prefixes
   sampled with Zipf 1.1. Rewards `prefix_affinity` because the
   same prefix repeats often enough to land on the same provider
   twice.
3. **Tenant token-burst Zipf.** One hot tenant out of N. Rewards
   `least_token_usage` because it spreads the hot tenant across
   providers.

## What the latency model assumes

```text
observed_ms = base_ms * provider_factor
            - kv_cache_bonus_ms  if prefix was seen on this provider
                                  in the last K requests
            + queue_term_ms       (in-flight count * per-req overhead)
            + lognormal noise     (mu=0, sigma=0.3)
```

The lognormal noise creates the heavy tail that makes P99 the right
comparison metric. The KV-cache bonus is what lets `prefix_affinity`
demonstrate value in simulation; without it the strategy is
indistinguishable from round-robin.

These assumptions are documented in `docs/ai-lb-benchmark.md` so a
reader can challenge them.

## Future work

* HTTP-driven mode against a vLLM Docker fixture (PR2).
* CSV output and a `--baseline path --fail-if-regress-pct N` flag
  so a future operator can wire this into a perf-regression gate.
* Cost model for `cost_optimized` and `cascade` strategies.
* Decision-overhead microbenchmark (the current bench reports mean
  decision wall-time, but a tight loop on just `select()` would
  pin the per-strategy per-call cost more precisely).
