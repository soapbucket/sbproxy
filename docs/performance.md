# Performance
*Last modified: 2026-04-24*

What SBproxy delivers on real hardware, with the methodology you'd need to reproduce it.

## TL;DR

On an 8 vCPU GCE instance, single binary, zero tuning beyond the defaults:

- **77,758 rps** through a passthrough proxy at **0.6 ms p99**.
- **138,770 rps** on a cache hit at **0.3 ms p99**.
- **50,713 rps** running the full chain (auth, rate limit, transforms, cache) at **0.6 ms p99**.
- **77,784 rps** for non-streaming AI gateway requests against a mocked LLM upstream.
- **0.3 ms p50** at the median proxy path. Most p99s land under 1 ms.

These are publishable medians from 60-second runs across three replicates. Run details below; raw artifacts and the full reproducibility recipe live in [`sbproxy-bench`](https://github.com/soapbucket/sbproxy-bench).

## Headline numbers

Matrix-v7 publishable run, c3-standard-8 GCE instances, LTO-enabled release build (`lto = "fat"`, `codegen-units = 1`), 60 s × 3 replicates per scenario, medians shown.

| Scenario | rps | p50 | p99 | What it tests |
|---|---:|---:|---:|---|
| Passthrough | 77,758 | 0.233 ms | 0.618 ms | Bare proxy. No policies, no transforms. |
| WAF blocking | 185,049 | 0.103 ms | 0.166 ms | Requests rejected by WAF before upstream. |
| Rate limit (sliding window) | 67,312 | 0.287 ms | 0.443 ms | Per-IP rate limit at admit threshold. |
| CEL policy | 55,810 | 0.356 ms | 0.530 ms | Custom CEL expression on every request. |
| Cache hit | 138,770 | 0.132 ms | 0.302 ms | Response served from in-process cache. |
| Cache (stale-while-revalidate) | 142,108 | 0.131 ms | 0.284 ms | SWR path returns cache, refreshes async. |
| Full chain | 50,713 | 0.382 ms | 0.618 ms | Auth + rate limit + cache + transforms + proxy. |
| Idle connections | 126,270 | 3.8 ms | 8.4 ms | 500 mostly-idle keep-alives plus traffic. |
| AI proxy (non-streaming) | 77,784 | 0.242 ms | 0.515 ms | OpenAI-compatible request, mocked LLM upstream. |
| AI proxy (streaming) | 196 | 101.8 ms | 102.4 ms | SSE streaming. Throughput is upstream-bound. |
| AI failover | 11,460 | 1.721 ms | 2.161 ms | Provider primary errors, fallback served. |
| AI streaming guardrails | 22,228 | 0.897 ms | 1.139 ms | Output guardrails scanning each SSE chunk. |

## How to read this

**Latency, not just throughput.** SBproxy's design priority is tight tail latency. The p99 column is the one that matters in production. Most proxy-path scenarios land p99 under 1 ms; the cache and WAF scenarios land under 0.5 ms.

**The full-chain number is the realistic one.** "Passthrough" is a useful ceiling, but real configs do work: parse a JWT, check a rate limiter, run a transform, look at the cache, then call upstream. Full-chain at 50k rps with 0.6 ms p99 is what you should expect when you stack features.

**The AI streaming row looks slow on purpose.** SSE streaming throughput is gated by the upstream model's token generation rate. The interesting numbers there are the per-chunk overhead and time-to-first-byte, not rps.

**WAF "blocking" is fast because it short-circuits.** That 185k rps is requests SBproxy rejects before they ever touch upstream. It's a different number from "throughput when traffic is clean," but it's the right number when you're sizing for an attack.

## Where these numbers are weak

Be honest with yourself about coverage:

- **Two scenarios are upstream-bound, not proxy-bound.** AI streaming (196 rps) and AI failover (11,460 rps) reflect upstream behaviour, not Pingora's ceiling.
- **Localhost numbers in older docs are lower.** Single-laptop runs hit ephemeral-port exhaustion around 150 concurrent connections and conflate proxy work with the load generator's CPU. Use the c3 numbers above as the trustworthy floor; expect higher on bigger hardware.
- **Hardware matters.** c3-standard-8 is a Sapphire Rapids instance with dedicated cores. Burstable VMs (e2, t-series) or AMD Milan (n2d) will land lower; recent EPYC and bare metal will land higher.
- **Configuration matters.** Logging at `debug`, full-body logging, or expensive Lua transforms can each cut throughput in half.

If you need numbers for your scenario, run the benchmark recipe yourself. Don't take the table above on faith.

## Hardware and methodology

| Setting | Value |
|---|---|
| Instance type (proxy + origin) | `c3-standard-8` (8 vCPU Sapphire Rapids, dedicated) |
| Instance type (loadgen) | `c3-standard-22` |
| Region / zone | `us-central1-a` |
| Build profile | `release` with `lto = "fat"`, `codegen-units = 1`, `strip = true` |
| Allocator | mimalloc |
| Run duration | 60 seconds, 3 replicates per scenario, median reported |
| Logging | Compile-stripped debug/trace via `tracing` `release_max_level_info` |
| Origin | Echo server returning a small JSON body |

The full set of scenarios, the harness code, the loadgen config, and the raw per-replicate output live in the [sbproxy-bench](https://github.com/soapbucket/sbproxy-bench) repo.

## Reproduce locally

You don't need GCE to get a useful read. The microbenchmarks and the local recipe below run on a laptop.

### Microbenchmarks (criterion)

In-process benchmarks of the config compiler, pipeline dispatch, host router, and other hot paths:

```bash
cargo bench --workspace                     # everything
cargo bench -p sbproxy-core                 # just one crate
cargo bench -- pipeline_dispatch            # one bench by name
```

Results land in `target/criterion/`. Open `target/criterion/report/index.html` for charts and regression analysis. Save and diff baselines:

```bash
cargo bench -- --save-baseline before
# change something
cargo bench -- --baseline before
```

### End-to-end local run

```bash
make build-release
./target/release/sbproxy --config examples/00-basic-proxy/sb.yml &

# In another terminal, drive load against the local proxy.
# oha is a simple choice; wrk and hey work too.
oha -n 10000 -c 100 http://127.0.0.1:8080/get
```

Localhost runs hit ephemeral-port exhaustion around 150 concurrent connections. They're useful for relative comparisons (before vs after a code change) and unreliable for absolute production numbers.

### Cloud benchmark

The full c3 benchmark used for the headline numbers is in the [sbproxy-bench](https://github.com/soapbucket/sbproxy-bench) repo, including the Terraform that provisions the GCE instances and the harness that runs each scenario through three replicates.

## Profiling a hot path

When you need to know *why* a scenario is slower than expected:

```bash
# Linux: perf + flamegraph
cargo flamegraph --bin sbproxy --release -- --config sb.yml

# macOS: samply (no sudo)
samply record ./target/release/sbproxy --config sb.yml

# Heap profiling
heaptrack ./target/release/sbproxy --config sb.yml
```

For per-request CPU breakdown, enable OpenTelemetry tracing in the config (`telemetry` block) and view spans in your collector of choice. The phase pipeline emits a span per phase, so you can pinpoint which middleware is dominating.

## Why the numbers look like this

A few design choices do most of the work:

- **Pingora foundation.** The same proxy framework Cloudflare runs at scale. Tokio runtime, careful epoll integration, no garbage collector to pause it.
- **mimalloc allocator.** Roughly 5 to 10% faster than glibc malloc on server workloads.
- **Compile-stripped logging.** `tracing` is configured with `release_max_level_info`, so debug and trace calls evaporate at compile time. No runtime filter cost on the hot path.
- **LTO + codegen-units = 1.** Across-crate inlining and smaller binaries. Costs build time, gives a 5 to 15% rps lift at the tail.
- **ArcSwap for hot reload.** New configs swap in atomically. Old requests finish on their snapshot, new ones pick up the new config. No locks on the request path.
- **`bumpalo` per-request arenas, `compact_str` for short strings, `smallvec` for small collections.** Fewer heap allocations per request.
- **Bloom filter + radix tree host routing.** O(1) negative lookup before any per-origin work.

See [architecture.md](architecture.md) for the full pipeline and [comparison.md](comparison.md) for how the numbers stack against other proxies.

## What to watch in production

For your own dashboards, the metrics that move first:

- `sbproxy_request_duration_seconds` (p50, p95, p99). The single most useful gauge.
- `sbproxy_upstream_duration_seconds`. Subtract from above to get pure proxy overhead.
- `sbproxy_active_connections`. Sustained climb means your upstream is slower than incoming.
- `sbproxy_cache_hit_ratio`. The number that moves p99 the most when caching is configured.
- `sbproxy_config_reload_total`. A spike means your reload tooling is flapping.
- `sbproxy_panic_total`. Should be zero. Page on it.

See [metrics-stability.md](metrics-stability.md) for the full catalogue and stability tier of every metric.
