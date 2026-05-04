# ai_crawl_tiers throughput harness (Q1.6)

*Last modified: 2026-04-30*

Drives 10k rps across the 402-challenge and redemption paths with five
pricing tiers. Reports p50 / p95 / p99 latency per path and the error
rate.

## Why a standalone Cargo project

This bench is NOT a workspace member. CI runs `cargo build --workspace`
plus `cargo test --workspace` against the proxy crates; including a
load harness in that build would slow every PR and pull `hdrhistogram`
into the proxy build graph for no reason.

The harness lives at `sbproxy-bench/harness/ai_crawl_tiers/` so a
maintainer can drop into the directory and run it directly:

```bash
# Terminal 1 - run the proxy under perf record (or eBPF, or flamegraph)
cargo build --release -p sbproxy
./target/release/sbproxy --config e2e/fixtures/wave1/tiers/sb.yml &

# Terminal 2 - drive load
cd sbproxy-bench/harness/ai_crawl_tiers
SBPROXY_BENCH=1 cargo run --release -- \
    --target-url http://127.0.0.1:8080 \
    --rps 10000 \
    --tiers 5 \
    --duration-secs 30
```

## Why the SBPROXY_BENCH env-var gate

A stray `cargo run` from the wrong directory should not slam someone's
local loopback. The harness refuses to start unless `SBPROXY_BENCH=1`
is set. CI never sets that variable; only the perf lab does.

## Output

Per-tier histograms with three significant digits, max sample 60 s.
Sample numbers from a baseline run on an `n2-standard-4` (Intel Skylake,
4 vCPU, 16 GiB) with the proxy and the harness on the same host:

| Path | p50 | p95 | p99 | rps actual |
|---|---|---|---|---|
| 402 challenge | TBD | TBD | TBD | TBD |
| 200 redemption | TBD | TBD | TBD | TBD |

Numbers will land alongside the G1.2 + G1.3 implementation merge.

## Future work

- Switch to HTTP/2 once the proxy carries an HTTP/2 listener on the
  same port; HTTP/1 keep-alive currently caps single-connection
  throughput.
- Add a CSV output mode for trend tracking in the perf-compare
  pipeline (see `scripts/perf-compare.sh`).
- Wire the harness into the perf-lab's regression suite once Q1.6
  baseline numbers are known.
