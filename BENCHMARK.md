# Benchmark
*Last modified: 2026-05-03*

Head-to-head results for SBproxy against the AI gateways and reverse
proxies most teams already evaluate. Numbers are from the public
competitor campaign **`20260424-220610`** in
[`sbproxy-bench`](https://github.com/soapbucket/sbproxy-bench), run on
identical hardware, same kernel, same load generator, same scenario
files.

If you only have time for one paragraph: SBproxy serves **68,512 RPS at
0.69 ms p99** as an AI gateway, on an 8 vCPU GCE box, with a 100% 2xx
rate. The next-fastest AI gateway in the same matrix sits at 18,159 RPS
and 4.30 ms p99. That is roughly 3.2x the throughput at one-sixth the
tail latency. Against general-purpose proxies SBproxy lands third behind
nginx and HAProxy, ahead of Kong, Envoy, Traefik, and Caddy.

## A01: AI gateway, non-streaming

OpenAI-compatible request, mocked LLM upstream. Same scenario file for
every engine.

| Engine | RPS | 2xx | p50 (ms) | p95 (ms) | p99 (ms) | Total requests |
|---|---:|---:|---:|---:|---:|---:|
| **sbproxy-rust** | **68,512** | 1.00 | **0.27** | **0.44** | **0.69** | 3,083,085 |
| sbproxy-go (archived) | 21,144 | 1.00 | 0.87 | 1.58 | 2.48 | 951,492 |
| bifrost | 18,159 | 1.00 | 0.87 | 2.47 | 4.30 | 817,146 |
| kong-ai | 17,534 | 1.00 | 0.77 | 2.65 | 6.17 | 789,018 |
| helicone | 4,194 | 1.00 | 4.60 | 7.13 | 8.94 | 188,711 |
| portkey | 1,178 | 1.00 | 16.19 | 19.79 | 29.15 | 52,971 |
| litellm | 221 | 1.00 | 88.85 | 102.81 | 112.13 | 9,917 |

What it tests: parse the request, route to a provider, forward to the
upstream, return the response. No streaming, no guardrails, no cache.
This is the gateway baseline most production traffic actually looks like.

## P01: Reverse proxy, passthrough

Plain HTTP forward to a static origin. No AI features, no policies. The
fairness test against the workhorse proxies most infra teams already
run.

| Engine | RPS | 2xx | p50 (ms) | p95 (ms) | p99 (ms) | Total requests |
|---|---:|---:|---:|---:|---:|---:|
| nginx | 90,376 | 1.00 | 0.20 | 0.29 | 0.73 | 4,066,957 |
| haproxy | 77,427 | 1.00 | 0.22 | 0.51 | 1.02 | 3,484,283 |
| **sbproxy-rust** | **69,915** | 1.00 | **0.25** | **0.46** | **0.69** | 3,146,201 |
| kong | 55,100 | 1.00 | 0.30 | 0.81 | 1.19 | 2,479,541 |
| envoy | 39,462 | 1.00 | 0.47 | 0.95 | 1.29 | 1,775,816 |
| traefik | 35,714 | 1.00 | 0.42 | 1.26 | 1.86 | 1,607,133 |
| sbproxy-go (archived) | 27,484 | 1.00 | 0.65 | 1.31 | 2.08 | 1,236,803 |
| caddy | 1,895 | 0.95 | 1.97 | 38.09 | 48.18 | 85,243 |

SBproxy lands inside the same tail-latency band as nginx and HAProxy
(0.69 ms p99 against 0.73 ms and 1.02 ms), at lower throughput. The
right reading: an AI gateway whose proxy floor is competitive with the
load balancers your network team trusts, not a faster reverse proxy.

## Hardware and method

| Setting | Value |
|---|---|
| Instance | `c3-standard-8` (Sapphire Rapids, 8 vCPU, 32 GB) |
| OS | Debian-based container images |
| Build | Release with `lto = "fat"`, `codegen-units = 1` |
| Load generator | `oha`, dedicated VM in the same zone as the SUT |
| Scenario | A01: c=20 keep-alive connections; P01: same |
| Warm-up | 30 s |
| Window | 5 m steady-state per engine |
| TLS | Disabled at proxy boundary (origin TLS terminated upstream) |
| Logging | `warn` level, INFO and DEBUG off |
| Tuning | Each competitor tuned per its own published perf guide |

The fairness rules live in
[`sbproxy-bench/docs/competitors/METHODOLOGY.md`](https://github.com/soapbucket/sbproxy-bench/blob/main/docs/competitors/METHODOLOGY.md).
The reproducibility recipe lives in
[`sbproxy-bench/docs/REPRODUCIBILITY.md`](https://github.com/soapbucket/sbproxy-bench/blob/main/docs/REPRODUCIBILITY.md).

Every flag applied to a competitor is recorded in its
`docs/competitors/{ai-gateways,proxies}/<engine>.md` file with a link
to the vendor doc that recommends it. No private tuning, no plugin
whitelist, no scenario shaped to favour SBproxy.

## What this run does not cover

The `20260424-220610` campaign is two scenarios: A01 (non-streaming AI
gateway) and P01 (passthrough proxy). It does not cover:

- **Streaming.** SSE throughput is upstream-bound; the per-chunk
  overhead and TTFB numbers belong in a separate run.
- **Full-chain configurations.** Auth + rate limit + transforms +
  cache + proxy. See `docs/performance.md` for the matrix-v7 numbers,
  including cache hits, WAF rejection, and the 50,713 RPS full-chain
  result.
- **Failover and guardrails.** AI failover and streaming guardrails
  also live in `docs/performance.md`.
- **Higher concurrency.** This campaign held c=20. SBproxy continues
  to scale past that on the same hardware; that data is in the
  matrix-v7 run.

If you need numbers for your scenario, run the harness on your
hardware. Do not take the table on faith.

## Reproducing

```bash
git clone https://github.com/soapbucket/sbproxy-bench
cd sbproxy-bench

# Local pre-flight, no cloud spend
./scripts/local-smoke.sh

# Smoke any single competitor
./scripts/competitor-smoke.sh kong-ai

# Full cloud matrix (one-time setup in docs/GCP_SETUP.md)
cd terraform && ./scripts/bootstrap.sh
make init && make up && make matrix && make down
```

Raw artifacts for the run cited above:
`sbproxy-bench/results/campaign-20260424-220610/`
(`summary.md`, `campaign.jsonl`, `ascii.txt`, plus the per-engine raw
`oha` output under `sbproxy-raw/`).

## Related reading

- [`docs/performance.md`](docs/performance.md) for the broader matrix-v7
  scenario set (cache, WAF, full chain, streaming, failover).
- [`docs/architecture.md`](docs/architecture.md) for why the numbers
  fall out where they do (Pingora request pipeline, compiled handler
  chain, redb-backed embedded KV).
- [`sbproxy-bench`](https://github.com/soapbucket/sbproxy-bench) for the
  full harness, terraform, and per-engine setup notes.
