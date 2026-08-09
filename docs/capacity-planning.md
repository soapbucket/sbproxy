# Capacity planning
*Last modified: 2026-08-09*

How fast SBproxy runs is measured and published. How big a pod it needs is
not. This page says exactly which is which, gives you a starting point that
states its own reasoning, and hands you the commands to replace that starting
point with a number measured on your traffic.

Read [performance.md](performance.md) for throughput and latency. This page is
about memory, pod sizing, and what happens when you get the sizing wrong.

## What is actually measured

| Question | Answer today | Source | Reproducible from this repo? |
|---|---|---|---|
| Requests per second, 12 scenarios | Published, `c3-standard-8` | [performance.md](performance.md) | No. Harness is in a separate repo. |
| p50 / p99 latency per scenario | Published | [performance.md](performance.md) | No. Same harness. |
| Throughput against 7 competing proxies and gateways | Published, campaign `20260424-220610` | [`BENCHMARK.md`](../BENCHMARK.md) | No. Same harness. |
| Three-node mesh throughput and failover | Published | [performance.md](performance.md) | No. Same harness. |
| Resident set at idle | 77.5 MB, one process, one machine, one config | [sidecar-deployment.md](sidecar-deployment.md) | Yes, one command. |
| Resident set under load | **Unknown.** Nothing published. | none | Yes, and the harness is already here. |
| Bytes allocated per request | **Unknown.** Nothing published. | none | Not without a heap profiler run. |
| Memory per concurrent connection | **Unknown.** Nothing published. | none | Yes, by differencing two runs. |
| CPU per 1000 rps | **Unknown.** Nothing published. | none | Yes, `/usr/bin/time` on the same runs. |

The one memory figure we have is 77.5 MB of resident set for an idle process
running [`examples/sidecar/sb.yml`](../examples/sidecar/sb.yml), taken with
`ps -o rss=` on a single developer machine. It is a real measurement and it is
also a sample of one, on a config with no cache, no classifier models, and no
upstream connections open. Do not size a fleet from it. It is the floor of a
floor.

### Why the throughput numbers cannot be reproduced here

Every rps figure on [performance.md](performance.md) and in
[`BENCHMARK.md`](../BENCHMARK.md) came out of
[sbproxy-bench](https://github.com/soapbucket/sbproxy-bench), which is a
different repository. It holds the Terraform that provisions the GCE
instances, the per-engine competitor configs and their tuning provenance, the
scenario definitions, and the raw `oha` output for every replicate. None of it
is vendored into this tree, so cloning this repo and running something will not
regenerate the headline table.

If you are evaluating SBproxy and want to check our arithmetic, clone that repo
and run the matrix. If you only want to know what SBproxy does on your traffic,
the local harness described below is more useful anyway, because our scenario
files are not your workload.

## The table nobody has filled in

This is the memory-under-load table this page owes you. The cells are empty
because nobody has run the measurement, and a guess here would be worse than a
blank, since somebody would size a cluster with it.

Every row is fillable in one sitting with
[`scripts/perf-regression-run.sh`](../scripts/perf-regression-run.sh), which
already reports both numbers. Commands are in the next section.

| Concurrency (`-c`) | Sustained rps | Idle RSS | Max RSS under load | Delta |
|---:|---:|---:|---:|---:|
| 32 | | | | |
| 128 | | | | |
| 512 | | | | |
| 2048 | | | | |

Run it on the config you actually deploy, not on the static-200 config the
script ships with. The static origin measures the proxy's own hot path with no
upstream connection pool, no TLS session state, and no cache, which is the
cheapest possible shape and therefore the least representative of yours.

Two things to record alongside the numbers, because they change the answer more
than concurrency does:

- The build. A debug binary is not what you ship, and the release profile uses
  `lto = "fat"` with `codegen-units = 1` and the mimalloc allocator, all of
  which move the resident set.
- The feature set compiled in. Local ONNX classifiers, the JavaScript engine,
  and the WASM runtime each carry their own footprint whether or not a request
  reaches them.

## Measuring it yourself

Both scripts need [`oha`](https://github.com/hatoo/oha) on `PATH`. The CI lane
pins `oha` 1.4.5, which is the version whose JSON shape the parser expects.

### The RSS harness

[`scripts/perf-regression-run.sh`](../scripts/perf-regression-run.sh) boots a
release binary, samples resident set at idle, polls it every 200 ms through a
load run, and writes one JSON file:

```bash
scripts/perf-regression-run.sh /tmp/bench.json my-label
```

Output shape, straight from the script:

```json
{
  "rps": 0.0,
  "p50_ms": 0.0,
  "p95_ms": 0.0,
  "p99_ms": 0.0,
  "idle_rss_kb": 0,
  "max_rss_kb": 0,
  "schema_version": "1"
}
```

Those zeros are the schema, not a result. Your run fills them in.

Environment overrides, with the script's defaults in parentheses:

| Variable | Default | What it changes |
|---|---|---|
| `DURATION_SECS` | 10 | Seconds of measured steady-state load |
| `WARMUP_SECS` | 3 | Discarded warm-up before measurement |
| `OHA_CONNS` | 32 | Concurrency, the column in the table above |
| `PROXY_PORT` | 28080 | Listen port for the bench proxy |
| `RSS_POLL_MS` | 200 | Resident-set sampling cadence |

So the four rows of the empty table are four runs:

```bash
for c in 32 128 512 2048; do
  OHA_CONNS="$c" DURATION_SECS=60 \
    scripts/perf-regression-run.sh "/tmp/bench-c${c}.json" "c${c}"
done
```

Bump `DURATION_SECS` past the default 10 for a publishable number. Ten seconds
is sized for a CI gate that has to finish, and a cache or a connection pool can
still be filling at that point.

Two caveats on the script as it stands. It builds the binary itself and always
benches the static-200 config it writes to a temp file, so pointing it at your
own config means editing the heredoc. And max RSS comes from polling `ps`
rather than reading `VmHWM`, which keeps it portable but means a spike shorter
than the 200 ms cadence can be missed. Lower `RSS_POLL_MS` if you are chasing a
transient.

### The scenario comparison

[`scripts/perf-compare.sh`](../scripts/perf-compare.sh) runs three shapes
(static origin, full middleware chain, echo) at concurrency 64, then reports
resident set at idle and after 100 requests. It takes a prebuilt binary:

```bash
SBPROXY_BIN=./target/release/sbproxy DURATION=30 scripts/perf-compare.sh
```

Its memory section is a smoke test rather than a load measurement. One hundred
sequential curls will not grow a connection pool or fill a cache, so treat the
"after 100 requests" figure as proof the process is not leaking on startup, not
as an answer to how much memory it needs at 50k rps.

### Profiling where the memory goes

When a number comes back higher than you expected and you need to know why,
[performance.md](performance.md) covers `heaptrack`, `samply`, and
`cargo flamegraph`.

One correction worth making here, because it will waste your afternoon
otherwise: [performance.md](performance.md) documents a criterion
microbenchmark suite and a `target/criterion/` report directory. There is no
criterion suite in this workspace. No crate declares a `[[bench]]` target, no
`benches/` directory exists, and `criterion` is not in `Cargo.lock`. Running
`cargo bench --workspace` compiles the workspace and benches nothing.

## Sizing a pod

### What ships today, and what it is based on

Three places in this repo already carry a `resources:` block, and they do not
agree with each other:

| Where | Requests | Limits | What it sizes |
|---|---|---|---|
| [`deploy/helm/sbproxy/values.yaml`](../deploy/helm/sbproxy/values.yaml) | 50m CPU, 64Mi | 500m CPU, 256Mi | The **operator** pod, not the proxy |
| [`deploy/k8s/sidecar/base/sidecar-patch.yaml`](../deploy/k8s/sidecar/base/sidecar-patch.yaml) | 100m CPU, 64Mi | 1000m CPU, 256Mi | A sidecar proxy container |
| [`deploy/examples/sample-sbproxy.yaml`](../deploy/examples/sample-sbproxy.yaml) | 100m CPU, 128Mi | 500m CPU, 256Mi | A gateway proxy pod via the CRD |

The Helm chart sizes the operator only. It has no data-plane deployment to
size, because the operator creates that from an `SBProxy` resource at runtime.

### The gap that will bite you first

`SBProxy.spec.resources` is optional and has no default. When it is omitted,
the operator reconciles a container with empty requests and empty limits, which
Kubernetes schedules as BestEffort: first to be evicted under node pressure,
and free to grow until the node runs out.

So set it. Always, on every `SBProxy`. An unsized proxy pod is not a proxy pod
with sensible defaults, it is a proxy pod with none.

### A starting point, and the arithmetic behind it

This is a starting point, not a recommendation. We have one idle measurement
and no load measurement, so the honest version of this block is "here is what
we extrapolated and here is every assumption, go check them."

```yaml
resources:
  requests:
    cpu: 500m
    memory: 192Mi
  limits:
    cpu: "2"
    memory: 512Mi
```

Where each number comes from:

- **`memory` request, 192Mi.** The one measurement we have is 77.5 MB idle on a
  minimal config. Round to 80Mi, then add roughly 110Mi of headroom for the
  parts of a real config that the idle measurement did not include: connection
  buffers, an upstream pool, and a response cache. The request is what the
  scheduler reserves, so it wants to be near steady-state resident set rather
  than near the peak.
- **`memory` limit, 512Mi.** Roughly 2.7x the request. The limit exists to
  contain a runaway, so it should sit above any peak you have measured and
  below the point where one bad pod takes a node down. We have not measured a
  peak, which is the whole problem with this block. The 256Mi limits already in
  the repo leave only about 178MB above the one idle figure we have, and no
  measurement says that is enough once a cache and a connection pool are
  filled.
- **`cpu` request, 500m.** Half a core. The proxy is event-driven and does no
  polling at rest, so a mostly-idle instance sits well under this, and the
  request is really about the scheduler placing the pod somewhere it can burst.
- **`cpu` limit, 2.** Published throughput was measured on 8 dedicated vCPUs.
  Two is a deliberate fraction of that, appropriate for a pod serving a
  fraction of that traffic. Raise it in step with your target rps rather than
  leaving it at 2 out of habit. CPU limits throttle rather than kill, so a
  limit set too low shows up as latency, not as a restart.

Adjust these once you have run the table above. That is the point of publishing
the reasoning instead of just the numbers.

### Things you can bound without measuring

Some of the resident set is not a mystery. These knobs put a ceiling on
specific contributors, so you can compute their worst case from config rather
than guessing at it.

| Knob | Default | Worst case it bounds |
|---|---|---|
| `response_cache.max_size` | 10000 entries | Entries times mean cached body size. One shared store per process, sized by the largest per-origin value. |
| `idempotency.max_concurrent_buffers` | 256 | Roughly `max_concurrent_buffers` times `max_request_body_bytes` (default 1 MiB), per origin. At both defaults that is 256 MiB. |
| Lua `max_memory_mb` | 8 | Allocator footprint of one Lua VM. |
| WASM `max_memory_pages` | 256 (16 MiB) | Linear memory of one module instance. |
| Prompt-injection body scan | 8 MiB | Request body buffered per scanned request. |
| Local classifier model size | 200 MiB | One loaded ONNX model. |
| Extension bundle | 64 MiB total, 16 MiB per file | One loaded bundle. |
| RAG response buffer | 2 MiB | Any single embedding or vector-store response. |

Three of those dominate everything else if you turn them on, and the arithmetic
is worth doing before you copy a limit from anywhere.

A local ONNX classifier at the 200 MiB cap is larger than the entire idle
process. The response cache is unbounded in bytes, because its cap counts
entries rather than bytes, so its ceiling is whatever your mean cached body
size happens to be times ten thousand. And idempotency at stock defaults bounds
at 256 MiB per origin, which is on its own equal to the 256Mi memory limit that
every shipped manifest in this repo carries. Enable idempotency on two origins
without raising that limit and the config permits twice the memory the pod is
allowed to have.

None of those three is a bug. They are caps chosen to be generous, on features
that are off by default. They are a problem only when a pod limit gets copied
from an example that assumed none of them were on. If you enable any of them,
size the pod around that feature and treat the base process as a rounding
error.

Cluster replication is not on this list on purpose. Replicated state is written
through to a redb database on disk before it is acknowledged, so
`replication.max_entries` and `replication.max_value_bytes` bound a disk shard,
not the heap.

## Watching memory in production

There is no process resident-set metric on `/metrics`. Nothing in the
[metrics catalog](metrics-stability.md) reports the proxy's own memory; the
only memory gauges are `sbproxy_model_host_gpu_vram_bytes` and
`sbproxy_model_host_gpu_memory_occupancy`, which describe GPU devices the model
host is using, not the proxy process.

So read memory from the layer below:

- **Kubernetes.** `container_memory_working_set_bytes` from cAdvisor is the
  value the OOM killer acts on, and it is what you should alert on. Compare it
  against the limit you set, not against the request.
- **A plain host.** `ps -o rss= -p $(pgrep -f 'sbproxy serve')` gives you the
  same number the 77.5 MB figure came from.

Two metrics that are exported and that move before memory does:

- `sbproxy_active_connections`, a gauge of current active connections. Each
  connection carries buffers, so a sustained climb here is the leading
  indicator of a resident set climbing behind it.
- `sbproxy_origin_active_connections`, the same thing per origin, which tells
  you which upstream is backing up.

A resident set that grows in step with active connections and then flattens
when they flatten is a pool filling, which is expected. A resident set that
keeps climbing while connections are flat is worth a `heaptrack` run.

## When the pod gets OOMKilled

Exceeding a memory limit is not a graceful event. The kernel kills the process,
Kubernetes records `OOMKilled` in the container's last state, and the pod
restarts. In-memory state goes with it: the response cache, rate-limit counters
on a standalone replica, and anything else the process was holding that is not
written through to disk or shared over the mesh.

Confirm that is what happened before you change anything:

```bash
kubectl describe pod <pod> | grep -A5 'Last State'
kubectl get pod <pod> -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}'
```

`OOMKilled` means the limit was too low or something was growing without a
bound. The difference matters, and the diagnostic is whether restarts cluster
at a traffic peak or arrive at a steady interval regardless of load. Peaks mean
the limit is too low for your peak. A steady interval means something grows
monotonically, and no limit will fix that.

Raising the limit is the right first move only in the first case. In the
second, run the harness above against the config that is restarting and watch
whether max RSS keeps climbing across successive runs.

A related failure that looks different: a CPU limit set too low does not kill
anything. The container is throttled, requests queue, and p99 climbs while
memory stays flat. If latency degraded and the pod never restarted, look at
`container_cpu_cfs_throttled_seconds_total` before you look at memory.

## Related reading

- [performance.md](performance.md) for throughput, latency, the tuning knobs,
  and profiling.
- [`BENCHMARK.md`](../BENCHMARK.md) for the head-to-head competitor campaign.
- [sidecar-deployment.md](sidecar-deployment.md) for the per-pod shape and
  where the one idle-RSS figure came from.
- [kubernetes.md](kubernetes.md) for the operator and the `SBProxy` CRD fields.
- [metrics-stability.md](metrics-stability.md) for the full metric catalog.
