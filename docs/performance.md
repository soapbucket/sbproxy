# Performance
*Last modified: 2026-04-12*

SBproxy is designed for high throughput with low per-request overhead. This document covers benchmark results, testing methodology, and how to run your own tests.

## Benchmark Results

**Environment:** Apple M-series (ARM64), macOS, Go 1.25, localhost loopback (single machine).

**Configuration:** Bare proxy action, request logging suppressed, host filter disabled, no policies or transforms. This isolates the proxy overhead from feature processing.

**Origin:** Go `net/http` echo server returning a minimal JSON response.

### Throughput (zero-error results only)

All results below completed with 0% error rate. Higher concurrency levels are omitted because localhost ephemeral port exhaustion introduces errors that are not representative of proxy performance. Production benchmarks on separate machines will follow.

| Concurrency | Requests | Proxied Req/s | Avg Latency | p50 | p95 | p99 |
|-------------|----------|--------------|-------------|------|------|------|
| 50 | 5,000 | 25,718 | 1.9ms | 1.7ms | 3.8ms | 5.0ms |
| 100 | 10,000 | 32,354 | 3.0ms | 2.7ms | 6.3ms | 8.5ms |

### Direct vs Proxied (100 concurrency, 10k requests)

| Metric | Direct | Proxied | Overhead |
|--------|--------|---------|----------|
| Req/s | 109,753 | 32,354 | - |
| Avg | 0.9ms | 3.0ms | +2.1ms |
| p50 | 0.6ms | 2.7ms | +2.1ms |
| p95 | 2.4ms | 6.3ms | +3.9ms |
| p99 | 3.2ms | 8.5ms | +5.3ms |

### Key Observations

- **32k+ req/s** at 100 concurrent connections with zero errors on a single laptop.
- **Sub-3ms average proxy overhead** at the optimal concurrency level.
- **Consistent tail latency:** p99 stays under 9ms at 100 concurrency.
- **Connection reuse:** The proxy maintains persistent upstream connections, so workloads with HTTP keep-alive benefit significantly.

### Localhost Limitations

These benchmarks run the load generator, proxy, and origin on the same machine. This understates production performance because:

1. **Ephemeral port exhaustion** limits concurrency above ~150. Separate machines eliminate this entirely.
2. **No connection pooling benefit.** Localhost connections are instant, so the proxy's connection pooling provides no measurable advantage. With real network latency, connection reuse is a significant win.
3. **CPU/memory contention.** All three processes compete for the same resources.

On dedicated infrastructure (e.g., separate 4-vCPU instances), expect substantially higher throughput.

## Running the Benchmark

### Prerequisites

- Go 1.25+
- [hey](https://github.com/rakyll/hey) HTTP load generator

```bash
# macOS
brew install hey

# Linux
go install github.com/rakyll/hey@latest
```

### Quick Test

The built-in load test script handles setup, execution, and teardown:

```bash
cd sbproxy

# Default: 100 requests, 10 concurrency
./e2e/load-test.sh

# Custom: 1000 requests, 50 concurrency
./e2e/load-test.sh -n 1000 -c 50
```

This starts a test origin server, launches sbproxy with a simple proxy config, runs the benchmark, and prints a comparison table.

### Manual Benchmark

For more control, run each component separately.

**1. Build the echo server and proxy:**

```bash
go build -o /tmp/echo-bench e2e/servers/echo-server.go
go build -o /tmp/sbproxy-bench ./cmd/sbproxy/
```

**2. Create a minimal config:**

```bash
mkdir -p /tmp/bench-cfg
cat > /tmp/bench-cfg/sb.yml <<'YAML'
proxy:
  http_bind_port: 8080
origins:
  "bench.test":
    action:
      type: proxy
      url: http://127.0.0.1:9090
YAML
```

**3. Start servers:**

```bash
# Terminal 1: origin
PORT=9090 /tmp/echo-bench

# Terminal 2: proxy (minimal features)
/tmp/sbproxy-bench serve \
  -f /tmp/bench-cfg/sb.yml \
  --log-level error \
  --request-log-level none \
  --disable-host-filter \
  --disable-sb-flags
```

**4. Increase file descriptor limit (macOS):**

```bash
ulimit -n 65536
```

**5. Warmup then benchmark:**

```bash
# Warmup
hey -n 2000 -c 50 -host bench.test http://127.0.0.1:8080/

# Benchmark
hey -n 10000 -c 100 -host bench.test http://127.0.0.1:8080/
```

### Tips for Accurate Results

- **Always warmup** before measuring. The first few hundred requests include connection establishment and runtime warmup.
- **Increase `ulimit -n`** on macOS. The default (256) is too low for high concurrency.
- **Use separate machines** for the origin and proxy when testing above 200 concurrency. Localhost tests are limited by ephemeral port exhaustion on the loopback interface.
- **Disable request logging** with `--request-log-level none` to measure proxy overhead without I/O contention from log writes.
- **Pin CPU frequency** if benchmarking on Linux to avoid turbo boost skewing results.

## Cloud Benchmark Setup

Localhost benchmarks are limited by ephemeral port exhaustion and resource contention. For production-grade numbers, run each component on a separate instance. The instructions below use GCP but apply to any cloud provider (AWS, Azure, etc.) with equivalent instance types.

### Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Load Generator  │────>│    SBproxy       │────>│  Origin Server   │
│  (hey / wrk)     │     │  (under test)    │     │  (echo server)   │
│  e2-standard-4   │     │  e2-standard-4   │     │  e2-standard-2   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        10.0.0.10              10.0.0.11              10.0.0.12
                    same zone, same VPC, internal IPs
```

All three instances must be in the **same zone** and **same VPC**. Use internal IPs to avoid NAT overhead and ensure consistent sub-millisecond network latency between instances.

### Instance Selection

| Role | GCP | AWS | Azure | Why |
|------|-----|-----|-------|-----|
| Load generator | e2-standard-4 | c5.xlarge | Standard_F4s_v2 | CPU-bound, needs cores to drive connections |
| SBproxy | e2-standard-4 | c5.xlarge | Standard_F4s_v2 | CPU-bound, match your production instance type |
| Origin | e2-standard-2 | c5.large | Standard_F2s_v2 | Minimal load, just echoing responses |

For testing at higher concurrency (1000+), scale the load generator to 8 or 16 vCPUs.

### OS Tuning (all three instances)

Apply these settings on every instance before running benchmarks. These are required to avoid hitting OS-level limits before the proxy is saturated.

```bash
# File descriptors - required for high concurrency
sudo sh -c 'cat >> /etc/security/limits.conf <<EOF
* soft nofile 65536
* hard nofile 65536
EOF'

# Apply immediately for current session
ulimit -n 65536

# Ephemeral port range - expand from default ~28k ports to ~64k
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# Allow reuse of TIME_WAIT sockets - critical for benchmarks
sudo sysctl -w net.ipv4.tcp_tw_reuse=1

# Increase connection tracking table (if conntrack is loaded)
sudo sysctl -w net.netfilter.nf_conntrack_max=262144 2>/dev/null || true

# Increase socket backlog for burst handling
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.core.netdev_max_backlog=65535

# Increase TCP memory limits
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.ipv4.tcp_fin_timeout=15

# Make persistent across reboots
sudo sh -c 'cat >> /etc/sysctl.d/99-benchmark.conf <<EOF
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
EOF'
```

### Verify Tuning

Before running benchmarks, verify the settings took effect:

```bash
# Should show 65536
ulimit -n

# Should show "1024 65535"
cat /proc/sys/net/ipv4/ip_local_port_range

# Should show 1
cat /proc/sys/net/ipv4/tcp_tw_reuse
```

### Building and Deploying

Build the binaries on your local machine and copy to each instance:

```bash
# Build for Linux
GOOS=linux GOARCH=amd64 go build -o sbproxy-linux ./cmd/sbproxy/
GOOS=linux GOARCH=amd64 go build -o echo-server-linux e2e/servers/echo-server.go

# Copy to instances
scp sbproxy-linux user@10.0.0.11:~/sbproxy
scp echo-server-linux user@10.0.0.12:~/echo-server
```

Install the load testing tool on the load generator:

```bash
# On load generator instance
go install github.com/rakyll/hey@latest
# or
sudo apt-get install -y wrk
```

### Running the Benchmark

**1. Start the origin server:**

```bash
# On origin instance (10.0.0.12)
PORT=8080 ./echo-server
```

**2. Create proxy config and start SBproxy:**

```bash
# On proxy instance (10.0.0.11)
cat > sb.yml <<'YAML'
proxy:
  http_bind_port: 8080
origins:
  "bench.test":
    action:
      type: proxy
      url: http://10.0.0.12:8080
YAML

./sbproxy serve \
  -f sb.yml \
  --log-level error \
  --request-log-level none \
  --disable-host-filter \
  --disable-sb-flags
```

**3. Warmup, then run progressive load tiers:**

```bash
# On load generator (10.0.0.10)
PROXY=http://10.0.0.11:8080/

# Warmup
hey -n 5000 -c 100 -host bench.test $PROXY

# Tier 1: baseline
hey -n 10000 -c 100 -host bench.test $PROXY

# Tier 2: moderate
hey -n 50000 -c 200 -host bench.test $PROXY

# Tier 3: heavy
hey -n 100000 -c 500 -host bench.test $PROXY

# Tier 4: stress
hey -n 100000 -c 1000 -host bench.test $PROXY

# Tier 5: find the ceiling
hey -n 200000 -c 2000 -host bench.test $PROXY
```

### What to Look For

A clean benchmark run should show:

- **0% error rate** across all tiers. Any errors indicate a bottleneck to investigate.
- **Linear throughput scaling** as concurrency increases, until a plateau.
- **Stable p99 latency.** A spike in p99 while p50 stays flat suggests contention.
- **Status code distribution** should be 100% `[200]`. Any `[502]` or `[503]` indicates proxy or origin saturation.

If you see errors:

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| `502 Bad Gateway` | Origin overloaded or port exhaustion | Scale origin, check `ulimit -n` and port range |
| `503 Service Unavailable` | Connection limiter rejecting | Increase `max_connections` in origin config |
| `dial tcp: connect: connection refused` | Origin not accepting connections | Check origin is running, increase its backlog |
| `context deadline exceeded` | Request timeout | Increase proxy timeout or scale origin |

### Comparing Against Other Proxies

To benchmark SBproxy against Nginx, Envoy, or other proxies, use the same origin server and load generator. Swap only the proxy instance:

```bash
# Same origin, same load generator, same parameters
# Just point the load generator at the other proxy's IP

# SBproxy
hey -n 100000 -c 500 -host bench.test http://10.0.0.11:8080/

# Nginx (on a different instance at 10.0.0.13)
hey -n 100000 -c 500 -host bench.test http://10.0.0.13:8080/
```

Keep everything else identical: same instance types, same zone, same origin, same OS tuning. Only change the proxy under test.
