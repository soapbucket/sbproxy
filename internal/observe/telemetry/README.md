# Telemetry Package

The `telemetry` package provides observability infrastructure for the Soapbucket proxy, including Prometheus metrics, OpenTelemetry tracing, and pprof profiling.

## Overview

This package provides:
- **Prometheus metrics** - Request counts, latency, errors, system metrics
- **OpenTelemetry tracing** - Distributed tracing with OTLP exporter
- **pprof profiling** - CPU, memory, and goroutine profiling
- **Telemetry HTTP server** - Dedicated metrics and profiling endpoint
- **Health checks** - Service health monitoring

## Components

### 1. Telemetry Server

HTTP server exposing metrics and profiling endpoints.

**Default Address:** `localhost:8888`

**Endpoints:**
- `GET /metrics` - Prometheus metrics
- `GET /health` - Health check
- `GET /debug/pprof/` - pprof index (if enabled)
- `GET /debug/pprof/heap` - Heap profile
- `GET /debug/pprof/goroutine` - Goroutine dump
- `GET /debug/pprof/profile` - CPU profile (30s)
- `GET /debug/pprof/trace` - Execution trace

**Configuration:**
```yaml
telemetry:
  bind_port: 8888
  bind_address: "127.0.0.1"
  enable_profiler: true
  certificate_file: ""      # Optional TLS
  certificate_key_file: ""  # Optional TLS
  min_tls_version: 12
```

### 2. Prometheus Metrics

Automatic metrics collection for HTTP requests.

**Default Metrics:**
- `http_requests_total` - Total HTTP requests (counter)
- `http_request_duration_seconds` - Request latency (histogram)
- `http_response_size_bytes` - Response size (histogram)
- `http_requests_in_flight` - Active requests (gauge)
- `go_*` - Go runtime metrics (memory, goroutines, GC, etc.)

**Usage:**
```go
import "github.com/soapbucket/proxy/internal/telemetry"

// Server automatically collects metrics
// Access via: curl http://localhost:8888/metrics
```

**Custom Metrics:**
```go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var requestsProcessed = promauto.NewCounter(prometheus.CounterOpts{
    Name: "proxy_requests_processed_total",
    Help: "Total number of processed requests",
})

// Increment counter
requestsProcessed.Inc()
```

### 3. OpenTelemetry Tracing

Distributed tracing with OTLP exporter.

**Features:**
- Automatic span creation for HTTP requests
- Context propagation
- Trace sampling
- Multiple backends (Jaeger, Zipkin, Tempo, etc.)

**Configuration:**
```yaml
otel:
  enabled: true
  service_name: "soapbucket-proxy"
  service_version: "1.0.0"
  otlp_endpoint: "localhost:4317"
  otlp_insecure: true
  sample_rate: 1.0
  environment: "production"
```

**Initialization:**
```go
import "github.com/soapbucket/proxy/internal/telemetry"

// Initialize during service startup
ctx := context.Background()
config := service.GetOTelConfig()
err := telemetry.InitializeOTel(ctx, config)

// Shutdown during service stop
shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
telemetry.ShutdownOTel(shutdownCtx)
```

**Span Attributes:**
- `http.method` - HTTP method
- `http.url` - Request URL
- `http.status_code` - Response status
- `request.id` - Internal request ID
- `user_agent.family` - Browser family
- `client.ip` - Client IP address

### 4. pprof Profiling

Built-in performance profiling.

**Enable Profiler:**
```yaml
telemetry:
  enable_profiler: true
```

**CPU Profiling:**
```bash
# Capture 30 second CPU profile
go tool pprof http://localhost:8888/debug/pprof/profile

# Capture 60 second profile
go tool pprof http://localhost:8888/debug/pprof/profile?seconds=60
```

**Memory Profiling:**
```bash
# Heap profile
go tool pprof http://localhost:8888/debug/pprof/heap

# Allocations
go tool pprof http://localhost:8888/debug/pprof/allocs
```

**Goroutine Analysis:**
```bash
# Text dump
curl http://localhost:8888/debug/pprof/goroutine?debug=1

# Interactive analysis
go tool pprof http://localhost:8888/debug/pprof/goroutine
```

**Execution Trace:**
```bash
# Capture 5 second trace
curl http://localhost:8888/debug/pprof/trace?seconds=5 > trace.out
go tool trace trace.out
```

## Quick Start

### 1. Basic Setup

```yaml
# config.yaml
telemetry:
  bind_port: 8888
  bind_address: "127.0.0.1"
  enable_profiler: true

otel:
  enabled: true
  service_name: "proxy"
  otlp_endpoint: "localhost:4317"
  otlp_insecure: true
```

### 2. View Metrics

```bash
curl http://localhost:8888/metrics
```

### 3. Check Health

```bash
curl http://localhost:8888/health
```

### 4. Profile CPU

```bash
go tool pprof http://localhost:8888/debug/pprof/profile?seconds=30
```

## Integration Examples

### With Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'soapbucket-proxy'
    static_configs:
      - targets: ['localhost:8888']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### With Jaeger

```bash
# Start Jaeger all-in-one
docker run -d --name jaeger \
  -e COLLECTOR_OTLP_ENABLED=true \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest

# Configure proxy
export SB_OTEL__ENABLED=true
export SB_OTEL__OTLP_ENDPOINT=localhost:4317
export SB_OTEL__OTLP_INSECURE=true

# View traces at http://localhost:16686
```

### With Grafana

```yaml
# docker-compose.yml
version: '3.8'
services:
  proxy:
    build: .
    ports:
      - "8080:8080"
      - "8888:8888"
    environment:
      - SB_OTEL__ENABLED=true
      - SB_OTEL__OTLP_ENDPOINT=tempo:4317
      
  tempo:
    image: grafana/tempo:latest
    ports:
      - "4317:4317"
      - "3200:3200"
      
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
```

## Performance Considerations

### Metrics Overhead

- **Per-request cost:** ~500 ns
- **Memory per metric:** ~1-2 KB
- **Recommendation:** Use selective sampling for high-traffic endpoints

### Tracing Overhead

- **Per-span cost:** ~2-5 μs
- **Memory per span:** ~200 bytes
- **Recommendation:** Use sampling in production

**Sampling Configuration:**
```yaml
otel:
  sample_rate: 0.1  # Sample 10% of requests
```

### Profiling Overhead

- **pprof endpoints:** Minimal overhead when not in use
- **CPU profiling:** 5-10% overhead during capture
- **Heap profiling:** Negligible overhead
- **Recommendation:** Enable in production, profile on-demand

## Security

### Bind to Localhost

```yaml
telemetry:
  bind_address: "127.0.0.1"  # Only accessible from local machine
```

### Use TLS

```yaml
telemetry:
  certificate_file: "/path/to/cert.pem"
  certificate_key_file: "/path/to/key.pem"
  min_tls_version: 13
```

### Firewall Rules

```bash
# Only allow from monitoring systems
iptables -A INPUT -p tcp --dport 8888 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8888 -j DROP
```

### Disable in Production

If not needed, disable profiler:

```yaml
telemetry:
  enable_profiler: false  # No pprof endpoints
```

## Troubleshooting

### Issue: Metrics Not Updating

**Check:**
1. Telemetry server is running: `curl http://localhost:8888/health`
2. Requests are being processed
3. No errors in logs

### Issue: Traces Not Appearing

**Check:**
1. OpenTelemetry is enabled: `SB_OTEL__ENABLED=true`
2. OTLP endpoint is reachable: `telnet localhost 4317`
3. Sample rate is not 0: `SB_OTEL__SAMPLE_RATE=1.0`
4. Check logs for OTel errors

### Issue: High Memory Usage

**Solutions:**
1. Reduce trace sampling rate
2. Limit span attributes
3. Check for metric cardinality explosion
4. Profile with pprof to find leaks

### Issue: Can't Access Profiler

**Check:**
1. Profiler is enabled: `enable_profiler: true`
2. Accessing from localhost: `curl http://localhost:8888/debug/pprof/`
3. No firewall blocking port 8888

## Best Practices

1. **Always enable telemetry server**
   ```yaml
   telemetry:
     bind_port: 8888
   ```

2. **Bind to localhost in production**
   ```yaml
   telemetry:
     bind_address: "127.0.0.1"
   ```

3. **Use sampling for high traffic**
   ```yaml
   otel:
     sample_rate: 0.1
   ```

4. **Enable profiler for debugging**
   ```yaml
   telemetry:
     enable_profiler: true
   ```

5. **Monitor Go runtime metrics**
   - Watch `go_goroutines` for goroutine leaks
   - Watch `go_memstats_alloc_bytes` for memory growth
   - Watch `go_gc_duration_seconds` for GC pressure

6. **Set up alerts**
   ```promql
   # High error rate
   rate(http_requests_total{status=~"5.."}[5m]) > 10
   
   # High latency
   histogram_quantile(0.95, http_request_duration_seconds_bucket) > 1
   
   # Memory growth
   go_memstats_alloc_bytes > 1e9
   ```

## Custom Instrumentation

### Add Custom Spans

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
)

func processRequest(ctx context.Context, req *Request) error {
    tracer := otel.Tracer("proxy")
    ctx, span := tracer.Start(ctx, "process_request")
    defer span.End()
    
    span.SetAttributes(
        attribute.String("request.id", req.ID),
        attribute.Int("request.size", req.Size),
    )
    
    // Do work...
    
    return nil
}
```

### Add Custom Metrics

```go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    cacheHits = promauto.NewCounter(prometheus.CounterOpts{
        Name: "cache_hits_total",
        Help: "Total cache hits",
    })
    
    cacheLatency = promauto.NewHistogram(prometheus.HistogramOpts{
        Name: "cache_latency_seconds",
        Help: "Cache operation latency",
        Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
    })
)

func getFromCache(key string) (interface{}, error) {
    start := time.Now()
    defer cacheLatency.Observe(time.Since(start).Seconds())
    
    value, err := cache.Get(key)
    if err == nil {
        cacheHits.Inc()
    }
    return value, err
}
```

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [OpenTelemetry Go](https://opentelemetry.io/docs/instrumentation/go/)
- [pprof User Guide](https://github.com/google/pprof/blob/main/doc/README.md)
- [Parent README](../../README.md) - Project overview

## License

Copyright © 2025 Soapbucket

