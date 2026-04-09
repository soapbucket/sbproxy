# Health Check Package

This package provides health check endpoints for the Soapbucket Proxy service, implementing industry-standard patterns for monitoring and Kubernetes-compatible probes.

## Endpoints

### `/health` - General Health Status

Returns comprehensive health information about the service and its components.

**Response Codes:**
- `200 OK` - Service is healthy or degraded but operational
- `503 Service Unavailable` - Service has errors and may not be fully operational

**Response Format:**
```json
{
  "status": "ok",
  "timestamp": "2025-11-04T12:00:00Z",
  "version": "v1.0.0",
  "build_hash": "abc123",
  "uptime": "1h30m",
  "checks": {
    "database": "ok",
    "cache": "ok"
  },
  "details": {}
}
```

**Status Values:**
- `ok` - All components healthy
- `degraded` - Some components degraded but service operational
- `shutting_down` - Service is in graceful shutdown mode
- `error` - One or more components have errors

**During Graceful Shutdown:**
When the service receives a shutdown signal (SIGTERM/SIGINT), the health endpoint includes additional details:
```json
{
  "status": "shutting_down",
  "timestamp": "2025-11-04T12:00:00Z",
  "version": "v1.0.0",
  "build_hash": "abc123",
  "uptime": "1h30m",
  "checks": {},
  "details": {
    "shutting_down": true,
    "inflight_requests": 5
  }
}
```

### `/ready` - Readiness Probe

Kubernetes-compatible readiness probe indicating whether the service can accept traffic.

**Response Codes:**
- `200 OK` - Service is ready to accept traffic
- `503 Service Unavailable` - Service is not ready (starting up, shutting down, or overloaded)

**Response Format:**
```json
{
  "status": "ready",
  "timestamp": "2025-11-04T12:00:00Z"
}
```

**During Graceful Shutdown:**
When the service is shutting down, the readiness probe immediately returns 503:
```json
{
  "status": "not_ready",
  "reason": "shutting_down",
  "inflight_requests": 5,
  "timestamp": "2025-11-04T12:00:00Z"
}
```

**Use Cases:**
- Kubernetes readiness probe
- Load balancer health check
- Traffic routing decisions

### `/live` - Liveness Probe

Kubernetes-compatible liveness probe indicating whether the service is alive and should not be restarted.

**Response Codes:**
- `200 OK` - Service is alive
- `503 Service Unavailable` - Service is dead (should be restarted)

**Response Format:**
```json
{
  "status": "alive",
  "timestamp": "2025-11-04T12:00:00Z"
}
```

**Use Cases:**
- Kubernetes liveness probe
- Service restart decisions

## Usage

### Kubernetes Configuration

#### Liveness Probe
```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

#### Readiness Probe
```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2
```

### Monitoring Setup

```bash
# Health check
curl http://localhost:8080/health

# Readiness check
curl http://localhost:8080/ready

# Liveness check
curl http://localhost:8080/live
```

## Implementing Custom Health Checks

You can register custom health checkers to monitor specific components:

```go
package main

import (
    "github.com/soapbucket/proxy/internal/health"
)

// DatabaseChecker checks database connectivity
type DatabaseChecker struct {
    db *sql.DB
}

func (d *DatabaseChecker) Name() string {
    return "database"
}

func (d *DatabaseChecker) Check() (string, error) {
    if err := d.db.Ping(); err != nil {
        return "", err
    }
    return "ok", nil
}

func main() {
    // Get the health manager
    healthMgr := health.GetManager()
    
    // Register your custom checker
    dbChecker := &DatabaseChecker{db: myDB}
    healthMgr.RegisterChecker(dbChecker)
}
```

## Architecture

### Health Manager

The `Manager` is a singleton that:
- Maintains a registry of health checkers
- Tracks service readiness, liveness, and shutdown state
- Tracks in-flight request count for graceful shutdown
- Aggregates health check results
- Provides HTTP handlers for health endpoints

### Thread Safety

All operations are thread-safe:
- Health checker registration uses mutex locks
- Readiness and liveness use atomic operations
- Multiple goroutines can safely check health status

### Startup Sequence

1. Service starts → `Initialize()` called → Service marked as **live** but **not ready**
2. Configuration loaded → Components initialized
3. All servers started → Service marked as **ready**
4. Service accepts traffic ✓

### Graceful Shutdown Sequence

When a shutdown signal (SIGTERM/SIGINT) is received:

1. **Shutdown initiated** → Service marked as **shutting down** and **not ready**
2. **Readiness probe fails** → `/ready` returns 503, load balancers stop routing new traffic
3. **New requests rejected** → Middleware returns 503 Service Unavailable
4. **In-flight requests tracked** → Service waits for active requests to complete
5. **Grace period** → Waits up to configured grace time (default: 30s) for requests to finish
6. **Forced shutdown** → After grace period or when all requests complete
7. **Service marked as not live** → Components closed
8. **Service stops** ✓

**Grace Time Configuration:**
```bash
# Set grace time via flag (seconds)
sb serve --grace-time 60

# Or via environment variable
export SB_GRACE_TIME=60
sb serve
```

**Shutdown Behavior:**
- ✅ In-flight requests complete successfully
- ✅ New requests immediately receive 503
- ✅ Health checks reflect shutdown state
- ✅ Load balancers stop routing traffic
- ✅ No request data loss during shutdown

## Best Practices

### Readiness vs. Liveness

**Readiness:**
- Use for temporary conditions (high load, dependencies unavailable)
- Service should recover automatically
- Load balancers should stop sending traffic
- **Don't restart the service**

**Liveness:**
- Use for permanent failures (deadlocks, infinite loops)
- Service cannot recover on its own
- **Restart the service**

### Health Check Design

1. **Keep it fast** - Health checks should complete in < 1 second
2. **Avoid cascading failures** - Don't fail if dependencies are degraded
3. **Use timeouts** - Set reasonable timeouts for external dependencies
4. **Monitor what matters** - Check actual functionality, not just connectivity

### Example Health Checker

```go
type CacheChecker struct {
    redis *redis.Client
    timeout time.Duration
}

func (c *CacheChecker) Check() (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
    defer cancel()
    
    if err := c.redis.Ping(ctx).Err(); err != nil {
        return "", fmt.Errorf("redis ping failed: %w", err)
    }
    
    // Check if we can actually read/write
    testKey := "health:check"
    if err := c.redis.Set(ctx, testKey, "ok", time.Second).Err(); err != nil {
        return "degraded", nil // Can connect but can't write
    }
    
    return "ok", nil
}
```

## Metrics and Monitoring

Consider exposing these metrics:
- Health check latency
- Health check success/failure rates
- Time spent in each state (ready/not ready)
- Number of failed health checks

## Testing

The package includes comprehensive tests:
- Unit tests for all handlers
- Thread safety tests
- Mock checker implementation for testing

Run tests:
```bash
go test ./internal/health -v
```

## Future Enhancements

Potential improvements:
- Health check caching (avoid hammering dependencies)
- Circuit breakers for health checks
- Dependency health aggregation
- Custom health check intervals per checker
- Health check history/trends
- Integration with metrics systems (Prometheus)

