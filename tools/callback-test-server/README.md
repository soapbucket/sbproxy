# Callback Test Server

A lightweight HTTP server for end-to-end testing of the proxy callback framework. Provides configurable endpoints that simulate real-world callback behavior including delays, ETags, Cache-Control headers, conditional requests, error injection, and parallel execution.

## Quick Start

```bash
cd tools/callback-test-server
go build -o callback-test-server
./callback-test-server
```

The server starts on port 9100 by default.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | 9100 | HTTP server port |
| `-verbose` | false | Enable verbose request logging |

## Endpoints

### POST /callback

Standard callback endpoint. Accepts JSON body and returns it merged with server metadata.

```bash
curl -X POST http://localhost:9100/callback \
  -H "Content-Type: application/json" \
  -d '{"origin_id": "test-origin", "hostname": "example.com"}'
```

Response:
```json
{
  "status": "ok",
  "origin_id": "test-origin",
  "hostname": "example.com",
  "timestamp": "2026-02-20T12:00:00Z",
  "server": "callback-test-server"
}
```

### POST /callback/slow

Callback with configurable delay. Use `?delay=500ms` query parameter (Go duration format).

```bash
# 500ms delay
curl -X POST "http://localhost:9100/callback/slow?delay=500ms"

# 2 second delay
curl -X POST "http://localhost:9100/callback/slow?delay=2s"
```

### POST /callback/etag

Returns responses with ETag and Cache-Control headers. Honors `If-None-Match` for conditional requests (returns 304 Not Modified).

```bash
# First request - gets full response with ETag
curl -v -X POST "http://localhost:9100/callback/etag?max_age=300&swr=60"

# Conditional request - returns 304 if ETag matches
curl -v -X POST "http://localhost:9100/callback/etag" \
  -H 'If-None-Match: "2"'
```

Query params:
- `max_age` - Cache-Control max-age in seconds (default: 300)
- `swr` - stale-while-revalidate in seconds (default: 60)
- `etag` - Custom ETag value (default: auto-generated from body size)

### POST /callback/error

Configurable error injection for testing error handling, circuit breakers, and negative caching.

```bash
# Always return 500
curl -X POST "http://localhost:9100/callback/error?status=500"

# 50% error rate (random)
curl -X POST "http://localhost:9100/callback/error?status=503&rate=0.5"

# Custom error message
curl -X POST "http://localhost:9100/callback/error?status=429&message=rate+limited"
```

Query params:
- `status` - HTTP status code (default: 500)
- `rate` - Error probability 0.0-1.0 (default: 1.0 = always error)
- `message` - Custom error message

### POST /callback/large

Returns a response of configurable size for testing response size limits and buffer pool behavior.

```bash
# 1MB response
curl -X POST "http://localhost:9100/callback/large?size=1048576"

# 15MB response (exceeds default 10MB limit)
curl -X POST "http://localhost:9100/callback/large?size=15728640"
```

Query params:
- `size` - Response body size in bytes (default: 1024, max: 100MB)

### POST /callback/parallel

Returns unique sequential data for testing parallel callback execution. Each response includes a monotonically increasing sequence number.

```bash
# Run 3 parallel requests
curl -X POST "http://localhost:9100/callback/parallel?delay=100ms" &
curl -X POST "http://localhost:9100/callback/parallel?delay=100ms" &
curl -X POST "http://localhost:9100/callback/parallel?delay=100ms" &
wait
```

Response includes `seq` (unique sequence number) and `worker_ts` (nanosecond timestamp).

Query params:
- `delay` - Simulated work delay (Go duration format, default: none)

### POST /callback/echo

Echoes back the full request details for debugging.

```bash
curl -X POST "http://localhost:9100/callback/echo" \
  -H "X-Custom: test" \
  -d '{"key": "value"}'
```

Response includes: method, path, headers, query params, and body.

### GET /callback/health

Health check endpoint.

```bash
curl http://localhost:9100/callback/health
```

### GET /callback/stats

Returns per-endpoint request count and latency statistics.

```bash
curl http://localhost:9100/callback/stats
```

### POST /callback/reset

Resets all statistics counters.

```bash
curl -X POST http://localhost:9100/callback/reset
```

## Testing Scenarios

### Singleflight / Thundering Herd

Send many concurrent requests to `/callback/slow?delay=500ms` and verify via `/callback/stats` that only a small number of actual requests hit the server.

### Stale-While-Revalidate

1. Configure callback with `cache_duration: "2s"` pointing to `/callback/etag?max_age=2&swr=10`
2. Make first request (cache miss, full response)
3. Wait 3 seconds (cache expires)
4. Make second request (should get stale data immediately, background refresh with If-None-Match)
5. Check `/callback/stats` for 304 responses

### Negative Caching

1. Configure callback pointing to `/callback/error?status=500`
2. Make 5 rapid requests
3. Check `/callback/stats` - with negative caching, only 1-2 requests should hit the server

### Parallel Execution

1. Configure 3 `on_load` callbacks with `parallel_on_load: true`, each pointing to `/callback/parallel?delay=100ms`
2. Check that all 3 get distinct `seq` values
3. Check that total time is ~100ms (not ~300ms)

### Response Size Limits

1. Configure callback with `max_response_size: 1048576` pointing to `/callback/large?size=2097152`
2. Verify the callback returns an error about exceeding the size limit

## Integration with Proxy Config

Example origin config using the callback test server:

```json
{
  "on_load": [
    {
      "url": "http://localhost:9100/callback/etag?max_age=60&swr=30",
      "method": "POST",
      "variable_name": "config_data",
      "cache_duration": "1m",
      "http_aware": true
    }
  ],
  "on_request": [
    {
      "url": "http://localhost:9100/callback",
      "method": "POST",
      "variable_name": "request_data",
      "cache_duration": "30s"
    }
  ],
  "parallel_on_load": true
}
```
