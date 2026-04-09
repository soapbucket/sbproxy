# E2E Test Server

A comprehensive unified test server for end-to-end proxy testing. Consolidates HTTP/HTTPS, WebSocket, GraphQL, and callback endpoints into a single configurable test suite.

## Features

- **HTTP/HTTPS Server**: REST API endpoints with TLS support
- **WebSocket Server**: Echo, timestamp, and broadcast endpoints
- **GraphQL Server**: Simple GraphQL API for testing
- **Test Scenarios**: JSON-configured test cases with predictable responses
- **Callback Endpoints**: Session and auth callback simulation with caching support
- **Cache Testing**: ETag, Last-Modified, and Cache-Control header support
- **Circuit Breaker Simulation**: Test circuit breaker behavior for callbacks
- **Response Validation**: Built-in validation helpers

## Quick Start

### Installation

```bash
cd /Users/rick/projects/proxy/tools/e2e-test-server
go mod download
go build
```

### Run with Default Configuration

```bash
./e2e-test-server
```

This starts:
- HTTP server on `:8090`
- HTTPS server on `:9443` (self-signed cert, changed from 8443 to avoid proxy conflict)
- WebSocket server on `:8091`
- GraphQL server on `:8092`

### Run with Custom Configuration

```bash
./e2e-test-server -config=custom-test-config.json
```

### Custom Ports

```bash
./e2e-test-server \
  -http-port=9090 \
  -https-port=9444 \
  -ws-port=9091 \
  -graphql-port=9092
```

### IPv6 Support

Bind to a specific IPv6 address:

```bash
./e2e-test-server -bind="::1"
# Servers will be available at:
# http://[::1]:8090
# https://[::1]:9443
# ws://[::1]:8091
# http://[::1]:8092/graphql
```

Bind to all IPv6 interfaces:

```bash
./e2e-test-server -bind="::"
```

Bind to a specific IPv4 address:

```bash
./e2e-test-server -bind="127.0.0.1"
```

By default (no `-bind` flag), the server listens on all interfaces (both IPv4 and IPv6).

## Test Configuration Format

Test scenarios are defined in JSON format:

```json
{
  "name": "Test Suite Name",
  "description": "Description of test suite",
  "scenarios": [
    {
      "id": "test-scenario-1",
      "name": "Test Scenario Name",
      "path": "/test/test-scenario-1",
      "method": "GET",
      "request": {
        "headers": {
          "Authorization": "Bearer test-token"
        }
      },
      "response": {
        "status": 200,
        "delay": 100,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "status": "success",
          "data": "test data"
        }
      }
    }
  ]
}
```

## HTTP Endpoints

### Built-in Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Server information |
| GET | `/health` | Health check |
| ANY | `/test/{scenario-id}` | Execute test scenario |
| POST | `/callback/session` | Session callback endpoint (with ETag caching) |
| POST | `/callback/auth` | Auth callback endpoint (with ETag caching) |
| POST | `/callback/{id}` | Configurable callback endpoint |
| GET | `/cache/{id}` | Cache testing endpoint with ETag/Last-Modified |
| GET | `/cache-test/{id}` | Advanced cache test with configurable duration |
| GET | `/circuit/{id}` | Circuit breaker simulation endpoint |
| POST | `/api/echo` | Echo request body |
| GET | `/api/headers` | Return request headers |
| GET | `/api/delay?ms=N` | Delayed response |
| GET | `/api/status/{code}` | Return specific status code |
| POST | `/validate` | Validate test response |

### Test Scenario Endpoints

Test scenarios are accessed via `/test/{scenario-id}`. Example:

```bash
# List all scenarios
curl http://localhost:8090/test/

# Execute specific scenario
curl http://localhost:8090/test/simple-200

# Response:
{
  "status": "success",
  "message": "Simple test response",
  "test_id": "simple-200"
}
```

## WebSocket Endpoints

| Path | Description |
|------|-------------|
| `/echo` | Echoes messages back to sender |
| `/timestamp` | Streams server timestamps every second |
| `/broadcast` | Broadcasts messages to all connected clients |
| `/test/{scenario-id}` | Execute test scenario via WebSocket |

### WebSocket Examples

```bash
# Install websocat (WebSocket CLI tool)
brew install websocat

# Echo test
echo "Hello WebSocket" | websocat ws://localhost:8091/echo

# Timestamp stream
websocat ws://localhost:8091/timestamp

# Test scenario
websocat ws://localhost:8091/test/simple-200
```

## GraphQL Endpoints

| Path | Description |
|------|-------------|
| `/graphql` | GraphQL endpoint (POST) |

### GraphQL Queries

```bash
# Query users
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { id name email } }"}'

# Query specific user
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: \"1\") { name email location { city } } }"}'

# Query posts
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ posts { id title tags } }"}'
```

## Callback Endpoints

### Session Callback

```bash
curl -X POST http://localhost:8090/callback/session

# Response:
{
  "user_preferences": {
    "theme": "dark",
    "language": "en",
    "timezone": "America/New_York"
  },
  "feature_flags": {
    "beta_features": true,
    "analytics": true
  },
  "subscription": {
    "tier": "premium",
    "active": true
  }
}

# With caching (ETag support):
curl -X POST http://localhost:8090/callback/session \
  -H "If-None-Match: \"abc123\""
# Returns 304 Not Modified if ETag matches
```

### Auth Callback

```bash
curl -X POST http://localhost:8090/callback/auth \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com"}'

# Response:
{
  "roles": ["admin", "user", "editor"],
  "permissions": {
    "read": true,
    "write": true,
    "delete": true,
    "admin": true
  },
  "access_level": 100
}

# With caching:
curl -X POST http://localhost:8090/callback/auth \
  -H "Content-Type: application/json" \
  -H "If-None-Match: \"def456\"" \
  -d '{"email": "admin@example.com"}'
# Returns 304 Not Modified if ETag matches
```

### Configurable Callback Endpoint

```bash
# Basic callback
curl -X POST http://localhost:8090/callback/test-callback \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'

# With custom status code
curl -X POST "http://localhost:8090/callback/test-callback?status=201" \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'

# With variable name wrapping
curl -X POST "http://localhost:8090/callback/test-callback?variable_name=user_data" \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'

# With cache headers
curl -X POST "http://localhost:8090/callback/test-callback?cache_control=public,max-age=3600&etag=\"test-etag\"" \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

## Cache Testing Endpoints

### Basic Cache Test

```bash
# First request (cache miss)
curl http://localhost:8090/cache/test-resource

# Response includes:
# - ETag header
# - Last-Modified header
# - Cache-Control header
# - X-Cache: MISS
# - X-Request-Count: 1
# - X-Cache-Hits: 0
# - X-Cache-Misses: 1

# Second request with If-None-Match (cache hit)
curl http://localhost:8090/cache/test-resource \
  -H "If-None-Match: \"abc123\""

# Returns 304 Not Modified with:
# - X-Cache: HIT
# - X-Cache-Hits: 1
```

### Advanced Cache Test

```bash
# Cache test with custom duration
curl "http://localhost:8090/cache-test/my-resource?duration=300"

# With If-Modified-Since
curl http://localhost:8090/cache-test/my-resource \
  -H "If-Modified-Since: Mon, 01 Jan 2024 00:00:00 GMT"
```

## Circuit Breaker Testing

```bash
# Success request (circuit closed)
curl http://localhost:8090/circuit/test-circuit

# Simulate failure
curl "http://localhost:8090/circuit/test-circuit?fail=true"

# After 5 failures (default threshold), circuit opens
curl http://localhost:8090/circuit/test-circuit
# Returns 503 Service Unavailable

# Reset circuit breaker
curl "http://localhost:8090/circuit/test-circuit?reset=true"

# Custom failure threshold
curl "http://localhost:8090/circuit/test-circuit?failure_threshold=3&fail=true"
```

## End-to-End Testing Flow

### 1. Start Test Server

```bash
./e2e-test-server -config=test-config.json
```

### 2. Configure Proxy

Create proxy test configuration pointing to test server:

```json
{
  "id": "test-origin",
  "hostname": "test.local",
  "action": {
    "type": "proxy",
    "url": "http://localhost:8090"
  }
}
```

### 3. Run Tests

```bash
# Test simple scenario
curl -H "Host: test.local" http://localhost:8080/test/simple-200

# Test with authentication
curl -H "Host: test.local" \
     -H "Authorization: Bearer test-token" \
     http://localhost:8080/test/auth-required

# Validate response
curl -X POST http://localhost:8090/validate \
  -H "Content-Type: application/json" \
  -d '{
    "scenario_id": "simple-200",
    "response": {
      "status": 200,
      "body": {"status": "success"}
    }
  }'
```

## Test Configuration Examples

See included test configs:
- `test-config.json` - Standard test scenarios
- `test-config-comprehensive.json` - Full feature test suite
- `test-config-callbacks.json` - Callback and caching test scenarios

### Using Callback/Cache Test Configuration

```bash
# Run with callback and cache test scenarios
./e2e-test-server -config=test-config-callbacks.json
```

This configuration includes scenarios for:
- Basic callback testing
- Callbacks with different status codes
- Callbacks with variable name wrapping
- Cache testing with ETag
- Cache testing with Last-Modified
- Circuit breaker simulation
- Cache expiration testing

## Creating Custom Test Scenarios

```json
{
  "scenarios": [
    {
      "id": "my-custom-test",
      "name": "My Custom Test",
      "path": "/test/my-custom-test",
      "method": "POST",
      "request": {
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "expected_field": "expected_value"
        }
      },
      "response": {
        "status": 201,
        "delay": 100,
        "headers": {
          "X-Custom-Header": "custom-value"
        },
        "body": {
          "status": "created",
          "id": "test-123"
        }
      },
      "metadata": {
        "tags": ["custom", "creation"],
        "description": "Tests custom resource creation"
      }
    }
  ]
}
```

## Response Validation

The `/validate` endpoint checks if actual responses match expected scenarios:

```bash
curl -X POST http://localhost:8090/validate \
  -H "Content-Type: application/json" \
  -d '{
    "scenario_id": "simple-200",
    "response": {
      "status": 200,
      "headers": {
        "Content-Type": "application/json"
      }
    }
  }'

# Response:
{
  "scenario_id": "simple-200",
  "valid": true,
  "checks": [
    "✅ Status code: 200",
    "✅ Header Content-Type: application/json"
  ],
  "total_checks": 2
}
```

## Integration with Proxy

### Proxy Configuration

```yaml
origins:
  - id: "e2e-test"
    hostname: "test.local"
    action:
      type: "proxy"
      url: "http://localhost:8090"
    
  - id: "e2e-ws-test"
    hostname: "ws.test.local"
    action:
      type: "websocket"
      url: "ws://localhost:8091"
    
  - id: "e2e-graphql-test"
    hostname: "graphql.test.local"
    action:
      type: "proxy"
      url: "http://localhost:8092"

session:
  callbacks:
    - url: "http://localhost:8090/callback/session"
      method: "POST"

authorization:
  jwt:
    authentication_callback:
      url: "http://localhost:8090/callback/auth"
      method: "POST"
```

### Test Scenarios

```bash
# Test HTTP proxy
curl -H "Host: test.local" http://localhost:8080/test/simple-200

# Test WebSocket proxy
websocat ws://localhost:8080/echo -H "Host: ws.test.local"

# Test GraphQL proxy
curl -H "Host: graphql.test.local" \
  -X POST http://localhost:8080/graphql \
  -d '{"query": "{ users { name } }"}'
```

## Kubernetes Deployment

See `k8s/` directory for Kubernetes manifests:

```bash
# Deploy test server
kubectl apply -f k8s/e2e-test-server.yaml

# Deploy proxy with test config
kubectl apply -f k8s/proxy-test-config.yaml

# Run tests
kubectl apply -f k8s/test-runner.yaml
```

## Development

### Adding New Endpoints

Edit the appropriate handler file:
- `http_handlers.go` - HTTP/REST endpoints
- `websocket_handlers.go` - WebSocket endpoints
- `graphql_handlers.go` - GraphQL endpoints

### Adding New Test Scenarios

Add to `test-config.json`:

```json
{
  "id": "new-scenario",
  "name": "New Test Scenario",
  "path": "/test/new-scenario",
  "method": "GET",
  "response": {
    "status": 200,
    "body": {"status": "success"}
  }
}
```

### Building

```bash
go build -o e2e-test-server
```

### Testing

```bash
# Start server
./e2e-test-server

# In another terminal, run tests
./test.sh
```

## Troubleshooting

### Port Already in Use

```bash
# Change ports
./e2e-test-server -http-port=9090 -https-port=9443
```

### TLS Certificate Errors

```bash
# Use -k flag with curl for self-signed certs
curl -k https://localhost:8443/health
```

### WebSocket Connection Issues

```bash
# Check WebSocket server is running
curl http://localhost:8091/health

# Test with verbose output
websocat -v ws://localhost:8091/echo
```

## Architecture

```
e2e-test-server/
├── main.go                    # Server initialization
├── http_handlers.go           # HTTP/REST handlers
├── websocket_handlers.go      # WebSocket handlers
├── graphql_handlers.go        # GraphQL handlers
├── tls.go                     # TLS certificate generation
├── test-config.json           # Test scenarios
├── go.mod                     # Go module definition
└── README.md                  # This file
```

## License

Copyright 2026 Soap Bucket LLC. All rights reserved. Proprietary and confidential.

