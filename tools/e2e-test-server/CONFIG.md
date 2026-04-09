# Configuration Guide

This document provides a comprehensive guide to configuring the e2e-test-server for end-to-end testing scenarios.

## Table of Contents

- [Command-Line Options](#command-line-options)
- [JSON Configuration File](#json-configuration-file)
- [Test Scenario Configuration](#test-scenario-configuration)
- [Default Configuration](#default-configuration)
- [Configuration Examples](#configuration-examples)
- [Advanced Configuration](#advanced-configuration)
- [Environment-Specific Configuration](#environment-specific-configuration)
- [TLS and Certificate Configuration](#tls-and-certificate-configuration)
- [IPv6 Configuration](#ipv6-configuration)
- [Port Configuration](#port-configuration)

## Command-Line Options

The e2e-test-server supports the following command-line flags:

### Basic Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-config` | string | `test-config.json` | Path to the JSON test configuration file |
| `-bind` | string | `""` (all interfaces) | Bind address for all servers (supports IPv4/IPv6) |
| `-http-port` | int | `8090` | HTTP server port |
| `-https-port` | int | `9443` | HTTPS server port (self-signed certificate) |
| `-mtls-port` | int | `9444` | mTLS HTTPS server port (requires client certificates) |
| `-ws-port` | int | `8091` | WebSocket server port |
| `-graphql-port` | int | `8092` | GraphQL server port |
| `-grpc-port` | int | `8093` | gRPC server port (HTTP/2) |
| `-mqtt-port` | int | `8094` | MQTT server port (WebSocket) |

### Usage Examples

```bash
# Use default configuration
./e2e-test-server

# Specify custom configuration file
./e2e-test-server -config=my-test-config.json

# Custom ports
./e2e-test-server -http-port=9090 -https-port=9444 -ws-port=9091

# Bind to specific IPv4 address
./e2e-test-server -bind=127.0.0.1

# Bind to specific IPv6 address
./e2e-test-server -bind="::1"

# Bind to all IPv6 interfaces
./e2e-test-server -bind="::"

# Combined options
./e2e-test-server \
  -config=comprehensive-config.json \
  -bind=0.0.0.0 \
  -http-port=8080 \
  -https-port=8443 \
  -ws-port=8081
```

## JSON Configuration File

The JSON configuration file defines test scenarios, default values, and metadata for the test server.

### Configuration File Structure

```json
{
  "name": "string",
  "description": "string",
  "defaults": {
    "status": 200,
    "headers": {}
  },
  "scenarios": [
    {
      "id": "string",
      "name": "string",
      "path": "string",
      "method": "string",
      "request": {},
      "response": {},
      "metadata": {}
    }
  ]
}
```

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Name of the test configuration |
| `description` | string | No | Description of the test suite |
| `defaults` | object | No | Default values applied to all scenarios |
| `scenarios` | array | Yes | Array of test scenario definitions |

### Defaults Object

The `defaults` object provides default values that are applied to all scenarios when not explicitly specified:

```json
{
  "defaults": {
    "status": 200,
    "headers": {
      "X-Test-Server": "e2e-test-server",
      "X-Test-Version": "1.0"
    }
  }
}
```

**Default Fields:**

- `status` (int): Default HTTP status code (default: 200)
- `headers` (object): Default response headers (key-value pairs)

## Test Scenario Configuration

Each test scenario defines a specific test case with request matching and response configuration.

### Scenario Structure

```json
{
  "id": "unique-scenario-id",
  "name": "Human-readable scenario name",
  "path": "/test/scenario-path",
  "method": "GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD",
  "request": {
    "headers": {},
    "query_params": {},
    "body": {},
    "body_json": "string"
  },
  "response": {
    "status": 200,
    "headers": {},
    "body": {},
    "body_raw": "string",
    "delay": 0
  },
  "metadata": {}
}
```

### Scenario Fields

#### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier for the scenario (used in `/test/{id}` endpoint) |
| `name` | string | Human-readable name for the scenario |
| `path` | string | URL path pattern (typically `/test/{id}`) |
| `method` | string | HTTP method (GET, POST, PUT, DELETE, etc.) |

#### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `request` | object | Request matching criteria (see below) |
| `response` | object | Response configuration (see below) |
| `metadata` | object | Custom metadata for categorization/tagging |

### Request Matching (`request` object)

The `request` object defines criteria for matching incoming requests:

```json
{
  "request": {
    "headers": {
      "Authorization": "Bearer test-token",
      "Content-Type": "application/json"
    },
    "query_params": {
      "page": "1",
      "per_page": "10"
    },
    "body": {
      "email": "test@example.com",
      "name": "Test User"
    },
    "body_json": "{\"exact\": \"json\", \"match\": true}"
  }
}
```

**Request Fields:**

- `headers` (object): Expected request headers (key-value pairs)
- `query_params` (object): Expected query parameters (key-value pairs)
- `body` (object): Expected request body (JSON object)
- `body_json` (string): Exact JSON string match for request body

**Note:** Request matching is currently informational. The server will respond according to the scenario configuration regardless of request content, but request matching can be used for documentation and validation purposes.

### Response Configuration (`response` object)

The `response` object defines the HTTP response to return:

```json
{
  "response": {
    "status": 200,
    "headers": {
      "Content-Type": "application/json",
      "X-Custom-Header": "custom-value"
    },
    "body": {
      "status": "success",
      "data": "response data"
    },
    "body_raw": "Raw response string (alternative to body)",
    "delay": 500
  }
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `status` | int | HTTP status code (default: 200, or from `defaults`) |
| `headers` | object | Response headers (key-value pairs) |
| `body` | object | JSON response body (automatically serialized) |
| `body_raw` | string | Raw response body (alternative to `body`, takes precedence) |
| `delay` | int | Response delay in milliseconds (0 = no delay) |

**Note:** If both `body` and `body_raw` are specified, `body_raw` takes precedence.

### Metadata Object

The `metadata` object allows custom categorization and tagging:

```json
{
  "metadata": {
    "category": "auth",
    "tags": ["authentication", "bearer-token"],
    "critical": true,
    "timeout_test": false
  }
}
```

Metadata is stored but not used by the server logic. It's useful for:
- Organizing scenarios by category
- Tagging scenarios for test suites
- Documenting scenario characteristics
- Filtering scenarios in test runners

## Default Configuration

If no configuration file is provided or the file cannot be loaded, the server uses a default configuration:

```json
{
  "name": "Default E2E Test Configuration",
  "description": "Basic test scenarios for proxy validation",
  "scenarios": [],
  "defaults": {
    "status": 200
  }
}
```

This minimal configuration allows the server to start, but no test scenarios will be available until a proper configuration file is loaded.

## Configuration Examples

### Minimal Configuration

```json
{
  "name": "Minimal Test Config",
  "description": "Basic test configuration",
  "scenarios": [
    {
      "id": "simple-200",
      "name": "Simple 200 OK",
      "path": "/test/simple-200",
      "method": "GET",
      "response": {
        "status": 200,
        "body": {
          "status": "success"
        }
      }
    }
  ]
}
```

### Standard Configuration

```json
{
  "name": "Standard Test Configuration",
  "description": "Common test scenarios",
  "defaults": {
    "status": 200,
    "headers": {
      "X-Test-Server": "e2e-test-server"
    }
  },
  "scenarios": [
    {
      "id": "health-check",
      "name": "Health Check",
      "path": "/test/health-check",
      "method": "GET",
      "response": {
        "status": 200,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "status": "healthy"
        }
      }
    },
    {
      "id": "auth-required",
      "name": "Authentication Required",
      "path": "/test/auth-required",
      "method": "GET",
      "request": {
        "headers": {
          "Authorization": "Bearer test-token"
        }
      },
      "response": {
        "status": 200,
        "body": {
          "authenticated": true
        }
      }
    }
  ]
}
```

### Comprehensive Configuration

See `test-config-comprehensive.json` for a full example with:
- Multiple HTTP methods
- Various status codes
- Complex request/response bodies
- Caching headers
- Redirects
- Error scenarios
- Performance testing scenarios

### Callback and Cache Configuration

See `test-config-callbacks.json` for examples of:
- Callback endpoint scenarios
- Cache testing scenarios
- ETag and Last-Modified headers
- Circuit breaker simulation
- Session and auth callbacks

## Advanced Configuration

### Response Delays

Simulate slow responses or network latency:

```json
{
  "id": "slow-response",
  "name": "Slow Response",
  "path": "/test/slow-response",
  "method": "GET",
  "response": {
    "status": 200,
    "delay": 2000,
    "body": {
      "delayed": true,
      "delay_ms": 2000
    }
  }
}
```

### Custom Headers

Set custom response headers:

```json
{
  "response": {
    "status": 200,
    "headers": {
      "Content-Type": "application/json",
      "X-Custom-Header": "custom-value",
      "X-Request-ID": "12345",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "X-RateLimit-Limit": "1000",
      "X-RateLimit-Remaining": "950"
    }
  }
}
```

### Redirect Responses

Configure redirect responses:

```json
{
  "id": "redirect-301",
  "name": "Permanent Redirect",
  "path": "/test/redirect-301",
  "method": "GET",
  "response": {
    "status": 301,
    "headers": {
      "Location": "/test/simple-200"
    },
    "body": {
      "redirect": true,
      "location": "/test/simple-200"
    }
  }
}
```

### Error Responses

Simulate various error conditions:

```json
{
  "id": "error-500",
  "name": "Internal Server Error",
  "path": "/test/error-500",
  "method": "GET",
  "response": {
    "status": 500,
    "headers": {
      "Content-Type": "application/json"
    },
    "body": {
      "error": "Internal server error",
      "code": "INTERNAL_ERROR"
    }
  }
}
```

### Raw Response Bodies

Use raw strings for non-JSON responses:

```json
{
  "response": {
    "status": 200,
    "headers": {
      "Content-Type": "text/html"
    },
    "body_raw": "<html><body><h1>Hello World</h1></body></html>"
  }
}
```

### Complex Request Bodies

Match complex JSON request bodies:

```json
{
  "request": {
    "body": {
      "user": {
        "name": "Test User",
        "email": "test@example.com",
        "preferences": {
          "theme": "dark",
          "language": "en"
        }
      },
      "metadata": {
        "source": "api",
        "version": "1.0"
      }
    }
  }
}
```

## Environment-Specific Configuration

### Development Environment

```bash
./e2e-test-server \
  -config=test-config.json \
  -bind=127.0.0.1 \
  -http-port=8090
```

### Production/CI Environment

```bash
./e2e-test-server \
  -config=test-config-comprehensive.json \
  -bind=0.0.0.0 \
  -http-port=80 \
  -https-port=443
```

### Docker Environment

```dockerfile
FROM golang:1.21-alpine
COPY e2e-test-server /app/
COPY test-config.json /app/
WORKDIR /app
CMD ["./e2e-test-server", "-config", "test-config.json"]
```

Or with custom config:

```bash
docker run -v $(pwd)/my-config.json:/app/test-config.json \
  -p 8090:8090 \
  e2e-test-server \
  -config=/app/test-config.json
```

### Kubernetes Environment

Use ConfigMaps for configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: e2e-test-config
data:
  test-config.json: |
    {
      "name": "Kubernetes E2E Test Configuration",
      "scenarios": [...]
    }
```

Reference in deployment:

```yaml
spec:
  containers:
  - name: e2e-test-server
    args:
    - -config=/config/test-config.json
    volumeMounts:
    - name: config
      mountPath: /config
  volumes:
  - name: config
    configMap:
      name: e2e-test-config
```

## TLS and Certificate Configuration

### HTTPS Server (Self-Signed Certificate)

The HTTPS server automatically generates a self-signed certificate. No additional configuration is required:

```bash
./e2e-test-server -https-port=9443
```

Access with certificate verification disabled:

```bash
curl -k https://localhost:9443/health
```

### mTLS Server (Mutual TLS)

The mTLS server requires client certificates. Certificate paths are hardcoded relative to the proxy root:

- CA Certificate: `../../test/certs/ca-cert.pem`
- Server Certificate: `../../test/certs/server-cert.pem`
- Server Key: `../../test/certs/server-key.pem`

Start mTLS server:

```bash
./e2e-test-server -mtls-port=9444
```

Access with client certificate:

```bash
curl --cert client-cert.pem --key client-key.pem \
  --cacert ca-cert.pem \
  https://localhost:9444/health
```

### gRPC Server (HTTP/2 with TLS)

The gRPC server uses HTTP/2 over TLS with a self-signed certificate:

```bash
./e2e-test-server -grpc-port=8093
```

## IPv6 Configuration

### Bind to IPv6 Loopback

```bash
./e2e-test-server -bind="::1"
```

Access endpoints:
- `http://[::1]:8090`
- `https://[::1]:9443`
- `ws://[::1]:8091`

### Bind to All IPv6 Interfaces

```bash
./e2e-test-server -bind="::"
```

### Bind to Specific IPv6 Address

```bash
./e2e-test-server -bind="2001:db8::1"
```

Access endpoints:
- `http://[2001:db8::1]:8090`

### IPv4 Address

```bash
./e2e-test-server -bind="127.0.0.1"
```

### All Interfaces (Default)

If `-bind` is not specified, the server listens on all interfaces (both IPv4 and IPv6):

```bash
./e2e-test-server
```

## Port Configuration

### Default Ports

| Service | Default Port | Description |
|---------|--------------|-------------|
| HTTP | 8090 | Standard HTTP server |
| HTTPS | 9443 | HTTPS with self-signed cert |
| mTLS | 9444 | Mutual TLS server |
| WebSocket | 8091 | WebSocket server |
| GraphQL | 8092 | GraphQL endpoint |
| gRPC | 8093 | gRPC over HTTP/2 |
| MQTT | 8094 | MQTT over WebSocket |

### Custom Ports

```bash
./e2e-test-server \
  -http-port=8080 \
  -https-port=8443 \
  -ws-port=8081 \
  -graphql-port=8082 \
  -grpc-port=8083 \
  -mqtt-port=8084
```

### Port Conflicts

If a port is already in use, change it:

```bash
# Port 8090 is in use
./e2e-test-server -http-port=9090
```

### Firewall Considerations

Ensure ports are open in firewall rules:

```bash
# Linux (iptables)
sudo iptables -A INPUT -p tcp --dport 8090 -j ACCEPT

# macOS (pfctl)
# Edit /etc/pf.conf or use application firewall settings
```

## Configuration Validation

### JSON Schema Validation

Validate your configuration file before use:

```bash
# Using jq
jq . test-config.json > /dev/null && echo "Valid JSON"

# Using Python
python3 -m json.tool test-config.json > /dev/null && echo "Valid JSON"
```

### Server Validation

The server will log warnings for invalid configurations:

```bash
./e2e-test-server -config=invalid-config.json
# Warning: Could not load config file invalid-config.json: ...
# Using default configuration
```

### Required Fields Check

Ensure all required fields are present:

- Top-level: `name`, `scenarios`
- Scenario: `id`, `name`, `path`, `method`

## Best Practices

### 1. Organize Scenarios by Category

Use metadata to categorize scenarios:

```json
{
  "metadata": {
    "category": "auth",
    "subcategory": "bearer-token"
  }
}
```

### 2. Use Descriptive IDs

```json
{
  "id": "auth-bearer-token-success",
  "name": "Bearer Token Authentication - Success"
}
```

### 3. Set Default Headers

Use the `defaults` object for common headers:

```json
{
  "defaults": {
    "headers": {
      "X-Test-Server": "e2e-test-server",
      "X-Test-Version": "1.0"
    }
  }
}
```

### 4. Document Scenarios

Use the `description` field and `metadata` for documentation:

```json
{
  "description": "Tests bearer token authentication with valid token",
  "metadata": {
    "purpose": "Verify proxy correctly forwards Authorization header",
    "expected_behavior": "Returns 200 with user data"
  }
}
```

### 5. Version Control

Keep configuration files in version control:

```bash
git add test-config.json
git commit -m "Add test scenarios for authentication"
```

### 6. Environment-Specific Configs

Maintain separate configs for different environments:

- `test-config-dev.json` - Development scenarios
- `test-config-staging.json` - Staging scenarios
- `test-config-prod.json` - Production scenarios

### 7. Modular Configuration

Split large configurations into multiple files and combine:

```bash
# Combine multiple configs
jq -s '.[0] * {scenarios: [.[].scenarios[]]}' \
  config-auth.json \
  config-api.json \
  config-cache.json \
  > combined-config.json
```

## Troubleshooting

### Configuration Not Loading

**Problem:** Server uses default configuration instead of your file.

**Solutions:**
1. Check file path is correct
2. Verify file permissions
3. Validate JSON syntax
4. Check file path relative to working directory

```bash
# Verify file exists
ls -la test-config.json

# Check JSON validity
jq . test-config.json

# Use absolute path
./e2e-test-server -config=/absolute/path/to/test-config.json
```

### Scenarios Not Found

**Problem:** `/test/{scenario-id}` returns 404.

**Solutions:**
1. Verify scenario ID matches exactly
2. Check scenario is in `scenarios` array
3. Ensure JSON is properly formatted
4. Check server logs for loaded scenarios

```bash
# List all scenarios
curl http://localhost:8090/test/

# Check server logs
./e2e-test-server -config=test-config.json 2>&1 | grep "Loaded"
```

### Port Already in Use

**Problem:** Server fails to start with "address already in use".

**Solutions:**
1. Change port using command-line flags
2. Stop other service using the port
3. Check what's using the port

```bash
# Find process using port
lsof -i :8090

# Change port
./e2e-test-server -http-port=9090
```

### Invalid JSON

**Problem:** Server reports JSON parsing error.

**Solutions:**
1. Validate JSON syntax
2. Check for trailing commas
3. Verify all strings are quoted
4. Check for unclosed brackets/braces

```bash
# Validate JSON
jq . test-config.json

# Or use Python
python3 -m json.tool test-config.json
```

## Related Documentation

- [README.md](README.md) - General project documentation
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
- [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) - Migration from older versions
- Example configurations:
  - `test-config.json` - Standard scenarios
  - `test-config-comprehensive.json` - Comprehensive scenarios
  - `test-config-callbacks.json` - Callback and cache scenarios

