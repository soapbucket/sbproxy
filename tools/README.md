# Proxy Tools

Command-line utilities for managing the proxy server.

## Available Tools

### 1. Config Loader (`config-loader/`)

**Purpose**: Load and manage origin configurations in the storage database.

**Features**:
- Load configurations from text files
- Auto-generate UUIDs for entries
- Upsert functionality (preserve UUIDs on updates)
- Delete by hostname or prefix
- Multi-database support (SQLite, PostgreSQL)
- Safety checks to prevent accidental data loss

**Quick Start**:
```bash
cd config-loader
go build -o config-loader
./config-loader -dsn 'sqlite:///tmp/config.db' -load configs.example.txt
```

**Documentation**: See [config-loader/README.md](config-loader/README.md)

### 2. CDB Generator (`cdbgen/`)

**Purpose**: Generate CDB (Constant Database) files from configuration data.

**Features**:
- Creates CDB files from text configurations
- Auto-generates UUIDs and injects into JSON
- Uses same input format as config-loader
- Read-only, high-performance storage
- Ideal for production deployments
- Atomic file replacement support

**Quick Start**:
```bash
cd cdbgen
go build
./cdbgen -input configs.example.txt -output configs.cdb
```

**Documentation**: See [cdbgen/README.md](cdbgen/README.md) | [Quick Start](cdbgen/QUICKSTART.md)

### 3. Crypto Tool (`crypto/`)

**Purpose**: Cryptographic key management utilities.

**Documentation**: See [crypto/README.md](crypto/README.md)

### 4. JWT Generator (`jwt-generator/`)

**Purpose**: Generate and manage JWT tokens for testing.

**Documentation**: See [jwt-generator/README.md](jwt-generator/README.md)

### 5. E2E Test Server (`e2e-test-server/`)

**Purpose**: Unified end-to-end testing server consolidating HTTP/HTTPS, WebSocket, GraphQL, and callback endpoints.

**Features**:
- **HTTP/HTTPS Server** - REST API, callback endpoints, test scenarios, TLS support
- **WebSocket Server** - Echo, timestamp streaming, broadcast messaging
- **GraphQL Server** - User and Post queries for testing
- **Test Configuration System** - JSON-based test scenarios with predictable responses
- **Response Validation** - Built-in validation helpers
- **Kubernetes Ready** - Complete manifests and automated test runner
- **Docker Support** - Production-ready containerization

**Consolidated from**:
- callback-test-server (session/auth callbacks)
- websocket-echo-server (WebSocket testing)
- graphql-test-server (GraphQL testing)
- tls-test-server (HTTPS/TLS variants)
- http3-test-server (HTTP/3 planned)

**Quick Start**:
```bash
cd e2e-test-server
./build.sh
./e2e-test-server

# In another terminal
./test.sh
```

**Ports**:
- HTTP: 8090
- HTTPS: 8443 (self-signed)
- WebSocket: 8091
- GraphQL: 8092

**Test Scenarios**:
```bash
# HTTP endpoint
curl http://localhost:8090/test/simple-200

# Session callback
curl -X POST http://localhost:8090/callback/session

# WebSocket echo
echo "test" | websocat ws://localhost:8091/echo

# GraphQL query
curl -X POST http://localhost:8092/graphql \
  -d '{"query": "{ users { name } }"}'
```

**Kubernetes Deployment**:
```bash
kubectl apply -f e2e-test-server/k8s/e2e-test-server.yaml
kubectl apply -f e2e-test-server/k8s/test-runner.yaml
```

**Documentation**: 
- See [e2e-test-server/README.md](e2e-test-server/README.md) for complete documentation
- See [e2e-test-server/QUICKSTART.md](e2e-test-server/QUICKSTART.md) for quick start guide
- See [e2e-test-server/CONSOLIDATION_SUMMARY.md](e2e-test-server/CONSOLIDATION_SUMMARY.md) for details on consolidation
- See [e2e-test-server/MIGRATION_GUIDE.md](e2e-test-server/MIGRATION_GUIDE.md) for migration from old test servers

### 6. Callback Test Server (`callback-test-server/`)

**Purpose**: Lightweight HTTP server for end-to-end testing of the proxy callback framework.

**Features**:
- **Standard callback** - Returns posted data as params
- **Configurable delays** - Simulate slow upstreams
- **ETag / Cache-Control** - Test HTTP-aware caching and conditional requests (304)
- **Error injection** - Configurable status codes and error rates
- **Large responses** - Test response size limits
- **Parallel testing** - Unique sequential responses for concurrency verification
- **Request echo** - Full request inspection
- **Stats endpoint** - Request counts and latency metrics

**Quick Start**:
```bash
cd callback-test-server
go build -o callback-test-server
./callback-test-server -port 9100 -verbose
```

**Endpoints**:
- `POST /callback` - Standard callback
- `POST /callback/slow?delay=500ms` - Delayed response
- `POST /callback/etag?max_age=300` - ETag + Cache-Control
- `POST /callback/error?status=500&rate=0.5` - Error injection
- `POST /callback/large?size=1048576` - Large response
- `POST /callback/parallel?delay=100ms` - Parallel testing
- `POST /callback/echo` - Request echo
- `GET /callback/health` - Health check
- `GET /callback/stats` - Request statistics

**Documentation**: See [callback-test-server/README.md](callback-test-server/README.md)

## Tool Overview

| Tool | Language | Purpose | Database/Storage |
|------|----------|---------|------------------|
| config-loader | Go | Origin config management | SQLite/PostgreSQL |
| cdbgen | Go | CDB file generation | CDB (read-only) |
| crypto | Go | Key management | N/A |
| jwt-generator | Go | JWT token generation | N/A |
| cert-pin-tool | Go | Certificate pinning | N/A |
| e2e-test-server | Go | Unified E2E testing server | N/A |
| callback-test-server | Go | Callback framework E2E testing | N/A |

**Note**: The e2e-test-server consolidates the functionality of the following previous test servers:
- callback-test-server
- websocket-echo-server  
- graphql-test-server
- tls-test-server
- http3-test-server (HTTP/3 support planned)

## Requirements

- Go 1.23 or later
- Docker (optional, for PostgreSQL testing)
- SQLite3 (optional, for database inspection)

## Getting Started

Each tool has its own directory with:
- Source code
- README.md with documentation
- Example files
- Test scripts

Navigate to the tool directory and follow its README for specific instructions.

## Development

### Building All Tools

```bash
cd /Users/rick/projects/proxy/tools
for tool in */; do
  if [ -f "$tool/main.go" ]; then
    echo "Building $tool..."
    (cd "$tool" && go build)
  fi
done
```

### Testing

Each tool includes test scripts:
- `test-*.sh` - Automated tests
- `*-demo.sh` - Interactive demos

## Integration

These tools integrate with the proxy's internal packages:
- `lib/storage` - Database access
- `lib/crypto` - Cryptographic operations
- `internal/logger` - Logging functionality

## Secrets Testing

For local/test secrets without cloud infrastructure, use the `file` vault provider.
Configure a vault with `"type": "file"` and `"address"` pointing to a JSON or YAML
file containing key-value pairs. Use the `crypto` tool to generate encryption keys
and encrypt values if needed (set the key in the vault's `"credentials"` field).

## Contributing

When adding new tools:
1. Create a new directory under `tools/`
2. Include a comprehensive README.md
3. Add example files and test scripts
4. Update this README.md with tool information
5. Follow the existing structure and patterns

## License

Copyright 2026 Soap Bucket LLC. All rights reserved. Proprietary and confidential.

