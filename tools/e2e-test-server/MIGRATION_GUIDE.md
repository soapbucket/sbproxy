# Migration Guide: Old Test Servers → E2E Test Server

This guide helps you migrate from the individual test servers to the new unified E2E Test Server.

## Quick Migration Matrix

| Old Server | Old Port | New Port | Migration Status |
|------------|----------|----------|------------------|
| callback-test-server | 9999 | 8090 (HTTP) | ✅ Direct replacement |
| websocket-echo-server | 8081 | 8091 (WS) | ✅ Direct replacement |
| graphql-test-server | 8082 | 8092 (GraphQL) | ✅ Direct replacement |
| tls-test-server | 9001-9004 | 9443 (HTTPS) | ✅ TLS consolidated (port changed from 8443 to avoid proxy conflict) |
| http3-test-server | 4433 | Future | ⚠️ HTTP/3 to be added |

## Step-by-Step Migration

### 1. Install E2E Test Server

```bash
cd /Users/rick/projects/proxy/tools/e2e-test-server
./build.sh
```

### 2. Update Your Scripts

#### From callback-test-server

**Old:**
```bash
cd tools/callback-test-server
go run main.go
# Server on http://localhost:9999
```

**New:**
```bash
cd tools/e2e-test-server
./e2e-test-server
# Server on http://localhost:8090
```

**Update URLs:**
```bash
# Old
curl http://localhost:9999/session/init
curl http://localhost:9999/auth/enrich

# New
curl http://localhost:8090/callback/session
curl http://localhost:8090/callback/auth
```

#### From websocket-echo-server

**Old:**
```bash
cd tools/websocket-echo-server
go run main.go -addr=:8081
# Server on ws://localhost:8081
```

**New:**
```bash
cd tools/e2e-test-server
./e2e-test-server -ws-port=8081
# Server on ws://localhost:8091 (or 8081 if specified)
```

**Update URLs:**
```bash
# Old
websocat ws://localhost:8081/echo

# New (default port)
websocat ws://localhost:8091/echo

# New (compatible port)
./e2e-test-server -ws-port=8081
websocat ws://localhost:8081/echo
```

#### From graphql-test-server

**Old:**
```bash
cd tools/graphql-test-server
go run main.go -addr=:8082
# Server on http://localhost:8082
```

**New:**
```bash
cd tools/e2e-test-server
./e2e-test-server -graphql-port=8082
# Server on http://localhost:8092 (or 8082 if specified)
```

**Update URLs:**
```bash
# Old
curl -X POST http://localhost:8082/graphql \
  -d '{"query": "{ users { name } }"}'

# New (default port)
curl -X POST http://localhost:8092/graphql \
  -d '{"query": "{ users { name } }"}'

# New (compatible port)
./e2e-test-server -graphql-port=8082
curl -X POST http://localhost:8082/graphql \
  -d '{"query": "{ users { name } }"}'
```

#### From tls-test-server

**Old:**
```bash
cd tools/tls-test-server
go run main.go
# Multiple servers on ports 9001-9004
```

**New:**
```bash
cd tools/e2e-test-server
./e2e-test-server
# HTTPS server on https://localhost:8443
```

**Update URLs:**
```bash
# Old - self-signed HTTPS
curl -k https://localhost:9002/test

# New - self-signed HTTPS
curl -k https://localhost:8443/health
curl -k https://localhost:8443/test/simple-200
```

### 3. Update Proxy Configurations

#### Callback Configuration

**Old proxy config:**
```json
{
  "session": {
    "callbacks": [
      {"url": "http://localhost:9999/session/init"}
    ]
  },
  "authorization": {
    "jwt": {
      "authentication_callback": {
        "url": "http://localhost:9999/auth/enrich"
      }
    }
  }
}
```

**New proxy config:**
```json
{
  "session": {
    "callbacks": [
      {"url": "http://localhost:8090/callback/session"}
    ]
  },
  "authorization": {
    "jwt": {
      "authentication_callback": {
        "url": "http://localhost:8090/callback/auth"
      }
    }
  }
}
```

#### Origin Configuration

**Old proxy config:**
```json
{
  "origins": [
    {
      "id": "ws-test",
      "hostname": "ws.test.local",
      "action": {
        "type": "websocket",
        "url": "ws://localhost:8081"
      }
    },
    {
      "id": "graphql-test",
      "hostname": "graphql.test.local",
      "action": {
        "type": "proxy",
        "url": "http://localhost:8082"
      }
    }
  ]
}
```

**New proxy config:**
```json
{
  "origins": [
    {
      "id": "e2e-test-http",
      "hostname": "test.local",
      "action": {
        "type": "proxy",
        "url": "http://localhost:8090"
      }
    },
    {
      "id": "e2e-test-ws",
      "hostname": "ws.test.local",
      "action": {
        "type": "websocket",
        "url": "ws://localhost:8091"
      }
    },
    {
      "id": "e2e-test-graphql",
      "hostname": "graphql.test.local",
      "action": {
        "type": "proxy",
        "url": "http://localhost:8092"
      }
    }
  ]
}
```

### 4. Update Test Scripts

**Old test script:**
```bash
#!/bin/bash

# Start servers
(cd tools/callback-test-server && go run main.go) &
(cd tools/websocket-echo-server && go run main.go) &
(cd tools/graphql-test-server && go run main.go) &

# Wait for startup
sleep 3

# Run tests
curl http://localhost:9999/health
curl http://localhost:8081/health
curl http://localhost:8082/health

# Cleanup
pkill -f callback-test-server
pkill -f websocket-echo-server
pkill -f graphql-test-server
```

**New test script:**
```bash
#!/bin/bash

# Start single server
cd tools/e2e-test-server
./e2e-test-server &
PID=$!

# Wait for startup
sleep 2

# Run tests
./test.sh

# Cleanup
kill $PID
```

### 5. Update Docker Compose

**Old docker-compose.yml:**
```yaml
services:
  callback-server:
    build: ./tools/callback-test-server
    ports:
      - "9999:9999"
  
  websocket-server:
    build: ./tools/websocket-echo-server
    ports:
      - "8081:8081"
  
  graphql-server:
    build: ./tools/graphql-test-server
    ports:
      - "8082:8082"
```

**New docker-compose.yml:**
```yaml
services:
  e2e-test-server:
    build: ./tools/e2e-test-server
    ports:
      - "8090:8090"  # HTTP
      - "8443:8443"  # HTTPS
      - "8091:8091"  # WebSocket
      - "8092:8092"  # GraphQL
    volumes:
      - ./test-config.json:/root/test-config.json
```

### 6. Update Kubernetes

**Old k8s deployment:**
```yaml
# Multiple deployments
apiVersion: apps/v1
kind: Deployment
metadata:
  name: callback-server
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: websocket-server
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: graphql-server
```

**New k8s deployment:**
```yaml
# Single deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: e2e-test-server
spec:
  template:
    spec:
      containers:
      - name: e2e-test-server
        image: e2e-test-server:latest
        ports:
        - containerPort: 8090  # HTTP
        - containerPort: 8443  # HTTPS
        - containerPort: 8091  # WebSocket
        - containerPort: 8092  # GraphQL
```

See `k8s/e2e-test-server.yaml` for complete example.

## Feature Mapping

### Callback Features

| Old Endpoint | New Endpoint | Notes |
|--------------|--------------|-------|
| `/session/init` | `/callback/session` | Same response format |
| `/auth/enrich` | `/callback/auth` | Same response format |
| `/auth/roles` | `/callback/auth` | Use admin@example.com |
| `/validate` | `/validate` | Enhanced validation |

### WebSocket Features

| Old Endpoint | New Endpoint | Notes |
|--------------|--------------|-------|
| `/echo` | `/echo` | Same behavior |
| `/timestamp` | `/timestamp` | Same behavior |
| `/broadcast` | `/broadcast` | Same behavior |
| - | `/test/{id}` | New: scenario support |

### GraphQL Features

| Old Feature | New Feature | Notes |
|-------------|-------------|-------|
| Users query | Users query | Same data |
| Posts query | Posts query | Same data |
| Mutations | Not included | Simple read-only for now |

## Advantages of New Server

### Unified Management
- ✅ Single server to start/stop
- ✅ One configuration file
- ✅ Consistent logging
- ✅ Easier debugging

### Test Scenarios
- ✅ JSON-based test definitions
- ✅ Predictable responses
- ✅ Easy to add new scenarios
- ✅ Response validation built-in

### Better Operations
- ✅ Single Docker image
- ✅ Simplified Kubernetes deployment
- ✅ Automated test runner
- ✅ Health checks included

## Compatibility Mode

To run with old ports for compatibility:

```bash
./e2e-test-server \
  -http-port=9999 \
  -ws-port=8081 \
  -graphql-port=8082
```

This makes the new server respond on the same ports as the old servers.

## Gradual Migration

### Phase 1: Parallel Running
Run both old and new servers side-by-side:

```bash
# Terminal 1 - Old servers
(cd tools/callback-test-server && go run main.go) &

# Terminal 2 - New server  
(cd tools/e2e-test-server && ./e2e-test-server)

# Test both
curl http://localhost:9999/health  # Old
curl http://localhost:8090/health  # New
```

### Phase 2: Switch Tests
Update test scripts to use new server, but keep old servers running.

### Phase 3: Full Migration
Stop old servers, use only new server.

### Phase 4: Cleanup
Archive old server code.

## Troubleshooting

### Port Conflicts

**Problem:** Port already in use

**Solution:**
```bash
# Use different ports
./e2e-test-server \
  -http-port=9090 \
  -https-port=9443 \
  -ws-port=9091 \
  -graphql-port=9092
```

### Different Response Format

**Problem:** Response format changed

**Solution:** Check scenario configuration in `test-config.json`. You can customize responses:

```json
{
  "scenarios": [
    {
      "id": "my-test",
      "response": {
        "body": {
          "custom": "format"
        }
      }
    }
  ]
}
```

### Missing Features

**Problem:** Feature from old server not available

**Solutions:**
1. Check if feature is in comprehensive config: `test-config-comprehensive.json`
2. Add custom scenario to your config file
3. Submit feature request or PR

## Testing Migration

Verify migration was successful:

```bash
# 1. Start new server
./e2e-test-server

# 2. Run test suite
./test.sh

# 3. Test all endpoints
curl http://localhost:8090/health
curl http://localhost:8090/callback/session
curl -X POST http://localhost:8092/graphql -d '{"query":"{ users { name } }"}'
websocat ws://localhost:8091/echo

# 4. Check all tests pass
# Expected: ✅ All tests passed!
```

## Rollback Plan

If you need to rollback to old servers:

```bash
# Stop new server
pkill e2e-test-server

# Start old servers
(cd tools/callback-test-server && go run main.go) &
(cd tools/websocket-echo-server && go run main.go) &
(cd tools/graphql-test-server && go run main.go) &
```

## Support

For migration issues:
1. Check this guide
2. Review [CONSOLIDATION_SUMMARY.md](CONSOLIDATION_SUMMARY.md)
3. Check example configs in `k8s/` directory
4. Open an issue with details

## Checklist

Use this checklist for migration:

- [ ] Build new e2e-test-server
- [ ] Test new server locally
- [ ] Update proxy configuration files
- [ ] Update test scripts
- [ ] Update Docker configurations
- [ ] Update Kubernetes manifests
- [ ] Update CI/CD pipelines
- [ ] Test end-to-end flow
- [ ] Document any customizations
- [ ] Archive old servers
- [ ] Update team documentation

## Timeline Recommendation

- **Week 1:** Test new server in development
- **Week 2:** Run parallel with old servers
- **Week 3:** Switch tests to new server
- **Week 4:** Full migration, archive old servers

## Questions?

Check the documentation:
- [README.md](README.md) - Full documentation
- [QUICKSTART.md](QUICKSTART.md) - Quick start
- [CONSOLIDATION_SUMMARY.md](CONSOLIDATION_SUMMARY.md) - What changed
- `k8s/README.md` - Kubernetes guide

