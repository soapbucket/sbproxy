# E2E Test Server - Quick Start Guide

Get up and running with the E2E Test Server in 5 minutes.

## Installation

```bash
cd /Users/rick/projects/proxy/tools/e2e-test-server
./build.sh
```

## Start the Server

```bash
./e2e-test-server
```

You should see:
```
🚀 E2E Test Server Suite Started
📝 Test Config: E2E Test Configuration
   HTTP:      http://localhost:8090
   HTTPS:     https://localhost:8443 (self-signed)
   WebSocket: ws://localhost:8091
   GraphQL:   http://localhost:8092

📋 Loaded 12 test scenarios
```

## Test It Works

In another terminal:

```bash
# Test HTTP endpoint
curl http://localhost:8090/health

# Test a scenario
curl http://localhost:8090/test/simple-200

# Test session callback
curl -X POST http://localhost:8090/callback/session

# Test GraphQL
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { name } }"}'

# Test WebSocket (requires websocat: brew install websocat)
echo "test" | websocat ws://localhost:8091/echo
```

## Run Test Suite

```bash
./test.sh
```

This runs all automated tests and shows pass/fail results.

## Using with Proxy

### 1. Create Proxy Test Config

Create `/tmp/proxy-test.json`:

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

### 2. Start Proxy with Test Config

```bash
cd /Users/rick/projects/proxy
go run main.go serve --config /tmp/proxy-test.json
```

### 3. Test Through Proxy

```bash
curl -H "Host: test.local" http://localhost:8080/test/simple-200
```

## Custom Test Scenarios

Edit `test-config.json` to add your own scenarios:

```json
{
  "scenarios": [
    {
      "id": "my-test",
      "name": "My Custom Test",
      "path": "/test/my-test",
      "method": "GET",
      "response": {
        "status": 200,
        "body": {
          "status": "success",
          "message": "My custom response"
        }
      }
    }
  ]
}
```

Restart the server and test:

```bash
curl http://localhost:8090/test/my-test
```

## Docker

### Build Docker Image

```bash
./docker-build.sh
```

### Run in Docker

```bash
docker run -p 8090:8090 -p 8443:8443 -p 8091:8091 -p 8092:8092 e2e-test-server:latest
```

## Kubernetes

### Deploy to Kubernetes

```bash
# Build and load images
./docker-build.sh
kind load docker-image e2e-test-server:latest  # if using kind

# Deploy
kubectl apply -f k8s/e2e-test-server.yaml

# Run tests
kubectl apply -f k8s/test-runner.yaml
kubectl logs job/e2e-test-runner
```

See `k8s/README.md` for detailed Kubernetes documentation.

## Common Use Cases

### 1. Test Proxy Authentication

```bash
# Server returns auth callback data
curl -X POST http://localhost:8090/callback/auth \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com"}'
```

### 2. Test Proxy Session Management

```bash
# Server returns session data
curl -X POST http://localhost:8090/callback/session
```

### 3. Test Error Handling

```bash
# Test various error codes
curl http://localhost:8090/test/not-found          # 404
curl http://localhost:8090/test/error-500          # 500
curl http://localhost:8090/test/rate-limited       # 429
```

### 4. Test Response Delays

```bash
# Test timeout handling
curl http://localhost:8090/api/delay?ms=2000
```

### 5. Test Custom Headers

```bash
# Response includes custom headers
curl -i http://localhost:8090/test/custom-headers
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore `test-config-comprehensive.json` for more examples
- Set up Kubernetes testing with `k8s/README.md`
- Integrate with your CI/CD pipeline

## Troubleshooting

**Port already in use?**
```bash
./e2e-test-server -http-port=9090 -https-port=9443
```

**Can't connect to server?**
```bash
# Check if server is running
curl http://localhost:8090/health

# Check logs for errors
./e2e-test-server  # logs to stdout
```

**Tests failing?**
```bash
# Run with verbose output
./test.sh 2>&1 | tee test-output.log
```

## Support

For issues or questions, see the main [README.md](README.md) or check the project documentation.

