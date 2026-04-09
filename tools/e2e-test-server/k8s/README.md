# Kubernetes Deployment for E2E Test Server

This directory contains Kubernetes manifests for deploying the E2E Test Server and Proxy for end-to-end testing.

## Prerequisites

- Kubernetes cluster (local or remote)
- `kubectl` configured
- Docker images built and available

## Build Docker Images

```bash
# Build E2E Test Server image
cd /Users/rick/projects/proxy/tools/e2e-test-server
./docker-build.sh

# Build Proxy image
cd /Users/rick/projects/proxy
docker build -t proxy:latest .
```

## Deploy

### 1. Deploy E2E Test Server

```bash
kubectl apply -f e2e-test-server.yaml
```

This creates:
- ConfigMap with test configuration
- Deployment with 2 replicas
- Service (ClusterIP)
- Headless service for direct pod access

### 2. Deploy Proxy with Test Configuration

```bash
kubectl apply -f proxy-test-config.yaml
```

This creates:
- ConfigMap with proxy test configuration
- Deployment with 2 replicas
- Service (ClusterIP)

### 3. Run Tests

```bash
# One-time test run
kubectl apply -f test-runner.yaml

# Check test results
kubectl logs job/e2e-test-runner

# For continuous testing (CronJob runs every 30 minutes)
kubectl get cronjobs
kubectl logs -l app=test-runner
```

## Verify Deployment

```bash
# Check pods
kubectl get pods -l app=e2e-test-server
kubectl get pods -l app=proxy-test

# Check services
kubectl get svc e2e-test-server
kubectl get svc proxy-test

# Test from within cluster
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://e2e-test-server/health
```

## Manual Testing

### Port Forward to Test Server

```bash
kubectl port-forward svc/e2e-test-server 8090:80

# In another terminal
curl http://localhost:8090/health
curl http://localhost:8090/test/simple-200
```

### Port Forward to Proxy

```bash
kubectl port-forward svc/proxy-test 8080:80

# In another terminal
curl -H "Host: test.local" http://localhost:8080/test/simple-200
```

## Configuration

### Custom Test Configuration

Edit the ConfigMap in `e2e-test-server.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: e2e-test-config
data:
  test-config.json: |
    {
      "name": "My Custom Tests",
      "scenarios": [
        {
          "id": "my-test",
          "name": "My Test",
          "path": "/test/my-test",
          "method": "GET",
          "response": {
            "status": 200,
            "body": {"status": "success"}
          }
        }
      ]
    }
```

Then apply:

```bash
kubectl apply -f e2e-test-server.yaml
kubectl rollout restart deployment/e2e-test-server
```

### Custom Proxy Configuration

Edit the ConfigMap in `proxy-test-config.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: proxy-test-config
data:
  proxy-config.json: |
    {
      "origins": [
        {
          "id": "my-origin",
          "hostname": "my.test.local",
          "action": {
            "type": "proxy",
            "url": "http://e2e-test-server"
          }
        }
      ]
    }
```

Then apply:

```bash
kubectl apply -f proxy-test-config.yaml
kubectl rollout restart deployment/proxy-test
```

## Scaling

```bash
# Scale E2E Test Server
kubectl scale deployment/e2e-test-server --replicas=5

# Scale Proxy
kubectl scale deployment/proxy-test --replicas=5

# Autoscaling
kubectl autoscale deployment/e2e-test-server --min=2 --max=10 --cpu-percent=80
kubectl autoscale deployment/proxy-test --min=2 --max=10 --cpu-percent=80
```

## Monitoring

```bash
# Watch pods
kubectl get pods -w

# Logs from E2E Test Server
kubectl logs -f deployment/e2e-test-server

# Logs from Proxy
kubectl logs -f deployment/proxy-test

# Logs from test runner
kubectl logs -f job/e2e-test-runner

# Get test results from CronJob
kubectl get jobs -l app=test-runner
kubectl logs -l app=test-runner --tail=100
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl describe pod <pod-name>

# Check events
kubectl get events --sort-by='.lastTimestamp'
```

### Service Not Reachable

```bash
# Check service endpoints
kubectl get endpoints e2e-test-server
kubectl get endpoints proxy-test

# Test from debug pod
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl -v http://e2e-test-server/health
```

### Tests Failing

```bash
# Check test runner logs
kubectl logs job/e2e-test-runner

# Run tests manually
kubectl run -it --rm test-debug --image=curlimages/curl --restart=Never -- sh
# Then inside the pod:
curl http://e2e-test-server/health
curl http://proxy-test/health
```

### Configuration Not Applied

```bash
# Verify ConfigMaps
kubectl get configmap e2e-test-config -o yaml
kubectl get configmap proxy-test-config -o yaml

# Restart deployments to pick up new config
kubectl rollout restart deployment/e2e-test-server
kubectl rollout restart deployment/proxy-test
```

## Cleanup

```bash
# Delete all resources
kubectl delete -f test-runner.yaml
kubectl delete -f proxy-test-config.yaml
kubectl delete -f e2e-test-server.yaml

# Or delete by label
kubectl delete all -l app=e2e-test-server
kubectl delete all -l app=proxy-test
kubectl delete all -l app=test-runner
```

## Production Considerations

For production-like testing:

1. **Resource Limits**: Adjust resource requests/limits based on load
2. **Persistent Storage**: Add PVCs if needed for test data
3. **Network Policies**: Add NetworkPolicies to control traffic
4. **Ingress**: Add Ingress resources for external access
5. **TLS**: Use cert-manager for proper TLS certificates
6. **Monitoring**: Add Prometheus ServiceMonitor resources
7. **Logging**: Configure log aggregation (e.g., ELK, Loki)

Example Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: proxy-test-ingress
spec:
  rules:
  - host: test.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: proxy-test
            port:
              number: 80
```

## CI/CD Integration

Use in CI/CD pipelines:

```bash
# Deploy
kubectl apply -f k8s/

# Wait for rollout
kubectl rollout status deployment/e2e-test-server
kubectl rollout status deployment/proxy-test

# Run tests
kubectl apply -f k8s/test-runner.yaml
kubectl wait --for=condition=complete --timeout=300s job/e2e-test-runner

# Get results
kubectl logs job/e2e-test-runner

# Cleanup
kubectl delete -f k8s/
```

