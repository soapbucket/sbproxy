# Operator quickstart: first 24 hours

This is the minimum production bring-up path for the OSS Kubernetes operator. Use
[`kubernetes.md`](kubernetes.md) for the full CRD and hot-reload reference after
the first deploy is healthy.

## 1. Deploy

Install the chart into its own namespace:

```bash
helm install sbproxy ./deploy/helm/sbproxy \
  --namespace sbproxy-system \
  --create-namespace \
  --set image.repository=ghcr.io/soapbucket/sbproxy-k8s-operator \
  --set image.tag=v1.1.0
```

For a single-node smoke check without the operator, run the data plane directly:

```bash
docker run --rm -p 8080:8080 -p 9090:9090 \
  -v "$PWD/sb.yml:/etc/sbproxy/sb.yml:ro" \
  ghcr.io/soapbucket/sbproxy:v1.1.0 \
  serve -f /etc/sbproxy/sb.yml
```

Create an `SBProxyConfig` and `SBProxy` after the chart is installed. The
operator reconciles them into a Deployment, Service, and ConfigMap.

## 2. Verify Readiness

Port-forward the proxy Service and check readiness:

```bash
kubectl port-forward svc/demo-svc 8080:8080 9090:9090
curl -fsS http://127.0.0.1:9090/readyz | jq .
```

Expected result: HTTP 200 with every required component reporting `ready`.
Optional integrations that are not configured should report `not_configured`,
not `stale` or `error`.

Component meanings:

- `ready`: the component is configured and has reported success recently.
- `not_configured`: the component is optional and disabled for this deployment.
- `stale`: the component was configured but has not reported success inside its freshness window.
- `error`: the component failed its latest readiness probe.

Use `/health` for the richer JSON payload with version, uptime, and readiness
checks. Use `/healthz` only as a simple liveness probe.

## 3. Scrape Metrics

Check the Prometheus endpoint:

```bash
curl -fsS http://127.0.0.1:9090/metrics | head
```

Import `dashboards/grafana/sbproxy-overview.json` into Grafana first. It gives
the first-day view: request rate, latency, error rate, active connections, and
origin health. Add `sbproxy-security.json`, `sbproxy-origins.json`, and
`sbproxy-ai-gateway.json` after the overview dashboard is green.

## 4. Tail Logs

Tail the operator and one proxy pod:

```bash
kubectl logs -n sbproxy-system deploy/sbproxy-operator -f
kubectl logs deploy/demo -f
```

A successful proxied request has a 2xx status and normal access-log fields such
as method, hostname, path, status, and duration. A denied request has a 4xx
status plus policy/auth context, for example `auth`, `rate_limit`, `waf`, or
`policy` fields depending on which layer made the decision.

If logs contain repeated readiness `stale` messages, check the matching
integration first. If logs contain config parse errors, the operator will keep
the last working Deployment while the bad config is corrected.

## 5. Roll Back

For Helm-managed operator changes:

```bash
helm history sbproxy -n sbproxy-system
helm rollback sbproxy <REVISION> -n sbproxy-system
```

For data-plane config changes, revert the `SBProxyConfig` manifest in Git and
apply it again:

```bash
kubectl apply -f sbproxyconfig.yaml
kubectl rollout status deploy/demo
```

If hot reload is enabled, the operator posts the new config to each pod without
restarting it. If hot reload fails or is disabled, it stamps a new config hash
on the Deployment and Kubernetes performs a rolling restart.
