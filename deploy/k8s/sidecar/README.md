# sbproxy sidecar deployment

Kustomize overlays and sample manifests for running sbproxy as a
**sidecar** on workload pods.

See [docs/sidecar-deployment.md](../../../docs/sidecar-deployment.md)
for the full operator guide: when to pick this shape over the
gateway / operator install, traffic capture options, telemetry
shape, identity, and failure modes.

## Layout

```
deploy/k8s/sidecar/
  base/         - kustomize base: ConfigMap + pod-template sidecar patch
  example/      - end-to-end worked example: client pod + sidecar + scrape
  istio/        - notes for layering on top of Istio sidecar injection
  webhook/      - mutating-webhook starting point (TLS + hosting are yours)
```

## Quick start (no service mesh, local kind cluster)

```bash
kind create cluster
kubectl apply -k deploy/k8s/sidecar/example/
kubectl wait --for=condition=Ready pod/agent-pod --timeout=60s
kubectl port-forward pod/agent-pod 15002:15002
curl -s http://127.0.0.1:15002/metrics | grep -i sbproxy
```

## Adapting to your workload

1. Copy `base/` into your repo as a kustomize component.
2. Replace the `sb.yml` ConfigMap with your sidecar-tuned config.
   The annotated starting point is at
   [`examples/sidecar/sb.yml`](../../../examples/sidecar/sb.yml).
3. Patch your workload Deployment to include the
   `sbproxy-init` init container and the `sbproxy` container
   (see `base/sidecar-patch.yaml`).
4. Restart the workload; the redirect rules are installed on
   each pod start.

## What this does not include

* **Automatic injection.** The kustomize overlay is explicit
  patching. A mutating webhook for automatic injection is at
  `webhook/`; production use requires you to host the webhook
  endpoint and provision its TLS.
* **SPIFFE identity.** The sidecar inherits the pod's
  service-account token by default. Binding the sidecar's
  identity to a SPIRE-issued SVID is a separate workstream.
* **Helm packaging.** The existing chart at
  `deploy/helm/sbproxy/` is operator-only; sidecar use is via
  kustomize today.
