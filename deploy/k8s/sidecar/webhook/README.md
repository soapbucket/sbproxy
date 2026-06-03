# Sidecar injection webhook (starting point)

Automatic sidecar injection in Kubernetes is a
`MutatingWebhookConfiguration` that intercepts pod creates and
patches in the sidecar containers. This directory is a starting
point, **not** a production-ready package: you need to provide
the webhook endpoint host and a TLS bundle the API server
trusts.

## What's here

* `mutatingwebhookconfiguration.yaml` - the webhook config that
  wires Kubernetes to call your endpoint on every pod create in
  namespaces labelled `sbproxy.dev/inject=enabled`.
* `webhook-deployment.yaml` - a placeholder Deployment for the
  webhook handler itself. The container image is a stub; replace
  with the handler you operate.
* `service.yaml` - the ClusterIP Service that fronts the webhook
  pods.

## What you must supply

1. **Webhook handler code**. The handler receives an
   `AdmissionReview`, patches the pod with the same containers
   the base kustomization installs, and returns the patched
   review. The patch payload is the contents of
   `deploy/k8s/sidecar/base/sidecar-patch.yaml` expressed as a
   JSON Patch.
2. **TLS material**. The API server validates the webhook with
   the CA bundle in `caBundle:`. Generate this via cert-manager
   with an `Issuer` of your choice, or roll a static cert and
   inline the base64-encoded CA.
3. **Namespace label**. Apply
   `kubectl label namespace <ns> sbproxy.dev/inject=enabled`
   on each namespace where the injection should fire.

## Alternatives

For most teams the explicit kustomize overlay at
`deploy/k8s/sidecar/base/` is the right starting point: it is
declarative, reviewable, and doesn't require operating a
webhook. Reach for the webhook once you have many workloads to
keep in sync and the patch contents are stable.
