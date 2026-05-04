#!/usr/bin/env bash
# CI-friendly smoke test for the sbproxy OSS Kubernetes operator.
#
# Verifies four acceptance items end to end:
#   1. helm install brings the proxy Deployment up to Available.
#   2. The proxy serves traffic through its Service.
#   3. Hot-reload of an SBProxyConfig (with adminAuthSecretRef set) does not
#      restart the proxy pod (pod identity + restart count unchanged).
#      Without adminAuthSecretRef the rollout-restart fallback bumps the
#      Deployment's config-hash annotation.
#   4. Leader election: scaling the operator to 2 replicas, killing the
#      leader pod, brings up a new leader within 30s.
#
# Idempotent: every kubectl/helm command is safe to re-run. Re-running the
# script against an existing kind cluster reuses it; pass NO_CLEANUP=1 to
# leave the cluster up after success.
#
# Requirements: kind, helm, kubectl, curl. The CI workflow loads
# `sbproxy:ci` and `sbproxy-operator:ci` images into the kind cluster
# before invoking this script; locally, override with environment vars.
#
# Usage:
#   bash deploy/helm/sbproxy/test/smoke.sh
#
# Environment overrides:
#   CLUSTER_NAME           kind cluster name. Default: sbproxy-smoke.
#   NAMESPACE              operator namespace. Default: sbproxy-system.
#   SAMPLE_NS              namespace for the SBProxy CR. Default: default.
#   PROXY_IMAGE            proxy image. Default: sbproxy:ci (CI-loaded).
#   OPERATOR_IMAGE         operator image. Default: sbproxy-operator:ci.
#   SKIP_KIND_CREATE       set to 1 if a kind cluster is already up.
#   NO_CLEANUP             set to 1 to leave the cluster up on success.

set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-sbproxy-smoke}"
NAMESPACE="${NAMESPACE:-sbproxy-system}"
SAMPLE_NS="${SAMPLE_NS:-default}"
PROXY_IMAGE="${PROXY_IMAGE:-sbproxy:ci}"
OPERATOR_IMAGE="${OPERATOR_IMAGE:-sbproxy-operator:ci}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
CHART_DIR="$ROOT_DIR/deploy/helm/sbproxy"
EXAMPLES_DIR="$ROOT_DIR/deploy/examples"

log()  { printf '\n>> %s\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ "${NO_CLEANUP:-0}" == "1" ]]; then
    log "NO_CLEANUP=1; leaving kind cluster $CLUSTER_NAME up"
    return
  fi
  if [[ "${SKIP_KIND_CREATE:-0}" == "1" ]]; then
    # Caller manages the cluster lifecycle.
    return
  fi
  log "tearing down kind cluster $CLUSTER_NAME"
  kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- 0. Cluster bring-up (idempotent) ---

if [[ "${SKIP_KIND_CREATE:-0}" != "1" ]]; then
  if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "kind cluster $CLUSTER_NAME already exists; reusing"
  else
    log "creating kind cluster $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME" --wait 60s
  fi
fi

# --- 1. helm install (or upgrade) ---

OPERATOR_REPO="${OPERATOR_IMAGE%:*}"
OPERATOR_TAG="${OPERATOR_IMAGE##*:}"
PROXY_REPO="${PROXY_IMAGE%:*}"
PROXY_TAG="${PROXY_IMAGE##*:}"

log "installing chart from $CHART_DIR (operator=$OPERATOR_IMAGE)"
helm upgrade --install sbproxy "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --set "image.repository=$OPERATOR_REPO" \
  --set "image.tag=$OPERATOR_TAG" \
  --set "image.pullPolicy=IfNotPresent" \
  --wait --timeout 180s

# --- 2. Apply sample SBProxyConfig + SBProxy ---

log "applying sample SBProxyConfig + SBProxy"
kubectl apply -f "$EXAMPLES_DIR/sample-sbproxyconfig.yaml"

# Patch the sample SBProxy to use the CI-loaded proxy image instead of the
# pinned ghcr release tag, so the kind node never has to pull from a remote
# registry. The patch is a no-op when PROXY_IMAGE is already the default.
kubectl apply -f "$EXAMPLES_DIR/sample-sbproxy.yaml"
kubectl patch sbproxy demo -n "$SAMPLE_NS" --type=merge \
  -p "{\"spec\":{\"image\":\"$PROXY_IMAGE\"}}"

# --- 3. Wait for the proxy Deployment to come up ---

log "waiting for proxy Deployment demo-proxy to become Available"
kubectl wait deployment/demo-proxy \
  --namespace "$SAMPLE_NS" \
  --for=condition=Available \
  --timeout=180s \
  || fail "demo-proxy did not become Available within 180s"

# --- 4. Smoke check the Service ---

log "port-forward + curl smoke check on demo-svc"
PF_LOG="$(mktemp -t sbproxy-pf.XXXXXX)"
PF_OUT="$(mktemp -t sbproxy-out.XXXXXX)"
kubectl port-forward --namespace "$SAMPLE_NS" svc/demo-svc 18080:8080 \
  >"$PF_LOG" 2>&1 &
PF_PID=$!

# Give port-forward a moment to bind. We retry the curl up to 5 times so
# we don't depend on a fixed sleep duration.
for _ in 1 2 3 4 5; do
  if curl --fail --silent --max-time 5 http://127.0.0.1:18080/ >"$PF_OUT" 2>&1; then
    break
  fi
  sleep 1
done

if ! curl --fail --silent --max-time 5 http://127.0.0.1:18080/ >"$PF_OUT" 2>&1; then
  cat "$PF_LOG"
  kill "$PF_PID" 2>/dev/null || true
  fail "proxy did not respond on port 18080"
fi
kill "$PF_PID" 2>/dev/null || true
log "proxy responded with: $(head -c 80 "$PF_OUT")"

# --- 5. Hot-reload / rollout-restart verification ---
#
# The hot-reload path (adminAuthSecretRef set) preserves pod identity and
# restart count. The rollout-restart fallback bumps the config-hash on the
# Deployment's pod template instead. The sample SBProxy ships without an
# adminAuthSecretRef, so this exercise covers the rollout-restart path by
# default; if a CI job pre-populates the secret + sets the ref before
# running this script, the script will detect that and assert the
# hot-reload acceptance instead.

log "capturing pre-update pod identity + Deployment hash"
ORIGINAL_POD_NAME=$(kubectl get pods -n "$SAMPLE_NS" \
  -l app.kubernetes.io/instance=demo \
  -o jsonpath='{.items[0].metadata.name}')
ORIGINAL_RESTART_COUNT=$(kubectl get pod "$ORIGINAL_POD_NAME" -n "$SAMPLE_NS" \
  -o jsonpath='{.status.containerStatuses[0].restartCount}')
ORIGINAL_HASH=$(kubectl get deployment demo-proxy -n "$SAMPLE_NS" \
  -o jsonpath='{.spec.template.metadata.annotations.sbproxy\.dev/config-hash}')
HAS_ADMIN_SECRET=$(kubectl get sbproxy demo -n "$SAMPLE_NS" \
  -o jsonpath='{.spec.adminAuthSecretRef.name}')

log "patching SBProxyConfig to trigger reload"
kubectl patch sbproxyconfig demo-config -n "$SAMPLE_NS" --type=merge \
  -p '{"spec":{"config":"origins:\n  - host: \"*\"\n    action:\n      type: mock\n      status: 200\n      body: \"updated\"\n"}}'

if [[ -n "$HAS_ADMIN_SECRET" ]]; then
  log "hot-reload path: verifying pod $ORIGINAL_POD_NAME was not restarted"
  # 6s is generous: the operator's reconcile loop runs immediately on the
  # SBProxyConfig change watch.
  sleep 6
  CURRENT_POD_NAME=$(kubectl get pods -n "$SAMPLE_NS" \
    -l app.kubernetes.io/instance=demo \
    -o jsonpath='{.items[0].metadata.name}')
  CURRENT_RESTART_COUNT=$(kubectl get pod "$CURRENT_POD_NAME" -n "$SAMPLE_NS" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")
  if [[ "$CURRENT_POD_NAME" != "$ORIGINAL_POD_NAME" ]]; then
    fail "pod was replaced ($ORIGINAL_POD_NAME -> $CURRENT_POD_NAME); expected hot-reload to preserve pod identity"
  fi
  if [[ "$CURRENT_RESTART_COUNT" != "$ORIGINAL_RESTART_COUNT" ]]; then
    fail "pod restart count changed ($ORIGINAL_RESTART_COUNT -> $CURRENT_RESTART_COUNT); expected hot-reload to leave the container running"
  fi
  log "hot-reload preserved pod $CURRENT_POD_NAME (restart count $CURRENT_RESTART_COUNT)"
else
  log "rollout-restart path: waiting for config-hash annotation to change"
  # kubectl wait does not have a generic "field changed" predicate, so we
  # poll the annotation. Bound the wait at 60s.
  for _ in $(seq 1 30); do
    NEW_HASH=$(kubectl get deployment demo-proxy -n "$SAMPLE_NS" \
      -o jsonpath='{.spec.template.metadata.annotations.sbproxy\.dev/config-hash}')
    if [[ "$NEW_HASH" != "$ORIGINAL_HASH" ]]; then
      break
    fi
    sleep 2
  done

  if [[ "$NEW_HASH" == "$ORIGINAL_HASH" ]]; then
    fail "config hash did not change after SBProxyConfig update"
  fi
  log "config hash bumped: $ORIGINAL_HASH -> $NEW_HASH"

  # Confirm the new pod template rolled out and the resulting Deployment is
  # still Available. This catches the "operator patched the annotation but
  # the pod can't pull or start" failure mode.
  kubectl rollout status deployment/demo-proxy -n "$SAMPLE_NS" --timeout=120s \
    || fail "demo-proxy rollout did not complete after config change"
fi

# --- 6. Leader election ---
#
# The chart ships with replicaCount=2 by default. Verify that a single
# replica holds the Lease, and that killing that replica triggers a hand-
# off to the standby within 30s.

log "verifying leader election: chart was installed with replicaCount=2"
kubectl rollout status deployment/sbproxy-k8s-operator -n "$NAMESPACE" --timeout=120s \
  || fail "operator deployment did not roll out within 120s"

# Wait up to 30s for the Lease to appear and have a holder.
ORIGINAL_HOLDER=""
for _ in $(seq 1 15); do
  ORIGINAL_HOLDER=$(kubectl get lease sbproxy-operator-leader -n "$NAMESPACE" \
    -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || echo "")
  if [[ -n "$ORIGINAL_HOLDER" ]]; then
    break
  fi
  sleep 2
done
if [[ -z "$ORIGINAL_HOLDER" ]]; then
  kubectl get pods -n "$NAMESPACE"
  kubectl get leases -n "$NAMESPACE"
  fail "no holder on Lease sbproxy-operator-leader within 30s"
fi
log "initial leader: $ORIGINAL_HOLDER"

# Resolve the leader pod name from the holder identity. The operator
# encodes the pod name as the prefix before the first underscore.
LEADER_POD="${ORIGINAL_HOLDER%%_*}"
log "deleting leader pod $LEADER_POD to force a handoff"
kubectl delete pod "$LEADER_POD" -n "$NAMESPACE" --grace-period=0 --force >/dev/null

# Wait up to 30s for a *different* holder to take over.
NEW_HOLDER=""
for _ in $(seq 1 15); do
  NEW_HOLDER=$(kubectl get lease sbproxy-operator-leader -n "$NAMESPACE" \
    -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || echo "")
  if [[ -n "$NEW_HOLDER" && "$NEW_HOLDER" != "$ORIGINAL_HOLDER" ]]; then
    break
  fi
  sleep 2
done
if [[ -z "$NEW_HOLDER" || "$NEW_HOLDER" == "$ORIGINAL_HOLDER" ]]; then
  kubectl get pods -n "$NAMESPACE"
  kubectl get lease sbproxy-operator-leader -n "$NAMESPACE" -o yaml
  fail "leader handoff did not complete within 30s (holder still $ORIGINAL_HOLDER)"
fi
log "leader handed off to $NEW_HOLDER"

log "PASS: smoke test succeeded"
