# Operator runbook

*Last modified: 2026-08-03*

This runbook is the dashboard/action companion to
[`quickstart-operator.md`](quickstart-operator.md). Use the quickstart for first
deploys; use this page when a dashboard panel is red.

## Dashboard Triage

1. Confirm `/readyz` and `/health` from the affected proxy pod.
2. Open `dashboards/grafana/sbproxy-overview.json` first to decide whether the
   problem is global or isolated to one origin / feature area.
3. Use the panel description to jump to the section below.
4. Capture the current config revision, pod name, and request id before
   restarting or rolling back.

## Inbound Traffic

Healthy range: request rate follows expected load, p95/p99 latency stays within
the deployment SLO, and 5xx errors stay near zero.

When red:

- Check `/readyz` for stale dependencies.
- Tail access logs and compare successful 2xx requests against denied 4xx/5xx
  requests.
- If latency rose after a config change, roll back the latest `SBProxyConfig`
  and watch the latency panel for recovery.

## Security Controls

Healthy range: WAF, auth, IP filter, bot detection, and rate-limit blocks should
match expected traffic patterns. Sudden spikes require investigation even when
the proxy is behaving correctly.

When red:

- Inspect the top offending host, path, source IP, or agent label.
- Confirm the policy in `sb.yml` is intentional.
- For auth failures, verify the credential source or JWKS feed before loosening
  policy.
- For WAF/rate-limit spikes, preserve sample request ids for incident review.

## AI Gateway

Healthy range: provider request rate, token usage, and provider errors follow
known traffic. Budget utilization should stay below alert thresholds.

When red:

- Check provider credentials and model routing in the active config.
- Confirm fallback providers are healthy before disabling a primary provider.
- For budget alerts, decide whether to raise the configured budget or block the
  caller.

### Hot-reload behavior

A `SIGHUP`, an admin reload, or a watched edit of `sb.yml` rebuilds the AI
provider catalog, the live AI client, and the compiled handler chain in place
and swaps them atomically. Adding a provider, rotating a `default_base_url`, or
fixing a typo in `ai_providers.yml` no longer requires a restart, and in-flight
requests are not shed. The process-wide AI budget tracker is deliberately not
part of the swap: per-scope token and cost accumulators must survive reloads
because budget windows are wall-clock-relative (daily, monthly), and wiping
them on reload would let already-spent budget through twice. Budget state is
in-memory, so a full process restart resets every accumulator to zero; there
is no admin endpoint for resetting a budget. Treat restarts during an active
budget window accordingly: spend already recorded is forgotten.

## Origins

Healthy range: origin latency and errors stay within SLO; circuit breakers
remain closed; cache hit/miss trends are expected for the workload.

When red:

- Check the upstream service directly from inside the cluster.
- Confirm service discovery and DNS resolution are returning current endpoints.
- If a circuit breaker opened, wait for the configured half-open interval or
  roll back the origin config that triggered failures.

## Extension bundles

Treat a bundle release as immutable files plus a config change. sbproxy has no
extension install command, TypeScript CLI, package manager, or runtime dependency
resolver. Your deployment system copies the bundle directories into place. If
JavaScript uses dependencies, build them ahead of time and ship one flat `.js`
entry artifact with all dependencies included.

### Install a local release

Stage each release in a new directory instead of overwriting the running entry
files:

```bash
install -d /opt/sbproxy/extension-releases/2026-08-02
cp -R ./bundles/. /opt/sbproxy/extension-releases/2026-08-02/
```

Point `sb.yml` at that release. A relative path resolves from the directory that
contains `sb.yml`. An absolute path decouples the release location from the
config directory:

```yaml
extensions:
  bundles_dir: /opt/sbproxy/extension-releases/2026-08-02
```

Every direct child needs a `bundle.yaml` and its declared `entry` file. Pin the
exact entry bytes in the manifest. The digest is 64 lowercase hexadecimal
characters only, without a `sha256:` prefix:

```bash
# macOS
shasum -a 256 /opt/sbproxy/extension-releases/2026-08-02/hello/entry.js

# Linux
sha256sum /opt/sbproxy/extension-releases/2026-08-02/hello/entry.js
```

Calculate the value after the artifact is final, then put that exact value in
`bundle.yaml`. A TypeScript digest covers the `.ts` entry bytes. If your build
produces a flat `.js` artifact instead, point `entry` at the `.js` file and hash
that final file.

### Validate before reload

Run both views before publishing:

```bash
sbproxy validate /etc/sbproxy/sb.yml
sbproxy doctor /etc/sbproxy/sb.yml --format json \
  | jq '.extensions | {scope, summary, bundles, hooks, collisions}'
```

`validate` performs the startup construction path and exits nonzero for a bad
source, manifest, digest, JavaScript or TypeScript export, WASM module, config
schema, or hook collision. `doctor` reports a stopped candidate with
`scope.mode: "doctor"`. An `active` hook was selected and wired in that
candidate after its chain prepared successfully. It has not served traffic, and
doctor is not reporting runtime health. Loaded hooks with no attachment are
`unconsumed`. A `not_evaluated` hook came from the loader-level fallback because
doctor could not finish candidate construction. Inspect
`extensions.summary.failed` in the JSON. An extension finding does not, by
itself, change the general doctor exit code.

### Reload and confirm the running generation

After validation, reload explicitly. The `sb.yml` file watcher does not treat an
entry artifact edit as a config change:

```bash
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" -X POST \
  "${SB_ADMIN_URL}/admin/reload" | jq '{config_revision, fully_applied, degraded}'

curl -fsS -u "oncall:${ONCALL_PASSWORD}" \
  "${SB_ADMIN_URL}/api/extensions" \
  | jq '{scope, summary, bundles, hooks, collisions}'
```

`GET /api/extensions` is authenticated, allows `read_only` operators, and
reports the pipeline generation serving traffic. Expect `scope.mode: "running"`
and the new config revision. `active` means the hook is attached to this
generation. `available` or `unconsumed` means it loaded but is not attached.
AI hooks become active when their compiled lifecycle chain attaches. Payment
hooks stay `unconsumed` until the payment dispatcher installs successfully.
`failed` and a nonempty `collisions` list need investigation.

Bundle loading is part of the candidate transaction. A bad digest, missing
export, invalid WASM artifact, unsupported Proxy-Wasm import, or colliding hook
name refuses the candidate. The old pipeline and old bundle registry continue
serving together. In-flight requests stay pinned to their original generation.

### Triage and rollback

Start with the bounded phase in the error or inventory record:

- `source`: the release directory, bundle directory, or entry is missing,
  unreadable, or outside its allowed root.
- `manifest`: `bundle.yaml` is malformed or violates the runtime and hook
  contract.
- `digest`: the entry bytes do not match `sha256`. Recompute the final artifact;
  do not change the manifest to bless an unexplained file.
- `javascript`: source, TypeScript transpilation, import rejection, or export
  preflight failed. Ship a dependency-free `.ts` entry or a prebuilt flat `.js`
  artifact.
- `wasm` or `proxy_wasm`: ABI, module validation, unsupported import, or resource
  validation failed.
- `collision`: two registrations claimed the same hook kind and type.

For rollback, restore `extensions.bundles_dir` to the prior immutable release,
run `validate`, and reload again. If the failed candidate never published, this
step is only needed to make the declared config match the generation that kept
serving.

The complete local release is runnable at
[examples/extension-bundles](../examples/extension-bundles/). The developer
contracts are in [scripting.md section 12](scripting.md#12-dynamic-extension-bundles),
and the inventory response is in
[admin-api-reference.md](admin-api-reference.md#get-apiextensions).

## Helm Value Reconciliation

The chart currently exposes operator-level values only. The following names were
used in early planning notes but are not Helm values in the merged chart:

- `proxy.notify.deadletter_capacity`
- `proxy.observability.otlp.queue_size`

Do not set those values in `deploy/helm/sbproxy/values.yaml`. Configure outbound
webhook behavior and OTLP behavior in `sb.yml` / proxy configuration as those
surfaces mature; keep Helm values for operator deployment concerns such as
image, replicas, leader election, RBAC, namespace, and dashboard provisioning.

## Rollback

Helm rollback:

```bash
helm history sbproxy -n sbproxy-system
helm rollback sbproxy 3 -n sbproxy-system
```

Config rollback:

```bash
kubectl apply -f sbproxyconfig.yaml
kubectl rollout status deploy/demo
```
