# Upgrade SBproxy

*Last modified: 2026-08-27*

Use this procedure for the Rust v1 release line. Upgrade a test or canary instance before the rest of a fleet, and keep the previous binary or image available until the new process has served traffic.

If you are moving from the archived Go `v0.1.x` implementation, read [MIGRATION.md](../MIGRATION.md) before this page. The config schema is called `schema-v1`; it is separate from the Rust binary version. The per-release record is [CHANGELOG.md](../CHANGELOG.md), and [release-notes.md](release-notes.md) groups the same changes by feature area; the [notes by version](#notable-changes-by-version) below pull out only what can bite during an upgrade.

## Before replacing anything

Choose a target release from the [GitHub releases page](https://github.com/soapbucket/sbproxy/releases), read its changelog entry, and record the version now running:

```bash
sbproxy --version
sbproxy validate /etc/sbproxy/sb.yml
cp /etc/sbproxy/sb.yml /etc/sbproxy/sb.yml.before-upgrade
```

`validate` compiles the configuration without binding a listener. Resolve errors here, not during a rollout. Keep secrets out of shell history and copy any referenced secret material with the backup method your platform already uses.

Validating with the **new** binary before rolling it out matters more than it used to: recent releases retire config keys that once parsed and did nothing, and a config carrying one now fails to compile with a message naming the replacement (see the notes below). Running the target release's `validate` against your current config surfaces every such refusal while both binaries are still on the box.

For a configuration change that accompanies the binary upgrade, preview it first:

```bash
sbproxy plan -f proposed-sb.yml --against /etc/sbproxy/sb.yml
sbproxy validate proposed-sb.yml
```

`plan` exits 2 when it finds changes. That is an informational result. It exits 3 for semantic validation errors.

## Install the target release

For an installer-managed node, pin the target tag instead of taking whatever release is latest:

```bash
export TARGET_VERSION=v1.12.0
curl -fsSL https://download.sbproxy.dev | SBPROXY_VERSION="$TARGET_VERSION" sh
sbproxy --version
```

Replace `v1.12.0` (the newest tag when this page was last updated) with the release tag you approved. The installer verifies the published SHA-256 checksum and verifies the Sigstore bundle when `cosign` is installed. See [SUPPLY-CHAIN.md](../SUPPLY-CHAIN.md) for the verification model.

For Docker, pull the same release tag, update the pinned image reference in your deployment manifest, and keep the explicit configuration command:

```bash
docker pull soapbucket/sbproxy:1.12.0
docker run --rm -p 8080:8080 \
  -v "$PWD/sb.yml:/etc/sbproxy/sb.yml:ro" \
  soapbucket/sbproxy:1.12.0 serve -f /etc/sbproxy/sb.yml
```

The published image has no default configuration command. In Kubernetes, update the `SBProxy.spec.image` tag and use the rollout procedure in [kubernetes.md](kubernetes.md).

## Roll out and verify

Restart one supervised instance, wait for it to become healthy, then continue with the next instance. For a systemd-managed node, that normally looks like this:

```bash
sudo systemctl restart sbproxy
sudo systemctl status sbproxy --no-pager
```

Make a representative request through the data plane. The `Host` header selects the origin you are testing:

```bash
curl -i -H 'Host: api.example.com' http://127.0.0.1:8080/status
```

For a running proxy with the admin server enabled, check the authenticated
`GET /api/health` endpoint on its configured bind address and port. The
default admin address is `127.0.0.1:9090`; see [admin.md](admin.md) for
authentication and reload checks. Watch access logs, error rate, latency,
provider failures, and budget behavior through the normal observation
window before expanding the rollout.

## Roll back

If the new binary fails validation, startup, or the canary traffic check, restore the prior binary or image and restart that instance. Restore the saved configuration only when the configuration changed as part of the rollout. Do not mix binary rollback with an unrelated configuration edit; validate the restored file before restarting.

For Kubernetes, restore the previous approved image tag and wait for the Deployment or StatefulSet rollout to complete. For Helm-managed operator changes, use `helm history` followed by `helm rollback`. The [operator quickstart](quickstart-operator.md) has the small-cluster commands.

After the fleet is stable on the intended version, remove the temporary `sb.yml.before-upgrade` copy according to your secret-retention policy.

## Notable changes by version

What follows is not the changelog; it is the subset that changes behavior under an existing config, refuses a config that used to load, or moves a metric label a dashboard might key on. Skipping versions compounds the list: upgrading 1.9.0 to 1.12.0 means reading all three sections below.

### Unreleased

- **For out-of-tree plugin authors only: a linked plugin returning `ActionOutcome::Responded` now gets a `501` on the wire.** The variant is the 0.2 signal that the handler already wrote a response through host state, and no host state a linked `ActionHandler` reaches writes one. HTTP/1.1 and HTTP/2 previously marked the request served and sent nothing, so the client saw an empty exchange and the access log had no status; HTTP/3 already answered `501`. All three now answer `501 Not Implemented` with an `application/json` body carrying the stable `unsupported_action_outcome` reason, tick `sbproxy_errors_total{error_type="unsupported_action_outcome"}`, and publish a `request_error` event. Nothing on the wire worked before, so no functioning deployment changes behavior; return `ActionOutcome::Response { status, headers, body }` instead.

- **Three `cel` transform `headers:` rules that used to load now refuse the config.** A `value_expr` can only read what its response phase binds, and no phase binds the whole response, so a rule reaching for the wrong half was resolving against an empty value and writing a wrong header. Each refusal names the origin, the rule, and the action. Run the target release's `sbproxy validate` against your config before rolling it out; if one fires, the rule was never producing the header you configured.
  - `response.body` on an origin every route of which streams (`proxy`, `load_balancer`, `a2a`). That phase runs before the first body byte arrives.
  - `response.headers` on an origin every route of which buffers (`static`, `mock`, `plugin`). That phase owns the body and does not yet own a response header map.
  - Any `headers:` rule at all on an origin whose action is `echo`, `beacon`, `redirect`, `storage`, `noop`, `mcp`, `grpc`, `graphql`, `ai_proxy`, or `websocket`, with no forward rule in the other two groups. Those actions never run the origin transform chain, so the rule ran in no phase and set no header. Use a `response_modifiers:` entry instead.
- **`op: append` on a `cel` header rule now emits every value.** On a `static` or `plugin` origin two `append` rules for one header used to leave only the second value, while the identical config on a `mock` origin emitted both. A response that previously carried one value for such a header now carries all of them, so a downstream parser reading only the first or the last may see something different.
- **One AI metric label moves for a `3xx`.** A race leg that answered `3xx` counted as `sbproxy_ai_provider_attempts_total{outcome="error"}` and now counts as `outcome="success"`, which is what every other dispatch path already reported. A `3xx` from an AI provider is rare, so most dashboards will not move; one keying on that series for a `race` origin should be checked.
- **A reload that changes `request_events`, `proxy.agent_registry`, or `proxy.notifications` now fails.** All three are applied at boot only: each opens its own embedded store or installs a process-global sink through a set-once slot, and none has a rebuild path. `request_events` shipped in 1.11.0 and its reload was previously accepted and then ignored, so a fleet that edits the block and reloads has been running the old sink since. The reload now refuses, names the block that moved, and the node keeps serving its previous config; restart to apply. The other two blocks are new in this release. If your rollout pipeline reloads rather than restarts, move edits to these three blocks onto a restart.

### 1.12.0

- **A broken `ai_policy.expression` now refuses the config.** A syntax error or an out-of-namespace binding previously logged once and booted with the policy silently absent. If your config stops loading on this upgrade, that policy was never running; fix the expression and it starts enforcing.
- **The response cache now stores the transform chain's output.** All existing response-cache entries are retired on upgrade, so expect one cold start per key. A request-dependent transform on a cached origin now refuses at config load.
- **A configured origin now owns `/health` on the data plane.** The proxy no longer answers `GET /health` itself when an origin or forward rule matches the request. A load balancer probing `/health` with a configured origin's `Host` header now reaches your upstream, and an upstream without that route answers 404, which health checkers read as unhealthy. Point such probes at the admin listener's health route or make the upstream serve the path. Probes against the pod IP or an unconfigured Host still get the built-in response.
- **`timeout_ms` on an AI provider is now enforced.** The key previously validated and did nothing. It bounds one dispatch attempt from connect through the end of the body, severing a streaming completion that runs past it; a forgotten low value starts cutting requests off on upgrade. Check yours before deploying.
- **Two metric label changes.** The `outcome` value `auth_denied` split into gateway-side refusals versus upstream auth failures, and single-tenant traffic's workspace label on the rate-limit series moved from `default` to `__default__`. Dashboards and alerts matching either need updating; budget behavior itself is unchanged.
- **Meter receipts fold retried attempts.** Provider fallback and origin retries now record extra attempts as `retry` and collapse them; the billing receipt remains `delivered`. Reconciliation that assumed one receipt row per attempt should expect the collapsed shape.

### 1.11.0

This release converted a set of accepted-but-inert config keys into compile errors. Each refusal names its replacement, and `sbproxy validate` with the new binary lists every one in your config before you roll anything:

- `origins.*.connection_pool.max_connections` (use a `concurrent_limit` policy) and `.max_lifetime_secs` (use `timeouts.idle_ms`). `connection_pool.idle_timeout_secs` is unaffected; it is live.
- `origins.*.traffic_capture` (use `mirror`).
- `origins.*.sessions.ttl_seconds` (use `sessions.budget`).
- `proxy.device_parser_file` (no replacement; nothing ever read it).
- `audit.sink: tracing` (use `memory` for the same behavior under an honest name, or `chain` for a trail that survives restart). `audit.path` or `audit.sign_with` under any sink other than `chain` is refused on the same grounds.
- The origin-level `rate_limit_headers:` block (the rate-limiting policy's own `headers` block emits `X-RateLimit-*` and `Retry-After`, and already did).
- `allowed_hosts:` on the `wasm` transform (it named a boundary nothing checked; a WASM module here has no network access at all).
- `on_request:` on the `cel` transform (transforms are response-side; the key compiled and never ran).
- The AI gateway's `context_overflow:` block (never wired; the compression settings are the lever that actually fits a prompt to a window).

Also worth checking: `compression.level` is now applied to the response encoders instead of being accepted and ignored, so a config that set an aggressive level starts paying for it on upgrade.

### 1.10.0

- **`engine: embedded` is removed from the model host.** It was opt-in at build time and never certified. A config that still sets it fails to parse; llama.cpp covers the CPU/Metal zero-external-binary case, and the `mistralrs` subprocess engine covers safetensors serving.
- **For out-of-tree plugin authors only:** `sbproxy-plugin` moved to 0.3.0 with a data-bearing `ActionOutcome::Response` variant; exhaustive matches on the 0.2 enum stop compiling. The migration note is on the enum's rustdoc. Source compatibility was not behavior compatibility: see the Unreleased entry above for what the retained 0.2 `Responded` variant now does on the wire.

### 1.9.0

- **Admin operator passwords are hashed at rest, and the plaintext field no longer parses.** `proxy.admin.operators[].password` is replaced by `password_hash`; compute it with `sbproxy admin hash-password`. The hash uses `key_management.crypto.pepper` when set and a fixed public default otherwise, so a leaked hash is offline-crackable unless the pepper is pinned. Pin it in production.
- **Unsupported `telemetry.propagation` values now fail boot** instead of silently propagating nothing.
- **A CEL syntax error is a config error everywhere CEL comes from config**, so expressions that never ran start being either enforced or refused.
- **Outbound HTTP re-authorizes redirects and egress authorization resolves DNS for real**, so an egress policy that previously looked permissive may start refusing dials it never actually vetted before.
