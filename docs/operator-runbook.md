# Operator runbook
*Last modified: 2026-05-03*

This is the on-call and operations runbook for the SBproxy AI Governance Gateway substrate. It covers deploy, upgrade, rollback, incident response, secret rotation, key compromise, capacity planning, DR, and the secret/key inventory for the OSS distribution.

Companion documents:

- `docs/threat-model.md` for the STRIDE breakdown that motivates the secret rotation and key compromise sections below.
- `docs/architecture.md` for the request-pipeline overview.
- `docs/adr-observability.md` for the OTel and exemplar contract.
- `docs/adr-slo-alert-taxonomy.md` for the alert-ID-to-section map.
- `docs/adr-webhook-security.md` for the webhook signing contract.

For the AI-discoverable capability catalog used by assistants reading this repository, see `docs/llms.txt`.

## Deploy

The supported deployment surface is the Helm chart at `deploy/helm/sbproxy/`. A first install needs three secret mounts and two config knobs:

1. Provision a Kubernetes secret carrying `LEDGER_HMAC_KEY` (raw bytes; minimum 32 bytes), the bot-auth directory anchor public key (PEM), and an empty placeholder for the audit signing key.
2. Set `proxy.observability.otlp.enabled: true` and `proxy.observability.otlp.endpoint` to the OTLP gRPC collector address. The default `localhost:4317` works for the reference stack at `examples/00-observability-stack/`.
3. Apply the Helm chart with the secret reference; the chart mounts secrets at `/etc/sbproxy/secrets/` and exposes them via `SBPROXY_LEDGER_ENDPOINT` and `SBPROXY_LEDGER_HMAC_KEY_FILE` env vars.

Provision the Grafana dashboards under `deploy/dashboards/` and the Prometheus rules under `deploy/alerts/` via the provisioning sidecar examples in `deploy/helm`. The reference Compose stack at `examples/00-observability-stack/` is the canonical preview; it boots Prometheus, Grafana, Tempo, Loki, and the OTel collector pre-provisioned with the dashboards and alerts. Operators new to the stack should boot it locally before running the Helm chart in production.

Verification steps after deploy:

1. `curl /healthz` returns 200.
2. `curl /readyz` returns 200 only when the ledger is reachable and the bot-auth directory is fresh. Deployments without optional pillars wired report those pillars as `not_configured`, not as failures.
3. The Grafana overview dashboard populates within one scrape interval.
4. A test 402 request flows through the structured-log access sink with the expected redaction (Authorization, ledger HMAC all replaced with `[redacted]`).

### Content-shaping deploy notes

The content-shaping pillar adds the projection cache, Markdown / JSON envelope transforms, and `Content-Signal` header pipeline. These are all in-process and ride the existing config-reload path. Two operator-facing playbooks ship with content shaping: shape-rollout (rolling out a new content shape per route safely) and licensing-policy-edit (changing RSL terms safely). Both are documented below in the "Playbooks" section.

The content-shaping readyz expectations:

1. `/readyz` reports `projection_cache:fresh` for every origin that has an `ai_crawl_control` policy with at least one tier. A `degraded` reading indicates the projection engine could not render one of the four documents at the last config reload.
2. The four projection routes (`/robots.txt`, `/llms.txt`, `/llms-full.txt`, `/licenses.xml`, `/.well-known/tdmrep.json`) return 200 on every `ai_crawl_control`-enabled origin. A 404 from the proxy on these routes means the projection cache is empty for that hostname.
3. The `content-shapes.json` Grafana dashboard populates within one scrape interval.
4. A test 200 response on `Accept: application/json` carries `Content-Type: application/json; profile="https://sbproxy.dev/schema/json-envelope/v1"` and a body matching the v1 schema.

Companion docs: [content-for-agents.md](content-for-agents.md), [rsl.md](rsl.md), [adr-content-negotiation-and-pricing.md](adr-content-negotiation-and-pricing.md), [adr-policy-graph-projections.md](adr-policy-graph-projections.md), [adr-json-envelope-schema.md](adr-json-envelope-schema.md).

#### Shape-rollout playbook

Goal: roll out a new content shape (Markdown or JSON envelope) on one route safely, verifying behaviour in dashboards before broad production rollout.

Steps:

1. **Configure the new tier in staging.** Add the new tier to `ai_crawl_control.tiers[]` with the matching `content_shape` and the per-shape pricing. Set `content_signal` per the editorial intent ([rsl.md](rsl.md) Recipe 1 and 2 cover the common cases). Apply the YAML to the staging cluster.

   ```yaml
   policies:
     - type: ai_crawl_control
       tiers:
         - route_pattern: /articles/*
           content_shape: markdown
           content_signal: ai-train
           citation_required: true
           price:
             amount_micros: 1000
             currency: USD
   ```

2. **Validate the projections via CLI before the proxy serves them.** Run `sbproxy projections render` against the YAML and confirm the four documents are well-formed and match the operator's intent.

   ```bash
   sbproxy projections render --kind robots --config ./sb.yml > /tmp/robots.txt
   sbproxy projections render --kind llms --config ./sb.yml > /tmp/llms.txt
   sbproxy projections render --kind licenses --config ./sb.yml > /tmp/licenses.xml
   sbproxy projections render --kind tdmrep --config ./sb.yml > /tmp/tdmrep.json
   xmllint --schema https://rsl.ai/spec/1.0/rsl.xsd --noout /tmp/licenses.xml
   ```

   A schema-validation failure on the RSL output is a hard stop. Fix the YAML before continuing.

3. **Smoke test the staging origin.** From outside the cluster, exercise the new shape with a known crawler-payment token.

   ```bash
   curl -i -H 'Host: blog.staging.example.com' \
           -H 'User-Agent: GPTBot/1.0' \
           -H 'Accept: text/markdown' \
           -H 'crawler-payment: tok_staging_smoke' \
           https://blog.staging.example.com/articles/foo
   ```

   Confirm `200 OK`, `Content-Type: text/markdown`, `Content-Signal: <expected>`, and `x-markdown-tokens: <reasonable>`. Repeat with `Accept: application/json` for the envelope shape; confirm the JSON body matches the v1 schema.

4. **Watch the dashboards in staging for one full traffic cycle.** Specifically watch:

   - `sbproxy_content_shape_served_total{origin, shape}` on the `content-shapes.json` dashboard. The new shape should appear with non-zero traffic.
   - The redaction-pipeline panel on the access-log dashboard. The Markdown projection and JSON envelope flow through the same redaction middleware as the HTML body; confirm no regressions on PII patterns the operator already redacts.

5. **Gradual production rollout.** Apply the YAML to one production cluster (or a single Helm release) at a time. Repeat the smoke test against the production hostname. Watch the same dashboard panels for a 30-minute window before rolling to the next cluster.

6. **Full production rollout.** When all staged clusters are green, apply the YAML to the remaining clusters via the standard hot-reload path (`SIGHUP` or `kubectl rollout restart`).

7. **Rollback path.** Revert the YAML to remove the new tier. The proxy hot-reloads the previous shape catalogue; in-flight requests on the new shape complete under the old config; new requests revert to the prior pricing and transformation. The audit trail captures the revert via the `PolicyProjectionRefresh` audit events emitted on the next config reload.

Common failure modes:

- **The new shape's tier does not match.** Symptom: requests with the new `Accept` header still get the old shape's price. Cause: tier ordering. The pricing pass is declaration-order first-match; if the catch-all tier appears before the new shape-specific tier, the catch-all wins. Fix: place the shape-specific tier before the catch-all in `tiers[]`.
- **`Content-Signal` is missing on responses.** Symptom: 200 responses have no `Content-Signal` header. Cause: neither the origin nor any matched tier has `content_signal:` set. Fix: set `content_signal` at the origin level for a default, or on the tier for an override.
- **The JSON envelope's `license` field is `"all-rights-reserved"`.** Symptom: agents complain about the missing URN. Cause: no `ai_crawl_control` policy is configured for the origin (the field falls back to the all-rights-reserved string when there is no projection cache entry). Fix: ensure the origin has at least one `ai_crawl_control` tier and confirm the projection cache populates after the next reload.

#### Licensing-policy-edit playbook

Goal: change the RSL license terms an origin advertises (the `content_signal` value, the per-tier override, the `citation_required` flag) safely, verifying the audit trail captures the edit. Use this when shifting an origin's editorial stance (e.g., flipping from `ai-train` to `ai-input` after a contract negotiation, or adding `citation_required` after a counterparty request).

Steps:

1. **Edit the YAML.** Change the `content_signal:` value at the origin or tier level. The closed value set is `ai-train`, `ai-input`, `search`. Adding or removing `citation_required: true` on a tier is part of the same edit cycle.

   ```yaml
   policies:
     - type: ai_crawl_control
       content_signal: ai-input        # was: ai-train
       tiers:
         - route_pattern: /articles/*
           citation_required: true     # newly required
           price:
             amount_micros: 1000
             currency: USD
   ```

2. **Validate the projection before pushing.** This is a hard gate; the licensing posture is a binding artifact for counterparties. Run `sbproxy projections render` and diff against the previously-served document.

   ```bash
   sbproxy projections render --kind licenses --config ./sb.yml > /tmp/licenses.new.xml
   curl -s https://blog.example.com/licenses.xml > /tmp/licenses.old.xml
   diff -u /tmp/licenses.old.xml /tmp/licenses.new.xml
   xmllint --schema https://rsl.ai/spec/1.0/rsl.xsd --noout /tmp/licenses.new.xml
   ```

   Confirm the `<ai-use type=...>` element changed in the expected direction. Confirm the URN structure is unchanged (the URN is `urn:rsl:1.0:<hostname>:<config_version>`; only the version segment changes per reload).

3. **Push to staging first.** Apply the YAML to the staging cluster and watch the `licensing-edits.json` audit dashboard panel for the `PolicyProjectionRefresh` audit event landing. The audit event carries the new document hash; cross-check it against `sha256` of the rendered `/tmp/licenses.new.xml`.

   ```bash
   sha256sum /tmp/licenses.new.xml
   # Expected: matches the audit event's after.doc_hash field for kind=licenses
   ```

   If the hashes do not match, the proxy rendered a different document than the CLI did. This is a serious signal; stop the rollout and investigate before pushing further.

4. **Verify the served document.** Fetch `/licenses.xml` from the staging origin and confirm it matches what the CLI rendered.

   ```bash
   curl -s -H 'Host: blog.staging.example.com' http://localhost:8080/licenses.xml > /tmp/licenses.served.xml
   diff -u /tmp/licenses.new.xml /tmp/licenses.served.xml
   ```

   Empty diff means the projection cache served the expected document. A non-empty diff means the projection cache is stale; check the reload log for projection-engine errors.

5. **Production rollout.** Apply the YAML to production via the standard hot-reload path. Watch the `licensing-edits.json` audit dashboard for the production `PolicyProjectionRefresh` events. Each origin emits one event per (hostname, projection kind) pair; an operator with 10 origins sees 40 events per reload.

6. **Rollback path.** Revert the YAML. The proxy regenerates the previous projection set on the next reload and emits a fresh `PolicyProjectionRefresh` audit event with the prior document hash. The old document hash and the new document hash are both in the audit trail; counterparties can verify what license terms applied at any point in time by walking the audit log.

Common failure modes:

- **The audit event has the new hash but the served document has the old hash.** Cause: the projection cache and the audit emitter raced; the audit event captured a reload that subsequently failed to install. Fix: trigger another reload (`SIGHUP`) and watch for a fresh audit event with the new hash; the projection cache should now be in sync.
- **The `<ai-use>` mapping is wrong.** Symptom: the diff in step 2 shows an unexpected `licensed="..."` value. Cause: the operator misread the mapping table; e.g., setting `content_signal: search` produces `<ai-use type="search-index">`, not `<ai-use type="training">`. Fix: re-read [rsl.md](rsl.md) "The mapping" section and adjust the YAML.
- **The URN segment did not change.** Symptom: the diff in step 2 shows the same URN before and after. Cause: the config-version hash is computed only on successful reload; if the reload was rejected (validation error), the URN segment stays at the previous version. Fix: check the reload log for the rejection and address the validation error.

## Upgrade

SBproxy is a single-binary upgrade. The proxy supports hot reload of its config without dropped connections (`SIGHUP` to the running process, or rolling restart via the Helm chart). The schema-v1 contract (pinned by the `v1_compat::v1_fixtures_compile_unmodified` test in `crates/sbproxy-config/`) means existing `sb.yml` files from the 1.0 line continue to parse. New blocks like `ai_crawl_control.tiers`, the `agent_class` resolver inputs, and the dynamic bot-auth directory URL are all additive: configs that do not set them keep the prior behaviour.

Pre-upgrade checks:

1. Run `sbproxy validate -c <config>` against the new binary; this compiles the config and prints any deprecation warnings.
2. Diff `deploy/dashboards/` and `deploy/alerts/` against your provisioned copies.
3. Confirm the OTLP exporter target is reachable from the new pod (the exporter is bind-tested at `/readyz`).

After the rolling restart, watch the per-agent dashboard for a 10 minute window. The `agent_id` label set should stabilize at or below the cardinality budget configured in `adr-metric-cardinality.md`; a sustained `__other__` over-cap demotion in any series indicates a mis-sized budget for the deployment, not a regression.

## Rollback

Rolling back is supported as long as the prior config did not enable features that are absent in the older binary (`ai_crawl_control.tiers`, the dynamic bot-auth directory, or the OTLP exporter). The Helm chart's previous `values.yaml` file plus the prior container image is sufficient.

Roll-back signal sources:

1. `sbproxy_readyz_failures_total` rises sustained.
2. The substrate dashboard's "ledger redeem error rate" panel crosses the alert threshold from `adr-slo-alert-taxonomy.md`.
3. Per-agent metrics show a sudden cardinality spike that the `__other__` demotion is not absorbing (indicates a label-policy regression).

Rollback procedure:

1. Re-apply the prior Helm chart version.
2. Restore the prior `sb.yml` (the schema-v1 compatibility test guarantees both binaries parse the same file when the new fields are absent).
3. Force a config reload (`SIGHUP`) so the in-memory state matches the rolled-back binary.
4. File an incident note in the audit log via the admin-action endpoint so the rollback itself is recorded (the OSS audit log sink captures this).

## Incident response

The alert taxonomy (per ADR `docs/adr-slo-alert-taxonomy.md`) maps every alert ID to a runbook section. On-call paths:

1. **Ledger unreachable.** `/readyz` reports `ledger:degraded`. Confirm the ledger endpoint from the proxy pod (`SBPROXY_LEDGER_ENDPOINT`); confirm the HMAC key file is readable; check the circuit breaker state in the policy-triggers dashboard. If the breaker is open, the ledger client is honoring the configured failure mode (fail-closed by default).
2. **Bot-auth directory stale.** Directory cache TTL exceeded with no successful refresh. Check egress from the proxy to the `Signature-Agent` host; verify the directory still self-signs. The proxy honors negative caching, so a single failed refresh does not collapse to "all bot-auth requests fail"; sustained failure does.
3. **OTLP exporter dropping.** Tracer batch queue full. Increase the queue size in `proxy.observability.otlp.queue_size` or reduce the trace sampling rate.
4. **Cardinality budget exceeded.** A new label value exhausted the budget. The `__other__` demotion is the safety net; the alert exists so an operator updates the budget table in `adr-metric-cardinality.md` and re-rolls a release. Do not silence the alert; over-cap demotion silently truncates the per-agent attribution if left in place.
5. **Rate-limit auto-suspend (`RATE-SUSPEND`).** A paying-tier workspace tripped auto-suspend. The cooldown is 60 minutes; confirm whether the trigger is legitimate abuse or misconfigured legitimate traffic before lifting. Lifting happens through the portal admin surface; the action is audited.

## Secret rotation

Three secrets are in scope: the ledger HMAC key, the outbound webhook signing key, and the bot-auth directory anchor public key. The proxy supports overlapping rotation: a new secret file lands at the configured path and the proxy hot-reloads via `SIGHUP`. During the overlap window (30 minutes by default), the proxy accepts and emits payloads signed with either the old or the new key.

Procedure:

1. Generate the new key (32 random bytes for HMAC; an Ed25519 keypair for outbound webhook signing; whatever PEM the directory anchor publishes).
2. Update the Kubernetes secret resource. Helm value: `proxy.secrets.<name>.next` carries the new key while `proxy.secrets.<name>` still carries the current key.
3. Send `SIGHUP` to the pods (the chart's `kubectl rollout restart` is also fine; hot reload preserves connections).
4. Verify both signing paths via the synthetic monitor harness (`sbproxy-bench/harness/synthetic/`).
5. After the overlap window, swap `proxy.secrets.<name>` to the new value and clear `proxy.secrets.<name>.next`.

### Outbound webhook subscription management

```
# List subscriptions for a tenant
sbproxy-admin webhook subscription list --tenant tenant_42

# Pause a subscription (operator override; customer cannot resume
# until operator unpauses)
sbproxy-admin webhook subscription pause \
  --subscription-id sub_01J... \
  --reason "abuse investigation"

# Replay a deadlettered delivery
sbproxy-admin webhook replay --deadletter-id <uuid>

# Force an immediate signing-key rotation (compromise scenario)
sbproxy-admin rotate-webhook-key \
  --tenant tenant_42 \
  --immediate \
  --reason "key compromise reported"
```

Every subcommand emits an `AdminAuditEvent`. Default deadletter retention is 30 days; replay before retention expires.

### Rate-limit auto-suspend recovery

A paying-tier workspace dropped to `AutoSuspend` (1 rps for 60 minutes) after 1 000 throttle events in a 5-minute window. The cooldown clears automatically; investigate whether to lift early.

```
sbproxy-admin tenant abuse status --tenant tenant_42
sbproxy-admin tenant abuse restore \
  --tenant tenant_42 \
  --reason "incident #2603 root-caused, legitimate burst"
```

The restore action is audited. A second auto-suspend within 24 hours promotes the tenant to `ManualReview`. ManualReview exit is operator-only and requires a non-empty reason. The full contract lives in `docs/rate-limits-and-budgets.md`.

## Key compromise

Three compromise scenarios are in scope.

1. **Ledger HMAC key compromise.** Treat the ledger as repudiated for the affected window. Rotate the key via the secret-rotation procedure above with a zero overlap window: the new key lands, the old key is revoked at the ledger, and the proxy fails closed for the brief period a request signed with the old key is in flight. Replay the affected window through the synthetic monitor harness to confirm the breaker recovered.
2. **Outbound webhook signing key compromise.** Rotate immediately with a zero overlap window. Inform every customer subscriber that notifications signed with the old key may have been forged by the attacker. The default deployment is single-tenant and the key is shared, so the rotation is fleet-wide.
3. **Bot-auth directory anchor compromise.** Rotate the anchor PEM, clear the directory cache (`/admin/bot-auth/cache/clear` or restart the pod), and force a fresh refresh against the directory URL.

In all three cases, emit an admin-action audit event recording the incident summary, the rotation timestamps, and the affected window; this is what ties the compromise to the audit chain.

## Audit batch chain (v1) cutover and verification

The signed audit log carries a per-workspace hash chain across batches: each batch's signed payload includes `prev_signature_sha256`, a SHA-256 of the previous batch's signature. This is the WOR-23 work and lives in the enterprise audit module. See [`enterprise.md`](enterprise.md) for the enterprise feature surface and how to request access.

### One-time migration steps (per workspace)

The migration is run once per workspace during the v1 chain rollout. It is idempotent: re-running after the marker batch already exists is a no-op.

1. Deploy the new enterprise build of SBproxy that knows about `prev_signature_sha256`. Confirm the rollout is healthy before issuing a flusher restart that would trigger live cutover.
2. Run the migration job:
   ```
   sbproxy-audit-migrate --emit-chain-v1-marker --workspace ws_abc
   ```
   The job reads the most recent v0 batch from the Postgres index, emits a marker batch (empty body, kid prefix `chain-v1-start`, `prev_signature_sha256 = chain_v1_genesis_hash()`), persists it to the object store and the index, and seeds the in-memory chain tail in the running flusher.
3. Confirm the next live flush chains on the marker:
   ```
   sbproxy-audit-verify --chain --keys-file keys.json marker.jsonl.gz first-live.jsonl.gz
   ```
   Expected output:
   ```
   ok: batch_id=<marker> workspace=ws_abc events=0 kid=chain-v1-start-2026-05-03 prev_sig_sha256=<genesis>
   ok: batch_id=<live>   workspace=ws_abc events=N kid=audit-2026-05-03      prev_sig_sha256=<sha256-of-marker-sig>
   chain ok: 2 batches, tail_sig_sha256=<hex>
   ```
4. Snapshot `audit_batches` and the bucket; the marker batch and the first live batch are now permanent on-disk evidence of the migration boundary.

### Routine verification (ongoing)

Run `sbproxy-audit-verify --chain` against any window of batches to confirm the chain walks cleanly. The verifier reports the first chain break it sees with the offending sequence number, batch id, expected hash, and actual hash. Expected outputs:

* Clean walk:
  ```
  chain ok: <N> batches, tail_sig_sha256=<hex>
  ```
* Broken link (the canonical "deleted batch" signal):
  ```
  chain break at seq=<N>, batch_id=<ulid>: prev_signature_sha256 mismatch (expected=<hex>, actual=<hex>)
  ```
* Per-batch verification failure:
  ```
  chain break at seq=<N>, batch_id=<ulid>: per-batch verification failed: audit.verify.bad_signature
  ```
* First-batch genesis mismatch (slice begins outside the chain genesis without a `--chain-anchor`):
  ```
  chain break at seq=0, batch_id=<ulid>: genesis anchor mismatch (expected=<hex>, actual=<hex>)
  ```

For partial slices (auditor pulled only the most recent month), supply `--chain-anchor <hex>` with the SHA-256 of the previous batch's signature so the verifier can resume from the correct anchor.

Exit codes: `0` on clean walk, `1` on any chain break or per-batch failure, `2` on usage errors.

## Capacity planning

Three resource consumers to track:

1. **Per-agent metric series.** Bounded by the cardinality budget in ADR `adr-metric-cardinality.md`. CI gate enforces the budget on every PR; in production, watch `sbproxy_observe_cardinality_demotions_total` and re-roll the budget before the demotion rate exceeds 1% of label-bearing updates.
2. **Trace export volume.** Head-based sampling at the rate configured in `proxy.observability.otlp.sample_rate`. The default ratio of 0.1 (10%) is sized for the reference workload; raise it for incident triage and lower it under steady-state load.
3. **Outbound webhook queue depth.** The framework's deadletter queue is sized via `proxy.notify.deadletter_capacity` (default 1024 entries). Sustained growth indicates a customer endpoint that is rejecting deliveries; check the per-tenant subscription panel on the audit-log dashboard before raising the cap.

## DR procedure

The proxy is by design near-stateless:

1. The proxy's only durable state is the bot-auth directory cache (in-memory, refreshed on boot) and the outbound webhook deadletter queue (configured backing). Both reconstruct from their respective sources after a regional failover.
2. Config (`sb.yml`) lives in source control and is the source of truth; the proxy can boot in any region with a copy.
3. The OTel and Prometheus pipelines are observability-only; loss in a regional failover degrades visibility but does not affect request handling.

Manual drill: in a staging cluster, terminate the proxy pod and time the recovery to first 200 from `/readyz`. Target is under 60 seconds; record the actual in the deploy log.

## Secret and key inventory

This table is the source of truth for secrets and keys the operator holds.

| Name | Type | Mount path | Rotation cadence | Compromise procedure |
|---|---|---|---|---|
| Ledger HMAC key | 32-byte symmetric | `/etc/sbproxy/secrets/ledger-hmac.key` (file referenced by `SBPROXY_LEDGER_HMAC_KEY_FILE`) | 90 days | "Ledger HMAC key compromise" above |
| Outbound webhook signing key | Ed25519 keypair | `/etc/sbproxy/secrets/notify-signing.pem` | 180 days | "Outbound webhook signing key compromise" above |
| Bot-auth directory anchor | PEM public key | `/etc/sbproxy/secrets/bot-auth-anchor.pem` | On vendor rotation | "Bot-auth directory anchor compromise" above |
| OTLP exporter mTLS cert | x509 keypair, optional | `/etc/sbproxy/secrets/otlp-client.pem` | Per collector policy | Reissue from collector CA, hot reload |
