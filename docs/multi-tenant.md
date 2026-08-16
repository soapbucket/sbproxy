# Multi-tenant deployment

*Last modified: 2026-08-16*

SBproxy serves multiple tenants from a single binary. Each tenant gets its own configuration scope under `proxy.tenants[]`; origins bind to a tenant via `origin.tenant_id`; request-time resolution walks origin → tenant → proxy with most-specific-wins by name.

This guide covers when to use the multi-tenant shape, how the three scopes compose, the isolation guarantees the proxy provides, and the `__default__` synthetic tenant that single-tenant deployments inherit transparently.

## When to use it

Reach for the multi-tenant shape when one or more of the following is true:

* **Per-tenant credentials.** Tenant A pays for OpenAI; tenant B pays for Anthropic; both run through the same proxy.
* **Per-tenant regulatory profile.** Healthcare tenants need HIPAA-shaped PII rules; fintech tenants need PCI; generic tenants need the default email + SSN + credit-card scrub.
* **Per-tenant attribution.** Spend rolls up to the tenant's owning project / cost-center for invoicing.
* **Per-tenant observability sinks.** Tenant A pushes logs to their own Loki under their AWS account; tenant B pushes to a Datadog tenant they own.

A single-tenant deployment does not need to opt in to any of this. Every origin without an explicit `tenant_id` resolves to the synthetic `__default__` tenant; existing configs see no behavior change.

## Three scopes

Credentials are configurable at three layers, listed from broadest to most specific:

* **`proxy.credentials:`**: operator defaults shared across every tenant.
* **`tenants[].credentials:`**: tenant-scoped overrides + additions.
* **`origins[].credentials:`**: origin-scoped overrides + additions (the most specific scope).

Resolution at request time walks origin → tenant → proxy. A block at a more specific scope shadows the broader scope when names match; otherwise the merged set is the union.

A tenant entry carries exactly three fields today: `id`, `credentials`, and `observability`. Policies stay at proxy and origin scope (there is no `tenants[].policies:` block), and secret backends are declared once at proxy scope under `proxy.secrets.backends:` (a per-tenant `vault:` block is a future direction, not a shipped key).

A credential's `key:` is the value an inbound caller presents, and the policy, budget, and attribution attached to it are what that caller then gets. The provider key SBproxy swaps in on the way out is a different field, `providers[].api_key`, and it is the one that takes a `vault://` or `awssm://` reference.

```yaml
proxy:
  credentials:
    - name: openai-shared
      type: ai_provider
      provider: openai
      key: sk-shared-default
      attrs: { project: shared-default }

  tenants:
    - id: acme-corp
      credentials:
        - name: openai-shared              # same NAME as proxy default, different key
          type: ai_provider
          provider: openai
          key: sk-acme-shared
          attrs: { project: acme-prod }

    - id: beta-corp
      credentials:
        - name: openai-experimental         # NEW credential, only for beta-corp
          type: ai_provider
          provider: openai
          key: sk-beta-experimental
          attrs: { project: beta-experimental }

origins:
  api.acme.example.com:
    tenant_id: acme-corp
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: vault://primary/secret/data/acme/openai?key=api_key

  api.beta.example.com:
    tenant_id: beta-corp
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: awssm://primary/beta/openai-experimental?key=api_key
```

In this config, a request to `api.acme.example.com` resolves `openai-shared` to acme-corp's copy; the same name on the proxy default is shadowed, so the proxy default's key does not authenticate there at all. A request to `api.beta.example.com` sees `openai-shared` from the proxy default plus `openai-experimental` from the tenant. The `__default__` tenant (any origin without `tenant_id`) sees only `openai-shared` from the proxy default.

`require_governed_key: true` is what makes any of that observable. Without it, a key that resolved at no scope still reaches the provider, with no policy, no budget, and no attribution, and nothing says so.

## The `__default__` tenant

`__default__` is the synthetic single-tenant fallback. Every origin without an explicit `tenant_id` resolves to `__default__`. The reserved name cannot be declared in `proxy.tenants[]`; doing so fails config compile.

The synthetic tenant inherits proxy-scope defaults verbatim and adds nothing of its own. Single-tenant deployments need no `proxy.tenants[]` declarations at all; the resolution layer collapses to the proxy-scope defaults.

## Per-request resolution

Every request carries a `tenant_id` on the request context, stamped by the routing layer from the matched origin. Downstream layers read it directly:

* **Credentials.** The credentials resolver walks origin → tenant → proxy and picks the credential whose `principals:` selectors match the inbound principal.
* **Policies.** Policies apply at origin scope (with proxy-wide blocks like `rate_limits:` above them). There is no tenant-scoped policy list; a policy that should differ per tenant lives on that tenant's origins.
* **Secrets.** Secret references resolve against the backends declared at proxy scope under `proxy.secrets.backends:`. Tenants do not declare their own backends; per-tenant isolation comes from per-backend path prefixes and the underlying store's ACLs.
* **Observability.** Per-tenant sink fan-out routes structured log lines to the tenant's declared sinks; the global access-log keeps recording every line for the proxy operator.

The resolution context is `(tenant_id, origin_idx, principal)`. A request that fails to match any tenant-scope or origin-scope credential falls back to the proxy default with no per-tenant attribution.

## Isolation guarantees

* **Compile-time tenant validation.** An origin that names an undeclared tenant fails config compile so an operator's typo surfaces at startup rather than at request time.
* **Vault namespace + mount prefix.** Each vault backend enforces a configured path prefix; references that escape the prefix are rejected at URL composition. Pair with the underlying vault's ACL (Vault policies, AWS IAM, Kubernetes RBAC) for defense in depth.
* **Tenant-scoped credentials.** A credential declared at tenant scope only applies to requests whose resolved `tenant_id` matches; the broader proxy scope does not see it.
* **Access log + audit log carry `tenant_id`.** Every emitted row is filterable by tenant downstream.
* **Per-tenant cardinality budgets.** A noisy tenant cannot exhaust the shared metric label space; once a tenant's budget is hit, the cardinality limiter demotes that tenant's new label values to the `__other__` catch-all rather than minting new series. The metric update still happens.

What is NOT guaranteed:

* **Process-level isolation.** Tenants still share one proxy process. A panicking tenant policy now denies that one request with a 500 and increments `sbproxy_policy_panic_total{policy}`, instead of crashing the proxy; this narrows the blast radius of a tenant-triggered panic but does not turn co-tenancy into hard isolation, since a fault outside policy evaluation can still affect every tenant. Production deployments running mutually-untrusting tenants should still run one proxy per trust boundary.
* **Resource quotas.** Per-tenant CPU and memory caps still require an outer orchestrator (cgroups, k8s ResourceQuota). Per-origin rate-limit policies and per-credential rate limits and budgets remain scoped as before. The workspace-level `rate_limits:` escalation ladder is now tenant-keyed: it buckets by the origin's configured tenant, an origin with no `tenant_id` falls into the `__default__` bucket, matching the old single-tenant behavior exactly, and per-tenant series appear on `sbproxy_rate_limit_total{workspace}`. The label value itself changed on upgrade, from `default` to `__default__`; update any dashboard or alert matching `workspace="default"`. That budget shapes request rate, not raw CPU or memory, so it does not cap what a tenant can consume on the shared process.

## Per-tenant cardinality budgets

Prometheus metric label cardinality is the single biggest operational risk in a multi-tenant deployment. SBproxy's cardinality limiter caps the unique label sets per metric family; a tenant that would push the proxy past the cap sees its newest label combinations demoted to a `__other__` catch-all. The cardinality budget is split per tenant so a single noisy tenant cannot demote labels for every other tenant.

Configure the per-tenant cap on the tenant's observability block:

```yaml
proxy:
  tenants:
    - id: acme
      observability:
        cardinality:
          max_series: 5000   # cap unique label values per (metric, label) for this tenant
    - id: noisy-corp
      observability:
        cardinality:
          max_series: 1000   # tighter cap for a tenant known to send wide cardinality
```

Omitting the block leaves the tenant on the proxy-wide per-label default (1000 unique values per label). The synthetic `__default__` tenant continues to share the proxy-wide budget so single-tenant deployments stay bit-for-bit identical to the earlier single-budget behavior.

Overflows fire the `sbproxy_label_cardinality_overflow_per_tenant_total{metric, label, tenant_id}` counter so dashboards can spot which tenant is approaching its cap. The proxy-wide `sbproxy_label_cardinality_overflow_total{metric, label}` counter keeps counting the same demotions without the tenant dimension.

## Audit log `tenant_id`

Every `SecurityAuditEntry` (policy denies, auth failures, framing violations) and every `ConfigAuditEntry` (config reloads, origin diffs) carries an optional `tenant_id` field. Stamp it on construction:

```rust,no_run
SecurityAuditEntry::policy_violation(...)
    .with_tenant_id(ctx.tenant_id.to_string())
    .emit();
```

The field is `#[serde(skip_serializing_if = "Option::is_none")]` so proxy-wide events (a config reload across all tenants) omit it and existing SIEM ingest pipelines stay backward-compatible. Downstream ClickHouse / Splunk / Elastic partitions can now `WHERE tenant_id = 'acme'` to scope investigations to one tenant.

## Adoption path

The recommended sequence:

1. **Start at proxy scope.** Declare every credential under `proxy.credentials:` and every secret backend under `proxy.secrets.backends:`. Confirm the deployment works end-to-end with the synthetic `__default__` tenant.
2. **Add the first tenant.** Declare a tenant under `proxy.tenants[]` with its own `credentials:` block. Bind one origin to that tenant via `origin.tenant_id`.
3. **Migrate per-tenant overrides incrementally.** When a tenant needs its own copy of a credential (different key, different budget), declare it at tenant scope with the same `name:` so it shadows the proxy default for that tenant only.
4. **Stand up per-tenant sinks.** Declare per-tenant observability sinks under `tenants[].observability.log.sinks:` once the credentials shape is stable. Tenant sinks default to the `external` redaction profile.
5. **Wire isolation tests.** Add an e2e fixture per tenant that asserts the tenant cannot read another tenant's secrets through any reference shape.

## Run it

The scope walk is invisible from a config listing and obvious from a curl, so [`examples/multi-tenant-saas/`](../examples/multi-tenant-saas/) is the config above with the provider pointed at a local OpenAI-shaped fixture. Every tenant reaches the same upstream, which means anything that differs between them came from the credential scopes.

```bash
cd examples/multi-tenant-saas
docker compose up -d --wait
```

Acme's own copy of `openai-shared` resolves at acme's origin:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions -H 'Host: acme.local' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-acme-shared' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

```
{"id":"chatcmpl-fixture","object":"chat.completion","created":0,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"fixture response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}
```

The proxy default carries the same name, so at acme's origin it is shadowed and its key is not a key:

```bash
curl -sS -i http://127.0.0.1:8080/v1/chat/completions -H 'Host: acme.local' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-shared-default' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

```
HTTP/1.1 401 Unauthorized
content-type: application/json
content-length: 40
Date: Sun, 02 Aug 2026 05:24:23 GMT
Connection: close

{"error":"governed credential required"}
```

Beta declared a new name instead, which adds rather than shadows, so both keys resolve at beta's origin. And `shared.local`, which declares no `tenant_id`, resolves to `__default__` and refuses beta's tenant-scoped key:

```bash
curl -sS -i http://127.0.0.1:8080/v1/chat/completions -H 'Host: shared.local' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer sk-beta-experimental' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

```
HTTP/1.1 401 Unauthorized
content-type: application/json
content-length: 40
Date: Sun, 02 Aug 2026 05:24:23 GMT
Connection: close

{"error":"governed credential required"}
```

Each served request is filed under the tenant that served it, which is what makes per-tenant spend reporting possible:

```
sbproxy_ai_requests_attributed_total{api_key_id="",model="",origin="acme.local",outcome="gateway_auth_denied",provider="",surface="chat_completions",tenant_id="acme-corp"} 1
sbproxy_ai_requests_attributed_total{api_key_id="",model="",origin="shared.local",outcome="gateway_auth_denied",provider="",surface="chat_completions",tenant_id="__default__"} 1
sbproxy_ai_requests_attributed_total{api_key_id="cfg:9:acme-corp:10:acme.local:openai-shared",model="gpt-4o-mini",origin="acme.local",outcome="ok",provider="openai",surface="chat_completions",tenant_id="acme-corp"} 1
```

`docker compose down -v` tears it down.

## Worked examples

The repository ships three worked examples covering the common shapes:

* `examples/multi-tenant-saas/`: the config above, runnable, with the three scopes asserted against a local fixture.
* `examples/ai-virtual-keys/`: single-tenant credentials block with two team-scoped keys.
* `examples/vault-reference/`: multi-tenant provider references across HashiCorp, AWS, GCP, Kubernetes, file, and static-map backends.

## Related reading

* `docs/configuration.md` for the per-field reference of the three scopes.
* `docs/secrets.md` for the vault backend setup.
* `docs/migration-credentials.md` for the `virtual_keys:` → `credentials:` migration that unblocks per-tenant credentials.
* `docs/observability.md` for the access-log columns, redaction layers, and per-tenant cardinality budget.
