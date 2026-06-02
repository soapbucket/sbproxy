# Multi-tenant deployment

*Last modified: 2026-06-02*

SBproxy serves multiple tenants from a single binary. Each tenant gets its own configuration scope under `proxy.tenants[]`; origins bind to a tenant via `origin.tenant_id`; request-time resolution walks origin → tenant → proxy with most-specific-wins by name.

This guide covers when to use the multi-tenant shape, how the three scopes compose, the isolation guarantees the proxy provides, and the `__default__` synthetic tenant that single-tenant deployments inherit transparently.

## When to use it

Reach for the multi-tenant shape when one or more of the following is true:

* **Per-tenant credentials.** Tenant A pays for OpenAI; tenant B pays for Anthropic; both run through the same proxy.
* **Per-tenant regulatory profile.** Healthcare tenants need HIPAA-shaped PII rules; fintech tenants need PCI; generic tenants need the default email + SSN + credit-card scrub.
* **Per-tenant attribution.** Spend rolls up to the tenant's owning project / cost-center for invoicing.
* **Per-tenant observability sinks.** Tenant A pushes logs to their own Loki under their AWS account; tenant B pushes to a Datadog tenant they own.

A single-tenant deployment does not need to opt in to any of this. Every origin without an explicit `tenant_id` resolves to the synthetic `__default__` tenant; existing configs see no behaviour change.

## Three scopes

Every credential / policy / vault block is configurable at three layers, listed from broadest to most specific:

* **`proxy.<block>`**: operator defaults shared across every tenant.
* **`tenants[].<block>`**: tenant-scoped overrides + additions.
* **`origins[].<block>`**: origin-scoped overrides + additions (the most specific scope).

Resolution at request time walks origin → tenant → proxy. A block at a more specific scope shadows the broader scope when names match; otherwise the merged set is the union.

```yaml
proxy:
  credentials:
    - name: openai-shared
      type: ai_provider
      provider: openai
      key: vault://env/OPENAI_PROXY_DEFAULT

  tenants:
    - id: acme-corp
      credentials:
        - name: openai-shared              # same NAME as proxy default, different key
          type: ai_provider
          provider: openai
          key: vault://hashi/secret/data/acme/openai
          attrs: { project: acme-prod }

    - id: beta-corp
      credentials:
        - name: openai-experimental         # NEW credential, only for beta-corp
          type: ai_provider
          provider: openai
          key: vault://aws/beta/openai-experimental?key=api_key
          attrs: { project: beta-experimental }

origins:
  api.acme.example.com:
    tenant_id: acme-corp
    action:
      type: ai_proxy
      providers:
        - name: openai

  api.beta.example.com:
    tenant_id: beta-corp
    action:
      type: ai_proxy
      providers:
        - name: openai
```

In this config, a request to `api.acme.example.com` resolves `openai-shared` to acme-corp's hashi-backed key; the same name on the proxy default is shadowed. A request to `api.beta.example.com` sees `openai-shared` from the proxy default plus `openai-experimental` from the tenant. The `__default__` tenant (any origin without `tenant_id`) sees only `openai-shared` from the proxy default.

## The `__default__` tenant

`__default__` is the synthetic single-tenant fallback. Every origin without an explicit `tenant_id` resolves to `__default__`. The reserved name cannot be declared in `proxy.tenants[]`; doing so fails config compile.

The synthetic tenant inherits proxy-scope defaults verbatim and adds nothing of its own. Single-tenant deployments need no `proxy.tenants[]` declarations at all; the resolution layer collapses to the proxy-scope defaults.

## Per-request resolution

Every request carries a `tenant_id` on the request context, stamped by the routing layer from the matched origin. Downstream layers read it directly:

* **Credentials.** The credentials resolver walks origin → tenant → proxy and picks the credential whose `principals:` selectors match the inbound principal.
* **Policies.** The policy engine walks the same scopes and unions the policy list, with most-specific-first ordering for `match_principal` selectors.
* **Vault.** Secret references resolve against the backend declared at the most specific scope that defines the named backend.
* **Observability.** Per-tenant sink fan-out routes structured log lines to the tenant's declared sinks; the global access-log keeps recording every line for the proxy operator.

The resolution context is `(tenant_id, origin_idx, principal)`. A request that fails to match any tenant-scope or origin-scope credential falls back to the proxy default with no per-tenant attribution.

## Isolation guarantees

* **Compile-time tenant validation.** An origin that names an undeclared tenant fails config compile so an operator's typo surfaces at startup rather than at request time.
* **Vault namespace + mount prefix.** Each vault backend enforces a configured path prefix; references that escape the prefix are rejected at URL composition. Pair with the underlying vault's ACL (Vault policies, AWS IAM, Kubernetes RBAC) for defence in depth.
* **Tenant-scoped credentials.** A credential declared at tenant scope only applies to requests whose resolved `tenant_id` matches; the broader proxy scope does not see it.
* **Access log + audit log carry `tenant_id`.** Every emitted row is filterable by tenant downstream.
* **Per-tenant cardinality budgets.** A noisy tenant cannot exhaust the shared metric label space; the cardinality limiter rejects new label sets once the per-tenant budget is hit.

What is NOT guaranteed:

* **Process-level isolation.** Tenants share the proxy process; a tenant whose policy triggers a panic crashes the whole proxy. Production deployments running mutually-untrusting tenants should run one proxy per trust boundary.
* **Resource quotas.** Per-tenant CPU / memory caps require an outer orchestrator (cgroups, k8s ResourceQuota). The proxy enforces per-tenant rate limits and per-credential budgets, not raw resources.

## Per-tenant cardinality budgets

Prometheus metric label cardinality is the single biggest operational risk in a multi-tenant deployment. SBproxy's cardinality limiter caps the unique label sets per metric family; a tenant that would push the proxy past the cap sees its newest label combinations demoted to a `__other__` catch-all. WOR-1067 split this budget per tenant so a single noisy tenant cannot demote labels for every other tenant.

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

Omitting the block leaves the tenant on the per-tenant default (10000 unique values per label). The synthetic `__default__` tenant continues to share the proxy-wide budget so single-tenant deployments stay bit-for-bit identical to pre-WOR-1067 behaviour.

Overflows fire the `sbproxy_label_cardinality_overflow_total{tenant_id, metric, label}` counter so dashboards can spot which tenant is approaching its cap.

## Audit log `tenant_id`

Every `SecurityAuditEntry` (policy denies, auth failures, framing violations) and every `ConfigAuditEntry` (config reloads, origin diffs) carries an optional `tenant_id` field. Stamp it on construction:

```rust
SecurityAuditEntry::policy_violation(...)
    .with_tenant_id(ctx.tenant_id.to_string())
    .emit();
```

The field is `#[serde(skip_serializing_if = "Option::is_none")]` so proxy-wide events (a config reload across all tenants) omit it and existing SIEM ingest pipelines stay backward-compatible. Downstream ClickHouse / Splunk / Elastic partitions can now `WHERE tenant_id = 'acme'` to scope investigations to one tenant.

## Adoption path

The recommended sequence:

1. **Start at proxy scope.** Declare every credential / policy / vault backend under `proxy.<block>:`. Confirm the deployment works end-to-end with the synthetic `__default__` tenant.
2. **Add the first tenant.** Declare a tenant under `proxy.tenants[]` with its own `credentials:` + `vault:` blocks. Bind one origin to that tenant via `origin.tenant_id`.
3. **Migrate per-tenant overrides incrementally.** When a tenant needs its own copy of a credential (different key, different budget), declare it at tenant scope with the same `name:` so it shadows the proxy default for that tenant only.
4. **Stand up per-tenant sinks.** Declare per-tenant observability sinks under `tenants[].observability.log.sinks:` once the credentials shape is stable. Tenant sinks default to the `external` redaction profile.
5. **Wire isolation tests.** Add an e2e fixture per tenant that asserts the tenant cannot read another tenant's secrets through any reference shape.

## Worked examples

The repository ships three worked examples covering the common shapes:

* `examples/ai-virtual-keys/`: single-tenant credentials block with two team-scoped keys.
* `examples/vault-reference/`: multi-tenant `vault://` references across HashiCorp / AWS / k8s / SQLite.
* `examples/multi-tenant-saas/` (planned): full SaaS deployment with per-tenant vaults, credentials, observability sinks, and isolation tests.

## Related reading

* `docs/configuration.md` for the per-field reference of the three scopes.
* `docs/secrets.md` for the vault backend setup.
* `docs/migration-credentials.md` for the `virtual_keys:` → `credentials:` migration that unblocks per-tenant credentials.
* `docs/observability.md` for the access-log columns, redaction layers, and per-tenant cardinality budget.
