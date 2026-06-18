# ADR: Vault Reference Schemes

*Last modified: 2026-06-18*

Status: accepted and implemented.

## Context

SBproxy currently documents and parses a single umbrella secret-reference form:

```text
vault://<backend>/<path>[?version=<n>][&key=<json-field>]
```

That shape overloads one string segment. The `vault://` scheme looks like HashiCorp Vault, but the first path segment actually selects any registered backend alias such as `hashi`, `aws`, `k8s`, `file`, or `env`. In a multi-tenant proxy this is hard to reason about because the URI does not say which provider type owns the reference. It also blocks clean support for GCP Secret Manager because another alias under the same umbrella would deepen the ambiguity.

The direction is to make the URI scheme name the provider type. Registered backend instance selection remains tenant-scoped.

## Decision

Use per-provider URI schemes. The scheme selects the backend type, and the URI authority selects the registered backend instance within the request's resolution scope.

```text
<scheme>://<backend-name>/<provider-path>[?version=<n>][&key=<json-field>]
```

Resolution walks the existing scopes in this order:

1. Origin scoped backends.
2. Tenant scoped backends.
3. Proxy scoped backends.

Within each scope, the resolver looks for a backend named `<backend-name>` whose configured type matches `<scheme>`. If no matching backend exists in a scope, it continues to the next scope. A name collision across different provider types is allowed because the scheme is part of the lookup key. A name collision within the same provider type follows the normal scope shadowing rule: origin wins over tenant, tenant wins over proxy.

The backend name is required in the URI authority. Do not use `?backend=name` as the primary selector.

Rationale:

* The authority segment is visible and stable in logs, config review, and redaction traces.
* Query parameters remain provider-specific selectors such as `version`, `key`, `project`, or `namespace`.
* Requiring the backend name avoids hidden behavior changes when a second backend of the same type is added to a scope.
* The same reference text can still resolve to tenant-specific physical stores because each tenant can declare the same backend name with a different endpoint, region, namespace, or credential.

## Scheme Table

| Scheme | Provider type | Canonical example | Notes |
|---|---|---|---|
| `vault://` | HashiCorp Vault KV | `vault://primary/secret/data/openai-prod?key=api_key` | `vault://` is HashiCorp Vault only after the migration. |
| `awssm://` | AWS Secrets Manager | `awssm://primary/prod/openai-keys?version=3&key=api_key` | Path is the Secrets Manager secret id under the backend's configured prefix. |
| `gcpsm://` | GCP Secret Manager | `gcpsm://primary/projects/acme/secrets/openai-key?version=latest` | Child implementation may allow a shorter secret id when the backend config fixes the project. |
| `k8ssecret://` | Kubernetes Secret | `k8ssecret://primary/sbproxy-secrets/openai-key` | Backend config fixes the default namespace. An explicit namespace may be carried as `?namespace=<name>` and must match backend policy. |
| `secretfile://` | Local file secret store | `secretfile://local/openai-prod?key=api_key` | Use a backend-configured root directory. Do not use reserved `file://`. |
| `secret://` | Local static secret map | `secret://local/openai-prod` | Covers operator-provided static secret maps. Existing `secret:<name>` remains the legacy shorthand. |

Do not add an `env://` replacement or another URI replacement for environment variables. Environment variables keep the existing `${ENV_NAME}` form. That form is already unambiguous, does not need backend registration, and avoids treating process environment as a network-style URI authority.

SQLite-backed or other local stores are not part of the first migration table. If retained later, add a provider-specific scheme rather than placing them under `vault://`.

## Provider Path Rules

The parser should keep provider paths mostly opaque. Provider-specific validation belongs in the backend implementation.

Common query parameters:

| Query parameter | Meaning |
|---|---|
| `version` | Version selector where the provider supports versioning. |
| `key` | JSON or map sub-field selector extracted from the secret value. |

Other query parameters are provider-specific and should round trip through the parsed reference for backend validation.

Provider-specific path guidance:

* HashiCorp Vault: path is the KV path relative to the backend's mount rules, matching today's backend behavior.
* AWS Secrets Manager: path is the secret id. The backend may prepend its configured `mount_prefix` and must reject escapes.
* GCP Secret Manager: path may be a full resource path or a backend-relative secret id. `version` defaults to `latest`.
* Kubernetes Secret: path is `<secret>` or `<secret>/<key>`. Prefer `key` query for new examples when the key could contain `/`.
* File secret store: path is relative to the backend root. Absolute host filesystem paths remain the legacy `file:/path` shape.

## Schema Version

This fits `schema-v1`.

The config schema models secret-bearing fields as strings today. The provider-reference URI grammar is parsed by `sbproxy-vault`, and the schema generator does not yet emit the vault backend blocks. Changing the accepted URI grammar does not require a schema-version bump as long as:

* Existing string fields remain strings.
* The `v1_compat` test stays green.
* New backend configuration fields are additive.

If a future ticket changes secret-bearing fields from strings to tagged objects, that change needs its own schema decision.

## Deprecation Timeline

Use one minor release of accept-with-warning for the legacy umbrella form:

```text
vault://<alias>/<path>
```

The compatibility shim is scheduled for removal in SBproxy `1.2.0`.

During the deprecation window:

* Parse legacy references through a compatibility shim.
* Resolve them against the existing alias behavior.
* Emit one warning per unique legacy reference per process lifetime.
* Include the migrated form and removal version in the warning when it can be inferred.

Operators can rewrite known aliases in-place or in CI with:

```bash
sbproxy config migrate sb.yml --out sb.migrated.yml
```

The migration helper rewrites legacy AWS aliases to `awssm://...`,
Kubernetes aliases to `k8ssecret://...`, file aliases to
`secretfile://...`, and environment aliases to `${NAME}`. Legacy
HashiCorp aliases remain syntactically valid because HashiCorp Vault
owns `vault://` after the migration, but the runtime still logs the
deprecation warning during the window.

After the window, remove the shim and reject legacy umbrella references during config validation.

Do not remove legacy non-vault shapes in this work. These remain valid:

```text
${ENV_NAME}
file:/path/to/secret
secret:<name>
```

## Examples

Proxy default and tenant override using the same reference text:

```yaml
proxy:
  vault:
    - name: primary
      type: hashicorp
      addr: https://vault.shared.example/v1
      mount: secret/tenants/shared

tenants:
  acme:
    vault:
      - name: primary
        type: hashicorp
        addr: https://vault.acme.example/v1
        mount: secret/tenants/acme

origins:
  "api.acme.example":
    tenant_id: acme
    action:
      type: proxy
      url: http://127.0.0.1:9000
      providers:
        - provider: openai
          api_key: vault://primary/secret/data/openai-prod?key=api_key
```

The `vault://primary/...` reference resolves against the tenant scoped HashiCorp backend for `acme`. The same reference on a default tenant origin resolves against the proxy scoped backend.

Mixed provider examples:

```yaml
auth:
  bearer:
    tokens:
      - ${INTERNAL_BEARER_TOKEN}
      - vault://primary/secret/data/inbound/admin-token?key=token
      - awssm://primary/prod/sbproxy-inbound-tokens?version=3&key=admin
      - gcpsm://primary/projects/acme/secrets/inbound-token?version=latest
      - k8ssecret://primary/sbproxy-secrets/inbound-token
      - secret://local/admin-token
```

## Implementation Notes

`VaultRef` carries:

* `scheme` or provider type.
* `backend` from the URI authority.
* provider path.
* common `version` and `key` query fields.
* extra query parameters.
* a legacy marker for the compatibility shim.

The runtime accepts old `vault://<alias>` references with a warning during the deprecation window. Public docs, examples, and generated reference text use the provider-specific scheme table above.
