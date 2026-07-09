# Secret Backends

*Last modified: 2026-07-09*

SBproxy resolves secret material through provider-specific reference schemes. The scheme names the provider type, the authority names the configured backend instance, and the path is interpreted by that provider:

```text
<scheme>://<backend-name>/<provider-path>[?version=<n>][&key=<json-field>]
```

Backend instances are declared once, at proxy scope, under `proxy.secrets.backends:`. There is no per-tenant or per-origin backend list. A reference resolves against the backend whose `name` matches the authority segment and whose provider type matches the scheme; to keep tenants on separate stores, declare one named backend per store and reference the right name from each origin.

## Scheme Table

| Scheme | Provider type | Example |
|---|---|---|
| `vault://` | HashiCorp Vault KV | `vault://primary/secret/data/openai-prod?key=api_key` |
| `awssm://` | AWS Secrets Manager | `awssm://primary/openai-prod?version=3&key=api_key` |
| `gcpsm://` | GCP Secret Manager | `gcpsm://primary/openai-api-key?version=latest` |
| `k8ssecret://` | Kubernetes Secret | `k8ssecret://primary/sbproxy-secrets/openai-key` |
| `secretfile://` | Local YAML or JSON secret file | `secretfile://local/openai-prod?key=api_key` |
| `secret://` | Local static secret map | `secret://local/openai-prod` |

Environment variables keep the existing `${ENV_NAME}` form. Do not use an env URI. The legacy non-vault forms also remain valid:

```text
${ENV_NAME}
file:/path/to/secret
secret:<name>
```

The old umbrella form, `vault://<alias>/...`, is still accepted with a warning as of SBproxy 1.5.0; a removal release has not been announced. To rewrite known aliases, run:

```bash
sbproxy config migrate sb.yml --out sb.migrated.yml
```

## HashiCorp Vault

The HashiCorp client speaks KV v1 or KV v2 against Vault OSS or Vault Enterprise. The operator picks one of three auth methods at backend construction.

### Configuration

```yaml
proxy:
  secrets:
    backends:
      - type: hashicorp
        name: primary
        addr: https://vault.shared.example/v1
        mount: secret/tenants/acme-corp
        engine: v2
        cache_ttl_secs: 300
        auth:
          type: token
          token: ${VAULT_TOKEN_ACME}
```

| Field | Type | Description |
|---|---|---|
| `addr` | string | Vault server URL. Trailing slash is normalised. |
| `mount` | string | KV mount path. Tenant-isolated deployments scope this to a per-tenant directory. |
| `engine` | enum | `v1` or `v2`. KV v2 is the default for new Vault deployments. |
| `cache_ttl_secs` | integer | TTL in seconds on cached reads. Default is 300. |
| `auth` | object | One of `token`, `approle`, or `kubernetes`. |
| `namespace` | string | Optional `X-Vault-Namespace` header for Vault Enterprise. |

### Auth Methods

Token auth uses an operator-supplied static token:

```yaml
auth:
  type: token
  token: ${VAULT_TOKEN_ACME}
```

AppRole exchanges `role_id` and `secret_id` at backend construction. The backend refreshes the token on a 403 and retries the read once.

```yaml
auth:
  type: approle
  role_id: acme-prod
  secret_id: ${VAULT_SECRET_ID_ACME}
  mount: approle
```

Kubernetes auth exchanges the pod's service-account JWT for a Vault token. Use it for in-cluster deployments where the pod has a Vault role bound to its service account.

```yaml
auth:
  type: kubernetes
  role: sbproxy-acme
  jwt_path: /var/run/secrets/kubernetes.io/serviceaccount/token
  mount: kubernetes
```

### Reference Shape

```text
vault://primary/<sub-path>[?version=<n>][&key=<json-field>]
```

Sub-paths are interpreted under the configured `mount`. A relative reference such as `secret/data/openai-prod` is rewritten to the canonical KV v2 URL. References that already encode `<mount>/data/...` are taken verbatim. The backend rejects paths that escape the configured mount prefix.

## AWS Secrets Manager

The AWS client speaks the official Secrets Manager API. The default credential chain works in EC2, ECS, EKS, Lambda, SSO, and web identity contexts. The operator can also supply static keys or an assumed IAM role for cross-account access.

### Configuration

```yaml
proxy:
  secrets:
    backends:
      - type: aws
        name: primary
        region: us-east-1
        mount_prefix: prod/sbproxy/tenants/acme-corp
        cache_ttl_secs: 300
        auth:
          type: default_chain
```

| Field | Type | Description |
|---|---|---|
| `region` | string | AWS region. Required. |
| `mount_prefix` | string | Path prefix every read must stay inside. Tenant deployments scope this to a per-tenant directory. |
| `cache_ttl_secs` | integer | TTL in seconds on cached reads. Default is 300. |
| `auth` | object | One of `static_keys`, `default_chain`, or `assumed_role`. |

### Auth Methods

Static keys are useful for development and CI. Production deployments should prefer the default chain or assumed role.

```yaml
auth:
  type: static_keys
  access_key_id: ${AWS_ACCESS_KEY_ID}
  secret_access_key: ${AWS_SECRET_ACCESS_KEY}
  session_token: ${AWS_SESSION_TOKEN}
```

Default chain picks up env vars, EC2 instance profile, ECS task role, SSO, web identity, and other AWS-standard sources.

```yaml
auth:
  type: default_chain
```

Assumed role exchanges the proxy's identity for a session in a different account.

```yaml
auth:
  type: assumed_role
  role_arn: arn:aws:iam::222222222222:role/sbproxy-acme
  external_id: opt-in-string-from-trust-policy
  session_name: sbproxy
```

### Reference Shape

```text
awssm://primary/<secret-id>[?version=<n>][&key=<json-field>]
```

The path is a Secrets Manager secret id under the configured `mount_prefix`. A relative reference such as `openai-prod` lands at `<mount_prefix>/openai-prod`. References that already encode the prefix are taken verbatim. The backend rejects paths that escape it.

Binary secrets are returned base64-encoded so the resolved value is text across all backends.

## GCP Secret Manager

The GCP backend reads Secret Manager through the `AccessSecretVersion` API. It supports Application Default Credentials, service-account key files or inline JSON, and external-account Workload Identity Federation files.

### Configuration

```yaml
proxy:
  secrets:
    backends:
      - type: gcp
        name: primary
        project_id: acme-prod
        cache_ttl_secs: 300
        auth: application_default
```

| Field | Type | Description |
|---|---|---|
| `project_id` | string | Default project for short references such as `gcpsm://primary/openai-api-key`. If omitted, the backend uses `GOOGLE_CLOUD_PROJECT`, `GCLOUD_PROJECT`, or the ADC project id. |
| `endpoint` | string | Secret Manager API endpoint. Defaults to `https://secretmanager.googleapis.com`. |
| `cache_ttl_secs` | integer | TTL on cached reads. Default is 300 seconds. |
| `auth` | enum or object | `application_default`, `service_account_key_file`, `service_account_key_json`, or `external_account_file`. |

### Reference Shape

```text
gcpsm://primary/<secret>[?version=<n>][&key=<json-field>]
gcpsm://primary/projects/<project>/secrets/<secret>[?version=<n>][&key=<json-field>]
gcpsm://primary/projects/<project>/secrets/<secret>/versions/<version>[&key=<json-field>]
```

The default version is `latest`. Secret payload bytes must decode as UTF-8. Use `key=<json-field>` when the payload is a JSON object and the config field needs one member.

## Kubernetes Secrets

The Kubernetes backend reads Secret objects through the standard Kubernetes API. Each backend is bound to one namespace; cross-namespace reads are rejected at URL composition.

### Configuration

```yaml
proxy:
  secrets:
    backends:
      - type: k8s
        name: primary
        namespace: tenant-acme
        cache_ttl_secs: 300
        auth:
          type: in_cluster
```

| Field | Type | Description |
|---|---|---|
| `namespace` | string | Namespace the backend reads from. Cross-namespace references are rejected. |
| `cache_ttl_secs` | integer | TTL in seconds on cached reads. Default is 300. |
| `auth` | object | One of `in_cluster` or `kubeconfig`. |

### Auth Methods

In-cluster auth reads the pod's service-account token and Kubernetes API server address from the standard in-cluster files and env vars.

```yaml
auth:
  type: in_cluster
```

Kubeconfig auth selects an explicit kubeconfig file for out-of-cluster operators.

```yaml
auth:
  type: kubeconfig
  path: /home/operator/.kube/config
  context: acme-prod
```

### Reference Shape

```text
k8ssecret://primary/<secret>[/<key>]
k8ssecret://primary/<namespace>/<secret>[/<key>]
```

Valid shapes:

| Reference path | Behaviour |
|---|---|
| `<secret>` | Returns the whole secret as a JSON map of key to decoded value. |
| `<secret>/<key>` | Returns a single field from the configured namespace. |
| `<namespace>/<secret>[/<key>]` | Uses an explicit namespace. It must match the backend's configured namespace. |

Both `data` and `stringData` fields are honoured. `data` keys are base64-decoded automatically. UTF-8 is required; binary fields surface as decode errors.

## File And Static Map Backends

Use `secretfile://` for a backend-configured YAML or JSON secret file. Use `secret://` for a backend-configured static secret map. Keep `file:/path/to/secret` and `secret:<name>` for legacy configs that already use those forms.

Configure these backends under `proxy.secrets.backends`. Each has a `name` used in the reference. A `local` backend's `entries` values may be `${ENV}` so real secrets stay in the environment rather than the config file. A reference in an AI provider `api_key` resolves against these at startup, and an unresolved reference stops the proxy from starting rather than being sent verbatim as a bearer token.

```yaml
proxy:
  secrets:
    backends:
      - type: file
        name: local
        path: /etc/sbproxy/secrets.yaml
        format: yaml
      - type: local
        name: app
        entries:
          openai_key: "${OPENAI_KEY}"
```

```text
secretfile://local/openai-prod?key=api_key
secret://app/openai_key
```

## Scope

Backends are declared at proxy scope under `proxy.secrets.backends`, and every origin resolves references against that one set. A reference names the backend it wants, so you can point different origins at different physical stores by giving each store its own backend name:

```yaml
proxy:
  secrets:
    backends:
      - type: hashicorp
        name: shared
        addr: https://vault.shared.example/v1
        mount: secret/tenants/shared
        auth:
          type: token
          token: ${VAULT_TOKEN}
      - type: hashicorp
        name: acme
        addr: https://vault.acme.example/v1
        mount: secret/tenants/acme-corp
        auth:
          type: token
          token: ${VAULT_TOKEN_ACME}
```

An origin that reads `vault://acme/secret/data/openai-prod?key=api_key` resolves through the `acme` backend; one that reads `vault://shared/...` uses the shared store.

Per-tenant and per-origin backend scopes (where the same reference name resolves to a different physical store depending on the request's tenant) are not wired yet. Give each store a distinct backend name at proxy scope for now.

## Cache Semantics

Every backend caches successful reads for the configured TTL. A `set` on the same key invalidates the cache so a follow-up `get` sees the new value. There is no proactive watch-based invalidation today. A future watch hook can invalidate Kubernetes entries when Secret objects change.

## Related Reading

* `docs/configuration.md` for the `proxy.secrets` block and reference URI grammar.
* `docs/multi-tenant.md` for the inheritance model and isolation guarantees.
* `docs/migration-credentials.md` for the `virtual_keys:` to `credentials:` migration and the vault reference migration note.
