# Secret backends

*Last modified: 2026-06-02*

SBproxy resolves secret material from any of three MVP vault backends, plus the legacy file / env / static-secret shapes. Every backend implements the same `VaultBackend` trait; the operator picks per-backend defaults at config-load and references each backend through the unified `vault://<backend>/<path>[?version=<n>][&key=<json-field>]` URI.

This guide covers the three production-ready backends:

* **HashiCorp Vault** for operators running Vault as the source of truth.
* **AWS Secrets Manager** for in-AWS deployments using the AWS-native credential chain.
* **Kubernetes Secrets** for cluster-local resolution where Secrets live alongside the workload.

Every backend honours an in-process TTL cache (5 minutes by default, configurable per backend) so the hot path does not round-trip to the secret store on every resolution. Every backend enforces a tenant prefix so a misconfigured reference cannot leak across tenants.

## HashiCorp Vault

The HashiCorp client speaks KV v1 or KV v2 against any Vault deployment (OSS or Enterprise). The operator picks one of three auth methods at backend construction.

### Configuration

```yaml
proxy:
  vault:
    - name: hashi
      type: hashicorp
      addr: https://vault.shared.example/v1
      mount: secret/tenants/acme-corp
      engine: v2
      cache_ttl: 5m
      auth:
        type: token
        token: vault://env/VAULT_TOKEN_ACME
```

| Field | Type | Description |
|---|---|---|
| `addr` | string | Vault server URL. Trailing slash is normalised. |
| `mount` | string | KV mount path. Tenant-isolated deployments scope this to a per-tenant directory. |
| `engine` | enum | `v1` or `v2`. KV v2 is the default for new Vault deployments. |
| `cache_ttl` | duration | TTL on cached reads (default 5 minutes). |
| `auth` | object | One of `token`, `approle`, `kubernetes`. See below. |
| `namespace` | string | Optional `X-Vault-Namespace` header (Vault Enterprise). |

### Auth methods

**Token**: operator-supplied static token. Most common for development and small deployments.

```yaml
auth:
  type: token
  token: vault://env/VAULT_TOKEN_ACME
```

**AppRole**: `role_id` + `secret_id` exchanged at backend construction. The backend refreshes the token on a 403 and retries the read once; subsequent token expiries surface to the operator.

```yaml
auth:
  type: approle
  role_id: acme-prod
  secret_id: vault://env/VAULT_SECRET_ID_ACME
  mount: approle             # defaults to `approle`
```

**Kubernetes**: the pod's service-account JWT is exchanged for a Vault token at backend construction. Recommended for in-cluster deployments where the pod has a Vault role bound to its service account.

```yaml
auth:
  type: kubernetes
  role: sbproxy-acme
  jwt_path: /var/run/secrets/kubernetes.io/serviceaccount/token  # default
  mount: kubernetes                                              # default
```

### Reference shape

```
vault://hashi/<sub-path>[?version=<n>][&key=<json-field>]
```

Sub-paths are interpreted under the configured `mount`. A relative reference (`secret/data/openai-prod`) is rewritten to the canonical KV v2 URL; references that already encode `<mount>/data/...` are taken verbatim. The backend rejects paths that escape the configured mount prefix.

### Tenant isolation

Scope each tenant to its own mount directory (`secret/tenants/acme-corp/`) and bind the tenant's Vault token / AppRole role to that path through Vault policy. Cross-tenant reads at the API surface are blocked by Vault's ACL; the backend's mount-prefix guard provides defence in depth against operator typos.

## AWS Secrets Manager

The AWS client speaks the official Secrets Manager API via `aws-sdk-secretsmanager`. The default credential chain works in EC2, ECS, EKS, Lambda, and SSO contexts; the operator can also supply static keys or an assumed IAM role for cross-account access.

### Configuration

```yaml
proxy:
  vault:
    - name: aws
      type: aws_secrets_manager
      region: us-east-1
      mount_prefix: prod/sbproxy/tenants/acme-corp
      cache_ttl: 5m
      auth:
        type: default_chain
```

| Field | Type | Description |
|---|---|---|
| `region` | string | AWS region. Required. |
| `mount_prefix` | string | Path prefix every read must stay inside. Tenant-isolated deployments scope this to a per-tenant directory. |
| `cache_ttl` | duration | TTL on cached reads (default 5 minutes). |
| `auth` | object | One of `static_keys`, `default_chain`, `assumed_role`. See below. |

### Auth methods

**Static keys**: operator-supplied access keys. Useful for development and CI; production deployments should prefer the default chain or assumed role.

```yaml
auth:
  type: static_keys
  access_key_id: vault://env/AWS_ACCESS_KEY_ID
  secret_access_key: vault://env/AWS_SECRET_ACCESS_KEY
  session_token: vault://env/AWS_SESSION_TOKEN   # optional
```

**Default chain**: picks up env vars, EC2 instance profile, ECS task role, SSO, web identity, etc. Recommended for in-AWS deployments.

```yaml
auth:
  type: default_chain
```

**Assumed role**: exchange the proxy's identity for a session in a different account via STS. Used for cross-account access where the proxy lives in account A and the tenant's secrets live in account B.

```yaml
auth:
  type: assumed_role
  role_arn: arn:aws:iam::222222222222:role/sbproxy-acme
  external_id: opt-in-string-from-trust-policy   # optional
  session_name: sbproxy                          # optional
```

### Reference shape

```
vault://aws/<sub-path>[?version=<n>][&key=<json-field>]
```

Sub-paths are interpreted as Secrets Manager secret names under the configured `mount_prefix`. A relative reference (`openai-prod`) lands at `<mount_prefix>/openai-prod`. References that already encode the prefix are taken verbatim; the backend rejects paths that escape it.

Binary secrets (`SecretBinary` rather than `SecretString`) are returned base64-encoded so the on-wire shape is uniform across backends.

### Tenant isolation

Two complementary controls:

* **IAM policy.** Scope `secretsmanager:GetSecretValue` to `arn:aws:secretsmanager:*:*:secret:prod/sbproxy/tenants/${aws:PrincipalTag/sbproxy-tenant}/*` so the proxy's role can only read the tenant's namespace. The principal-tag approach lets one IAM role serve multiple tenants without ACL drift.
* **Backend mount prefix.** The proxy enforces the prefix at URL composition; a typo or malicious reference that escapes the prefix is rejected before any AWS call.

## Kubernetes Secrets

The Kubernetes client speaks the standard Secrets API via the `kube` crate. Each backend is bound to a single namespace; cross-namespace reads are rejected at URL composition.

### Configuration

```yaml
proxy:
  vault:
    - name: k8s
      type: kubernetes
      namespace: tenant-acme
      cache_ttl: 5m
      auth:
        type: in_cluster
```

| Field | Type | Description |
|---|---|---|
| `namespace` | string | Namespace the backend reads from. Cross-namespace references are rejected. |
| `cache_ttl` | duration | TTL on cached reads (default 5 minutes). |
| `auth` | object | One of `in_cluster`, `kubeconfig`. See below. |

### Auth methods

**InCluster**: the pod's service-account token from `/var/run/secrets/kubernetes.io/serviceaccount/` and the API server address from `KUBERNETES_SERVICE_HOST`. Recommended for in-cluster deployments.

```yaml
auth:
  type: in_cluster
```

**Kubeconfig**: explicit kubeconfig path for out-of-cluster operators driving reads from a bastion against a remote cluster.

```yaml
auth:
  type: kubeconfig
  path: /home/operator/.kube/config
  context: acme-prod          # optional: pick a context inside the kubeconfig
```

### Reference shape

```
vault://k8s/<secret>[/<key>]
vault://k8s/<namespace>/<secret>[/<key>]
```

Three valid shapes:

| Reference | Behaviour |
|---|---|
| `<secret>` | Returns the whole secret as a JSON map of key → decoded value. |
| `<secret>/<key>` | Returns a single field. |
| `<ns>/<secret>[/<key>]` | Namespace-explicit reference. The namespace MUST match the backend's configured namespace; mismatch is rejected. |

Both `data` (base64-encoded) and `stringData` (plaintext) fields are honoured. `data` keys are decoded automatically. UTF-8 is required; binary fields surface as decode errors so the operator catches them before they reach the resolver.

### Tenant isolation

A backend per tenant, each scoped to the tenant's namespace. Cross-namespace reads are rejected at URL composition. Pair with the cluster's namespace-level RBAC so the proxy's service account can only `get` Secrets within its namespace.

The write path is not implemented: operators write Kubernetes Secrets through the cluster's GitOps / SealedSecrets workflow rather than through the proxy. A `set` on the backend returns a helpful error pointing at this.

## Legacy reference shapes

The unified `vault://` URI is the canonical form; the legacy shapes keep working unchanged so existing configs do not need to migrate to switch backends.

| Legacy reference | Equivalent `vault://` |
|---|---|
| `${OPENAI_API_KEY}` | `vault://env/OPENAI_API_KEY` |
| `file:/etc/sbproxy/secrets/openai` | `vault://file/etc/sbproxy/secrets/openai` |
| `secret:openai-prod` | `vault://static_secret/openai-prod` (when `proxy.secrets.map.openai-prod` is set) |

The resolver tries each parser in turn: a string without the `vault://` prefix falls through to the legacy parsers exactly as before.

## Multi-tenant resolution

A backend's `<name>` is operator-chosen; the same name re-declared at proxy / tenant / origin scope shadows the broader scope. A request resolved in the context of a tenant walks origin → tenant → proxy and uses the first scope that declares the named backend. See `docs/multi-tenant.md` for the full resolution model.

## Cache semantics

Every backend caches successful reads for the configured TTL. A `set` on the same key invalidates the cache so a follow-up `get` sees the new value. There is no proactive watch-based invalidation today; a future watch hook lands on the Kubernetes backend once the resolver picks up `kube-runtime` watch events.

## Related reading

* `docs/configuration.md` for the proxy / tenant / origin scopes and the `vault.<name>` reference grammar.
* `docs/multi-tenant.md` for the inheritance model and isolation guarantees.
* `docs/migration-credentials.md` for the `virtual_keys:` → `credentials:` migration.
