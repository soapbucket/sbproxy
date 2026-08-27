# Secret Backends

*Last modified: 2026-08-27*

SBproxy resolves every secret-bearing config value through one reference grammar, checked by one function. A provider credential under `credentials:`, a `source:` block's `credential` field, the `pepper` and `master_key` under `key_management.crypto`, and the value each provider URI on this page resolves to are all meant to go through that same grammar, in the same order, with the same failure behavior. There is nothing field-specific to learn: a form that works in one secret-bearing field works in all of them.

Three shapes read a value directly (an environment variable, a file, or a value already in hand); a fourth shape is a provider URI that names a configured backend:

```text
<scheme>://<backend-name>/<provider-path>[?version=<n>][&key=<json-field>]
```

The scheme names the provider type, the authority names the configured backend instance, and the path is interpreted by that provider. Backend instances are declared once, at proxy scope, under `proxy.secrets.backends:`. There is no per-tenant or per-origin backend list. A reference resolves against the backend whose `name` matches the authority segment and whose provider type matches the scheme; to keep tenants on separate stores, declare one named backend per store and reference the right name from each origin. See [Reference Forms](#reference-forms) below for the complete grammar, and the sections after that for configuring each backend type.

## Backends are process-owned: changing them needs a restart

The resolver is built once, at startup, and it owns live connections to whatever you configured: a Vault client, an AWS or GCP SDK client, a Kubernetes API client. Swapping that out underneath a running proxy is not something a config reload can do safely, so it does not try.

A reload whose `proxy.secrets` block differs from the one the process started with is **refused**, with an error saying a restart is required. The previous config keeps serving and nothing from the candidate is applied. This includes adding a backend, removing one, renaming one, repointing a Vault address, and changing the rotation or fallback settings.

Earlier versions accepted the reload and silently ignored the change. That was worse than refusing: the new backend never existed, so the first reference to it failed at handler construction with an error that named the reference rather than the real cause, and the reload that introduced it had already reported success. If you are used to that behavior, the refusal is the fix, not a regression.

Everything else in a config still hot-reloads normally. Only the `proxy.secrets` block carries this restriction, and only when it actually changes; reloading an unchanged block is a no-op. The values behind a reference are re-resolved on every reload, so rotating a secret **in** Vault or Secrets Manager needs no restart. It is only changing where SBproxy looks that does.

## Reference Forms

Four shapes make up the current vocabulary. Anything that does not match one of them is a literal value, passed through unchanged.

1. **`${VAR_NAME}`** - whole-value environment variable substitution. The entire value must be exactly `${VAR_NAME}`; an env-style token embedded inside a larger string, like `"Bearer ${TOKEN}"`, is left alone as a literal and logs a warning, because only a whole-value wrapper expands.
2. **`env:VAR_NAME`** - the same environment variable lookup, spelled as an explicit prefix instead of a `${}` wrapper. Fails the same way as `${VAR_NAME}` for the same missing variable; use whichever spelling reads better in context.
3. **`file:/path/to/secret`** - read the file at the given path and use its trimmed contents as the value.
4. **A provider URI**, `<scheme>://<backend-name>/<provider-path>[?version=<n>][&key=<json-field>]` - resolved against a named backend declared under `proxy.secrets.backends:`. A miss (unknown backend, missing key, unreachable store) is a hard error; the reference is never sent upstream verbatim.

### Provider URI Schemes

| Scheme | Provider type | Example |
|---|---|---|
| `vault://` | HashiCorp Vault KV | `vault://primary/secret/data/openai-prod?key=api_key` |
| `awssm://` | AWS Secrets Manager | `awssm://primary/openai-prod?version=3&key=api_key` |
| `gcpsm://` | GCP Secret Manager | `gcpsm://primary/openai-api-key?version=latest` |
| `azurekv://` | Azure Key Vault | `azurekv://primary/openai-api-key?version=6a2b45c8f9e14e0d` |
| `k8ssecret://` | Kubernetes Secret | `k8ssecret://primary/sbproxy-secrets/openai-key` |
| `secretfile://` | Local YAML or JSON secret file | `secretfile://local/openai-prod?key=api_key` |
| `localsecret://` | Local static secret map | `localsecret://local/openai-prod` |
| `secret://` | Local static secret map (deprecated alias of `localsecret://`) | `secret://local/openai-prod` |

`localsecret://` selects the local static-map provider, the same provider a backend configures with `type: local` (see [File And Static Map Backends](#file-and-static-map-backends) below). It has no relationship to environment variables: `localsecret://env/some-key` looks up a key named `some-key` in a backend named `env`, which is not the `env:` environment-variable form above. There is no `env://` URI scheme; write `${VAR_NAME}` or `env:VAR_NAME` for environment variables instead. `secret://` resolves identically and still works, but logs a one-time deprecation warning; write `localsecret://` in new config.

See [`examples/vault-reference/`](../examples/vault-reference/) for a
complete working config showing every scheme above alongside `${ENV}`.

### Where These Forms Are Refused

Two of the four read the proxy host directly: `env:NAME` (and its `${VAR_NAME}` and legacy `vault://env/NAME` spellings) reads the process environment, and `file:PATH` reads the filesystem. Config text the operator did not write is not allowed to use them, because the party that wrote that text is not the party that owns the host it compiles on:

* A **config-authority bundle** may not carry one, at publish and again at the subscriber.
* A **git-sourced document** may not carry one when its `source:` block sets `confine: true`. That is off by default, so an ordinary GitOps repository keeps writing `env:` and `file:` as documented here, and gets one warning per finding at boot naming what `confine: true` would refuse; see [Config source (GitOps)](configuration.md#config-source-gitops).
* An **extension bundle manifest** may not supply one for its own config vars, and there the provider URIs are refused too, because guest code reads its config.

A provider URI resolves in all but the last case, because it can only reach a backend the operator declared under `proxy.secrets.backends`. The full rule, and what it does not cover, is in [Confined fragments](configuration.md#confined-fragments).

### Deprecated Forms

Two older shapes still work, each logging a one-time warning, and neither is what to write in new config:

* **`vault://env/NAME`** resolves `NAME` from the environment, identically to `${NAME}` or `env:NAME`. It predates the provider-specific schemes above; replace it with `${NAME}` or `env:NAME`.
* **`vault://<alias>/...`** for `alias` in `aws`, `k8s`, `file`, `hashi` rewrites to the matching provider-specific scheme (`awssm://`, `k8ssecret://`, `secretfile://`, `vault://`) with `<alias>` carried over as the backend name. Still accepted with a warning as of SBproxy 1.11.0; the warning names 1.2.0 as the scheduled removal version, but no release has actually removed it yet.

Run this to rewrite known legacy aliases across a config file:

```bash
sbproxy config migrate sb.yml --out sb.migrated.yml
```

### Removed Forms

The Go-era `secret:<name>` colon form (no `//`) is gone. It is not a fallback and does not pass through: writing it fails config load with a message pointing at the replacement, `localsecret://<backend>/<name>` with a backend declared under `proxy.secrets.backends`. The `proxy.secrets.map` key that used to serve this form no longer resolves it, but the key is not fully inert: a non-empty map still installs the process secret resolver even when no backends are declared, and `sbproxy plan` validates any leftover `secret:<name>` string reference against the map's keys, reporting an undeclared one as a `missing-vault-key` finding. Do not confuse the removed colon form with `secret://`/`localsecret://`, the URI scheme documented above, which is deprecated-but-working (`secret://`) or current (`localsecret://`), not removed.

> **Implementation note.** The vocabulary above is transcribed from `crates/sbproxy-vault/src/resolver.rs`'s `SecretResolver::resolve`, the target every secret-bearing field is meant to route through. Most already do: provider credentials, the `source:` block's `credential` field, and at-rest key material under `key_management.crypto` all resolve through it. Two call sites are narrower today, for different reasons:
>
> * A backend's own construction fields (a Vault `auth.token`, AWS static keys, and similar, in the `proxy.secrets.backends:` entries below) only expand whole-value `${VAR}` and fall back to the literal string on a missing variable instead of erroring. This is a bootstrapping constraint, not a migration gap: these values configure the backend that `SecretResolver` will use, so they cannot depend on it existing yet.
> * `proxy.cluster.security.shared_key` accepts only `env:NAME`, `file:PATH`, or an inline value of at least 16 bytes, and rejects every provider URI scheme outright, including `vault://`. Those two forms are also the two a confined document may not carry. A clustered node whose config comes from a `source:` block with `confine: true` writes `shared_key: "${SB_CLUSTER_SHARED_KEY}"` instead: `${VAR}` survives confinement, is substituted before the key is validated, and fails the compile closed when the variable is unset. This one is deliberate: a provider URI is long enough to clear the inline-entropy floor, so accepting it as a literal would silently install a well-known string, published in a doc like this one, as the cluster's shared key.
>
> If you find some other field silently accepting a different syntax than what is documented here, treat that as a bug worth filing rather than a feature of that field.

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
| `addr` | string | Vault server URL. Trailing slash is normalized. |
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

## Azure Key Vault

The Azure backend reads secrets through the Key Vault `GetSecret` REST API. It supports system-assigned and user-assigned managed identity, service-principal client credentials, and the logged-in Azure CLI for local development.

### Configuration

```yaml
proxy:
  secrets:
    backends:
      - type: azure
        name: primary
        vault_url: https://acme-prod.vault.azure.net
        cache_ttl_secs: 300
        auth: managed_identity
```

| Field | Type | Description |
|---|---|---|
| `vault_url` | string | Key Vault URL such as `https://acme-prod.vault.azure.net`. Required. The token audience follows the vault's DNS suffix, so sovereign-cloud vaults (`*.vault.azure.cn`, `*.vault.usgovcloudapi.net`) work without extra settings. |
| `cache_ttl_secs` | integer | TTL in seconds on cached reads. Default is 300. |
| `auth` | enum or object | `managed_identity`, `user_assigned_identity`, `service_principal`, or `azure_cli`. |

### Auth Methods

Managed identity is the default and the recommended choice for in-Azure deployments. On VMs and VM scale sets the backend requests tokens from the instance metadata service; on App Service, Functions, and Container Apps it uses the platform identity endpoint advertised through `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`.

```yaml
auth: managed_identity
```

A user-assigned identity is selected by client id:

```yaml
auth:
  user_assigned_identity:
    client_id: 11111111-2222-3333-4444-555555555555
```

Service-principal auth exchanges client credentials at the Microsoft Entra token endpoint. The optional `authority` field overrides the login host for sovereign clouds; it defaults to `https://login.microsoftonline.com`.

```yaml
auth:
  service_principal:
    tenant_id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    client_id: 11111111-2222-3333-4444-555555555555
    client_secret: ${AZURE_CLIENT_SECRET}
```

Azure CLI auth shells out to `az account get-access-token`, reusing the operator's `az login` session. Use it for local development against a real vault, not for production deployments.

```yaml
auth: azure_cli
```

### Reference Shape

```text
azurekv://primary/<secret>[?version=<id>][&key=<json-field>]
azurekv://primary/<secret>/<version>[?key=<json-field>]
azurekv://primary/secrets/<secret>[/<version>]
```

Without a version pin the current secret version is served; `?version=latest` spells the same thing explicitly, matching the other cloud backends. A pin is the Key Vault version id from the secret's URL, such as `?version=6a2b45c8f9e14e0d`. Secret names use letters, digits, and dashes, as Key Vault requires. The backend is read-only; add secret versions through Azure Key Vault APIs or infrastructure automation.

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

| Reference path | Behavior |
|---|---|
| `<secret>` | Returns the whole secret as a JSON map of key to decoded value. |
| `<secret>/<key>` | Returns a single field from the configured namespace. |
| `<namespace>/<secret>[/<key>]` | Uses an explicit namespace. It must match the backend's configured namespace. |

Both `data` and `stringData` fields are honored. `data` keys are base64-decoded automatically. UTF-8 is required; binary fields surface as decode errors.

## File And Static Map Backends

Use `secretfile://` for a backend-configured YAML or JSON secret file. Use `localsecret://` for a backend-configured static secret map (`secret://` still works, but is the deprecated spelling). The legacy `file:/path/to/secret` form remains valid. The removed `secret:<name>` form does not; migrate it to `localsecret://<backend>/<name>`.

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
localsecret://app/openai_key
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

## Generating Secret Values

Everything above covers referencing secrets that already exist. Some secrets you have to invent yourself: a static virtual key in a `credentials:` block, and the `pepper` and `master_key` under `key_management.crypto`. For all three, generate 32 bytes from a cryptographic random source and use the hex form:

```bash
openssl rand -hex 32
```

That prints 64 hex characters, which is the recommended size for each of these values. On Windows, `openssl` is available in Git Bash but not in plain PowerShell; the PowerShell equivalent is:

```powershell
$b = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
($b | ForEach-Object ToString x2) -join ''
```

Do not derive these values from passwords, hostnames, or anything guessable, and do not reuse one value across the three roles. Generate each one once, store it in your secret manager or an environment variable, and reference it from the config (`env:NAME`, `file:PATH`, or a backend URI from the [Provider URI Schemes](#provider-uri-schemes) table above).

Two of the three have a better alternative than hand-generation:

* **Virtual keys:** the dynamic key-management admin API mints keys server-side (`POST /admin/keys`) with the right shape and entropy, and returns the plaintext token exactly once. Prefer minting over inventing a static key; see [key-management.md](key-management.md). A hand-generated static key is fine for local walkthroughs, but replace placeholder values like `sk-your-virtual-key` before anything reachable beyond localhost.
* **`pepper` and `master_key`:** if you leave them unset, sbproxy generates an ephemeral value at boot and warns. That is a fallback so a first run works, not a recommendation. Stored key hashes and encrypted credentials do not survive a restart without stable values, so set both before minting any key you intend to keep.

## Related Reading

* `docs/configuration.md` for the `proxy.secrets` block and reference URI grammar.
* `docs/multi-tenant.md` for the inheritance model and isolation guarantees.
* `docs/migration-credentials.md` for the `virtual_keys:` to `credentials:` migration and the vault reference migration note.
* `docs/key-management.md` for the dynamic key store the `pepper` and `master_key` protect.
