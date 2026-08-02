# Secret reference provider schemes

*Last modified: 2026-07-28*

This example shows provider-specific secret reference schemes alongside the
`${ENV}` form. Secret backends are configured at proxy scope. To isolate
tenants in different physical stores, give each backend a distinct name and
use the matching name in that tenant's origin configuration.

## Grammar

```text
<scheme>://<backend>/<path>[?version=<n>][&key=<json-field>]
```

| Segment | Meaning |
|---|---|
| `<scheme>` | Provider type: `vault`, `awssm`, `gcpsm`, `azurekv`, `k8ssecret`, `secretfile`, or `secret`. |
| `<backend>` | Operator-chosen name from `proxy.secrets.backends`. |
| `<path>` | Provider-specific path. The parser carries it verbatim. |
| `version=<n>` | Optional version pin for versioned providers. |
| `key=<json-field>` | Optional sub-field selector for JSON-shaped secrets. |

Environment variables stay as `${VAR}`. The legacy environment alias under the old umbrella form is deprecated.

## Tenant boundaries

The backend segment names one entry under `proxy.secrets.backends`, and the
scheme must match that entry's provider type. Backend definitions do not
inherit through origin or tenant scope.

For two physical HashiCorp Vaults, declare two backend names:

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
          token: ${VAULT_TOKEN_SHARED}
      - type: hashicorp
        name: acme
        addr: https://vault.acme.example/v1
        mount: secret/tenants/acme-corp
        auth:
          type: token
          token: ${VAULT_TOKEN_ACME}
  tenants:
    - id: acme-corp
origins:
  api.acme.example.com:
    tenant_id: acme-corp
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: vault://acme/openai-prod?key=api_key
```

The `vault://acme/openai-prod` reference always uses the `acme` backend. An
origin configured with `vault://shared/...` uses the shared store. Pair these
explicit names with Vault policies, cloud IAM, or Kubernetes RBAC so the
backend rejects cross-tenant reads even if a config is wrong.

## What you will see in `sb.yml`

* `action.providers[].api_key: ${OPENAI_API_KEY}` keeps the example runnable.
* Commented production alternatives show `vault://`, `awssm://`, `gcpsm://`, `azurekv://`, `k8ssecret://`, and `secretfile://` references.
* `authentication.bearer.tokens` uses `${INTERNAL_BEARER_TOKEN}` for the runnable path and comments the provider-backed alternatives.
* A commented, valid `proxy.secrets.backends` block shows where production
  backends belong. Provider-specific setup is in
  [`docs/secrets.md`](../../docs/secrets.md).

## Migration

Legacy `vault://<alias>/...` forms are accepted with a warning during the compatibility window. Rewrite known aliases with:

```bash
sbproxy config migrate examples/vault-reference/sb.yml --out /tmp/sb.migrated.yml
```

See `docs/migration-credentials.md` for the old-to-new reference table and the deprecation window.

## Run

```bash
export OPENAI_API_KEY=sk-...
export INTERNAL_BEARER_TOKEN=test-bearer-1
make run CONFIG=examples/vault-reference/sb.yml
```

## Test

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: api.acme.example.com' \
  -H 'Authorization: Bearer test-bearer-1' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```
