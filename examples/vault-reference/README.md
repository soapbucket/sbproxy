# Secret Reference Provider Schemes

This example shows the provider-specific secret reference schemes alongside the legacy `${ENV}` form, and demonstrates how the same URI can resolve to different physical vaults across tenants.

## Grammar

```text
<scheme>://<backend>/<path>[?version=<n>][&key=<json-field>]
```

| Segment | Meaning |
|---|---|
| `<scheme>` | Provider type: `vault`, `awssm`, `gcpsm`, `k8ssecret`, `secretfile`, or `secret`. |
| `<backend>` | Operator-chosen name of a backend block configured per scope. |
| `<path>` | Provider-specific path. The parser carries it verbatim. |
| `version=<n>` | Optional version pin for versioned providers. |
| `key=<json-field>` | Optional sub-field selector for JSON-shaped secrets. |

Environment variables stay as `${VAR}`. The legacy environment alias under the old umbrella form is deprecated.

## Tenancy

The URI itself is tenant-agnostic. The backend segment names a backend block, and the scheme requires the block to have the matching provider type. Resolution at request time walks the scopes from most specific to least specific: origin -> tenant -> proxy. The first scope that declares the matching backend serves the reference.

Example: two tenants, one shared HashiCorp Vault for the proxy default, plus a tenant-specific Vault for acme-corp:

```yaml
proxy:
  vault:
    - name: primary
      type: hashicorp
      addr: https://vault.shared.example/v1
      token: ${VAULT_TOKEN_SHARED}
  tenants:
    - id: acme-corp
      vault:
        - name: primary              # same name, different Vault instance
          type: hashicorp
          addr: https://vault.acme.example/v1
          token: ${VAULT_TOKEN_ACME}
origins:
  api.acme.example.com:
    tenant_id: acme-corp
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: vault://primary/secret/data/openai-prod?key=api_key
```

The `vault://primary/secret/data/openai-prod` reference resolves against acme-corp's `primary` HashiCorp backend at `vault.acme.example`. The same reference used by an origin without a tenant-specific override resolves against the proxy default at `vault.shared.example`.

## What You'll See In `sb.yml`

* `action.providers[].api_key: ${OPENAI_API_KEY}` keeps the example runnable.
* Commented production alternatives show `vault://`, `awssm://`, `gcpsm://`, `k8ssecret://`, and `secretfile://` references.
* `authentication.bearer.tokens` uses `${INTERNAL_BEARER_TOKEN}` for the runnable path and comments the provider-backed alternatives.
* The `proxy.vault` and `tenants[].vault` blocks are shown commented out until the public config schema exposes backend blocks at every scope. The example still documents the resolution model from one file.

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
