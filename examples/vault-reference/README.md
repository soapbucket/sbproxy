# vault:// reference URI

This example shows the unified `vault://` reference URI alongside the legacy `${ENV}` / `file:` / `secret:` shapes, and demonstrates how the same URI resolves to different physical vaults across tenants.

## Grammar

```
vault://<backend>/<path>[?version=<n>][&key=<json-field>]
```

| Segment | Meaning |
|---|---|
| `<backend>` | Operator-chosen name of a backend block configured per-scope. |
| `<path>` | Backend-specific path inside the vault. The parser carries it verbatim. |
| `version=<n>` | Optional version pin (HashiCorp KVv2, AWS Secrets Manager). |
| `key=<json-field>` | Optional sub-field selector for JSON-shaped secrets. |

## Tenancy

The URI itself is tenant-agnostic. The `<backend>` segment names a backend block; the block is configured at proxy scope, tenant scope, or origin scope. Resolution at request time walks the scopes from most specific to least specific: origin -> tenant -> proxy. The first scope that declares the named backend serves the reference. A tenant that does not redeclare a named backend transparently inherits the proxy default, so single-tenant configs need no changes.

Example: two tenants, one shared HashiCorp Vault for the proxy default, plus a tenant-specific Vault for acme-corp:

```yaml
proxy:
  vault:
    - name: hashi
      type: hashicorp
      addr: https://vault.shared.example/v1
      token: vault://env/VAULT_TOKEN_SHARED
  tenants:
    - id: acme-corp
      vault:
        - name: hashi              # same NAME, different Vault instance
          type: hashicorp
          addr: https://vault.acme.example/v1
          token: vault://env/VAULT_TOKEN_ACME
origins:
  api.acme.example.com:
    tenant_id: acme-corp
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: vault://hashi/secret/data/openai-prod?key=api_key
```

The `vault://hashi/secret/data/openai-prod` reference resolves against acme-corp's `hashi` block (Vault at `vault.acme.example`). The same reference used by a different origin scoped to `__default__` would resolve against the proxy default (Vault at `vault.shared.example`). The reference text is identical; the resolution context differs.

## What you'll see in `sb.yml`

* `action.providers[].api_key: vault://env/OPENAI_API_KEY` — env-backed reference, tenant-agnostic by construction.
* `authentication.bearer.tokens` mixes `vault://env`, `vault://hashi`, `vault://aws`, `vault://k8s`, `vault://sqlite` references alongside the legacy `${ENV}` and `secret:` shapes.
* The `proxy.vault` and `tenants[].vault` blocks are shown commented out: the config schema for those blocks lands alongside the credentials epic. The example illustrates the resolution model so the multi-tenant intent is clear from a single file.

## Status

* The parser ships in `sbproxy-vault::vault_ref::VaultRef`.
* The `env`, `file`, and `static-secret` backends keep working through the legacy resolver path.
* The `hashi`, `aws`, `k8s`, `sqlite`, and `cdb` backend implementations land in follow-up tickets; the parser already understands their reference shape so this config compiles today, but resolving one of those references returns an unimplemented-backend error at request time.

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
