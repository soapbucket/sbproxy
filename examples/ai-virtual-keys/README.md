# AI gateway: per-team virtual keys

*Last modified: 2026-06-04*

Two virtual keys, two teams. The frontend team's key is allow-listed to `claude-3-5-haiku-latest`; the data team's key also gets `claude-3-5-sonnet-latest`. A key that asks for a model outside its allow-list is rejected with `403` before any upstream call. Each credential also carries a declared budget and tags that flow to the `sbproxy_ai_key_*` metric series for per-team attribution. The gateway matches the virtual key locally from `Authorization: Bearer ...` and swaps in the real provider key, so clients never see the upstream Anthropic key.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export TEAM_FRONTEND_KEY=vk-frontend-...
export TEAM_DATA_KEY=vk-data-...
make run CONFIG=examples/ai-virtual-keys/sb.yml
```

All three env vars are required.

## How the keys relate

Two independent secrets are in play, and they never mix on the wire:

- The **upstream provider key** (`ANTHROPIC_API_KEY`) authenticates the gateway *to Anthropic*. It lives on the `providers:` entry and is the only credential SBproxy ever sends upstream.
- The **virtual keys** (`TEAM_FRONTEND_KEY`, `TEAM_DATA_KEY`) authenticate *your clients to the gateway*. Each one is an opaque string you choose, listed under `credentials:`.

When a request arrives with `Authorization: Bearer <virtual-key>`, the gateway matches that key against its configured set locally, attaches the matched identity (`project`, `tags`) so spend shows up per team in the `sbproxy_ai_key_*` metrics, then attaches the real provider key for the call to Anthropic. The virtual key is never forwarded upstream, and clients never see the Anthropic key.

A virtual key can be any string. The `vk-frontend-...` / `vk-data-...` values are just a readable convention; no particular format is required.

## Secrets: env vars or a vault

This example reads every secret from an environment variable with `${...}` interpolation so it stays copy-paste runnable. The same fields accept a vault reference instead, so in production no secret has to sit in the shell environment or the config file.

Any `${VAR}` above can be a `vault://<backend>/<path>` URI backed by HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets. The upstream key and the virtual keys both resolve the same way:

```yaml
providers:
  - name: anthropic
    # env var (this example) ...
    api_key: ${ANTHROPIC_API_KEY}
    # ... or a vault reference (production):
    # api_key: vault://hashi/secret/data/anthropic-prod?key=api_key

credentials:
  - name: team-frontend
    type: ai_provider
    provider: anthropic
    # key: vault://hashi/secret/data/team-frontend?key=virtual_key
    key: ${TEAM_FRONTEND_KEY}
```

See [docs/secrets.md](../../docs/secrets.md) for backend setup, the three auth methods, the in-process TTL cache, and the full URI syntax (`?version=`, `&key=`).

## Try it

Frontend team, allowed model:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H "Authorization: Bearer ${TEAM_FRONTEND_KEY}" \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-3-5-haiku-latest",
      "messages": [{"role": "user", "content": "Hello from frontend."}]
    }' | head -n 1
HTTP/1.1 200 OK
```

Frontend team, blocked model:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H "Authorization: Bearer ${TEAM_FRONTEND_KEY}" \
    -H 'Content-Type: application/json' \
    -d '{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"Try Sonnet."}]}' \
    | head -n 5
HTTP/1.1 403 Forbidden
content-type: application/json

{"error":"model 'claude-3-5-sonnet-latest' is not allowed for this key"}
```

Data team, allowed Sonnet:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H "Authorization: Bearer ${TEAM_DATA_KEY}" \
    -H 'Content-Type: application/json' \
    -d '{"model":"claude-3-5-sonnet-latest","messages":[{"role":"user","content":"Hello from data team."}]}' \
    | head -n 1
HTTP/1.1 200 OK
```

## A note on unknown keys

Matching a virtual key gives a request its identity and per-key model scoping; it is not a blanket authentication gate. An unrecognized bearer token simply matches no key: it picks up no per-team scoping and falls through to the action-level gates (and, with no `auth:` provider configured, would reach the upstream). To reject unknown callers outright, pair the gateway with an `auth:` provider, for example the `api_key` or `bearer` provider in [docs/configuration.md](../../docs/configuration.md) or OIDC login in [docs/auth-oidc.md](../../docs/auth-oidc.md).

## What this exercises

- `models.allow` on a credential - per-key model scoping. A key that requests a model outside its allow-list is rejected with a `403` before any upstream call.
- `tags` and `project` under `attrs:` - propagate to the `sbproxy_ai_key_*` metrics and the access log for per-team attribution.
- `attrs.budget` and the per-credential `rate_limit` policy - recorded as attribution metadata on the matched key. Enforced spend and rate ceilings are configured at the action level (the `budget:` block and rate-limit policies); see [docs/ai-gateway.md](../../docs/ai-gateway.md).

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/metrics-stability.md](../../docs/metrics-stability.md) - per-key metric labels
