# Weighted prompt versioning

*Last modified: 2026-08-25*

SBproxy can publish several immutable versions of a named prompt and select one
by stable relative weight. Rollouts are scoped to a compiled tenant/origin,
validated before publication, and owned by the same immutable generation as
the AI route that consumes them. No Redis is required.

The feature has two supported entry points:

- `sbproxy ai prompt select` and `POST /admin/ai-toolkit/prompts/select` let an
  operator dry-run a stable cohort assignment without returning prompt content.
- A live `ai_proxy` request carrying a bare prompt name can select that rollout
  after the runtime prompt overlay misses and before provider dispatch.

## Configure a rollout

Rollouts are a list under `proxy.ai_toolkit.prompt_rollouts`.

<!-- sbproxy-config: examples/ai-prompt-rollout/sb.yml -->
```yaml
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    port: 9090
    username: admin
    password: ${SB_ADMIN_PASSWORD}
  ai_toolkit:
    limits:
      max_rollouts: 16
      max_rollout_versions: 8
    agents: []
    workflows: []
    datasets: []
    prompt_rollouts:
      - origin: ai.local
        name: support-system
        salt: support-rollout-2026-08
        versions:
          - version: 1
            content: You are a helpful support assistant.
            weight: 90.0
          - version: 2
            content: You are a concise support assistant. Give the next action first.
            weight: 10.0

origins:
  "ai.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: AI toolkit control-plane scope
```

| Field | Meaning |
|---|---|
| `origin` | Existing key in `origins`; supplies the tenant/origin scope. |
| `name` | Stable rollout and prompt identifier. Every member is normalized to this name. |
| `salt` | Stable operator-controlled cohort salt. Changing it intentionally reshuffles assignments. It is excluded from admin snapshots and typed events. |
| `versions[].version` | Positive immutable numeric version, unique in the rollout. |
| `versions[].content` | Prompt template/content selected for the version. It is never returned by the toolkit admin response, snapshot, typed event, or metric. |
| `versions[].weight` | Finite, non-negative relative weight. The exact sum must be positive and finite. |

The runtime sorts members by numeric version before publication, so YAML order
cannot change assignments. Duplicate names or versions, zero versions,
non-finite or negative weights, an empty/zero-total rollout, oversize content,
and count-limit violations refuse the candidate generation. A refused reload
leaves the prior rollout live.

## Dry-run a selection

Use the standard admin environment variables:

```bash
export SB_ADMIN_URL='http://127.0.0.1:9090'
export SB_ADMIN_USERNAME='admin'
export SB_ADMIN_PASSWORD='replace-me'

sbproxy ai prompt select \
  --origin ai.local \
  --name support-system \
  --cohort customer-42
```

The command sends this authenticated request:

```json
{
  "origin": "ai.local",
  "name": "support-system",
  "cohort": "customer-42"
}
```

The response carries only the selected prompt name, numeric version, relative
weight, and a one-way cohort digest. It omits content, rollout salt, and the raw
cohort. The raw cohort is used for selection and digesting, then discarded.

The CLI also accepts `--admin-url`, `--username`, and `--password` directly.
See [Admin API reference](admin-api-reference.md#ai-toolkit-admin) for the wire
and error contract.

## Use a rollout on a live AI request

On an `ai_proxy` origin, a bare gateway prompt reference checks the mutable
runtime prompt overlay first. If the overlay does not own the name, it checks
the generation-owned rollout in that origin's scope:

```json
{
  "model": "support-model",
  "prompt": "support-system",
  "messages": [
    {"role": "user", "content": "How do I reset my password?"}
  ]
}
```

The selected content is inserted verbatim as a system message and the gateway-only
`prompt` field is removed before provider dispatch. The Responses object form
`"prompt":{"id":"support-system"}` uses the same rollout and applies the
selected content verbatim as instructions before translation. Rollout content
does not interpolate the object form's `variables`; use the stored-prompt layer
when strict template rendering is required.

If neither the runtime overlay nor a rollout with that bare name exists, the
request falls through to the config-declared stored-prompt layer. An explicit reference such as
`support-system@2` always addresses an exact stored-prompt version and does not
run weighted selection. This keeps the two contracts distinct:

- `proxy.ai_toolkit.prompt_rollouts` chooses one immutable version stably for a
  cohort.
- The AI action's existing `prompts` store resolves and renders exact named
  templates, including runtime overlay pins.

For live requests, SBproxy derives a content-free cohort key from the resolved
tenant and accountable public API-key identity. Raw request text and secret key
material do not participate. The returned rollout content stays inside the
request pipeline and is never copied to observability payloads.

## Stable cohort contract

Selection length-frames the UTF-8 bytes of the rollout name, cohort, and salt,
hashes them with SHA-256, and maps the first eight digest bytes onto exact
cumulative binary-weight units in canonical version order. The ranges are
half-open, so a zero-weight version is never selected.

The same `(scope, rollout generation, cohort)` therefore selects the same
version across processes and restarts. A weight/version change may remap some
cohorts; a salt change intentionally creates an independent assignment.

The separate event/admin cohort digest length-frames scope, rollout name, salt,
and cohort before SHA-256. Only its 64-character lowercase hex result is
serialized. It exists for correlation without retaining the cohort value.

## Observability and privacy

- `GET /admin/ai-toolkit/snapshot?origin=...` lists rollout names and
  version/weight pairs only. Content and salt are excluded.
- `ai_prompt_rollout_selected` publishes one successful admin or live selection
  with scoped prompt id, version, closed outcome, and cohort digest. It contains
  no prompt/request content or raw cohort.
- `sbproxy_ai_toolkit_operations_total{capability="prompt_rollout",outcome="..."}`
  counts selections. Prompt name, version, cohort, tenant, origin, content, and
  digest are deliberately not labels.

The Grafana AI dashboard breaks the single metric family into a prompt-rollout
outcome panel. Use typed events or the bounded admin snapshot for per-selection
diagnosis rather than adding high-cardinality metric labels.

## Runnable example

[`examples/ai-prompt-rollout`](../examples/ai-prompt-rollout/) contains the
complete no-Redis config and CLI sequence.
