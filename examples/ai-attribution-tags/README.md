# ai-attribution-tags

*Last modified: 2026-06-04*

Tokenomics layer: tag every AI request with the operator's
project / feature / team / customer / env / agent_type / risk_tier /
trace_id so the spend record lands on the right dashboard row and
the downstream ledger can join token spend to business outcomes.

See the surrounding stack:
- [`ai-budget`](../ai-budget/) - workspace-wide cost cap that
  downgrades model tier when the budget burns down.
- [`ai-virtual-keys`](../ai-virtual-keys/) - per-team credential
  defaults; the attribution tags here ride on top of that pattern.

## Where the tags come from

Two paths produce the tag set; they compose:

1. **Per-credential defaults under `credentials[].attrs:`**. The
   operator pins which project / team / cost-center / tags a
   credential lands under. Every request authenticated by that
   credential carries the defaults.
2. **Per-request `SB-Attr-<Key>` headers** on the inbound HTTP
   request. The AI handler parses the headers and lifts them into
   the attribution tag set, overriding or filling in fields the
   credential leaves blank.

| Tag | Header | Use |
|---|---|---|
| `project` | `SB-Attr-Project` | Objective / product the request advances |
| `feature` | `SB-Attr-Feature` | Feature inside the project (feature-level burn dashboards) |
| `okr` | `SB-Attr-Okr` | Key-result id (ledger join key for outcome-to-spend reports) |
| `team` | `SB-Attr-Team` | Owning team for chargeback / showback |
| `customer` | `SB-Attr-Customer` | End customer / account / segment |
| `environment` | `SB-Attr-Env` | `prod` / `staging` / `dev` |
| `agent_type` | `SB-Attr-Agent` | `runtime` or `development` |
| `risk_tier` | `SB-Attr-Risk` | `internal-only` / `customer-facing` / `regulated` |
| `trace_id` | `SB-Attr-Trace-Id` | Caller-supplied workflow correlation id (ledger Allocate-layer join key) |

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export TEAM_FRONTEND_KEY=vk-frontend-...
make run CONFIG=examples/ai-attribution-tags/sb.yml
```

## Test (credential defaults only)

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H "Authorization: Bearer ${TEAM_FRONTEND_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"hi"}]}'
```

The access-log row carries `project=frontend`, `team=frontend-eng`,
`cost_center=cc-frontend-2026`, `tags=[tier-haiku, lane-prod, region-us-east]`,
all pulled from the credential's `attrs:`.

## Test (per-request override + augment)

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H "Authorization: Bearer ${TEAM_FRONTEND_KEY}" \
  -H 'Content-Type: application/json' \
  -H 'SB-Attr-Project: chatbot-revamp' \
  -H 'SB-Attr-Feature: regen-button' \
  -H 'SB-Attr-Env: staging' \
  -H 'SB-Attr-Trace-Id: trc_01HABC...' \
  -H 'SB-Attr-Agent: development' \
  -H 'SB-Attr-Risk: internal-only' \
  -d '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"regen"}]}'
```

This row's tag set:
- `project: chatbot-revamp` (per-request header wins over the
  `frontend` credential default).
- `feature: regen-button` (added; the credential had none).
- `environment: staging`.
- `trace_id: trc_01HABC...` (the ledger's join key for the
  downstream outcome record).
- `agent_type: development`.
- `risk_tier: internal-only`.
- `team: frontend-eng`, `cost_center: cc-frontend-2026`, `tags`
  (still from the credential; no header override).

## What lands on the spend record

The same tag set rides on the access-log row, the
`sbproxy_ai_tokens_total` and `sbproxy_ai_cost_usd_total`
Prometheus counters (project / team / agent_type / environment
labels), and the OpenTelemetry span attributes. A downstream
Token-to-Value Ledger consumes the access log + the
`trace_id` join key to compute cost per verified outcome.

## See also

- [`ai-budget`](../ai-budget/) - the budget enforcer reads the
  matched principal's `attrs:` to apply caps; the same `attrs:`
  block here doubles as a per-team budget hook.
- [`access-log`](../access-log/) - the access-log row is the
  primary delivery vehicle for the tag set off-proxy.
