# Redis-backed AI context compression

*Last modified: 2026-07-19*

This example runs the ordered AI context-compression pipeline with a
process-wide Redis state backend. A dedicated `openai-summarizer` provider
reduces older plain-text chat history into a bounded running summary, then
`window_fit` applies an explicit target-model-counted input budget. The route
also declares a stateless `compact` profile that runs `rag_select`,
`compact_serialization`, `position_reorder`, and `window_fit` in that order.

Request workers are stateless. The client remains the source of truth for the
conversation and sends the complete canonical `messages` array on every turn.
Redis stores the shared running summary, its version, expiry, and content-free
integrity metadata. It does not turn SBproxy into a conversation-history
server and it does not store the raw transcript.

## Prerequisites

- An SBproxy binary built from this checkout.
- `curl`, `jq`, `openssl`, and `awk` for the commands below.
- Redis reachable through a `redis://` or `rediss://` DSN.
- An OpenAI API key. The primary request uses `gpt-4o`; internal summaries use
  the separately configured `gpt-4o-mini` provider entry.

For a local Redis process:

```bash
docker run --rm --name sbproxy-compression-redis \
  -p 6379:6379 redis:7-alpine
```

In another shell, start SBproxy from the repository root:

```bash
export OPENAI_API_KEY='<set this in your shell>'
export ADMIN_PASSWORD="$(openssl rand -hex 24)"
export SB_REDIS_URL=redis://127.0.0.1:6379/0

sbproxy serve --log-format json \
  -f examples/ai-context-compression-redis/sb.yml
```

The config does not contain credentials. `OPENAI_API_KEY` and
`ADMIN_PASSWORD` are required environment references. `SB_REDIS_URL` defaults
to the local passwordless development address above; set it explicitly to the
authenticated or TLS DSN used by a deployed Redis service.

## Session identity and stateless workers

Stateful compression requires a captured session ID. For this HTTP chat
surface, the supported request-envelope mechanism is:

```text
X-Sb-Session-Id: 01HQRP1KJVH3JPCJ8SAVAV6F4Z
```

The value must be a valid 26-character ULID. This example sets
`sessions.auto_generate: never`, so a missing or invalid header does not create
compression state. The `summary_buffer` lever skips with a missing-session
outcome while the request continues through the remaining pipeline. A valid
captured value is echoed in the response as `X-Sb-Session-Id`.

The caller must reuse the same ULID and resend the full history on later
turns. Any request worker can handle a turn because the state key is isolated
by tenant, AI origin, and the captured session. The raw session ID is not
stored in the compression record or returned by the compression Admin API.

## Profile selection and explicit budgets

The route default, selected by `on` or by no explicit selector, runs
`summary_buffer` and then fits the result to 16,384 input tokens. The named
`compact` profile selects marked retrieval chunks, compacts safe structured
chunks, moves relevant evidence toward the edges, and fits the result to 4,096
input tokens. It does not read or write summary state. `off` preserves the
caller's complete message list.

Selectors resolve in this order: `X-Compression`, governed key
`compression_profile`, CEL `compression:<selector>`, then route default. A
header is useful for an explicit caller override:

```bash
# Route default, including Redis summary state.
curl -H 'X-Compression: on' ...

# Named stateless profile. No session ID or Redis summary operation is needed.
curl -H 'X-Compression: compact' ...

# Preserve the complete caller context.
curl -H 'X-Compression: off' ...
```

SBproxy strips `X-Compression` before dispatch. It rejects a malformed,
repeated, or undeclared header with `400`. Invalid governed-key or CEL choices
resolve safely to `off` and are visible as `invalid_operator` telemetry.

Explicit-budget fitting uses the target-model counter and the smaller of the
configured budget and known model capacity. It preserves the leading system
and developer instructions, the complete newest turn, contiguous recent
history, and complete OpenAI or Anthropic tool exchanges. If protected
material cannot fit, the lever skips without changing the request.

This route declares a named profile, so semantic-cache reads and writes are
bypassed for every request on the route. The cache key does not partition by
compression behavior yet. The same bypass applies to any selected pipeline
that contains `rag_select`, `compact_serialization`, or `position_reorder`.

## Marked retrieval context

The three retrieval-aware levers act only on explicit blocks inside a
string-valued `content` field with role `user` or `tool`. They do not infer
retrieval context from ordinary text. Marker-like text in `system`,
`developer`, or `assistant` content remains protected.

A block uses this exact line-delimited grammar:

```text
<sbproxy-retrieval>
<sbproxy-query>
Which deployment evidence explains the outage?
</sbproxy-query>
<sbproxy-chunk id="deploy-log" score="0.95" format="text">
The checkout deployment failed because catalog-v42 was missing.
</sbproxy-chunk>
</sbproxy-retrieval>
```

The block, query, and chunk tags occupy complete lines. Tags are lowercase and
exact. A block cannot nest and contains exactly one non-empty query followed
by zero or more chunks. Each chunk opening tag uses attributes in this order:
`id`, optional `score`, then `format`. The ID contains from 1 to 64 ASCII
letters, digits, `.`, `_`, or `-`. A score is finite and falls from 0 through
1. Formats are `text`, `json`, and the rendered `sbproxy_table_v1`. A query or
chunk body cannot contain its own closing tag as a complete line. LF and CRLF
are accepted, but one block must use a consistent line ending.

The parser accepts at most 32 blocks per request, 1,024 chunks per block, and
4,096 chunks per request. Each retrieval-aware lever parses the complete
working message list. If any apparent block is malformed or exceeds a limit,
that lever skips without committing a partial rewrite. Later levers still run.
In particular, a later `window_fit` may trim the request, so a retrieval skip
does not promise that the whole provider request stays unchanged.

Ranking has three modes. `auto` uses supplied scores only when every chunk in
the block has one; otherwise it uses deterministic lexical ranking. `supplied`
requires every score and skips a block with a missing score. `lexical` ignores
scores and ranks normalized TF-IDF similarity between the marked query and
each chunk. Stable source order breaks ties.

`rag_select` keeps the query and ranks each block independently. It applies
`min_relevance_percent`, then `max_chunks`. With `drop_empty: true`, a block
whose chunks are all removed remains as a valid wrapper containing its query.
`compact_serialization` considers only marked JSON chunks. It first removes
insignificant JSON whitespace. A uniform top-level array of scalar-valued
objects can use `sbproxy_table_v1`: one sorted JSON column array followed by
tab-separated canonical JSON scalar rows. The public Table v1 decoder returns
the exact original JSON `Value`; insignificant whitespace and object-key order
are not part of that promise.

`position_reorder` ranks the surviving chunks and places rank 1 at the start,
rank 2 at the end, rank 3 after rank 1, and rank 4 before rank 2. It changes
only chunk order. Because this is a non-expanding transformation, it can apply
with zero tokens saved.

This command sends a valid marked block through the stateless profile:

```bash
export SB_DATA_URL=${SB_DATA_URL:-http://127.0.0.1:8080}

MARKED_CONTEXT="$(cat <<'MARKERS'
Caller note before the marked block.
<sbproxy-retrieval>
<sbproxy-query>
Which deployment evidence explains the outage?
</sbproxy-query>
<sbproxy-chunk id="distractor" score="0.10" format="text">
The office lunch menu changed on Tuesday.
</sbproxy-chunk>
<sbproxy-chunk id="required" score="0.95" format="text">
The checkout deployment failed because catalog-v42 was missing.
</sbproxy-chunk>
<sbproxy-chunk id="context" score="0.30" format="text">
The deployment started at 12:01 UTC.
</sbproxy-chunk>
<sbproxy-chunk id="useful" score="0.70" format="text">
The catalog service reported ImagePullBackOff.
</sbproxy-chunk>
</sbproxy-retrieval>
Caller note after the marked block.
MARKERS
)"

jq -n --arg content "$MARKED_CONTEXT" '{
  model: "gpt-4o",
  messages: [{role: "user", content: $content}]
}' > /tmp/sbproxy-compression-marked.json

curl --fail-with-body -sS \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -H 'X-Compression: compact' \
  --data-binary @/tmp/sbproxy-compression-marked.json \
  "${SB_DATA_URL}/v1/chat/completions" \
  | jq -r '.choices[0].message.content'
```

## Send two turns

The synthetic history below is intentionally long enough to cross
`min_tokens: 4096`. It contains only ordinary `system`, `user`, and
`assistant` text messages, which are eligible for `summary_buffer`.

```bash
export SB_DATA_URL=http://127.0.0.1:8080
export SB_SESSION_ID=01HQRP1KJVH3JPCJ8SAVAV6F4Z

HISTORY="$(awk 'BEGIN {
  for (i = 0; i < 500; i++) {
    printf "Decision %d: launch stays within budget, preserves audit logs, and keeps Friday as the review deadline. ", i
  }
}')"

jq -n --arg history "$HISTORY" '{
  model: "gpt-4o",
  messages: [
    {role: "system", content: "You are a concise project reviewer."},
    {role: "user", content: $history},
    {role: "assistant", content: "I recorded the historical constraints."},
    {role: "user", content: "The launch budget is fixed at ten thousand dollars."},
    {role: "assistant", content: "Budget noted."},
    {role: "user", content: "The security review must remain a release gate."},
    {role: "assistant", content: "Security remains a gate."},
    {role: "user", content: "List the top two delivery risks."}
  ]
}' > /tmp/sbproxy-compression-turn-1.json

# Exercise the named stateless profile without a captured session.
curl --fail-with-body -sS \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -H 'X-Compression: compact' \
  --data-binary @/tmp/sbproxy-compression-turn-1.json \
  "${SB_DATA_URL}/v1/chat/completions" \
  | jq -r '.choices[0].message.content'

# Exercise the explicit off override. The request still reaches the provider.
curl --fail-with-body -sS \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -H 'X-Compression: off' \
  --data-binary @/tmp/sbproxy-compression-turn-1.json \
  "${SB_DATA_URL}/v1/chat/completions" \
  | jq -r '.choices[0].message.content'

curl --fail-with-body -sS \
  -D /tmp/sbproxy-compression-turn-1.headers \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -H "X-Sb-Session-Id: ${SB_SESSION_ID}" \
  --data-binary @/tmp/sbproxy-compression-turn-1.json \
  "${SB_DATA_URL}/v1/chat/completions" \
  | tee /tmp/sbproxy-compression-turn-1.response.json

grep -i '^x-sb-session-id:' /tmp/sbproxy-compression-turn-1.headers
TURN_1_REPLY="$(jq -r '.choices[0].message.content' \
  /tmp/sbproxy-compression-turn-1.response.json)"

jq --arg reply "$TURN_1_REPLY" \
  '.messages += [
    {role: "assistant", content: $reply},
    {role: "user", content: "Turn those risks into a three-step plan."}
  ]' \
  /tmp/sbproxy-compression-turn-1.json \
  > /tmp/sbproxy-compression-turn-2.json

curl --fail-with-body -sS \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -H "X-Sb-Session-Id: ${SB_SESSION_ID}" \
  --data-binary @/tmp/sbproxy-compression-turn-2.json \
  "${SB_DATA_URL}/v1/chat/completions" \
  | tee /tmp/sbproxy-compression-turn-2.response.json \
  | jq -r '.choices[0].message.content'
```

The first eligible turn creates a record. On the second turn, the stored
summary is accepted only when its protected prefix and covered-history digest
still match the full history supplied by the caller. A branched or rewritten
history skips the stateful replacement instead of applying a summary from the
wrong branch.

To verify that state is outside the gateway worker, stop and restart SBproxy
without stopping Redis, then resend the second curl with the same session ID
and complete history. The replacement process loads the existing record and
does not need worker-local conversation memory. Resending an exact covered
history reuses the summary without a state write, so that exact reuse does not
refresh the record TTL; a newly committed incremental summary does.

Requests with top-level tools, functions, response schemas, or other
structured controls are intentionally ineligible for `summary_buffer`.
`window_fit` remains the deterministic final lever.

## Admin metadata and lifecycle

The Admin server binds to loopback. Metadata routes require an authenticated
operator. Delete and purge require the `admin` role. These script-friendly
reads use HTTP Basic authentication:

```bash
export SB_ADMIN_URL=http://127.0.0.1:9090

RECORDS="$(curl --fail-with-body -sS \
  -u "admin:${ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/compression/sessions?tenant=compression-redis-demo&origin=ai.local&backend=redis&limit=10")"
printf '%s\n' "$RECORDS" | jq

RECORD_ID="$(printf '%s\n' "$RECORDS" | jq -r '.records[0].id // empty')"
test -n "$RECORD_ID"

curl --fail-with-body -sS \
  -u "admin:${ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/compression/sessions/${RECORD_ID}" \
  | jq
```

List and detail responses contain bounded metadata, not the summary text or
the caller's session ID. Content inspection is default-denied here because
`allow_admin_content_inspection: false` is explicit. Even the full admin gets
`403` from the content route:

```bash
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  -u "admin:${ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/compression/sessions/${RECORD_ID}/content"
# HTTP 403
```

Content inspection can only be enabled per AI origin. When enabled, it still
requires the `admin` role, emits a content-free event to the
`sbproxy::admin::audit` tracing target before returning content, and adds
no-store response headers. Durable retention depends on the configured tracing
collector. If an installed audit sink reports a failure, the route withholds
the summary and returns `503`.

Cookie-authenticated mutations must send the CSRF token returned by
`POST /admin/login`. This deletes one record using that convention:

```bash
COOKIE_JAR="$(mktemp)"
LOGIN="$(curl --fail-with-body -sS \
  -c "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg username admin --arg password "$ADMIN_PASSWORD" \
    '{username: $username, password: $password}')" \
  "${SB_ADMIN_URL}/admin/login")"
CSRF_TOKEN="$(printf '%s\n' "$LOGIN" | jq -r '.csrf_token')"

curl --fail-with-body -sS \
  -b "$COOKIE_JAR" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -X DELETE \
  "${SB_ADMIN_URL}/admin/compression/sessions/${RECORD_ID}" \
  | jq

rm -f "$COOKIE_JAR"
```

Per-request Basic authentication is CSRF-exempt. A bounded, explicitly scoped
purge can therefore be used by an operations script after a test run:

```bash
curl --fail-with-body -sS \
  -u "admin:${ADMIN_PASSWORD}" \
  -H 'Content-Type: application/json' \
  -X POST \
  -d '{"tenant":"compression-redis-demo","origin":"ai.local","backend":"redis","limit":100}' \
  "${SB_ADMIN_URL}/admin/compression/sessions/purge" \
  | jq
```

Follow `next_cursor` when either a list or purge response returns one. An
unscoped all-record purge requires the separate confirmation string enforced
by the API; the scoped commands above are safer for normal lifecycle work.
Redis removes expired records at their TTL, so the Admin API does not expose an
expired-record filter or purge scope.
Delete and purge remove the current running-summary state; they do not revoke
the captured session ID. A later eligible request using that session can create
a fresh record.

## Metrics and estimated token savings

The authenticated Admin endpoint exposes Prometheus text format:

```bash
curl --fail-with-body -sS \
  -u "admin:${ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/metrics" \
  | grep '^sbproxy_ai_compression_'
```

`sbproxy_ai_compression_tokens_saved_total` is an integer counter incremented
from SBproxy's model-aware estimate for each applied lever. `summary_buffer`,
`window_fit`, `rag_select`, and `compact_serialization` commit only a strict
reduction. `position_reorder` may commit a changed, non-expanding order with
zero savings. Summing the lever counters still gives the exact cumulative
initial-to-final reduction in that shared estimate for the process:

```promql
sum(sbproxy_ai_compression_tokens_saved_total{tenant_id="compression-redis-demo"})
```

Break the same estimate-relative counter down by lever:

```promql
sum by (lever) (
  sbproxy_ai_compression_tokens_saved_total{tenant_id="compression-redis-demo"}
)
```

Use the invocation counter to see applied reorder operations, including the
valid zero-saving case:

```promql
sum by (lever, outcome, reason) (
  rate(sbproxy_ai_compression_lever_total{
    tenant_id="compression-redis-demo",
    lever=~"rag_select|compact_serialization|position_reorder"
  }[5m])
)
```

`sbproxy_ai_compression_request_tokens_saved` is a histogram observed once per
compression request, with `tenant_id`, `api_key_id`, `outcome`, and `backend`
labels. Its `_sum` series is the equivalent estimate-relative cumulative
saving measured once per request:

```promql
sum(sbproxy_ai_compression_request_tokens_saved_sum{tenant_id="compression-redis-demo"})
```

Selection decisions are closed and content-free:

```promql
sum by (source, outcome) (
  rate(sbproxy_ai_compression_selection_total{tenant_id="compression-redis-demo"}[5m])
)
```

After a terminal provider request succeeds, the value counters record applied
levers that reduced the estimate. `position_reorder` is intentionally absent
from value accounting because its valid contribution can be structural with
zero tokens saved. The fifth label states whether the target-model count came
from a registered tokenizer or the heuristic fallback:

```promql
sum by (model, lever, token_count_precision) (
  rate(sbproxy_ai_compression_value_tokens_saved_total{tenant_id="compression-redis-demo"}[5m])
)
```

```promql
sum by (model, lever, token_count_precision) (
  rate(sbproxy_ai_compression_value_cost_saved_micros_total{tenant_id="compression-redis-demo"}[5m])
) / 1000000
```

An unknown model price keeps the saved-token estimate and contributes zero
avoided cost. Neither metric claims exact provider usage.

Counters reset when a process restarts. For a dashboard range that spans
restarts, use `increase(...[$__range])`; Prometheus applies its normal range
boundary extrapolation. Use the request histogram's `_bucket` series for
per-request distributions; never sum buckets to recover token counts.
For model families without a dedicated tokenizer, the counter uses the
documented UTF-8 byte-length heuristic, not a Unicode character count, and is
not reconciled to provider-reported usage after dispatch.

Metric dimensions are bounded. Lever, outcome, reason, backend, selection
source, and selection outcome use closed label sets. Tenant and public API key
identifiers pass through the shared cardinality budget; request text, marker
IDs, queries, chunk bodies, scores, and credentials never become labels.

Every executed non-empty pipeline emits exactly one content-free
`ai_compression_summary` event. With the JSON log format used above, a safely
redacted example is:

```json
{"timestamp":"<redacted>","level":"INFO","fields":{"message":"AI context compression pipeline summary","event":"ai_compression_summary","tenant_id":"<redacted>","api_key_id":"<redacted>","outcome":"applied","initial_tokens":12480,"final_tokens":1320,"tokens_saved":11160,"levers_run":2,"levers_applied":1,"latency_ms":640,"backend":"redis","consistency":"serialized","cache_bypass":true,"selection_source":"route_default","selection_outcome":"default","lever_outcomes":"<content-free JSON omitted>","targets":"<configured numeric targets omitted>"},"target":"ai_compression"}
```

The event never includes request messages, generated summary text, raw session
IDs, provider credentials, or raw backend errors. Applied events log at
`INFO`, failures at `WARN`, and expected skips at `DEBUG`.

Each explicit header, governed-key, or CEL selection emits an
`ai_compression_selection` event with only tenant, source, outcome, and an
optional closed reason. Route-default resolution also emits it when named
profiles or an explicit input budget require semantic-cache separation. It
does not log the header or profile name. The summary event's `targets` field
includes only configured controls. Retrieval targets contain
`rag_select.min_tokens`, ranking mode, `max_chunks`, relevance percentage,
`drop_empty`, compact-serialization threshold and tabular controls, or the
position-reorder ranking mode. A WindowFit target includes
`input_budget_tokens` when configured.

## Read the value report

The same successful value records are available through the authenticated
Admin endpoint. Compression stays separate from the local-serving completion
counts:

```bash
curl --fail-with-body -sS \
  -u "admin:${ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/model-host/value" \
  | jq '{compression,compression_totals,total_compression_tokens_saved,total_compression_gross_cost_saved_micros}'
```

Each row includes `model`, `lever`, `tokens_saved`,
`gross_cost_saved_micros`, and `token_count_precision`. The precision value is
`model_tokenizer` for a registered target-model tokenizer and `heuristic` for
the UTF-8 byte-length fallback. It describes the SBproxy estimate, not the
provider's billed input count.

## Run the evaluation gate

The repository includes deterministic off/on smoke evaluation for the real
runner and production stateless levers. Its retrieval cases and coding-agent
shapes are independently authored, synthetic structural evidence. They are
not captured production traffic and do not measure target-model answer
quality:

```bash
cd sbproxy-bench/harness/context_compression_eval
cargo nextest run --all-targets --locked
cargo run --locked -- check \
  --pipeline-config pipelines/phase1-pipeline-smoke.json \
  --input fixtures/phase1-pipeline-smoke.jsonl \
  --provenance fixtures/provenance.json \
  --json-report reports/phase1-pipeline-smoke.json \
  --markdown-report reports/phase1-pipeline-smoke.md
```

CI checks report pairs for `rag-select-smoke`,
`compact-serialization-smoke`, `position-reorder-smoke`,
`phase1-pipeline-smoke`, and `window-fit-smoke`. The harness also normalizes
operator-supplied RULER, HELMET, LongBench-v2, and NoLiMa interchange rows.
Those adapters import contexts and already generated off/on predictions for
reporting. They do not download a suite, run a target model, or produce an
official benchmark score.

## Safe degradation

The Redis binding is mandatory for the configured stateful lever. Removing
`proxy.l2_cache_settings`, selecting a non-Redis driver, or supplying a
syntactically invalid Redis DSN makes pipeline construction fail instead of
silently changing consistency. Connections are lazy: an unreachable Redis
server or a connection-level TLS/authentication problem is reported on the
first state operation, not at process startup.

Redis connection setup is bounded to 500 milliseconds, one command response
to 1 second, and a complete state operation to 2 seconds. Failed connections
are replaced so a recovered or restarted Redis service does not require an
SBproxy restart.

After startup, Redis command failures, lease contention, stale versions,
summarizer timeouts, and rejected summaries are closed outcomes. A failed
lever keeps the current request's working message list unchanged and the later
`window_fit` lever still runs. There is no hidden in-memory state fallback and
no cross-session reuse. The request can continue to its primary provider with
the last safe message list while metrics and the redacted summary event expose
the degraded outcome.

Redis is the only canonical summary store. `backend: mesh` is rejected, and
there is no worker-memory fallback. This feature has no OmniRoute dependency,
state import, or migration format; it starts with native SBproxy state.

Monitor these Redis-specific health series:

```promql
sum by (operation, outcome) (
  rate(sbproxy_ai_compression_state_operations_total{backend="redis"}[5m])
)
```

```promql
sum by (event) (
  rate(sbproxy_ai_compression_redis_coordination_total[5m])
)
```

## See also

- [Legacy deterministic context-window fitting](../ai-llm-aware-resilience/)
