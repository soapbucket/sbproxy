# Redis-backed AI context compression

*Last modified: 2026-07-18*

This example runs the ordered AI context-compression pipeline with a
process-wide Redis state backend. A dedicated `openai-summarizer` provider
reduces older plain-text chat history into a bounded running summary, then
`window_fit` applies the existing deterministic context-fitting heuristic.

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
from SBproxy's model-aware estimate for each applied lever. Since every
accepted lever must strictly reduce the working message list, summing the lever
counters gives the exact cumulative initial-to-final reduction in that shared
estimate for the process:

```promql
sum(sbproxy_ai_compression_tokens_saved_total{tenant_id="compression-redis-demo"})
```

Break the same estimate-relative counter down by lever:

```promql
sum by (lever) (
  sbproxy_ai_compression_tokens_saved_total{tenant_id="compression-redis-demo"}
)
```

`sbproxy_ai_compression_request_tokens_saved` is a histogram observed once per
compression request, with `tenant_id`, `api_key_id`, `outcome`, and `backend`
labels. Its `_sum` series is the equivalent estimate-relative cumulative
saving measured once per request:

```promql
sum(sbproxy_ai_compression_request_tokens_saved_sum{tenant_id="compression-redis-demo"})
```

Counters reset when a process restarts. For a dashboard range that spans
restarts, use `increase(...[$__range])`; Prometheus applies its normal range
boundary extrapolation. Use the request histogram's `_bucket` series for
per-request distributions; never sum buckets to recover token counts.
For model families without a dedicated tokenizer, the counter uses the
documented character heuristic and is not reconciled to provider-reported
usage after dispatch.

Applied pipelines emit one content-free `ai_compression_summary` event. With
the JSON log format used above, a safely redacted example is:

```json
{"timestamp":"<redacted>","level":"INFO","fields":{"message":"AI context compression pipeline summary","event":"ai_compression_summary","tenant_id":"<redacted>","api_key_id":"<redacted>","outcome":"applied","initial_tokens":12480,"final_tokens":1320,"tokens_saved":11160,"levers_run":2,"levers_applied":1,"latency_ms":640,"backend":"redis","consistency":"serialized","cache_bypass":true,"lever_outcomes":"<content-free JSON omitted>","targets":"<configured numeric targets omitted>"},"target":"ai_compression"}
```

The event never includes request messages, generated summary text, raw session
IDs, provider credentials, or raw backend errors. Applied events log at
`INFO`, failures at `WARN`, and expected skips at `DEBUG`.

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
