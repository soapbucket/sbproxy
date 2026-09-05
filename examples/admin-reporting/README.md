# Admin reporting

Who spent what, as a shareable link and a CSV. Two tenants, three
governed keys, two models, and named human callers, so the admin API's
reporting routes have something real to group on.

Three routes read one in-memory ring through one filter parser:

| Route | Answers |
|---|---|
| `GET /api/requests` | Which requests happened. |
| `GET /api/requests/report` | Which composite group spent what. |
| `GET /api/requests/export` | Hand me those rows as CSV or JSONL. |

A filter that selects rows on the first selects exactly the same rows on
the other two, so a grouped number always drills through to the rows
behind it, including the unattributed group: a row with no model, no
key, or no resolved human groups under the empty string, and `?model=`
selects exactly those rows. In a deployment that resolves no end user
that group is usually the largest one, and a billing pipeline iterating
report groups must not lose it. See
[`docs/admin-api-reference.md`](../../docs/admin-api-reference.md) for
the route reference and
[`docs/admin-ui.md`](../../docs/admin-ui.md) for the console view that
drives them.

## Run

A local OpenAI-shaped fixture stands in for the provider, so this runs
with no upstream account. Start it first. It listens on 18086 rather
than the 18080 most examples use, so this walkthrough and
[`examples/usage-bridge-queue/`](../usage-bridge-queue/) can run at the
same time:

```bash
python3 - <<'PY' &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        model = body.get("model", "gpt-4o-mini")
        pt, ct = (900, 300) if model == "gpt-4o" else (120, 40)
        out = json.dumps({
            "id": "chatcmpl-fixture", "object": "chat.completion",
            "created": 1755648000, "model": model,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": pt, "completion_tokens": ct,
                      "total_tokens": pt + ct},
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 18086), H).serve_forever()
PY

make run CONFIG=examples/admin-reporting/sb.yml
```

## Drive attributed traffic

Three headers carry the attribution the report groups on. `Host` picks
the origin, and the origin stamps its tenant. `Authorization` selects
the governed key. `X-Sb-User-Id` names the human behind the call, which
is sbproxy's equivalent of the "Creator" dimension OpenRouter's org
exports group by. `X-Sb-Property-Feature` is an optional custom
property that rides along into both export formats.

```bash
drive() {
  curl -s -o /dev/null http://127.0.0.1:8080/v1/chat/completions \
    -H "Host: $1" -H "Authorization: Bearer $2" \
    -H "X-Sb-User-Id: $3" -H "X-Sb-Property-Feature: $5" \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"$4\",\"messages\":[{\"role\":\"user\",\"content\":\"Hi\"}]}"
}

drive acme.ai.local   vk-acme-platform   dev@acme.test    gpt-4o-mini summarize
drive acme.ai.local   vk-acme-platform   dev@acme.test    gpt-4o-mini summarize
drive acme.ai.local   vk-acme-platform   ops@acme.test    gpt-4o      incident-triage
drive acme.ai.local   vk-acme-research   sci@acme.test    gpt-4o-mini literature-scan
drive globex.ai.local vk-globex-platform dev@globex.test  gpt-4o-mini summarize
```

## Report on it

Four dimensions at once, which is the point: `/api/usage/spend` breaks
down one dimension at a time, so "which human, on which key, on which
model" would take four queries and a join.

```bash
export SB_ADMIN='admin:demo-change-me'
curl -s -u "$SB_ADMIN" \
  'http://127.0.0.1:9090/api/requests/report?group_by=model,api_key_id,tenant,user' \
  | python3 -m json.tool
```

<!-- CAPTURE: curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/api/requests/report?group_by=model,api_key_id,tenant,user' | python3 -m json.tool -->

```json
{
    "schema_version": 1,
    "group_by": [
        "model",
        "api_key_id",
        "tenant",
        "user"
    ],
    "rows": [
        {
            "requests": 1,
            "tokens_in": 900,
            "tokens_out": 300,
            "cost_usd_micros": 5250,
            "group": {
                "model": "gpt-4o",
                "api_key_id": "cfg:4:acme:13:acme.ai.local:acme-platform",
                "tenant": "acme",
                "user": "ops@acme.test"
            }
        },
        {
            "requests": 2,
            "tokens_in": 240,
            "tokens_out": 80,
            "cost_usd_micros": 84,
            "group": {
                "model": "gpt-4o-mini",
                "api_key_id": "cfg:4:acme:13:acme.ai.local:acme-platform",
                "tenant": "acme",
                "user": "dev@acme.test"
            }
        },
        {
            "requests": 1,
            "tokens_in": 120,
            "tokens_out": 40,
            "cost_usd_micros": 42,
            "group": {
                "model": "gpt-4o-mini",
                "api_key_id": "cfg:4:acme:13:acme.ai.local:acme-research",
                "tenant": "acme",
                "user": "sci@acme.test"
            }
        },
        {
            "requests": 1,
            "tokens_in": 120,
            "tokens_out": 40,
            "cost_usd_micros": 42,
            "group": {
                "model": "gpt-4o-mini",
                "api_key_id": "cfg:6:globex:15:globex.ai.local:globex-platform",
                "tenant": "globex",
                "user": "dev@globex.test"
            }
        }
    ],
    "totals": {
        "requests": 5,
        "tokens_in": 1380,
        "tokens_out": 460,
        "cost_usd_micros": 5418
    }
}
```

Row one is the answer: one `gpt-4o` call from `ops@acme.test` on the
`acme-platform` key is 97% of the window's spend, 125 times what a
`gpt-4o-mini` call cost. Rows sort by spend first, so the expensive
outlier is never buried under the cheap majority.

Filter to confirm. Every `GET /api/requests` filter applies, so
narrowing the report narrows the rows behind it identically:

```bash
curl -s -u "$SB_ADMIN" \
  'http://127.0.0.1:9090/api/requests/report?group_by=model&user=ops%40acme.test' \
  | python3 -m json.tool
```

<!-- CAPTURE: curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/api/requests/report?group_by=model&user=ops%40acme.test' | python3 -m json.tool -->

```json
{
    "schema_version": 1,
    "group_by": [
        "model"
    ],
    "rows": [
        {
            "requests": 1,
            "tokens_in": 900,
            "tokens_out": 300,
            "cost_usd_micros": 5250,
            "group": {
                "model": "gpt-4o"
            }
        }
    ],
    "totals": {
        "requests": 1,
        "tokens_in": 900,
        "tokens_out": 300,
        "cost_usd_micros": 5250
    }
}
```

## Share the view

The admin console's Reports page serializes the same filter and
grouping state into URL query params, following LiteLLM's pattern:
there is no saved-filter object to manage, because the address bar is
the saved filter. On a binary built with the console embedded, open
`/reports?tenant=acme&group_by=model,user` on the admin port and the
page restores both the filter and the grouping before its first fetch.

## Export the rows

Two formats over the same filtered view. CSV for the spreadsheet:

```bash
curl -s -u "$SB_ADMIN" \
  'http://127.0.0.1:9090/api/requests/export?format=csv&tenant=acme' \
  -o acme-requests.csv
head -3 acme-requests.csv
```

<!-- CAPTURE: curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/api/requests/export?format=csv&tenant=acme' -o /tmp/acme-requests.csv; head -3 /tmp/acme-requests.csv -->

```text
timestamp,origin,method,path,status,latency_ms,client_ip,request_id,trace_id,session_id,parent_session_id,cache_status,retry_count,failover_engaged,failover_from,failover_to,load_balancer_strategy,load_balancer_target,provider,model,tokens_in,tokens_out,cost_usd_micros,guardrail_category,guardrail_action,api_key_id,key_mode,key_provider,tenant_id,user_id,error_class,config_revision,policy_version,deny_reason,policy_decisions,properties,credential_source,tokens_cached,tokens_cache_write,service_tier
<RFC3339>,acme.ai.local,POST,/v1/chat/completions,200,<LATENCY>,127.0.0.1:<PORT>,<HEX32>,<HEX32>,,,disabled,0,false,,,round_robin,openai,openai,gpt-4o-mini,120,40,42,,,cfg:4:acme:13:acme.ai.local:acme-research,minted,,acme,sci@acme.test,,8cb4b33d8ffc,c:8cb4b33d8ffc:ae10235dbb7fdde7,,[],"{""feature"":""literature-scan""}",provider_entry,,,
<RFC3339>,acme.ai.local,POST,/v1/chat/completions,200,<LATENCY>,127.0.0.1:<PORT>,<HEX32>,<HEX32>,,,disabled,0,false,,,round_robin,openai,openai,gpt-4o,900,300,5250,,,cfg:4:acme:13:acme.ai.local:acme-platform,minted,,acme,ops@acme.test,,8cb4b33d8ffc,c:8cb4b33d8ffc:cd949575bc0dca2d,,[],"{""feature"":""incident-triage""}",provider_entry,,,
```

Forty fixed columns, the `globex` row filtered out, and the
`properties` cell carrying JSON with its inner quotes doubled per RFC
4180 so the record still splits into 40 fields. Cells that would open
with `=`, `+`, `-`, `@`, a tab, or a carriage return get a leading
apostrophe first, so an export nobody inspected cannot execute a
formula in whichever laptop opens it.

JSONL for tooling, filtered to one human:

```bash
curl -s -u "$SB_ADMIN" \
  'http://127.0.0.1:9090/api/requests/export?format=jsonl&user=dev%40acme.test' \
  | head -1 | python3 -m json.tool
```

<!-- CAPTURE: curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/api/requests/export?format=jsonl&user=dev%40acme.test' | head -1 | python3 -m json.tool -->

```json
{
    "timestamp": "<RFC3339>",
    "origin": "acme.ai.local",
    "method": "POST",
    "path": "/v1/chat/completions",
    "status": 200,
    "latency_ms": <LATENCY>,
    "client_ip": "127.0.0.1:<PORT>",
    "request_id": "<HEX32>",
    "trace_id": "<HEX32>",
    "properties": {
        "feature": "summarize"
    },
    "cache_status": "disabled",
    "retry_count": 0,
    "failover_engaged": false,
    "load_balancer_strategy": "round_robin",
    "load_balancer_target": "openai",
    "provider": "openai",
    "model": "gpt-4o-mini",
    "tokens_in": 120,
    "tokens_out": 40,
    "cost_usd_micros": 42,
    "api_key_id": "cfg:4:acme:13:acme.ai.local:acme-platform",
    "key_mode": "minted",
    "credential_source": "provider_entry",
    "tenant_id": "acme",
    "user_id": "dev@acme.test",
    "config_revision": "8cb4b33d8ffc",
    "policy_version": "c:8cb4b33d8ffc:cd949575bc0dca2d"
}
```

That line is byte-identical to the row `GET /api/requests` returns, and
it carries `request_id`, `trace_id`, `config_revision`, and
`policy_version`, which is what turns an exported cost row back into
the request, the trace, and the config generation that produced it.

## Watch the exports

An export is the one admin route that returns the operational log in
bulk, so each one is an audited action and a counted event:

```bash
curl -s -u "$SB_ADMIN" 'http://127.0.0.1:9090/metrics' | grep admin_request_export
```

<!-- CAPTURE: curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/metrics' | grep admin_request_export -->

```text
# HELP sbproxy_admin_request_export_rows_total Rows written by admin request-log exports, by format
# TYPE sbproxy_admin_request_export_rows_total counter
sbproxy_admin_request_export_rows_total{format="csv"} 4
sbproxy_admin_request_export_rows_total{format="jsonl"} 2
# HELP sbproxy_admin_request_exports_total Admin request-log exports served, by format
# TYPE sbproxy_admin_request_exports_total counter
sbproxy_admin_request_exports_total{format="csv"} 1
sbproxy_admin_request_exports_total{format="jsonl"} 1
```

The matching `export_request_log` records are on the admin audit
channel, naming the operator, the format, the row count, and which
filter dimensions were set. One per export, newest first, and the row
counts are the same numbers the metric families above carry:

```bash
curl -s -u "$SB_ADMIN" \
  'http://127.0.0.1:9090/api/audit/events?channel=admin' | python3 -m json.tool
```

<!-- CAPTURE: curl -s -u admin:demo-change-me 'http://127.0.0.1:9090/api/audit/events?channel=admin' | python3 -m json.tool -->

```json
[
    {
        "timestamp": "2026-08-21T01:11:55.330677+00:00",
        "channel": "admin",
        "kind": "export_request_log",
        "actor": "admin",
        "detail": "format=jsonl rows=2 filters=user"
    },
    {
        "timestamp": "2026-08-21T01:11:55.318527+00:00",
        "channel": "admin",
        "kind": "export_request_log",
        "actor": "admin",
        "detail": "format=csv rows=4 filters=tenant"
    }
]
```

`filters=tenant` names the dimension, not the value. The record is
bounded by a closed set of dimension names rather than by operator-typed
text, so an audit chain cannot be grown by anyone who can type a long
query string.

## Retention boundary

This ring is operational, not durable: it holds
`proxy.admin.max_log_entries` rows (1000 here) and clears on restart.
That is also the ceiling on any single export, no matter what `limit`
a caller asks for. For durable windowed spend history use
`GET /api/usage/spend`, whose rollups survive restarts. For an
unbounded durable feed, ship the structured access log to your pipeline
(see [`docs/access-log.md`](../../docs/access-log.md)).
