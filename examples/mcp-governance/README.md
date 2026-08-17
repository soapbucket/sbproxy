# MCP governance pack

*Last modified: 2026-08-16*

Every governance surface described in [docs/mcp-security.md](../../docs/mcp-security.md), turned on at once. Nothing here is on by default in the product. Bearer auth, default-deny RBAC, a pinned tool allowlist, a checked-in tool-versioning lockfile, streamable HTTP sessions, per-upstream egress gating, registry approval status, protocol pinning, argument policies in CEL and Rego, deterministic session-flow enforcement, response-side content filtering, and a fail-closed governance-evidence feed all have to be configured, one line at a time, before any of them do anything. This example is that configuration written out. If you have been reading the coverage table in the docs and wondering what "full (config-reachable)" actually looks like assembled, this is it.

It is also opinionated on purpose. `mode: block` where the docs default to `warn`, `fail_closed` on the evidence stream, egress deny-by-default on every upstream. Treat it as the ceiling, not a starting point: turn individual blocks down (or back off) to match what your deployment can tolerate before it ships.

## What each block enforces

- `authentication: bearer` - a caller needs `Authorization: Bearer <token>` before the gateway looks at anything else. The first example in this repo to pair auth with `action.type: mcp`.
- `sessions.enabled` - the gateway issues an `Mcp-Session-Id` on `initialize` and requires it on every request after. Also what gives the session-flow guardrail below cross-call memory.
- `rbac_policies` - default-deny. A caller matching no rule is refused, and adding a tool upstream never silently widens who can call it.
- `guardrails: [tool_allowlist, lethal_trifecta]` - a second, coarser allowlist on top of RBAC, plus a session-scoped guardrail that denies a session the moment it has touched tool access, private data, and external communication all at once. The trifecta's patterns here (`billing.*`, `notify.*`) name no tool this walkthrough advertises, on purpose: the guardrail is genuinely evaluated on every call, it just never sees all three legs from this config. Point it at your own tool names to make it live.
- `tool_versioning` - every advertised tool is checked against a committed contract digest on each catalog refresh. `block_unlocked: true` means a tool with no lockfile entry is blocked, not just flagged.
- `federated_servers[].egress` - deny-by-default per upstream. A federated server's connect is authorized the same way an `ai_proxy` provider dial is, and every dial's outcome (allowed, denied, ungated) is recorded.
- `federated_servers[].status` - `draft` hides a server's tools from `tools/list` and refuses every call against them; `approved` (the default) is fully callable; `deprecated` stays callable but warns on every call.
- `federated_servers[].protocol` / `.downgrade` - pin a server to a known protocol era, or let the gateway remember the strongest era and auth posture an upstream has shown and flag or refuse a later contact that looks weaker.
- `argument_policies` - a CEL or Rego expression evaluated against the parsed tool-call arguments, after RBAC and JSON-Schema validation, before dispatch. `false` is a violation.
- `flow` - Meta's Rule of Two. A session that has touched an untrusted, sensitive source and then tries an outbound call is refused, even though every individual call along the way was itself allowed.
- `content_filters` - the secret and PII detector catalog, run against tool-call arguments on the way out, tool-call results on the way back, and `resources/read` and `prompts/get` results too. `response_filter` never sees any of this traffic; MCP writes its own response outside that phase.
- `mcp_audit.capture_arguments` - opt-in, redacted, size-bounded verbatim arguments on every governance record, refused or dispatched. See the privacy note near the bottom before you turn this on for real.
- `events.fail_closed: [mcp_governance_decision]` - if the evidence record for a governed decision cannot be queued, the call it describes is refused rather than served with no evidence behind it.

## The three upstreams

Three `federated_servers[]` entries, all pointed at `test.sbproxy.dev`, the project's public test service, which serves two live tools: `hello` (greets a `name`) and `echo` (echoes back a `message`). Every call below is a real round trip, not a transcript.

- **`reports`** - approved, trusted. The outbound leg of the session-flow demo, and where the RBAC-allowed and RBAC-denied calls land.
- **`crm`** - approved but not trusted, and marked sensitive. Reading it is what taints a session and marks it sensitive; it stands in for a customer-data source you would not want a tainted session talking to afterward.
- **`legacy`** - `status: draft`, never approved. Exists only so a draft server's refusal has something real to point at.

`tool-versions.lock.yaml` pins the four tools this walkthrough actually calls (`reports.hello`, `reports.echo`, `crm.echo`, `legacy.echo`). Two more real, live tools on the shared upstream (`crm.hello`, `legacy.hello`) are deliberately left out of the lockfile: with `block_unlocked: true`, that means they are missing from `tools/list` and refused on `tools/call`, which is the escape hatch this feature exists to close, sitting right next to the tools that are pinned.

## Run

```bash
sbproxy serve -f examples/mcp-governance/sb.yml
```

Run it from the repository root: the config's Rego policy and lockfile paths are resolved relative to the working directory the proxy is started from, the same convention `transforms[] type: wasm` uses. Use absolute paths in production. The evidence file `mcp-governance-events.ndjson` is written to that same working directory.

Run every curl below from a second terminal. `sessions.enabled: true` means the gateway needs a session before it answers anything past `initialize`, so each scenario below mints its own with this recipe:

```bash
mint_session() {
  curl -sD - -o /dev/null -m 10 -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' \
    -H 'Authorization: Bearer governance-demo-token' \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-demo","version":"1.0.0"}}}' \
  | grep -i '^mcp-session-id:' | tr -d '\r' | cut -d' ' -f2
}

finish_session() {
  curl -sS -o /dev/null -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' \
    -H 'Authorization: Bearer governance-demo-token' \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' \
    -H "Mcp-Session-Id: $1" \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
}
```

## Try it

Each scenario mints a fresh session, so nothing below depends on the order you run them in, except the flow-violation scenario, which needs its two calls back to back.

### An allowed tool call

```bash
SESSION=$(mint_session); finish_session "$SESSION"

curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Authorization: Bearer governance-demo-token' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -H "Mcp-Session-Id: $SESSION" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reports.hello","arguments":{"name":"Ada"}}}' | jq .
```

`reports.hello` is RBAC-allowed for `analyst`, on the allowlist, locked at its real contract digest, approved, and not yet tainted. It dispatches for real:

```json
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Hello, Ada!"}]}}
```

### An RBAC-denied call

```bash
SESSION=$(mint_session); finish_session "$SESSION"

curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Authorization: Bearer governance-demo-token' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -H "Mcp-Session-Id: $SESSION" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"reports.echo","arguments":{"message":"hi"}}}' | jq .
```

`reports.echo` clears the tool allowlist and the version lockfile, same as `reports.hello` does, but `analyst`'s `tool_access` never named it. RBAC refuses it before the upstream is ever contacted:

```json
{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"tool 'reports.echo' is denied by RBAC policy for caller"}}
```

### An argument-policy block

```bash
SESSION=$(mint_session); finish_session "$SESSION"

curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Authorization: Bearer governance-demo-token' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -H "Mcp-Session-Id: $SESSION" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"crm.echo","arguments":{"message":"read ../../etc/passwd"}}}' | jq .
```

RBAC allows `crm.echo` for `analyst`, so the call reaches `argument_policies[]`. Both the CEL rule and its Rego twin evaluate `mcp.arguments.message` and find the path-traversal sequence; the CEL rule is listed first, so it is the one the refusal names:

```json
{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"tool 'crm.echo' is denied by argument policy 'no-path-traversal-in-message'"}}
```

### A flow-violation block, under `rule: two_of_three`

Two calls, one session. The first reads from `crm`, which is untrusted and sensitive; the second is an outbound call to `reports.*`.

```bash
SESSION=$(mint_session); finish_session "$SESSION"

# Taints the session (crm is not in trusted_servers) and marks it
# sensitive (crm is in sensitive_servers). Allowed and dispatched.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Authorization: Bearer governance-demo-token' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -H "Mcp-Session-Id: $SESSION" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"crm.echo","arguments":{"message":"customer lookup for case 4412"}}}' | jq .

# The third leg. Integrity is tainted and sensitive_touched is set, so
# the outbound attempt trips the default two_of_three rule.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Authorization: Bearer governance-demo-token' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -H "Mcp-Session-Id: $SESSION" \
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"reports.hello","arguments":{"name":"Ada"}}}' | jq .
```

The first call succeeds normally. The second is refused, even though `reports.hello` was the exact call that succeeded, unblocked, at the top of this walkthrough, in a different session:

```json
{"jsonrpc":"2.0","id":6,"error":{"code":-32602,"message":"tool 'reports.hello' is refused by the session-flow guardrail (flow_exfil_block)"}}
```

### A draft-server refusal

```bash
SESSION=$(mint_session); finish_session "$SESSION"

curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Authorization: Bearer governance-demo-token' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -H "Mcp-Session-Id: $SESSION" \
  -d '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"legacy.echo","arguments":{"message":"hi"}}}' | jq .
```

`legacy` is `status: draft`. The refusal names the status rather than pretending the tool does not exist, and it fires before RBAC, the protocol pin, or anything else on that server entry is even consulted:

```json
{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"tool 'legacy.echo' is served by federated server 'legacy', which has status 'draft' and is not yet approved for calls"}}
```

`legacy.echo` also never appeared in the earlier `tools/list` output, if you called it: a draft server's tools are hidden from the catalog, not merely refused on call.

### A secret redacted on the way out (bonus)

Not one of the six required scenarios, but the clearest single proof that `content_filters` runs where `response_filter` cannot reach: MCP writes its own response outside the generic HTTP body-filter phase, so this is the only path a fake API key in a tool argument gets caught on.

```bash
SESSION=$(mint_session); finish_session "$SESSION"

curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Authorization: Bearer governance-demo-token' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -H "Mcp-Session-Id: $SESSION" \
  -d '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"crm.echo","arguments":{"message":"my key is sk-FAKEFAKEFAKEFAKEFAKEFAKE, do not share it"}}}' | jq .
```

`content_filters.secrets: redact` catches the key shape and mutates the argument before it ever reaches the upstream, so the real `echo` tool, which just echoes its input, only ever sees and returns the redacted text:

```json
{"jsonrpc":"2.0","id":8,"result":{"content":[{"type":"text","text":"my key is [REDACTED:APIKEY], do not share it"}]}}
```

### The events sink receiving governance records

Every scenario above emitted a `mcp_governance_decision` record to `mcp-governance-events.ndjson` (this config's `events.sink: file` path), whether it dispatched or was refused. `events.fail_closed` covers the same type, so if the file sink had failed to accept one of these records, the call behind it would have come back refused with an `evidence_unavailable` error instead of proceeding quietly with no evidence behind it.

```bash
tail -n 8 mcp-governance-events.ndjson | jq -c '{event_type, tenant_id, data: {tool: .data["gen_ai.tool.name"], server: .data["sbproxy.tool.server"], verdict: .data["sbproxy.decision.verdict"], reason: .data["sbproxy.decision.reason"], rule: .data["sbproxy.decision.rule_id"], seq: .data["sbproxy.evidence.seq"]}}'
```

One line per decision, RBAC deny, argument-policy deny, flow deny, draft deny, content-filter warn, and the plain allows in between, each carrying `sbproxy.evidence.seq`: a per-tenant, gapless counter, so a SIEM consuming this file can tell a dropped record from a quiet afternoon.

## Privacy note on `mcp_audit.capture_arguments`

This example turns it on. Every tool-invocation record in `mcp-governance-events.ndjson`, not just the refused ones, carries `gen_ai.tool.call.arguments`: the call's arguments, redacted through the same `content_filters` pass this config runs and capped at 8 KiB. A category only mutates the match out of the captured text when its mode is `redact`, not `warn`. This config sets `secrets: redact` but `pii: warn`, so the credential shape from the earlier scenario is scrubbed from this record too, while your customers' names, case numbers, or anything else that is sensitive only because of what your business does with it, is not, which is exactly what shows up in `crm.echo`'s `message` argument in the scenarios above. Set `content_filters.pii: redact` if you want that caught here as well.

Turning this on is a real decision, not a default you should inherit from an example. Look at what your own tools actually receive before you flip it in production, and remember that with a webhook sink instead of the file sink used here, those bytes leave your network.

## What this exercises

- `authentication: bearer` paired with `action.type: mcp`
- `sessions.enabled` with a `ttl`
- `rbac_policies` with named tool access and a per-tool quota
- `guardrails[].type: tool_allowlist` and `guardrails[].type: lethal_trifecta`
- `tool_versioning` with `mode: block`, `block_unlocked: true`, and a committed lockfile
- `federated_servers[].egress` deny-by-default, per server
- `federated_servers[].status`, `.approved_by`, `.approved_at` (both the explicit and the absent-means-approved forms)
- `federated_servers[].protocol` pinned, `.downgrade: block`
- `argument_policies[]` with a CEL rule and its Rego twin over the same predicate
- `flow` under the default `rule: two_of_three`
- `content_filters` in `redact` and `warn` mode
- `mcp_audit.capture_arguments`
- `events.sink: file`, `events.types`, and `events.fail_closed`

## See also

- [docs/mcp-security.md](../../docs/mcp-security.md) - the threat-by-threat writeup every block above is answering
- [docs/mcp.md](../../docs/mcp.md) - wire format and the full `federated_servers[]` field reference
- [docs/events.md](../../docs/events.md) - the `events:` block, fail-closed delivery, and retention
- [docs/tool-versioning.md](../../docs/tool-versioning.md) - the compatibility oracle and the lockfile format
- [examples/mcp-federation](../mcp-federation/) - the base federation mechanics this example builds on
- [examples/mcp-rbac-quotas](../mcp-rbac-quotas/) - RBAC and per-tool quotas on their own, without everything else turned on
