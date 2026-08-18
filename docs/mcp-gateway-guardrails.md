# MCP gateway guardrails
*Last modified: 2026-08-17*

SBproxy's MCP gateway carries a small set of guardrail mechanisms for
tool traffic: egress control, session risk accumulation, output
quarantine, stdio supervision, run-as-user auth, and result
compaction. They are implemented inside the sbproxy repository and are
configured on the `mcp` action. For fusing several such verdicts under
one rule instead of stopping at the first hit, see
[`examples/ai-guardrail-mesh/`](../examples/ai-guardrail-mesh/); for an
out-of-process classifier guardrail on the same request path, see
[`examples/prompt-injection-sidecar/`](../examples/prompt-injection-sidecar/).

## Mechanisms

### Deterministic egress

OpenAPI-backed MCP servers can set an egress policy so REST tool calls
only reach listed hosts or suffixes. Redirects are followed manually
and every redirect target is checked before the gateway opens the next
connection. Judge and token-exchange destinations use the shared
`sbproxy_security::egress` authorizer purposes (`AiJudge`,
`TokenExchange`). The judge transport is gated by
`dual_llm_quarantine.egress`, covered in the next section.

The same `egress` policy also gates a plain `type: mcp` server's base
connect over `streamable_http` or `sse` (`EgressPurpose::McpUpstream`),
not only an OpenAPI-backed server's REST calls. `stdio` servers spawn a
local process and never consult it. Every dial this gate sees, allowed,
denied, or ungated (no `egress:` configured), is recorded and readable at
`GET /api/egress` (see [admin-api-reference.md](admin-api-reference.md)),
so an unsanctioned or misconfigured upstream leaves a record even when
egress is not enforced. See
[mcp-security.md](mcp-security.md#untrusted-or-unexpected-upstream-servers)
for the threat this closes and its honest limits.

```yaml
action:
  type: mcp
  mode: gateway
  egress:
    mode: deny_by_default
    suffixes: [example.com]
  federated_servers:
    - type: openapi
      origin: api.example.com
      spec_path: ./openapi.yaml
      egress:
        mode: deny_by_default
        hosts: [api.example.com]
    - origin: tools.internal
      prefix: tools
      egress:
        mode: deny_by_default
        hosts: [tools.internal]
```

### Registry approval status and protocol pinning

Every `federated_servers[]` entry carries a `status`
(`draft` / `approved` / `deprecated`, absent means `approved`) plus
operator-attested `approved_by` / `approved_at`. `draft` hides that
server's tools from `tools/list` and refuses every `tools/call` against
them, naming the status in the refusal; `deprecated` stays fully callable
but emits a warn-level `mcp_governance_decision` event on every call, so a
slow migration off a sunset server stays visible without an outage.

`protocol` (`auto` / `2025-06-18` / `2026-07-28`, default `auto`) pins a
server to a known era, or lets the gateway remember the strongest
protocol era and auth posture an upstream has shown per tenant.
`downgrade` (`warn` / `block`, default `warn`) decides what happens when a
later contact looks weaker than that remembered peer profile, on either
axis, until the operator re-approves by pinning `protocol` explicitly.

```yaml
federated_servers:
  - origin: partner.example
    prefix: partner
    status: draft
    protocol: auto
    downgrade: block
```

See [mcp.md](mcp.md#federated_servers) for the full field reference and
[mcp-security.md](mcp-security.md#servers-nobody-sanctioned) for the
threat this answers, and where it does not reach.

### Argument and result policies

`argument_policies[]` evaluates a CEL or OPA-compatible Rego expression
against the tool-call context (name, server, session, tenant, principal,
parsed arguments), after RBAC and JSON-Schema validation pass and before
the call dispatches. `result_policies[]` is the same mechanism pointed at
the tool-call result instead, after dispatch and after `content_filters`.
Both are `mode: warn` (default, logs and allows) or `block` (refuses with
a JSON-RPC error), and both fail closed on an expression that cannot be
evaluated.

```yaml
action:
  type: mcp
  mode: gateway
  argument_policies:
    - name: internal-recipients-only
      when: mcp.tool.name == "send_email"
      engine: cel
      source: mcp.arguments.to.endsWith("@company.com")
      mode: block
```

See [mcp-security.md](mcp-security.md#a-permitted-tool-called-with-an-argument-that-should-not-be)
for the full evaluation order and the CEL and Rego context bindings.

### Session flow (Rule of Two)

`flow` tracks two session-scoped labels, `integrity` and
`sensitive_touched`, and refuses (or warns on) a session that has both
touched untrusted, sensitive input and then attempts an outbound call,
under the default `rule: two_of_three`. Requires `sessions.enabled` for
cross-call memory; without it, the check degrades to single-call scope
exactly like `lethal_trifecta` above.

```yaml
action:
  type: mcp
  mode: gateway
  sessions:
    enabled: true
  flow:
    mode: block
    trusted_servers: [internal-docs]
    sensitive_servers: [customer-db]
    outbound_tools: ["email.*", "slack.*"]
```

See [mcp-security.md](mcp-security.md#a-session-that-reads-something-untrusted-then-tries-to-leave)
for the full semantics, the `taint_and_outbound` alternative rule, and
the honest limits of a deterministic approximation.

### Content filters

`content_filters` runs the same secret- and PII-shape detector catalogue
`pii:`/`dlp:` use elsewhere against tool-call arguments (outbound) and
tool-call results, `resources/read`, and `prompts/get` responses
(inbound), a seam the generic HTTP `response_filter` phase never reaches
for an MCP origin. `secrets` and `pii` are each `off` (default) / `warn` /
`redact` / `block`.

```yaml
action:
  type: mcp
  mode: gateway
  content_filters:
    secrets: redact
    pii: warn
```

See [mcp-security.md](mcp-security.md#credentials-reaching-a-tool-that-should-not-see-them)
for the detector shapes and what a fixed catalogue does not catch.

A `warn`, `redact`, or `block` hit carries bounded detection spans on
the underlying `McpContentFilterHit` / `McpContentFilterVerdict::Denied`
value, and logs them at the `sbproxy::mcp::content_filter` tracing
target as `span_count` and `spans_dropped` alongside the existing
`category`/`mode`/`detectors` fields. Each span is an entity type plus a
byte offset and length into the pre-redaction document, never the
matched value, and the count is capped at 32 per category so a document
stuffed with hundreds of matches cannot bloat the record; anything past
the cap only moves `spans_dropped`.

### Governance evidence and fail-closed delivery

Every guardrail above, plus RBAC, quotas, and the version gate, emits an
`mcp_governance_decision` record over `events:` when a sink is configured,
carrying a per-tenant gapless sequence number (`sbproxy.evidence.seq`).
Naming the type under `events.fail_closed` refuses the governed call
instead of serving it silently when the record cannot be queued.

```yaml
events:
  sink: file
  path: /var/log/sbproxy/mcp-governance.ndjson
  types: [mcp_governance_decision]
  fail_closed: [mcp_governance_decision]
```

See [events.md](events.md) for the wire shape, delivery semantics, and
retention, and
[mcp-security-coverage.md](mcp-security-coverage.md#which-records-are-tamper-evident-by-name)
for which of these records are hash-chained versus sequence-protected.

### Lethal-trifecta session guardrail

When MCP sessions are enabled, the gateway records whether a session
has used tools, private-data tools, and external-communication tools.
A call that completes all three is denied before upstream IO.

```yaml
action:
  type: mcp
  mode: gateway
  sessions:
    enabled: true
  guardrails:
    - type: lethal_trifecta
      private_data_tools: [db.*, files.read]
      external_comm_tools: [slack.*, email.*]
```

Without sessions, the guardrail still blocks a single tool that is
classified as both private data and external communication.

See [`examples/mcp-sessions/`](../examples/mcp-sessions/) for the session
lifecycle this guardrail's risk accumulation reads from, and
[`examples/mcp-rbac-quotas/`](../examples/mcp-rbac-quotas/) for per-tool
RBAC and quotas enforced alongside it.

### Dual-LLM quarantine

The quarantine gate is opt-in. When enabled, untrusted MCP tool text
blocks are evaluated by a secondary LLM judge (`ToolOutputJudge`)
before any served session-ledger outcome, compaction, or client
response. The judge call is no-tools, fail-closed (timeout, malformed
response, and egress denial all quarantine), and emits only a digest
or closed reason code, never matched text or raw tool output.

```yaml
action:
  type: mcp
  mode: gateway
  dual_llm_quarantine:
    enabled: true
    endpoint: https://judge.example/v1/chat/completions
    model: judge-model
    timeout: 10s
    egress:
      mode: deny_by_default
      hosts: [judge.example]
```

`egress` scopes an allowlist to the judge endpoint alone, in the same
shape `federated_servers[].egress` uses (purpose `AiJudge`). It is its
own field rather than a share of the action-level `egress:` block
above, deliberately: an operator's existing OpenAPI-tool allowlist is
scoped to their own upstream API, and reusing it here would silently
start gating the judge endpoint too on upgrade. Omitted, the judge call
is ungated (allow-all) but every call still lands in the runtime egress
inventory at `GET /api/egress`, so an operator can see what the judge
is reaching before deciding to lock it down.

### Supervised local stdio MCP

Local stdio MCP servers use `transport: stdio`, a required `command`,
and optional `args`. The gateway supervises one process per exchange,
writes one JSON-RPC request line to stdin, reads one response line from
stdout, and kills the child on timeout or oversized output.

```yaml
action:
  type: mcp
  mode: gateway
  federated_servers:
    - origin: local-tools
      prefix: local
      transport: stdio
      command: /usr/local/bin/my-mcp-server
      args: [--stdio]
      timeout: 5s
```

### Run-as-user MCP auth

Upstreams can opt into per-caller upstream Authorization minting.
When `run_as_user_auth` is true, `upstream_auth` is required and the
gateway mints an `Authorization` credential for the
`McpExecutionContext` (inbound principal / optional delegation).
Identity and tokens never enter tool arguments. Anonymous and
shared-key callers fail closed. `stdio` plus run-as-user is a config
error until a safe secret-delivery path exists for local children.

```yaml
action:
  type: mcp
  mode: gateway
  federated_servers:
    - origin: github.example.com
      prefix: gh
      run_as_user_auth: true
      upstream_auth:
        type: per_user_credential
        credential_template: "vault://users/{subject_id}/mcp-token"
```

Supported `upstream_auth.type` values: `service_credential`,
`token_exchange`, and `per_user_credential`.

See [`examples/mcp-oauth-discovery/`](../examples/mcp-oauth-discovery/) for
the OAuth discovery surface (RFC 9728) a caller authenticates against
before run-as-user auth mints its own upstream credential.

### Token compaction

Tool-result compaction is disabled by default. When enabled, oversized
MCP `content[].text` blocks are truncated at a UTF-8 boundary and
annotated with omitted byte count metadata. Compaction runs only after
quarantine releases the output.

```yaml
action:
  type: mcp
  mode: gateway
  token_compaction:
    enabled: true
    max_text_bytes: 8192
```

## Verification surface

The implementation has focused unit coverage for egress policy
matching, redirect-safe OpenAPI egress denial, stdio supervision,
session risk accumulation, dual-LLM judge fail-closed behavior,
run-as-user mint/attach without arg injection, and config compilation
for the opt-in guards. Argument/result policies, session flow, content
filters, registry approval status, and governance evidence delivery are
covered together end to end in
[`e2e/tests/mcp_governance_pack_e2e.rs`](../e2e/tests/mcp_governance_pack_e2e.rs);
see [mcp-security-coverage.md](mcp-security-coverage.md) for which named
test proves which guardrail. The full workspace verification remains the
release gate.
