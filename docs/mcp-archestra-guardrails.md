# MCP Archestra guardrails
*Last modified: 2026-07-19*

WOR-1787 adds a small set of MCP gateway mechanisms borrowed from the
Archestra teardown. They are implemented inside the sbproxy repository
and are configured on the `mcp` action. The Terraform provider is not
implemented.

## Mechanisms

### Deterministic egress

OpenAPI-backed MCP servers can set an egress policy so REST tool calls
only reach listed hosts or suffixes. Redirects are followed manually
and every redirect target is checked before the gateway opens the next
connection. Judge and token-exchange destinations use the shared
`sbproxy_security::egress` authorizer purposes (`AiJudge`,
`TokenExchange`) when wired.

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
```

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

### Dual-LLM quarantine

The quarantine gate is opt-in. When enabled, untrusted MCP tool text
blocks are evaluated by a secondary LLM judge (`ToolOutputJudge`)
before any served session-ledger outcome, compaction, or client
response. The judge call is no-tools, fail-closed (timeout, malformed
response, and egress denial all quarantine), and emits only a digest
or closed reason code — never matched text or raw tool output.

```yaml
action:
  type: mcp
  mode: gateway
  dual_llm_quarantine:
    enabled: true
    endpoint: https://judge.example/v1/chat/completions
    model: judge-model
    timeout: 10s
```

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
for the opt-in guards. The full workspace verification remains the
release gate.
