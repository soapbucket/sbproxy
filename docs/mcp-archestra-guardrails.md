# MCP Archestra guardrails
*Last modified: 2026-07-09*

WOR-1787 adds a small set of MCP gateway mechanisms borrowed from the
Archestra teardown. They are implemented inside the sbproxy repository
and are configured on the `mcp` action. The Terraform provider is not
implemented.

## Mechanisms

### Deterministic egress

OpenAPI-backed MCP servers can set an egress policy so REST tool calls
only reach listed hosts or suffixes. Redirects are followed manually
and every redirect target is checked before the gateway opens the next
connection.

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

The quarantine gate is opt-in. It scans MCP text result blocks for
configured suspicious patterns and returns a JSON-RPC error instead of
handing that output back to the caller.

```yaml
action:
  type: mcp
  mode: gateway
  dual_llm_quarantine:
    enabled: true
    suspicious_patterns:
      - ignore previous instructions
      - exfiltrate
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

Upstreams can opt into a bounded caller identity envelope. When
`run_as_user_auth` is true, outbound tool arguments include
`_sbproxy_run_as_user` with tenant, subject, source, virtual key name,
and common attribution fields. Arbitrary JWT claims and metadata are
not forwarded.

```yaml
action:
  type: mcp
  mode: gateway
  federated_servers:
    - origin: github.example.com
      prefix: gh
      run_as_user_auth: true
```

### Token compaction

Tool-result compaction is disabled by default. When enabled, oversized
MCP `content[].text` blocks are truncated at a UTF-8 boundary and
annotated with omitted byte count metadata.

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
session risk accumulation, and config compilation for the opt-in
guards. The full workspace verification remains the release gate.
