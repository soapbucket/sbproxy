# Agent orchestration

*Last modified: 2026-08-26*

SBproxy's AI toolkit runs bounded, finite-state workflows against an
operator-declared agent registry. Agents, workflows, schemas, limits, secrets,
and the egress allowlist are compiled into one immutable pipeline generation.
Operators discover and invoke that generation through the authenticated admin
API or the `sbproxy ai workflow` CLI.

This is not the inbound A2A proxy feature. The [`a2a` action](a2a-gateway.md)
governs HTTP traffic sent by an external caller to an upstream A2A agent. The
AI toolkit is an outbound orchestrator: it selects a configured agent by
capability and calls it as one state in a workflow.

## Configure agents and workflows

Agents and workflows live under `proxy.ai_toolkit`. Every resource names an
existing configured origin; that origin supplies the tenant and origin scope
used for discovery, execution, snapshots, events, and retained summaries.

<!-- sbproxy-config: examples/ai-agent-orchestration/sb.yml -->
```yaml
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    port: 9090
    username: admin
    password: ${SB_ADMIN_PASSWORD:-change-this-before-running}
  ai_toolkit:
    limits:
      max_agents: 8
      max_workflows: 8
      agent_concurrency: 4
      default_workflow_timeout_ms: 2000
      max_workflow_timeout_ms: 5000
    agents:
      - origin: ai.local
        id: local-researcher
        endpoint: http://127.0.0.1:18777/invoke
        auth:
          shared_secret: env:SB_AGENT_SECRET
        capabilities:
          - name: research
            description: Return a bounded research summary
            input_schema:
              type: object
              required: [question]
              properties:
                question: {type: string}
              additionalProperties: false
            output_schema:
              type: object
              required: [summary]
              properties:
                summary: {type: string}
              additionalProperties: false
    workflows:
      - origin: ai.local
        name: research-flow
        initial_state: research
        max_steps: 2
        timeout_ms: 2000
        states:
          - name: research
            action: research
            transitions: {}

egress:
  agent_orchestration:
    mode: deny_by_default
    hosts: ["127.0.0.1"]
    ports: [18777]
    allow_private: true

origins:
  "ai.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: AI toolkit control-plane scope
```

`auth.shared_secret` must be a secret reference such as
`env:SB_AGENT_SECRET`; inline secret material is a compile error. The reference
is resolved only while SBproxy constructs a candidate runtime and the resolved
value is not retained in the parsed configuration, logs, snapshots, or events.

Agent calls require a top-level `egress.agent_orchestration` block with
`mode: deny_by_default`. Host, port, DNS resolution, redirects, and private-IP
access are governed at that boundary. A configured agent with no armed policy
fails closed instead of dialing an ungoverned destination.

Each capability declares JSON Schema for its input and output. Both schemas are
compiled before publication. A workflow state names a capability in `action`;
the runtime selects a scoped agent that advertises it, validates the request,
makes the governed call, validates the response, and uses its outcome label to
choose the next state.

## Discover, validate, and run

Use the standard admin environment variables so credentials do not appear in
shell history:

```bash
export SB_ADMIN_URL='http://127.0.0.1:9090'
export SB_ADMIN_USERNAME='admin'
export SB_ADMIN_PASSWORD='replace-me'
```

Discover all scoped agents, or filter by one exact capability:

```bash
sbproxy ai workflow discover --origin ai.local
sbproxy ai workflow discover --origin ai.local --capability research
```

Validate a YAML workflow without publishing or invoking it:

```bash
sbproxy ai workflow validate workflow.yml --origin ai.local
```

Run one of the workflows already published by the current config generation:

```bash
sbproxy ai workflow run \
  --origin ai.local \
  --workflow research-flow \
  --input input.json
```

The same commands accept `--admin-url`, `--username`, and `--password`.
Discovery uses `GET /admin/ai-toolkit/agents`; validation and execution use the
workflow routes documented in [Admin API reference](admin-api-reference.md#ai-toolkit-admin).

## Finite-state and resource contract

Every entered state is invoked exactly once. Its returned outcome advances to
the named transition; no matching transition completes the workflow. Cycles
are allowed only within the configured step and deadline bounds.

The public FSM type also enforces these hard ceilings in addition to the
operator-configured toolkit limits:

| Dimension | Hard maximum |
|---|---:|
| States | 256 |
| Transition edges | 2,048 |
| Execution steps/history records | 1,024 |
| Workflow, state, or transition-target identifier | 256 bytes |
| Action label | 512 bytes |
| Outcome label | 4,096 bytes |
| Aggregate graph strings | 1 MiB |
| Retained history strings | 1 MiB |

Toolkit limits additionally bound agent and workflow counts, request and
response bytes, JSON Schema bytes, identifier and description bytes,
concurrency, per-run deadlines, and retained redacted operation summaries.
Limits are checked before publication or before a body exceeding a boundary is
materialized. Concurrency is fail-fast; a saturated runtime does not grow an
unbounded waiting queue.

Those bounds belong to the runtime this page documents. The lower-level
`sbproxy_ai::agent_orchestration::AgentRegistry` an embedder can call
directly is an offline building block with no cap, no eviction, and no
tenant keying. Reach for the runtime above on any path a request can
drive.

## What operators can observe

- `GET /admin/ai-toolkit/snapshot` returns scoped, bounded inventories and
  operation summaries. It excludes agent request/response bodies, endpoints,
  credentials, tokens, and secret references.
- `ai_workflow_operation` is the typed terminal event for workflow executions.
  Its payload is limited to the scoped origin/workflow identifiers, closed
  outcome, step count, and duration.
- `sbproxy_ai_toolkit_operations_total{capability="workflow",outcome="..."}`
  is the Prometheus counter. Both labels use closed vocabularies; workflow,
  agent, tenant, origin, and run identifiers are deliberately not metric
  labels.

The Grafana AI dashboard includes a workflow-outcomes panel. See
[Events](events.md) and [Metrics stability](metrics-stability.md) for the wire
and label contracts.

## Runnable example

[`examples/ai-agent-orchestration`](../examples/ai-agent-orchestration/) contains
the complete config, workflow document, input, and CLI sequence. It needs no
Redis; only workflow execution needs the compatible loopback agent declared by
the example.
