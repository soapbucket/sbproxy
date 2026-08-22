# Agent orchestration
*Last modified: 2026-08-22*

`sbproxy_ai::agent_orchestration` (WOR-2672) is an in-process toolkit for
building a multi-agent workflow on top of the AI gateway: capability
discovery, an FSM-based orchestrator, and a shared-secret agent
authentication scheme. It is a library an embedder drives from its own
code; it does not touch the request path or add any configuration
surface.

## Not the same "A2A" as `a2a-gateway.md`

SBproxy already ships a distinct, unrelated feature also named A2A: the
`a2a` action, `a2a` policy, and `a2a_agent_card_rewrite` transform (see
[a2a-gateway.md](a2a-gateway.md)), which proxy and govern *inbound HTTP*
Agent-to-Agent protocol traffic between a caller and an upstream agent,
authenticated by RFC 8693 `act` claim chains or trusted reverse-proxy
headers.

`agent_orchestration` is a different concern: it does not proxy HTTP at
all. It is what an embedder reaches for when *building* a multi-agent
pipeline in-process (which agent to call next, what it can do, and a
lightweight token scheme for authenticating calls between cooperating
agents an operator controls). The module was named `agent_orchestration`
rather than `a2a` specifically to keep the two apart; if you are looking
for the request-path feature, you want `a2a-gateway.md` instead.

## Capability discovery

`AgentRegistry` is a central registry of agents and the capabilities
(name, description, JSON Schema input/output) each one advertises, so an
orchestrator can find a peer able to perform a task before invoking it:

```rust,ignore
use sbproxy_ai::agent_orchestration::{AgentCapability, AgentRegistry};
use serde_json::json;

let registry = AgentRegistry::new();
registry.register(
    "research-agent",
    vec![AgentCapability {
        name: "web_search".to_string(),
        description: "Search the web and summarize results".to_string(),
        input_schema: json!({"type": "object", "properties": {"query": {"type": "string"}}}),
        output_schema: json!({"type": "object", "properties": {"summary": {"type": "string"}}}),
    }],
);

let holders = registry.find_by_capability("web_search"); // ["research-agent"]
```

## FSM-based orchestration

`FsmWorkflow` describes a directed graph of named states; each state
names the agent (or action label) to invoke and maps outcome labels to
the next state. `FsmExecution` drives one in-progress run and records
history:

```rust,ignore
use sbproxy_ai::agent_orchestration::{FsmExecution, FsmState, FsmWorkflow};
use std::collections::HashMap;

let mut states = HashMap::new();
states.insert("triage".to_string(), FsmState {
    name: "triage".to_string(),
    action: "research-agent".to_string(),
    transitions: [("needs_code".to_string(), "code".to_string()),
                  ("needs_summary".to_string(), "summarize".to_string())].into(),
});
states.insert("code".to_string(), FsmState {
    name: "code".to_string(), action: "coding-agent".to_string(), transitions: HashMap::new(),
});
states.insert("summarize".to_string(), FsmState {
    name: "summarize".to_string(), action: "summarizer-agent".to_string(), transitions: HashMap::new(),
});

let workflow = FsmWorkflow { name: "support-triage".to_string(), states, initial_state: "triage".to_string() };
let mut exec = FsmExecution::new(workflow);
let next = exec.transition("needs_code"); // Some("code")
assert!(!exec.is_completed());
```

A state with no matching transition for the result it receives is
terminal: `FsmExecution::is_completed` flips to `true` and
`FsmExecution::history` carries the full `(state, result)` trail for
audit.

## Agent authentication

A minimal, dependency-free scheme for authenticating calls between
cooperating agents that share a secret: the token is the hex-encoded
SHA-256 digest of `"<agent_id>:<secret>"`, so no token database is
required to verify one.

```rust,ignore
use sbproxy_ai::agent_orchestration::{generate_agent_token, verify_agent_token, A2AAuthConfig};

let config = A2AAuthConfig { shared_secret: "op-managed-secret".to_string() };
let token = generate_agent_token("coding-agent", &config.shared_secret);
assert!(verify_agent_token("coding-agent", &token, &config.shared_secret));
```

This is intentionally simple: a shared secret, not a PKI or a claims
chain. It authenticates one agent to another inside a boundary an
operator already controls (the workflow orchestrator and the agents it
calls); it is not a substitute for the proxy's own RFC 8693 `act` chain
verification on inbound HTTP A2A traffic.

## Runnable example

[`crates/sbproxy-ai/examples/agent_orchestration_workflow.rs`](../crates/sbproxy-ai/examples/agent_orchestration_workflow.rs)
wires all three pieces together into one triage-then-dispatch workflow:

```bash
cargo run -p sbproxy-ai --example agent_orchestration_workflow
```

## See also

- [a2a-gateway.md](a2a-gateway.md) - the proxy's own, unrelated A2A
  request-path feature.
- [mcp-and-agents.md](mcp-and-agents.md) - the map across MCP and A2A
  traffic this module sits beside without touching either transport.
