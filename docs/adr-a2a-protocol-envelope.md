# ADR: A2A protocol envelope and policy hook points

*Last modified: 2026-05-03*

## Status

Accepted. SBproxy is the inspection point for agent-to-agent traffic regardless of operator deployment shape. Builds on `adr-agent-class-taxonomy.md` (the `AgentClass` taxonomy and resolver chain), `adr-event-envelope.md` (event schema A2A hops attach to), `adr-end-to-end-idempotency.md` (request-id propagation reused here for chain reconstruction), and `adr-schema-versioning.md` (closed-enum amendment rules). Consumed by the `sbproxy-modules/policy/a2a.rs` module and the audit and dashboard surfaces.

## Context

A2A (agent-to-agent) is the umbrella term for emerging protocols that standardize how one AI agent calls another AI agent over the network. The two drafts driving the space at this writing are:

- **Anthropic A2A** (`draft-anthropic-a2a-v0`). Built on the MCP transport surface; A2A invocation is modeled as an MCP tool call where the "tool" is another agent. Carries a `parent_request_id` and `chain_depth` in the request body envelope.
- **Google A2A** (`draft-google-a2a-v0`). Defines a dedicated `application/a2a+json` content type with its own envelope; carries `caller_agent_id`, `callee_agent_id`, `task_id`, and a parent chain in a top-level `chain` array.

Both drafts converge on the same operational requirements:

1. The receiving agent needs to know which agent called it (provenance).
2. The infrastructure needs to detect cycles to prevent wallet drain.
3. The audit log needs to reconstruct the full call graph.
4. Policy needs a place to gate the call (depth caps, allow lists, callee permissions).

SBproxy is the natural inspection point for all of this: A2A calls are HTTP requests; they pass through the proxy on their way out (caller side) and on their way in (callee side); the proxy already exposes per-route policy, audit, and metrics. SBproxy makes A2A a first-class request shape rather than a generic POST that happens to carry agent traffic.

The hard constraint is spec churn. Both drafts are at v0 and are likely to change before either becomes a stable reference. The ADR commits to an internal abstraction (`A2AContext`) and to feature-flagged parsers; the wire format we accept is determined at GA cut by which spec is most stable then.

## Decision

### Detection

A request is treated as A2A when one of the following is true:

1. The `Content-Type` header is `application/a2a+json` or any subtype matching `application/a2a+json; version=*` (Google A2A path).
2. The `MCP-Method` header is present and the method name is `agents.invoke` (Anthropic A2A path; A2A invocation is modeled as a specific MCP method per the draft).
3. The path matches a configured `a2a.route_glob` (operator escape hatch for non-standard deployments).

Detection runs once in the request filter, before any policy evaluation. The result is stored in `RequestContext.a2a: Option<A2AContext>` and never recomputed downstream.

### `A2AContext` shape

```rust
pub struct A2AContext {
    pub spec: A2ASpec,                   // which draft fired
    pub caller_agent_id: AgentIdRef,     // resolved via the agent-class resolver chain
    pub callee_agent_id: Option<AgentIdRef>, // present when callee is determined upstream
    pub task_id: String,                 // opaque task identifier (caller-assigned)
    pub parent_request_id: Option<String>, // request_id of the parent hop, if any
    pub chain_depth: u32,                // 1 for the first hop, +1 per nested call
    pub chain: Vec<ChainHop>,            // full ancestor chain (oldest first)
    pub raw_envelope_version: String,    // e.g. "anthropic-v0", "google-v0"
}

pub enum A2ASpec { AnthropicV0, GoogleV0 }

pub struct ChainHop {
    pub agent_id: AgentIdRef,
    pub request_id: String,
    pub timestamp_ms: u64,
}
```

Parsing populates the struct from the wire envelope; missing fields use zero values (`chain_depth = 1`, empty `chain`) and an audit event records the gap.

### Feature flags

The parser surface is feature-flagged:

```toml
[features]
default = []
a2a-anthropic = []
a2a-google = []
a2a = ["a2a-anthropic", "a2a-google"]   # convenience
```

The default OSS build does not compile either parser. Operators opt in per spec. We do not ship "experimental A2A" as a separate flag; the v0 designation in `raw_envelope_version` already communicates instability.

When neither flag is enabled and a request matches A2A detection (e.g. by content type), the proxy logs a debug event and treats the request as a plain HTTP POST. Detection without parsing avoids forcing a build-time decision in environments where A2A traffic exists but is not yet a policy target.

### Policy hook points

A new policy module `sbproxy-modules/policy/a2a.rs` exposes per-route configuration:

```yaml
policies:
  - type: a2a
    config:
      max_chain_depth: 5             # default 5; operator-tunable, hard ceiling 32
      allow_cycles: false            # default false; cycle = callee already in chain
      cycle_detection: strict        # strict | by_agent_id | by_callable_endpoint
      callee_allowlist:              # optional; if present, only listed agents may be called
        - "agent:openai:gpt-5"
        - "agent:anthropic:claude-4"
      caller_denylist: []            # optional; agents that may never initiate A2A from this route
      bill_caller_only: true         # default true; see Pricing section
```

The policy fires in the request filter, after authentication and after the resolver chain has populated `caller_agent_id`. Failure modes:

- Chain depth exceeds `max_chain_depth`: 429 Too Many Requests with `Retry-After: 0` and body `{"error":"a2a_chain_depth_exceeded","limit":N,"depth":M}`. We use 429 (not 400) because depth is a transient policy decision, not a malformed request.
- Cycle detected: 409 Conflict with body `{"error":"a2a_cycle_detected","callee":"...","cycle_position":N}`. The cycle position is the index in the chain where the callee already appears.
- Callee not on allowlist: 403 Forbidden with body `{"error":"a2a_callee_not_allowed","callee":"..."}`.
- Caller on denylist: 403 Forbidden with body `{"error":"a2a_caller_denied","caller":"..."}`.

All four denial paths emit an audit event and increment a per-reason counter.

### Cycle detection modes

The `cycle_detection` knob exposes three semantics for "cycle":

- `strict`: the exact `(agent_id, request_id)` pair must not appear earlier in the chain. Detects only true loops where the same physical request is replayed; almost never fires in practice but is the safest baseline.
- `by_agent_id` (default): the callee `agent_id` must not appear anywhere earlier in the chain. Detects "agent A calls agent B which calls agent A again." Most operators want this.
- `by_callable_endpoint`: the callee `(agent_id, callable_endpoint)` tuple must not appear. Allows agent A to call agent B which calls agent A with a different method, on the theory that different methods are different calls. Useful for orchestration patterns where one agent dispatches and another agent reports back.

### Chain depth ceiling

`max_chain_depth` defaults to 5. Justification: empirical traces from existing MCP deployments show chain depth >= 4 is rare even in pathological orchestration setups; 5 leaves headroom for legitimate use without enabling runaway recursion. The hard ceiling of 32 is enforced regardless of operator config and reflects a memory-bound on the chain reconstruction path (each hop is ~256 bytes; 32 hops cap at 8 KB per request envelope).

Operators that need deeper chains (e.g. agent-mesh research deployments) can disable the policy entirely. The hard ceiling cannot be lifted via config; it is a code change that requires an ADR amendment.

### Pricing semantics

A2A calls bill the caller's wallet, never the callee's. This is invariant. The reasoning:

1. The caller initiated the call. Charging the callee creates a zero-day attack where one agent can drain another agent's budget by calling it in a loop.
2. The callee's wallet is the wallet of the agent that owns the resource being called, not the wallet of the agent doing the calling. Callee-bills semantics would put the callee on the hook for work it did not request.
3. Cycle detection enforces that the chain cannot contain the same agent twice (in `by_agent_id` mode), which in combination with caller-bills makes it impossible for a malicious agent to exhaust its own wallet via A2A loops.

The `bill_caller_only` config knob defaults to `true` and exists only as a kill switch for experimental "pay-per-callee" deployments; setting it to `false` requires the callee to opt in via a per-route policy, and the audit log marks every such transaction with `pricing_anomaly: callee_billed`.

When the caller carries an `actor_sub`, the chargeback walks the caller's `actor_sub`, not the callee's. The `actor_sub` propagates through every hop in the chain by being copied from the parent request's `actor_sub` into the child request envelope; the callee can verify the parent chain by inspecting the chain's `parent_request_id` against the audit log.

### Audit and observability

Every A2A hop emits an audit event with the full chain. The event payload includes:

- `request_id` (this hop)
- `parent_request_id` (the calling hop, or null for the chain root)
- `chain_depth`
- `caller_agent_id`, `callee_agent_id`
- `task_id`
- `actor_sub`, `actor_idp` (when present)
- `policy_decision` (`allow` | `deny:<reason>`)
- `spec` (`anthropic-v0` | `google-v0`)

The event type is `a2a_hop`; reconstruction of the full call graph is a join on `(task_id, parent_request_id)` keys and is the responsibility of the audit pipeline.

Three new metrics (`sbproxy_a2a_*`):

- `sbproxy_a2a_hops_total` (counter, labels `route`, `spec`, `decision`) - one increment per detected A2A hop.
- `sbproxy_a2a_chain_depth` (histogram, labels `route`, `spec`) - depth distribution.
- `sbproxy_a2a_denied_total` (counter, labels `route`, `reason`) - denial reason in `{depth, cycle, callee_not_allowed, caller_denied}`.

`task_id` is intentionally not a metric label; cardinality would be unbounded.

### Worked example

Agent A (`agent:internal:my-orchestrator`) calls agent B (`agent:openai:gpt-5`) which calls agent C (`agent:anthropic:claude-4`). The proxy sits between every hop. The configured policy on the public-facing route is `max_chain_depth: 5, cycle_detection: by_agent_id, callee_allowlist: ["agent:openai:gpt-5", "agent:anthropic:claude-4"]`.

1. Hop 1 (A -> B). `chain_depth = 1`, `chain = [A]`. Callee `B` is on allowlist. Cycle check: `B` not in chain. Policy allows. Audit event `a2a_hop` emitted.
2. Hop 2 (B -> C). The proxy receives B's outbound call to C. `chain_depth = 2`, `chain = [A, B]`. Callee `C` is on allowlist. Cycle check: `C` not in chain. Policy allows. Audit event emitted with `parent_request_id` pointing at hop 1.
3. Hop 3 (C -> A). C tries to call A back. `chain_depth = 3`, `chain = [A, B, C]`. Callee `A` is in chain (position 0). Policy denies with 409 Conflict, body `{"error":"a2a_cycle_detected","callee":"agent:internal:my-orchestrator","cycle_position":0}`. Audit event emitted with `policy_decision: deny:cycle`.

Total events for the chain: 3 `a2a_hop` events plus 1 cycle-denial event. The audit pipeline reconstructs the call graph from the `task_id`-keyed join.

## Compatibility, schema rules, alternatives

Schema implications per `adr-schema-versioning.md`:

- One new `Policy` variant (`Policy::A2A`).
- One new `AuditEventType` (`a2a_hop`).
- New optional field in `RequestContext` (`a2a: Option<A2AContext>`).
- Three new metrics (additive; no cardinality change to existing metrics).

All additive; no closed-enum break.

Alternatives considered:

**Implement A2A as a thin shim over MCP.** Rejected for the Google draft (which is not MCP-shaped) but accepted for the Anthropic draft (which is). The detection logic handles both; the policy hook is shared.

**Make A2A opt-out instead of opt-in (via feature flag).** Rejected. A2A specs are at v0 and can break. Compiling parsers into the OSS default build commits us to a draft we may need to drop. Opt-in keeps the surface clean.

**Bill the callee.** Rejected, as discussed in the Pricing section.

**Treat A2A as just another HTTP POST and rely on per-route policy alone.** Rejected. Per-route policy cannot inspect chain depth or detect cycles; both require parsing the A2A envelope. The shared `A2AContext` is the minimum useful abstraction.

**Ship a single unified A2A spec rather than two feature flags.** Considered. The draft authors are aware of each other and a unification effort is plausible, but at GA cut neither has converged. Two flags now, collapse to one when the ecosystem agrees.

## Open questions

1. **Spec churn.** Both A2A drafts will likely revise their wire format before GA. The feature-flag strategy contains the blast radius (an operator using the Anthropic flag is unaffected by Google draft churn), but any breaking change in either draft requires a parser rev. Open question: do we promise an N-1 spec compat window, or do we cut over hard? Leaning toward N-1 with a deprecation warning in the audit log for one full minor release.
2. **Reconciling the two drafts.** If the Anthropic and Google drafts diverge sharply on cycle semantics or chain representation, the unified `A2AContext` may need to grow spec-tagged variant data. Open question: do we expose spec-specific fields on the context, or do we always normalize to a lossy lowest-common-denominator? Leaning toward normalize-to-LCD with a `raw_envelope: serde_json::Value` escape hatch for policy modules that need spec-specific access.
3. **A2A over WebSocket / SSE.** The drafts assume request-response HTTP. Streaming A2A (one agent subscribing to another agent's event stream) is not in scope for the current cut. Open question: does the chain reconstruction model survive long-lived connections, or do we need a different abstraction?
4. **Quoting and pricing for A2A hops.** When agent B is invoked by agent A and B's call is paywalled (402), does the 402 challenge present to A, to A's `actor_sub`, or to a separate "intermediary" account? The current decision is "to the caller", which means the 402 propagates back up the chain to A and A is responsible for paying. Open question: can intermediary agents add a markup? Out of scope here.

## References

1. `docs/adr-agent-class-taxonomy.md` - `AgentClass` taxonomy and the resolver chain consumed by `caller_agent_id` resolution.
2. `docs/adr-event-envelope.md` - event schema that the `a2a_hop` event extends.
3. `docs/adr-end-to-end-idempotency.md` - `request_id` propagation reused for chain reconstruction.
4. `docs/adr-schema-versioning.md` - closed-enum amendment rules.
5. `draft-anthropic-a2a-v0` (Anthropic A2A draft).
6. `draft-google-a2a-v0` (Google A2A draft).
7. MCP specification (Model Context Protocol, current revision).
