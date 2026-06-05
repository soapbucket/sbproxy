# A2A gateway
*Last modified: 2026-05-31*

The `a2a` action proxies agent-to-agent requests to an upstream A2A endpoint and surfaces the agent's typed AgentCard for capability discovery and modality negotiation. Pairs with MCP federation (one gateway, two protocols) and the AP2 / ACP / RAR payment surfaces.

## Wire shape

The A2A protocol is JSON-RPC over HTTP. Clients call `POST /<agent>/tasks/sendSubscribe` (or the streaming variant) with a JSON-RPC envelope; the agent responds with a `Task` document. The gateway sits in front of one or more agent endpoints and is responsible for two things the bare proxy cannot do on its own: telling a calling agent what each upstream advertises, and gating the call when the caller and the agent disagree on modality.

## AgentCard

```yaml
origins:
  "agent.example.com":
    action:
      type: a2a
      url: http://backend:9000/a2a
      agent_card:
        name: "Reservation assistant"
        description: "Books and modifies restaurant reservations."
        version: "0.3.0"
        url: "https://agent.example.com/"
        capabilities:
          streaming: true
          pushNotifications: false
          stateTransitionHistory: false
        defaultInputModes:
          - "application/json"
          - "text/plain"
        defaultOutputModes:
          - "application/json"
        skills:
          - id: "find_table"
            description: "Find a free table by time + party size"
```

The whole card round-trips through the gateway: SBproxy types only the fields it consumes (`capabilities`, `defaultInputModes`, `defaultOutputModes`, `name`, `description`, `version`, `url`, `skills`). Anything else the operator pastes (the A2A spec's optional `provider`, `authentication`, `supportsAuthenticatedExtendedCard`, etc.) lives on `extensions` and serialises back verbatim.

## Capability discovery

The gateway can serve the card itself at `/.well-known/agent.json` so an A2A client can probe SBproxy and get back the agent it would route to. The handler emission is configured by the operator on the action; absent it, the well-known path falls through to the upstream so a real agent that already serves its own card keeps doing so.

`capabilities.streaming` and `capabilities.pushNotifications` are surfaced under CEL so policies can branch on what the agent advertises before forwarding. A typical use is gating an A2A request that requests streaming when the agent does not advertise it; the policy rejects with a 400 before the upstream is contacted.

## Modality negotiation

SBproxy ships pure-function helpers `AgentCard::negotiate_input` and `AgentCard::negotiate_output` that pair the caller's `Content-Type` and `Accept` against the agent's advertised `defaultInputModes` and `defaultOutputModes`. Each call returns one of four typed outcomes:

| Outcome | When | Effect on the upstream call |
|---|---|---|
| `Matched(mode)` | the caller's preference overlaps with the agent's advertised modes | proceed with `mode` |
| `NoCallerPreference(mode)` | the caller omitted `Content-Type` / `Accept` | proceed; gateway echoes `mode` |
| `AgentUndeclared(mode)` | the agent's mode list is empty (no restriction) | proceed with the caller's preference |
| `Mismatch { requested, advertised }` | no overlap | gateway returns 406 with both lists in the error body |

The negotiator is case-insensitive on the MIME `type/subtype` head and strips `;`-parameters before comparing, so `application/json; charset=utf-8` matches `application/json`. The output side honours `*/*` by collapsing to the agent's first declared output mode.

## See also

- The A2A x402 payment bridge.
- The agentgateway / Bifrost / SBproxy capability benchmark.
- `crates/sbproxy-modules/src/action/a2a.rs` - the proxy action itself.
- `crates/sbproxy-modules/src/action/a2a_card.rs` - typed AgentCard + negotiator.
