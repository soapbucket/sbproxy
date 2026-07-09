# A2A gateway
*Last modified: 2026-07-09*

The `a2a` action proxies agent-to-agent requests to an upstream A2A endpoint. Pairs with MCP federation (one gateway, two protocols) and the AP2 / ACP / RAR payment surfaces.

## What ships and what does not

Shipped today:

- The `a2a` action: proxies JSON-RPC A2A traffic to the configured upstream `url`, with `host_override` and forwarding-header controls.
- The `a2a` policy: per-hop checks on the inbound agent-to-agent envelope (chain depth, cycle detection, callee allowlist, caller deny), with per-deny-reason metrics.
- The `a2a_agent_card_rewrite` transform: parses agent-card JSON responses and substitutes upstream URLs with the proxy hostname. Its path-aware wiring into the response pipeline is still pending, so configuring it today passes bodies through unchanged.
- The typed `AgentCard` parser and the modality negotiators, as library code with no gateway call sites yet (details below).

Design-stage, not in the current binary:

- Serving the configured card at `/.well-known/agent.json`. The `agent_card` block is stored on the action, but nothing serves it; the well-known path proxies through to the upstream like any other path.
- CEL bindings for `capabilities.*`. Policies cannot branch on what the card advertises.
- 406 modality negotiation on the request path. No 406 is emitted today.

## Wire shape

The A2A protocol is JSON-RPC over HTTP. Clients call `POST /<agent>/tasks/sendSubscribe` (or the streaming variant) with a JSON-RPC envelope; the agent responds with a `Task` document. The gateway sits in front of one or more agent endpoints; the discovery and negotiation surfaces below are what the design adds on top of the bare proxy.

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

The action stores the card verbatim as JSON; the config accepts any card body. The typed `AgentCard` parser in `sbproxy-modules` types only the fields it consumes (`capabilities`, `defaultInputModes`, `defaultOutputModes`, `name`, `description`, `version`, `url`, `skills`). Anything else the operator pastes (the A2A spec's optional `provider`, `authentication`, `supportsAuthenticatedExtendedCard`, etc.) lands on `extensions` and serialises back verbatim, so a card round-trips through the parser without loss.

## Capability discovery (design)

The design has the gateway serve the card itself at `/.well-known/agent.json` so an A2A client can probe SBproxy and get back the agent it would route to, falling through to the upstream when the operator configures no card. None of that is wired: today the well-known path is proxied to the upstream unmodified, and the only shipped code that touches it is the `a2a_agent_card_rewrite` transform described above.

The design also surfaces `capabilities.streaming` and `capabilities.pushNotifications` under CEL so policies could reject, before forwarding, an A2A request that asks for streaming when the agent does not advertise it. Those bindings do not exist yet.

## Modality negotiation (library only)

SBproxy ships pure-function helpers `AgentCard::negotiate_input` and `AgentCard::negotiate_output` that pair the caller's `Content-Type` and `Accept` against the agent's advertised `defaultInputModes` and `defaultOutputModes`. They are library code: nothing on the gateway's request path calls them yet, so the "effect" column below describes the intended wiring, not current behaviour. Each call returns one of four typed outcomes:

| Outcome | When | Intended effect on the upstream call |
|---|---|---|
| `Matched(mode)` | the caller's preference overlaps with the agent's advertised modes | proceed with `mode` |
| `NoCallerPreference(mode)` | the caller omitted `Content-Type` / `Accept` | proceed; gateway echoes `mode` |
| `AgentUndeclared(mode)` | the agent's mode list is empty (no restriction) | proceed with the caller's preference |
| `Mismatch { requested, advertised }` | no overlap | gateway would return 406 with both lists in the error body |

The negotiator is case-insensitive on the MIME `type/subtype` head and strips `;`-parameters before comparing, so `application/json; charset=utf-8` matches `application/json`. The output side honours `*/*` by collapsing to the agent's first declared output mode.

## See also

- The A2A x402 payment bridge.
- The agentgateway / Bifrost / SBproxy capability benchmark.
- `crates/sbproxy-modules/src/action/a2a.rs` - the proxy action itself.
- `crates/sbproxy-modules/src/action/a2a_card.rs` - typed AgentCard + negotiator.
