# A2A gateway
*Last modified: 2026-07-31*

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

## Where the envelope comes from, and why it matters

The `a2a` policy decides on an envelope: who is calling, who is being
called, and how deep the delegation chain already runs. Those checks are
only worth as much as the envelope is, so it is worth being explicit
about where each field originates.

There are two sources, and they are not equally trustworthy.

**A signed token. Preferred.** SBproxy reads the [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1)
`act` (actor) claim chain off the verified principal. Each delegation
hop nests one `act` inside the last, so the chain is part of what the
issuer signed. A caller cannot shorten it without invalidating the
token. When the principal carries an `act` chain it overrides whatever
the transport claimed, and the hop is recorded as `allow:verified`.

**The `X-A2A-*` headers. Only from a trusted peer.** The envelope may
instead arrive as `X-A2A-Caller-Agent-Id`, `X-A2A-Callee-Agent-Id`,
`X-A2A-Task-Id`, `X-A2A-Parent-Request-Id`, `X-A2A-Chain-Depth`, and
`X-A2A-Chain`. These are read **only** when the immediate peer appears
in `proxy.trusted_proxies`. From anyone else they are stripped on
ingress and ignored, and the hop is recorded as `allow:unverified`.

The reason is that every one of these headers is an input the caller
would otherwise choose for itself. A caller that sets its own
`X-A2A-Chain-Depth: 1` clears any `max_chain_depth`. One that omits
`X-A2A-Chain` presents an empty chain, and cycle detection has nothing
to compare. One that sets its own `X-A2A-Caller-Agent-Id` renames itself
off `caller_denylist`. Honouring these from an arbitrary client makes
the policy advisory: it governs well-behaved agents that declare
themselves honestly and does nothing to the ones you configured it for.

So configure one of:

- an authentication provider that yields a verified principal with `act`
  claims, or
- `proxy.trusted_proxies` covering the sidecar or mesh ingress that
  stamps the envelope, which must itself sit between the caller and
  SBproxy.

If neither is configured the policy still runs, but it evaluates an
empty envelope: depth 1, no chain, no caller identity. Nothing trips.
Watch `sbproxy_a2a_hops_total{decision="allow:unverified"}` for that
case, and `decision="skip:undetected"` for requests the policy never
engaged on at all. A route showing only those two is configured but not
protecting anything.

## Which requests are treated as A2A

Detection is what decides whether the policy runs. It has three inputs,
and only one of them is yours:

| Signal | Controlled by | Notes |
|---|---|---|
| `Content-Type: application/a2a+json` | the caller | Google A2A draft |
| `MCP-Method: agents.invoke` | the caller | Anthropic A2A draft |
| `route_glob` | the operator | Declares a path as A2A regardless of headers |

Because the first two are the caller's to send or withhold, a caller
that wants to avoid the policy simply sends neither, and an undetected
request is allowed. **Set `route_glob` on any route you actually intend
to govern.** It is the only signal a caller cannot opt out of.

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
