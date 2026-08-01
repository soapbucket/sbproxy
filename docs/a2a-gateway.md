# A2A gateway
*Last modified: 2026-07-31*

The `a2a` action proxies agent-to-agent requests to an upstream A2A endpoint. Pairs with MCP federation (one gateway, two protocols) and the AP2 / ACP / RAR payment surfaces.

## What ships and what does not

Shipped today:

- The `a2a` action: proxies JSON-RPC A2A traffic to the configured upstream `url`, with `host_override` and forwarding-header controls.
- The `a2a` policy: per-hop checks on the inbound agent-to-agent envelope (chain depth, cycle detection, callee allowlist, caller deny), with per-deny-reason metrics, plus a `failure_posture` knob for requests detection cannot classify.
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
protecting anything. The second of those is a knob as well as a
counter; see [Failure posture](#failure-posture-what-happens-to-a-request-that-is-not-detected).

## Which requests are treated as A2A

Detection is what decides whether the policy runs. It has four inputs,
and only one of them is yours:

| Signal | Controlled by | Notes |
|---|---|---|
| `A2A-Version: 1.x` | the caller | Ratified A2A 1.0. Rides plain `application/json`, so the header is the only thing that distinguishes it |
| `Content-Type: application/a2a+json` | the caller | Google A2A draft |
| `MCP-Method: agents.invoke` | the caller | Anthropic A2A draft |
| `route_glob` | the operator | Declares a path as A2A regardless of headers |

The checks run in that order, and a signal SBproxy cannot interpret
never cancels the ones after it. An `A2A-Version` naming a major this
build has not shipped means "do not decode this as 1.x", not "this is
not A2A traffic": the content type, the MCP method, and above all your
`route_glob` are still consulted. That ordering matters because the
alternative is a bypass in one header.

Because the first three signals are the caller's to send or withhold, a
caller that wants to avoid the policy simply sends none of them. **Set
`route_glob` on any route you actually intend to govern.** It is the
only signal a caller cannot opt out of.

## Failure posture: what happens to a request that is not detected

Detection can miss. When it does, `failure_posture` decides what the
policy does with the request.

```yaml
policies:
  - type: a2a
    route_glob: "/agents/**"
    max_chain_depth: 5
    # open (default) | closed | observe | degraded
    failure_posture: open
```

| Posture | Traffic | `sbproxy_a2a_hops_total{decision=...}` |
|---|---|---|
| `open` (default) | allowed | `skip:undetected` |
| `closed` | refused, 403, `{"error":"a2a_undetected"}` | `deny:undetected` |
| `observe` | allowed | `observe:undetected` |
| `degraded` | allowed | `degraded:undetected` |

`observe` and `degraded` both let the request through, and they answer
different questions. `observe` is the rollout posture: it counts the
requests `closed` would have refused, so you can size the blast radius
of the change before you make it. `degraded` is a steady state: the
request went through and the A2A guarantee was explicitly not made for
it, on its own series so you can alert on it rather than on a default
you will forget about.

Each posture gets its own `decision` value rather than sharing one with
a second label. A route that is quietly ungoverned and a route that is
mid-rollout look identical if they land in the same series, which is
exactly the shape a bypass hides in.

### Why the default is `open`

SBproxy's rule is to fail closed for anything enforcing a security
boundary, and to fail open only where refusing would turn a
non-security failure into an outage. This is the second case, and it is
worth being precise about why.

A policy attaches to an origin, not to a path, and it runs on every
request that origin serves. If the default were `closed`, then the
moment you upgraded, every origin carrying an `a2a` policy would begin
refusing its own health checks, its metrics scrape, and any ordinary
non-A2A request it happens to also serve. That is an upgrade causing an
outage, not a boundary being enforced.

What makes `open` defensible rather than merely convenient is that the
gap it leaves is both closable and visible. `route_glob` is a detection
signal the caller cannot opt out of, so declaring the route governs
every request on it whatever the caller sends. And an undetected
request is counted at `decision="skip:undetected"`, so an ungoverned
route shows up on a dashboard instead of reading green.

### Closing it

1. Set `route_glob` first. Most of what `closed` would refuse is
   traffic that should have been detected in the first place, and the
   glob fixes that without refusing anything.
2. Set `failure_posture: observe` and watch
   `sbproxy_a2a_hops_total{decision="observe:undetected"}` for a day.
   Anything that shows up there is a request `closed` will refuse.
3. Set `failure_posture: closed` once that series is either empty or
   only contains traffic you are happy to refuse.

Step 3 is the right end state for an origin that serves agent traffic
and nothing else. It is the wrong one for an origin where the A2A route
sits alongside a website.

A note on the shape of the key: the policy block ignores keys it does
not recognise, so `failure_postures: closed` or `failure-posture:
closed` compiles and does nothing. Misspell the *value* and config
compile fails naming the policy; misspell the *key* and you get the
default. Check the metric after a change rather than trusting that the
config was read.

## What the policy reads from the request body

The checks above run on headers and the verified principal. Two further
controls need the JSON-RPC body, and on A2A 1.0 routes the proxy buffers
the request so they can run.

### Push-notification targets

A2A 1.0 lets a caller register a webhook with
`CreateTaskPushNotificationConfig` and have the upstream agent POST task
status and artifacts to it. The URL is caller-supplied and the dial is
made by an authenticated backend, which is the confused-deputy shape.
Because the payload carries artifacts, a target inside private space
exfiltrates rather than merely probes.

Registrations are validated before the body reaches the agent. The
default posture refuses private address space and non-HTTP schemes.
Internal callbacks are a legitimate deployment, so name the host:

```yaml
policies:
  - type: a2a
    route_glob: "/agents/**"
    push_target_allowlist:
      - "callbacks.internal.example"
```

The denial body names the class of block and never echoes a resolved
address, so a refusal cannot be used to map your network:

```json
{"error":"a2a_push_target_blocked","reason":"blocked: private address space"}
```

Two limits are worth stating plainly. This is registration-time
validation, and the party that later dials the URL is the upstream
agent, not the proxy. So it cannot close the DNS-rebinding window
between registration and delivery; that needs the agent to pin the
address it validated, which is a contract with the upstream rather than
something a gateway can impose. And it applies to A2A 1.0 only, because
the v0 drafts have no push-notification surface.

Watch `sbproxy_a2a_methods_total{method="CreateTaskPushNotificationConfig"}`
for registration volume and
`sbproxy_a2a_denied_total{reason="push_target_blocked"}` for refusals.

### Message content

An A2A message body is a place an injection travels between agents with
nobody reading it. Compose `prompt_injection_v2` on the same origin and
the classifier scans `params.message.parts[*].text` on `SendMessage` and
`SendStreamingMessage`, with the action chosen by how far down the
delegation chain the hop sits.

The full configuration, including why the agent boundary has its own
action vocabulary and why the default rejects on delegated hops, is in
[prompt-injection-v2.md](prompt-injection-v2.md#the-agent-boundary).

### Cost

Buffering holds the request until the body has arrived, on a hop that a
fan-out step multiplies. It is enabled only for detected A2A 1.0 routes,
and only when an `a2a` policy is configured on the origin. The v0 drafts
and non-A2A traffic are unaffected.

## What is not scanned: the response direction

Everything above governs the request. Nothing governs what comes back.

Artifacts returned by the callee, and the `TaskArtifactUpdateEvent`
stream on `SendStreamingMessage`, are proxied without inspection. There
is no response-direction parser and no response-direction
prompt-injection scan. An agent that returns an injection in its output,
whether because it was compromised or because it faithfully relayed
poisoned content it retrieved, reaches the calling agent unexamined.

That matters more than it first sounds, because the calling agent is
usually the one with the tools. Treat callee output as untrusted input
at the caller, and do not read the request-side controls as covering the
round trip.

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
