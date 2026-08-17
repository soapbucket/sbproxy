# MCP and agent traffic

*Last modified: 2026-08-16*

![Initialize an MCP session against the admin API and confirm the notification handshake](assets/admin-mcp.gif)

If you are exposing tools to an agent, or you are the agent calling
someone else's tools, this page is the map. SBproxy speaks two
protocols for agent traffic: MCP (Model Context Protocol, for tool
calling) and A2A (Agent-to-Agent, for agent-to-agent delegation). Both
run through the same gateway as your HTTP and AI traffic, so the same
auth, rate limiting, and observability apply.

This page links out to the deep reference for each piece rather than
repeating it. Start here to find the right page; go there for the
config.

## Find your task

Jump straight to a page:

- Federate several upstream MCP servers behind one endpoint -
  [`mcp.md`](mcp.md)
- Stop a tool description or tool output from acting as an instruction
  to the model - [`mcp-security.md`](mcp-security.md)
- Enforce egress allowlisting, session risk, or output quarantine on
  MCP traffic - [`mcp-gateway-guardrails.md`](mcp-gateway-guardrails.md)
- Ship a breaking tool change without breaking every caller at once -
  [`tool-versioning.md`](tool-versioning.md)
- Let an agent client check health or read config without a human
  holding the admin credential - [`admin-mcp.md`](admin-mcp.md)
- Proxy or police agent-to-agent delegation chains -
  [`a2a-gateway.md`](a2a-gateway.md)
- Advertise skills for a cooperative agent to discover -
  [`agent-skills.md`](agent-skills.md)
- Shape and price content served to an agent, not a tool call -
  [`content-for-agents.md`](content-for-agents.md)
- Cut an agent's token spend on a large tool catalog -
  [`cloudflare-code-mode.md`](cloudflare-code-mode.md)
- Rate-limit by resolved agent identity instead of IP -
  [`agent-budget.md`](agent-budget.md)

## MCP gateway: federate and govern tool calls

[`mcp.md`](mcp.md) is the wire-level reference: the `mcp` action, the
JSON-RPC method set it serves (`initialize`, `tools/list`,
`tools/call`, `resources/*`, `prompts/*`, `ping`), and what it
deliberately does not serve. Configure it once and the gateway
federates one or more upstream MCP servers behind a single endpoint,
namespacing tools and resources per upstream.

Four things sit on top of the wire protocol:

- **Security** ([`mcp-security.md`](mcp-security.md)) walks the threat
  classes specific to MCP: a tool description or tool output that
  reads as instruction to the model, credentials an agent should never
  hold, and tenant isolation across federated servers. Read this before
  federating a server you do not control.
- **Guardrails** ([`mcp-gateway-guardrails.md`](mcp-gateway-guardrails.md))
  are the mechanisms that enforce the policy `mcp-security.md`
  describes: deterministic egress allowlisting, the lethal-trifecta
  session guardrail (private-data tools + external-communication tools
  in one session gets denied), dual-LLM output quarantine, stdio
  supervision, and run-as-user auth.
- **Tool lifecycle** ([`tool-versioning.md`](tool-versioning.md)) is
  what MCP has no native answer for: publishing several versions of one
  tool, resolving the right version per consumer, and a compatibility
  oracle that fails a version bump when a breaking change ships without
  a matching major version.
- **Admin over MCP** ([`admin-mcp.md`](admin-mcp.md)) turns the
  gateway's own admin API into governed MCP tools, so an agent client
  like Claude Code or Cursor can check health or read config without a
  human shelling out with an admin credential.

Agent identity feeding all of the above (`agent_id`, `agent_class`) is
resolved by the agent-class resolver described in
[`configuration.md`](configuration.md) and used directly by
[`agent-budget.md`](agent-budget.md) (a semantic rate-limit primitive
keyed on the resolved agent, not IP) and
[`headless-detection.md`](headless-detection.md). There is no separate
"agent identity" doc; the resolver is documented alongside the modules
that consume it.

## A2A gateway: agent-to-agent delegation

[`a2a-gateway.md`](a2a-gateway.md) covers the `a2a` action (proxies
JSON-RPC A2A traffic to an upstream), the `a2a` policy (per-hop chain
depth, cycle detection, callee allowlist), and the agent card rewrite
transform. It pairs with MCP federation, one gateway serving both
protocols, and it is explicit about what is shipped (the action, the
policy, card serving) versus design-stage (CEL bindings on capability
negotiation, 406 modality responses).

The trust story matters here more than the wire format: the envelope
(who is calling, who is being called, how deep the chain already runs)
is only as trustworthy as its source, and `a2a-gateway.md` details why
a signed `act` claim chain beats the `X-A2A-*` headers, which are
honored only from a `proxy.trusted_proxies` peer.

## Agent Skills discovery

[`agent-skills.md`](agent-skills.md) is a different thing from tool
calling: it is a `/.well-known/agent-skills/index.json` manifest a
cooperative agent fetches to discover what an origin advertises, with
each artifact hashed and re-hashed on every serve. Relevant if you want
agents to discover capabilities before ever making a tool call.

## Content shaping for agents

[`content-for-agents.md`](content-for-agents.md) covers a different
direction of agent traffic: an agent fetching your pages instead of
calling your tools. Two-pass `Accept` negotiation picks a price tier and then a
body shape (Markdown, or a JSON envelope with a token estimate), a
`Content-Signal` header carries your per-origin editorial stance, and
four projection documents (`robots.txt`, `llms.txt`, `/licenses.xml`,
`/.well-known/tdmrep.json`) publish your license posture in the format
each consumer expects. Pairs with
[`ai-crawl-control.md`](ai-crawl-control.md) when that content is also
priced; see [`payments.md`](payments.md) for the payment side.

## Cloudflare Code Mode

[`cloudflare-code-mode.md`](cloudflare-code-mode.md) emits a typed
TypeScript module covering the whole MCP federation registry, so an
agent on the Cloudflare Code Mode runtime imports one module and calls
tools as ordinary async functions instead of paying the token cost of
individual tool-call JSON for a large catalog.

## Runnable examples

- [`examples/mcp-federation/`](../examples/mcp-federation/) - federating
  multiple upstream MCP servers behind one gateway.
- [`examples/mcp-rbac-quotas/`](../examples/mcp-rbac-quotas/) - per-tool
  RBAC and quotas.
- [`examples/mcp-sessions/`](../examples/mcp-sessions/) - session-scoped
  guardrails including the lethal-trifecta check.
- [`examples/mcp-oauth-discovery/`](../examples/mcp-oauth-discovery/) -
  OAuth2 discovery for MCP clients.
- [`examples/mcp-progressive-discovery/`](../examples/mcp-progressive-discovery/) -
  progressive tool discovery.
- [`examples/mcp-tool-versioning/`](../examples/mcp-tool-versioning/) and
  [`examples/mcp-tool-rollout/`](../examples/mcp-tool-rollout/) - the
  rollout plane from `tool-versioning.md`.
- [`examples/mcp-code-mode/`](../examples/mcp-code-mode/) - the
  Cloudflare Code Mode emitter.
- [`examples/admin-mcp/`](../examples/admin-mcp/) - the admin API
  exposed as governed MCP tools.
- [`examples/a2a-protocol/`](../examples/a2a-protocol/) - the `a2a`
  action and policy.
- [`examples/a2a-prompt-injection/`](../examples/a2a-prompt-injection/) -
  A2A traffic under the prompt-injection guardrail.

## Who this is for

**AI users** wiring an agent framework to real tools: start at
`mcp.md` for the wire shape, then `mcp-security.md` before federating
anything you do not control. **Developers** building an MCP or A2A
integration: `tool-versioning.md` and `a2a-gateway.md`'s trust section
are the two pages that stop a breaking change or a spoofed envelope
from reaching production. **SRE leads** operating this in production:
`mcp-gateway-guardrails.md`'s session and egress controls are what you
tune per incident, and `agent-budget.md` is the rate-limit primitive
sized for agent traffic rather than human traffic.
