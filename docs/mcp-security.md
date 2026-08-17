# MCP security

*Last modified: 2026-08-16*

MCP moves two things that a language model will act on: the tool definitions it
advertises, and the tool output it returns. Both arrive from a server you may
not control, and both reach the model as text it treats as instruction. That is
the whole problem in one sentence, and it is why a gateway in the path is worth
having.

This page walks the threat classes that show up in MCP deployments, what
SBproxy does about each, and where it stops. The last part matters as much as
the first. A control you think you have is worse than one you know you lack.

For the general picture across all traffic types, start at
[security.md](security.md). For the API side, see
[api-security.md](api-security.md).

## Reading this page

Each section has the same four parts: what goes wrong, what the gateway does,
the config, and what is still yours to solve. Nothing here is a claim that a
category is fully handled by a proxy, because most of them are not.

The public taxonomy for this space is the OWASP MCP Top 10, currently in
incubation. It is worth reading alongside this page:
[owasp.org/www-project-mcp-top-10](https://owasp.org/www-project-mcp-top-10/).
The sections below are organized around the same problems, described in our own
terms and mapped to configuration that exists.

## Credentials reaching a tool that should not see them

**What goes wrong.** An agent holds a credential for one service. A tool
description asks it to pass that credential as an argument, or an upstream MCP
server is compromised and starts requesting one. The agent complies, because a
tool description reads as instruction.

**What the gateway does.** Upstream credentials are resolved by the gateway and
attached on the way out, so the model never holds them. Per-tool RBAC decides
which principal can call what, and a default-deny policy means a tool nobody
granted is refused rather than reachable.

<!-- sbproxy-config-excerpt -->
```yaml
origins:
  "mcp.example.com":
    action:
      type: mcp
      mode: gateway
      rbac_policies:
        read_only:
          default_allow: false
          tool_access:
            - principals: []
              allowed: ["gh.search_repos"]
      federated_servers:
        - origin: github.example.com
          prefix: gh
          rbac: read_only
```

`default_allow: false` is the setting that matters. A caller matching no rule is
refused, so adding a tool upstream does not silently widen access.

See [`examples/mcp-rbac-quotas/`](../examples/mcp-rbac-quotas/) for a
complete working config of RBAC and per-tool quotas together.

**Still yours.** The gateway cannot see a credential the agent already holds and
chooses to type into a tool argument. If your agent has a long-lived secret in
its context, no proxy can unsee that. Scope credentials down and keep them out
of the model's reach in the first place.

## Access widening quietly over time

**What goes wrong.** A tool is approved at one scope. Later it gains a
parameter, or the upstream adds a sibling tool with a similar name, and the
grant that was reviewed no longer describes what is reachable.

**What the gateway does.** A collapsed allowlist pins the tool surface for the
whole origin, and per-tool quotas cap how often any of it can be called.

<!-- sbproxy-config-excerpt -->
```yaml
      guardrails:
        - type: tool_allowlist
          allow:
            - gh.search_repos
            - gh.get_issue
      rbac_policies:
        read_only:
          default_allow: false
          tool_quotas:
            - tool_name: "gh.search_repos"
              principals: []
              rate:
                per: "1m"
                max: 30
```

A call past the window returns JSON-RPC error `-32099` rather than reaching the
upstream. A tool outside the allowlist is not advertised and not callable.

**Still yours.** Deciding what the right scope is. The gateway enforces the
list you write; it has no opinion about whether `gh.delete_repo` belongs on it.

A related way to keep the surface small is not advertising the whole
federated catalogue to the model in the first place; see
[`examples/mcp-progressive-discovery/`](../examples/mcp-progressive-discovery/).

## A tool definition changing after you approved it

**What goes wrong.** This is the rug pull. A server advertises a benign tool,
you review it, and later the description or schema changes to something that
steers the model differently. Nothing in the protocol tells you it happened.

**What the gateway does.** Tool contracts are pinned by digest in a committed
lockfile and re-checked on every catalog refresh. Movement is graded by a
compatibility oracle and either reported or blocked.

<!-- sbproxy-config-excerpt -->
```yaml
      tool_versioning:
        lockfile: "tool-versions.lock.yaml"
        mode: block
```

The digest covers the fields that change behavior: `name`, `description`,
`inputSchema`, `outputSchema`, and `annotations`. `title` and `icons` are
excluded on purpose, so a label edit does not refuse a tool. `annotations` is
in the list because a server flipping `readOnlyHint` to `true` can turn a call
into one a host auto-approves, and that is a change worth noticing.

Verdicts land on `sbproxy_mcp_tool_compat_verdicts_total`, and each change
emits an audit event: `mcp.tool_versioning.changed`,
`mcp.tool_versioning.renamed`, `mcp.tool_versioning.removed`, or
`mcp.tool_versioning.needs_confirmation`.

Renames are caught too. The digest covers the name, so a renamed tool would
otherwise look like a brand new one; the gate re-digests each baseline with the
old name substituted in to recognize the same contract wearing a new label.

**Still yours.** Producing the baseline is no longer hand work: `sbproxy mcp
lock` generates it from the live catalog, and `sbproxy mcp verify-lock` diffs
against it and exits nonzero on drift, documented in
[tool-versioning.md](tool-versioning.md), where a test also asserts the
shipped example matches what the gate computes. Wiring `verify-lock` into
your own CI, so drift actually blocks a merge, is still yours to do.

See [`examples/mcp-tool-versioning/`](../examples/mcp-tool-versioning/) for
the lockfile and compatibility oracle above, and
[`examples/mcp-tool-rollout/`](../examples/mcp-tool-rollout/) for pinning a
tool to a specific upstream version during a rollout.

## Text in a tool definition that a reviewer cannot see

**What goes wrong.** A description contains characters that render as nothing
to a human reading the catalog but are still tokens to a model. Unicode TAG
blocks are the sharpest version, since they are invisible in almost every
editor and terminal.

**What the gateway does.** Every catalog refresh diffs the advertised text and
reports what conceals content: TAG blocks, bidirectional controls, zero-width
characters, and other control characters. It also reports static poisoning
indicators such as credential paths, instructions inside comment markup, and
directives aimed at a model.

Both run automatically. There is no config to turn on.

```
sbproxy_mcp_concealed_text_findings_total{field,class,kind}
sbproxy_mcp_poison_indicators_total{field,indicator,kind}
```

Reports are edge triggered, so a catalog that keeps advertising the same hidden
payload says so once rather than on every refresh.

**Still yours, and read this one carefully.** Neither report is an injection
detector and nothing gates on either. They are signals for a human or a SIEM
rule, deliberately, because the false-positive cost of blocking on a heuristic
is a broken catalog. Right-to-left script is a language, not an attack, and is
not flagged. If you want enforcement here, drive it from the metric or the log
rather than expecting the gateway to refuse.

## Prompt injection arriving in tool output

**What goes wrong.** A tool returns text containing instructions. The model
reads it as instruction, because to a model there is no difference between data
and instruction in a context window.

**What the gateway does.** Two mechanisms, both opt-in.

The lethal-trifecta guardrail tracks whether a session has touched tools,
private data, and external communication. A call that would complete all three
is denied before any upstream IO.

<!-- sbproxy-config-excerpt -->
```yaml
      sessions:
        enabled: true
      guardrails:
        - type: lethal_trifecta
          private_data_tools: [db.*, files.read]
          external_comm_tools: [slack.*, email.*]
```

The dual-LLM quarantine sends untrusted tool text to a secondary judge before it
reaches the client. The judge call carries no tools and is fail-closed: a
timeout, a malformed response, or an egress denial all quarantine.

<!-- sbproxy-config-excerpt -->
```yaml
      dual_llm_quarantine:
        enabled: true
        endpoint: https://judge.example/v1/chat/completions
        model: judge-model
        timeout: 10s
```

**Still yours.** Neither is a solved-problem control. The trifecta guardrail
constrains the damage rather than detecting the injection, which is the honest
framing: it assumes the model will be steered and removes the combination that
makes steering costly. The quarantine judge is another model, with everything
that implies.

See [`examples/mcp-sessions/`](../examples/mcp-sessions/) for the session
lifecycle the trifecta guardrail's risk accumulation depends on, and
[`examples/prompt-injection-sidecar/`](../examples/prompt-injection-sidecar/)
for an out-of-process classifier that can scan tool output directly.

## Untrusted or unexpected upstream servers

**What goes wrong.** A federated server resolves somewhere you did not intend,
or a tool call reaches a host nobody approved. In the worst version this is an
internal address.

**What the gateway does.** For an OpenAPI-backed federated server
(`type: openapi`), egress is deny-by-default per origin and per federated
server, and the authorizer refuses destinations that resolve to private
address space unless explicitly allowed.

<!-- sbproxy-config-excerpt -->
```yaml
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

**Still yours.** This egress control is scoped to OpenAPI-backed servers. A
plain `type: mcp` federated server dials its configured `origin` directly:
there is no deny-by-default allowlist and no private-address check on that
path today, so keeping the origin honest is a network-design problem, not a
config one. SBproxy also does not implement per-upstream certificate pinning.
TLS validation is standard chain validation. If you need to pin a specific key
for an upstream, that is not available here today.

See [`examples/mcp-federation/`](../examples/mcp-federation/) for a complete
working config of multiple federated upstreams behind one gateway.

## Weak authentication on the MCP endpoint itself

**What goes wrong.** The MCP endpoint is reachable by anything that can route to
it, including a browser page on an unrelated site.

**What the gateway does.** On the 2026-07-28 revision, the transport trust check
runs before authentication, before any OAuth challenge, and before any catalog
work. A request addressed to an authority this gateway does not serve is refused
with an empty body, so a disallowed origin learns nothing about the endpoint.

<!-- sbproxy-config-excerpt -->
```yaml
      modern_http:
        public_origin: "https://mcp.example.com"
        allowed_origins:
          - "https://console.example.com"
        strict_parameter_headers: true
```

An origin with an exact hostname derives its own anchor, so `modern_http` is
optional there. A wildcard hostname cannot, and without `public_origin` every
2026-07-28 request to it is refused with a `421`.

Refusals are recorded as `mcp_transport_denied` security audit events with a
closed reason label, so a SIEM rule can route on the failure mode without
parsing prose.

This gate classifies a request as 2026-07-28 traffic from
`MCP-Protocol-Version` and `Mcp-Method` alone, which every compliant client
sets and a cross-origin browser `fetch()` cannot set without a preflight. A
request that omits both headers is classified as legacy here and reaches
authentication before the gateway refuses it, once there is a body to read.
The catalog and the OAuth challenge stay behind that later, body-aware check
either way, so the gap is an extra authentication round-trip, not disclosure.

Ordinary auth composes on top: see [auth-oidc.md](auth-oidc.md) and
[mcp.md](mcp.md) for the OAuth discovery surface.

**Still yours.** A caller that authenticates correctly and then behaves badly is
an authorization problem, not an authentication one. See the RBAC section above.

## No usable record of what happened

**What goes wrong.** An incident review asks which tool was called, by whom,
with what, and the answer is scattered across application logs that were never
designed for the question.

**What the gateway does.** Every governed decision emits a structured record on
the security audit stream, and tool dispatch is metered.

```
sbproxy_mcp_tool_dispatch_total
sbproxy_mcp_tool_dispatch_duration_seconds
sbproxy_mcp_tool_cost_usd_total
```

Evidence is structured logs aimed at your SIEM rather than a separate store, so
it lands beside every other denial you already collect. The session ledger
records per-session activity; see [mcp.md](mcp.md).

**Still yours.** Retention, correlation, and alerting. The gateway emits; your
SIEM decides what matters.

## Servers nobody sanctioned

**What goes wrong.** A team wires an agent to an MCP server directly, bypassing
whatever governance you put in the path. You find out later.

**What the gateway does.** Less than you might hope, and this is the category
where a proxy is weakest. It is a choke-point architecture rather than a
feature: if agent traffic is required to egress through SBproxy, an unsanctioned
server is one that egress policy refuses.

**Still yours.** Making the gateway the only route out. That is network design,
not proxy configuration. A proxy cannot discover a connection that never
traverses it.

## Context crossing a boundary it should not

**What goes wrong.** One tenant's catalog, tools, or context reaches another
tenant's agent.

**What the gateway does.** MCP catalogs are tenant-scoped. A key policy naming
an MCP gateway resolves only within the request route's tenant, so a reference
that crosses a tenant boundary resolves to nothing rather than to someone else's
catalog. Two tenants may run gateways with the same `server_info.name` without
seeing each other's tools.

**Worth checking on an existing config.** This scoping is newer than the
feature. A reference that crosses tenants now yields a successful request with
an empty tool array, which is quiet. Give the MCP origin the same `tenant_id` as
the `ai_proxy` origin whose keys name it, and grep for
`inject_mcp references an unknown MCP gateway` to find one. Details in
[key-management.md](key-management.md).

## Where to go next

- [mcp.md](mcp.md) for the gateway itself: wire shape, sessions, OAuth, and the
  dual-era transport.
- [mcp-gateway-guardrails.md](mcp-gateway-guardrails.md) for the guardrail
  mechanisms in depth, including supervised stdio and run-as-user.
- [tool-versioning.md](tool-versioning.md) for the digest recipe and the
  compatibility oracle.
- [security.md](security.md) for the whole picture.
