# MCP security

*Last modified: 2026-08-29*

For a row-by-row scorecard against the OWASP MCP Top 10, coverage stated
plainly as full, partial, or out of gateway scope, see
[mcp-security-coverage.md](mcp-security-coverage.md). This page is the
threat-by-threat narrative behind that table.

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

An MCP origin's responses are written directly, outside the generic HTTP
`response_filter` phase the `pii:`/`dlp:` policy blocks are wired to, so those
controls never see a tool-call argument or result on their own. `content_filters`
closes that seam for MCP specifically, reusing the same detector catalogue:

<!-- sbproxy-config-excerpt -->
```yaml
      content_filters:
        secrets: redact
        pii: warn
```

`secrets` matches API-key and token shapes (`openai_key`, `anthropic_key`,
`aws_access`, `github_token`, `slack_token`); `pii` matches personal-data shapes
(`email`, `us_ssn`, `credit_card`, `phone_us`, `ipv4`, `iban`). Both run against
tool-call arguments on the way out and tool-call results on the way back, and
against `resources/read` and `prompts/get` results too, before any of them
reaches the upstream server or the caller. `redact` replaces a match with
the same `[REDACTED:<NAME>]` marker `pii:` uses and emits a governance event
on a `tools/call`, or a `security_audit` entry (no `mcp_governance_decision`
event, the same boundary the peer-downgrade and approval-status checks below
already draw for these two methods) on a `resources/read` or `prompts/get`;
`block` refuses the call or the result outright either way. Both default to
`off`. A tool-call's own captured audit arguments (`mcp_audit.capture_arguments:
true`) pass through the same redaction before they ever reach the
`mcp_governance_decision` event, so a shape `content_filters` strips from the
wire cannot reappear in the evidence trail instead.

**Still yours.** A regex catalogue matches known shapes, not every secret
format an upstream could mint, and it cannot see a credential the agent already
holds and chooses to type into a tool argument as ordinary-looking text. If your
agent has a long-lived secret in its context, no proxy can unsee that. Scope
credentials down and keep them out of the model's reach in the first place.

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

A reviewed grant can also expire. Set `ttl` on a `tool_access[]` row and
`grant_ledger.path` so a restart cannot silently extend the window. After `ttl`
elapses the matching `tools/call` is refused with JSON-RPC `-32098` until
`POST /api/mcp/grants/renew`.

High-risk tools can require a human at the gateway (not MCP elicitation).
`approval.store` plus `approval.tools[]` (prefer `digest`) parks the call,
returns `-32097` immediately, and resumes once on a retry after
`POST /api/mcp/approvals/{id}/approve`. Approvals bind to the tool contract and
canonical arguments, so a rename does not consume another tool's decision.
TrueFoundry is the surveyed SOTA for this gate. Approve from
`POST /api/mcp/approvals/{id}/approve` or `/admin/ui/mcp-approvals`.

A reviewed grant can also expire. Set `ttl` on a `tool_access[]` row and
`grant_ledger.path` so the window survives a restart. After the ttl elapses
the matching `tools/call` is refused with JSON-RPC `-32098` until
`POST /api/mcp/grants/renew`.

**Still yours.** Deciding what the right scope is. The gateway enforces the
list you write; it has no opinion about whether `gh.delete_repo` belongs on it.

A related way to keep the surface small is not advertising the whole
federated catalogue to the model in the first place; see
[`examples/mcp-progressive-discovery/`](../examples/mcp-progressive-discovery/).

## A permitted tool called with an argument that should not be

**What goes wrong.** RBAC and an allowlist answer "can this caller invoke
`send_email` at all", not "should this particular call go through". A
principal allowed to call a tool can still supply an argument that steers it
somewhere it should not go: an external recipient on an internal-only tool, a
path outside a sandboxed directory, a destination host outside an approved
set. JSON-Schema validation checks shape, not intent.

**What the gateway does.** `argument_policies[]` evaluates a CEL or
OPA-compatible Rego expression against the tool-call context, including the
parsed arguments, after RBAC and JSON-Schema validation pass and before the
call dispatches:

<!-- sbproxy-config-excerpt -->
```yaml
      argument_policies:
        - name: internal-recipients-only
          when: mcp.tool.name == "send_email"
          engine: cel
          source: mcp.arguments.to.endsWith("@company.com")
          mode: block
        - name: internal-recipients-only-rego
          engine: rego
          source: |
            package sbproxy
            default allow := false
            allow if {
                endswith(input.mcp.arguments.to, "@company.com")
            }
          mode: block
```

An expression can also live in its own file: `path` reads it once at
config-compile time instead of taking it inline as `source`, mirroring
`federated_servers[].spec_path`. Exactly one of `source`/`path` is
required per rule.

The expression's boolean result follows the CEL/Rego convention used
everywhere else in this gateway: `true` is compliant, `false` is a
violation. `mode: warn` (the default) logs the violation and emits a
`mcp_governance_decision` event with verdict `warn`, but the call still
proceeds; `mode: block` refuses it with a JSON-RPC error and verdict `deny`,
naming the rule as `sbproxy.decision.rule_id`. A rule can only turn an
already-passed RBAC allow into a refusal, never the reverse: it runs after
RBAC and per-tool quota, so an RBAC denial always wins and an argument
policy never even evaluates against a call RBAC already refused. A rule
whose expression cannot be evaluated, or whose engine panics, refuses the
call regardless of the configured `mode`, the same fail-closed posture
`policy: rego` already has. Optional `principals[]` selectors, the same
shape as `rbac_policies[].tool_access[].principals`, scope a rule to one
tenant, team, or project.

**Still yours.** Writing the predicate. The gateway evaluates whatever CEL or
Rego you give it against `mcp.tool.name`, `mcp.server`, `mcp.session.id`,
`mcp.arguments`, `mcp.tenant`, and `mcp.principal.{sub,team,project,user}`; it
has no opinion about which arguments matter for your tools.

`result_policies[]` is the same mechanism pointed the other direction: a rule
evaluated against the tool-call *result*, after dispatch and after
`content_filters`, before the result enters the session or reaches the caller.
The vocabulary is identical plus one binding, `mcp.result`, so a rule can
correlate what was asked for with what came back:

<!-- sbproxy-config-excerpt -->
```yaml
      result_policies:
        - name: no-internal-hostnames-in-result
          engine: cel
          source: '!mcp.result.content[0].text.contains("internal.corp")'
          mode: block
```

Same polarity, same `mode: warn`/`block` split, same fail-closed posture on an
expression that cannot be evaluated, same monotonic ordering: a result policy
can only narrow what `content_filters` already allowed through, never widen it.

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
`mcp.tool_versioning.needs_confirmation`. An unbumped change graded a
violation also reaches your SIEM through `events:`: a
`mcp_governance_decision` record with reason `tool_definition_changed`,
verdict `deny` in `mode: block` or `warn` otherwise, and old/new digest
prefixes rather than the contract text itself. See [No usable record of
what happened](#no-usable-record-of-what-happened).

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
        egress:
          mode: deny_by_default
          hosts: [judge.example]
```

`egress` allowlists the judge endpoint itself; omitted, the judge call
is ungated but still recorded in the egress inventory. See
[mcp-gateway-guardrails.md](mcp-gateway-guardrails.md#dual-llm-quarantine).

**Still yours.** Neither is a solved-problem control. The trifecta guardrail
constrains the damage rather than detecting the injection, which is the honest
framing: it assumes the model will be steered and removes the combination that
makes steering costly. The quarantine judge is another model, with everything
that implies.

See [`examples/mcp-sessions/`](../examples/mcp-sessions/) for the session
lifecycle the trifecta guardrail's risk accumulation depends on, and
[`examples/prompt-injection-sidecar/`](../examples/prompt-injection-sidecar/)
for an out-of-process classifier that can scan tool output directly.

## A session that reads something untrusted, then tries to leave

**What goes wrong.** An agent session reads data from a source it does not
fully control (a federated server nobody has vetted, a search result, a
document another tenant uploaded), and the same session then calls a tool
that sends data somewhere external or changes state. If the read carried
injected instructions, the outbound call is how they leave. This is Meta's
Rule of Two: at most two of {touched untrusted input, touched sensitive
data, took an externally visible or state-changing action} in one session;
the third is the violation.

**What the gateway does.** `flow` tracks two session-scoped labels the
gateway can observe deterministically at the dispatch seam, most-restrictive-
wins and never lowering within a session: `integrity` (`trusted` ->
`tainted`, leg 1: touched untrusted input) and `sensitive_touched` (`false`
-> sticky `true`, leg 2: touched sensitive data). Leg 3 (the externally
visible or state-changing action) is not stored; it is evaluated fresh at
each `tools/call` against `outbound_tools`. A `tools/call` result (or a
`resources/read`) from a server outside `trusted_servers` taints the
session; one from a server in `sensitive_servers`, or a `tools/call` for a
tool matching `sensitive_tools`, sets `sensitive_touched`. The default rule,
`two_of_three`, is Rule of Two itself: the violation is a session that is
BOTH tainted AND has touched sensitive data, then attempts a call to a tool
matching `outbound_tools` -- the third leg.

<!-- sbproxy-config-excerpt -->
```yaml
      sessions:
        enabled: true
      flow:
        mode: block
        trusted_servers: [internal-docs, customer-db]
        sensitive_servers: [customer-db]
        sensitive_tools: ["db.query_pii"]
        outbound_tools: ["email.*", "slack.*"]
```

`customer-db` is internal infrastructure, so it belongs in `trusted_servers`
too: reading from it should mark `sensitive_touched`, not also taint
`integrity` the way a genuinely uncontrolled, external source would. The two
lists answer different questions -- "do I trust what this server tells me"
and "does this server's data need special handling" -- and a server can
answer yes to both.

`mode: warn` logs and emits a `mcp_governance_decision` event with verdict
`warn` but allows the call; `mode: block` refuses it before dispatch with
verdict `deny`. `mode: off` (the default) tracks nothing at all. Every
transition and violation carries its own `sbproxy.decision.rule_id`, so a
SIEM can tell exactly which leg (or leg combination) it is looking at:
`flow_taint` (a session newly tainted), `flow_sensitive_touched` (a session
newly touched sensitive data), and `flow_exfil_block` (all three legs, under
the default `rule: two_of_three`). This runs after RBAC, per-tool quota, and
`argument_policies[]` have already allowed the call, so it can only narrow
that allow, never widen it, and it composes with `lethal_trifecta` and
`dual_llm_quarantine` above rather than replacing either. Without
`sessions.enabled: true`, this degrades to single-call scope: with no memory
across calls, the only thing one call can prove is whether it is itself
simultaneously every leg the configured rule requires. The modern
2026-07-28 transport degrades to that same single-call scope today
regardless of `sessions.enabled`, since outbound federation does not yet
mint an `Mcp-Session-Id` on that path.

**Two rules, one default.** `flow.rule: two_of_three` (the default) is Rule
of Two proper, described above. `flow.rule: taint_and_outbound` is a
strictly stricter, explicit opt-in: the violation is tainted AND outbound,
with sensitivity never considered, so a session that has read anything
untrusted at all is gated the moment it tries an outbound call, and its
evidence carries `rule_id: flow_pair_block` instead. Reach for it when the
operating posture is "any untrusted read plus any outbound call is worth
refusing," and `sensitive_servers`/`sensitive_tools` are more configuration
than the deployment wants to maintain.

<!-- sbproxy-config-excerpt -->
```yaml
      flow:
        mode: block
        rule: taint_and_outbound
        trusted_servers: [internal-docs]
        outbound_tools: ["email.*", "slack.*"]
```

A custom CEL or Rego rule under `argument_policies[]` can read the same
labels directly, `mcp.session.integrity` and `mcp.session.sensitive_touched`,
to compose a policy the two built-in rules do not express, for example
denying outright the moment both legs are set rather than only gating the
tools named in `outbound_tools`.

**A rollout escape hatch.** `flow.taint_reads` (default `true`) is the one
knob that does not gate a leg directly. Set it `false` and the outbound
check stays live, reading whatever the session's labels currently are, but
nothing can ever move `integrity` off its `trusted` default: a `tools/call`
result or `resources/read` from an untrusted server stops tainting. Use it
to turn the outbound gate on before the read-side tainting it depends on,
if a deployment needs to see how `outbound_tools` alone behaves first.
`sensitive_touched` has no equivalent switch; leaving `sensitive_servers`
and `sensitive_tools` empty already keeps that axis inert.

**Still yours.** This is a deterministic, config-driven approximation of the
Rule of Two, not a semantic understanding of what a session actually did. It
has real false positives: a session that reads one untrusted, sensitive
paragraph for unrelated reasons and later, coincidentally, sends an
unrelated email is blocked exactly the same as one that is actually
exfiltrating. The literature proposing this class of control is explicit
about the same tradeoff, and the honest framing carries over here: this
constrains the blast radius of a session that might be compromised, it does
not detect whether one actually is. Naming which servers are
`trusted_servers`, which are `sensitive_servers`, and which tools are
`outbound_tools` is the operator's judgment call, not something the gateway
can infer from a catalog. The two axes default in opposite directions on
purpose: an empty `trusted_servers` list trusts nothing (fail closed, since
an unlabeled upstream is exactly the untrusted case this control exists
for), while an empty `sensitive_servers`/`sensitive_tools` reads
default-open (nothing is sensitive until an operator says so, since a
gateway cannot know what data a deployment considers sensitive). An empty
`outbound_tools` list makes the gate a no-op regardless of `mode` or `rule`.

## Untrusted or unexpected upstream servers

**What goes wrong.** A federated server resolves somewhere you did not intend,
or a tool call reaches a host nobody approved. In the worst version this is an
internal address.

**What the gateway does.** Egress is deny-by-default per origin and per
federated server, and the authorizer refuses destinations that resolve to
private address space unless explicitly allowed. This applies both to an
OpenAPI-backed server's REST calls (`type: openapi`) and, since WOR-2384, to
a plain `type: mcp` server's base connect over `streamable_http` or `sse`.
Every dial's outcome (allowed, denied, or ungated, when no `egress:` is
configured) is recorded and readable at `GET /api/egress`; see
[admin-api-reference.md](admin-api-reference.md).

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

**Still yours.** `stdio` servers spawn a local process and are outside this
control entirely; keeping the launched command honest is a supply-chain
problem, not a config one. Without an `egress:` block at all (the legacy
default, `mode: allow_by_default`), any server dials its origin unchecked,
same as before this control existed; the sighting inventory still records the
dial as `ungated` rather than staying silent about it. SBproxy also does not
implement per-upstream certificate pinning. TLS validation is standard chain
validation. If you need to pin a specific key for an upstream, that is not
available here today.

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

**What goes wrong.** An incident review asks which agent called which tool
with what arguments, and who approved that access, and the answer is
scattered across application logs that were never designed for the question.
This is MCP08 in the OWASP taxonomy: an interaction log an auditor can
actually answer that question from, without reconstructing it from call
volume or grepping free text.

**What the gateway does.** Every governed decision emits a `mcp_governance_decision`
record over `events:` (see [events.md](events.md)), and tool dispatch is
metered:

```
sbproxy_mcp_tool_dispatch_total
sbproxy_mcp_tool_dispatch_duration_seconds
sbproxy_mcp_tool_cost_usd_total
```

`mcp_governance_decision` is one wire event covering three moments, each with
its own reason and its own subset of fields:

- **Tool invocations.** Every dispatched `tools/call`, plus every call refused
  before dispatch (RBAC, per-tool quota, an argument policy, a downgraded
  peer, a `draft` server, a session-flow guardrail violation). Every one of
  these carries the decision and, opt-in, the arguments themselves (below);
  only a *dispatched* call also carries a salted digest of the arguments
  (`sbproxy.tool.arguments_hash`), since a call refused before dispatch was
  never captured to hash in the first place.
- **`resources/read` and `prompts/get` decisions.** A `draft`-server or
  peer-downgrade refusal, a deprecated-server warning, or a content-filter
  warn/redact/block on either method's result, reason and rule id matching
  the identical gate's `tools/call` record exactly. `mcp.method.name` names
  the method (`resources/read` or `prompts/get`) instead of `tools/call`;
  neither carries `gen_ai.tool.name`, since neither method names a tool.
- **Tool definition changes.** The version-lockfile gate's per-refresh
  contract check, reason `tool_definition_changed`. See [A tool definition
  changing after you approved it](#a-tool-definition-changing-after-you-approved-it).
- **Registry changes.** A federated server's approval status (`draft`,
  `approved`, `deprecated`) transitioning across a config reload, reason
  `server_status_changed`, emitted once per transition rather than once per
  call.

### Field mapping

The OWASP MCP Top 10 is still in incubation, so treat the left column as the
audit question rather than a stable section number. Right column names are
this event's actual field names.

| MCP08 asks | sbproxy field | Present on |
|---|---|---|
| Which tenant / caller | `tenant_id` (envelope), `sbproxy.tenant.id` | every record |
| Which tool | `gen_ai.tool.name` | tool-invocation and definition-change records |
| On which upstream server | `sbproxy.tool.server` | every record |
| With what arguments | `sbproxy.tool.arguments_hash` (dispatched calls only, salted digest) / `gen_ai.tool.call.arguments` (opt-in, verbatim, every tool-invocation record, dispatched or refused) | tool-invocation records |
| What was decided, and why | `sbproxy.decision.verdict`, `sbproxy.decision.reason` | every record |
| Under which rule | `sbproxy.decision.rule_id` | records where a named rule fired |
| When, in order, without gaps | `sbproxy.evidence.seq`, `sbproxy.evidence.instance`, `timestamp` (envelope) | every record |
| What the tool contract was before/after | `sbproxy.tool.digest.old`, `sbproxy.tool.digest.new` | definition-change records |
| What the registry status was before/after | `sbproxy.registry.status.old`, `sbproxy.registry.status.new` | registry-change records |

The gapless property on `sbproxy.evidence.seq` is per tenant **and per
emitting process**. The counter lives in proxy memory, so every replica and
every restart begins a new sequence at 1; `sbproxy.evidence.instance` names
the process that minted the number, and a hole is only a hole within one
`(sbproxy.evidence.instance, sbproxy.tenant.id)` pair. Group on the tenant
alone across two replicas and you get `1, 1, 2, 2, 3, 3`, which hides both
holes and duplicates; group on it across a restart and a fresh counter reads
as a rollback. A run whose tail was cut off is the case the sequence cannot
tell you about at all: a replica killed mid-stream and one shut down cleanly
both leave a sequence that simply stops.

Tool-invocation records carry the caller's own tenant, so gaps are detectable
within one tenant's own traffic on one instance. Definition-change and
registry-change records have no caller (they come from a background catalog
refresh or a config reload, not a request) and share one sequence under the
empty-tenant bucket; do not expect per-record-kind gaplessness across that
shared bucket, only across each tenant's own tool-invocation stream and the
shared background-event stream each on their own terms.

"Who approved that access" splits in two. Which rule authorized a call is on
the record (`sbproxy.decision.rule_id`, `sbproxy.decision.reason`). Who
approved a *server's* registry status (`federated_servers[].approved_by` /
`approved_at`) is operator-attested config, never verified by the gateway,
and travels through the ordinary config-change audit trail rather than a
dedicated event field: it is a fact about your process, not one the gateway
can witness.

### Verbatim argument capture

`sbproxy.tool.arguments_hash` ships by default on a *dispatched* call's
record: enough to confirm two calls used the same arguments, or that a
specific known-bad payload was replayed, without the arguments themselves
ever leaving the process. A call refused before dispatch (RBAC, quota, an
argument policy, a downgraded peer, a `draft` server, a session-flow
guardrail violation) carries no hash either, by default, for the same
reason it carries no upstream response: nothing was captured to hash. That
is deliberately not enough to answer "what were the arguments" on any
record, and closing that gap is an explicit opt-in:

<!-- sbproxy-config-excerpt -->
```yaml
      mcp_audit:
        capture_arguments: true
```

When set, every tool-invocation record, dispatched or refused, also carries
`gen_ai.tool.call.arguments`: the call's arguments, redacted (the same
secret-pattern scrub `mcp_audit`'s own content fields already go through)
and capped at 8 KiB, the same bound. Off by
default, because shipping raw tool-call arguments to every configured
`events:` sink is a real tradeoff, not a free one: the redaction pass
recognizes credential shapes, not your customers' PII or business-sensitive
free text sitting in an argument the model happened to fill in. Turn this on
only once you have looked at what your tools actually receive.

Evidence is structured logs aimed at your SIEM rather than a separate store,
so it lands beside every other denial you already collect. The session
ledger records per-session activity; see [mcp.md](mcp.md).

**Still yours.** Retention, correlation, and alerting. `sbproxy.evidence.seq`
is a gapless counter per tenant per emitting process while emission is
enabled, which is what makes SIEM-side retention safe to rely on: a consumer
grouping on `(sbproxy.evidence.instance, sbproxy.tenant.id)` can prove it has
every record rather than trusting that it does. See [events.md](events.md#retention).
The gateway emits; your SIEM decides what matters and how long to keep it.

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

**What goes wrong.** One tenant's catalog, tools, session state, or result
content reaches another tenant's agent.

**What the gateway does.** MCP catalogs are tenant-scoped. A key policy naming
an MCP gateway resolves only within the request route's tenant, so a reference
that crosses a tenant boundary resolves to nothing rather than to someone else's
catalog. Two tenants may run gateways with the same `server_info.name` without
seeing each other's tools. A cross-tenant reference is no longer only quiet in
the logs either: it emits a `mcp_inject_source_denied` audit event (readable
through `GET /api/audit/events` or the `security_audit` tracing target) alongside
the existing `warn!` line, so a misconfigured or probed reference is
SIEM-visible rather than something you have to know to grep for.

`sessions.enabled` state is bound to the tenant that minted it: a session id is
stamped with its tenant at `initialize` and every later request presenting it
is checked against that tenant, not just against existence and expiry. A
session id guessed or replayed by a different tenant is refused (the same
generic "unknown or expired" response a stranger gets, so the refusal itself
does not confirm the id belongs to someone) and audited as
`mcp_session_tenant_mismatch`. This was already an isolation invariant in
practice -- session ids were opaque per-deployment UUIDs before -- so turning
it on cannot change behavior for an existing legitimate config.

Session establishment is capacity-bounded too, per tenant and globally: a
live entry costs registry memory for as long as its TTL, so an unbounded
mint is a denial-of-service surface in its own right, and one tenant
minting sessions without bound should not be able to crowd out another's.
`initialize` refuses to mint a session once the caller's tenant already
holds 256 live sessions, or the registry holds 4096 across every tenant,
with an explicit JSON-RPC error rather than a `200` carrying no
`Mcp-Session-Id` header, so a caller cannot mistake refusal for silent
statelessness. The refusal is audited as `mcp_session_registry_saturated`
via `security_audit` rather than a `mcp_governance_decision` event --
`initialize` is never itself a `tools/call`, the boundary that event stays
scoped to throughout this page -- and counted on
`sbproxy_mcp_session_registry_saturated_total`. Neither cap touches an
existing session: one already minted keeps working and renewing its TTL on
every request exactly as before, and every other tenant's headroom is
unaffected; only the establishment of a *new* session, for a tenant or a
registry that is already full, is refused. The arithmetic is worth
stating plainly: 4096 global divided by 256 per tenant means sixteen
tenants can hold full sub-caps at once, so the global cap is a
deployment-sizing fact, not a per-tenant isolation guarantee.

The peer-profile registry that backs downgrade detection carries the
same shape of bound, with the same caps (256 pairs per tenant, 4096
globally), because a tracked profile is likewise memory an unbounded
peer set could exhaust. A federated call whose `(tenant, peer)` pair
cannot be tracked gets no downgrade baseline, and a control that cannot
observe cannot enforce: under `downgrade: block` that call is refused
fail-closed with rule id `peer_profile_saturated` and a
`mcp_governance_decision` record; under `warn` (the default) it is
served, logged once per tenant, and counted on
`sbproxy_mcp_peer_registry_saturated_total` either way. Pairs already
tracked keep enforcing normally while the registry is saturated.

And a tool-call *result* can carry another tenant's data through an upstream
that itself mixes tenants; `content_filters` (see "Credentials reaching a tool
that should not see them" above) and `result_policies[]` (see "A permitted tool
called with an argument that should not be") both run against the result
document specifically, so a shape a detector recognizes, or a rule an operator
writes against `mcp.result`, is caught before that document ever enters the
session or reaches the caller.

**Still yours.** `content_filters` is shape-based and `result_policies[]` is
whatever an operator writes; neither one understands your data model well
enough to know, unprompted, that a given field is another tenant's. Give the
MCP origin the same `tenant_id` as the `ai_proxy` origin whose keys name it if
cross-tenant injection was never the intent.

## Where to go next

- [mcp-security-coverage.md](mcp-security-coverage.md) for the OWASP MCP
  Top 10 scorecard this page's sections answer to.
- [mcp.md](mcp.md) for the gateway itself: wire shape, sessions, OAuth, and the
  dual-era transport.
- [mcp-gateway-guardrails.md](mcp-gateway-guardrails.md) for the guardrail
  mechanisms in depth, including supervised stdio and run-as-user.
- [tool-versioning.md](tool-versioning.md) for the digest recipe and the
  compatibility oracle.
- [events.md](events.md) for the `mcp_governance_decision` wire shape,
  fail-closed delivery, and retention.
- [security.md](security.md) for the whole picture.
