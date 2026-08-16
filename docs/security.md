# Security

*Last modified: 2026-08-16*

SBproxy sits between your clients and whatever they are calling, which makes it
a good place to enforce things the service behind it might have forgotten. This
page is the map: what the gateway is responsible for, what it is not, and where
to read next.

There are three surfaces worth keeping separate in your head, because they fail
differently and the controls do not transfer.

## The three surfaces

**Your API traffic.** Ordinary request and response governance: who is calling,
what they may reach, how much of it, and what comes back. Most of this is
familiar and most of it is solved by putting a policy in the path.
[api-security.md](api-security.md).

**Your MCP and agent traffic.** Different, and harder, because the payload is
partly instruction. A tool description reaches a model that treats it as
something to act on, so integrity of the definition matters as much as
authorization of the call. [mcp-security.md](mcp-security.md).

**The proxy itself.** Its own attack surface, the assumptions it makes, and the
trust boundaries it draws. [threat-model.md](threat-model.md).

Separately from all three: reporting a vulnerability in SBproxy, verifying a
release signature, and checking build provenance live in
[`SECURITY.md`](../SECURITY.md) at the repository root.

## What the gateway is actually good at

Being unavoidable. Every control on the pages above is enforcement at a choke
point, and that is the source of both its value and its limits.

The value: a policy in the path applies to every route, including the one added
last week by someone who did not read the security guide. Object-level
authorization, rate limits, schema validation, and egress control all work
better as a property of the network than as a habit of each service.

The limit: a control at the edge is only as good as the edge being the only way
in. If a service is directly reachable, every policy here is optional from an
attacker's point of view. That is a network design question, not a
configuration one, and it is the precondition for everything else on this page.

## What it is not good at

Business logic. The gateway can confirm a caller may invoke an operation. It
cannot know whether this particular invocation makes sense, and no amount of
policy configuration turns it into something that can.

Anything that never traverses it. An agent wired directly to an MCP server, a
service called over a private link, an SSRF that stays inside one process:
these are invisible here, and treating the gateway as coverage for them is the
mistake worth avoiding.

Detecting prompt injection reliably. SBproxy reports signals and constrains
consequences. Neither is detection, and the docs say so wherever the distinction
matters, because a control you believe in that does not work is worse than a
gap you have written down.

## Defaults worth knowing

A few behaviors are on without configuration, which is usually what you want but
occasionally surprising.

Upstreams that resolve to private address space are refused unless allowed, so
an SSRF attempt against cloud metadata does not leave the gateway.

MCP catalogs are scanned on every refresh for text that conceals content from a
reader and for static poisoning indicators. Both report; neither blocks.

Redaction runs before observability fan-out, so a value redacted from a response
does not reappear in a log or a trace.

Denials emit structured security audit records with stable event types and
closed reason labels, and never carry the offending header value.

## Where the gaps are

Stated plainly, because these are the ones people assume are covered.

Per-upstream certificate pinning is not implemented. TLS uses standard chain
validation. If your threat model requires pinning a specific key for a specific
upstream, that is not available here today.

There is no lockfile generator for MCP tool versioning yet, so the baseline that
feature reads is hand-assembled. The recipe is documented and tested, but the
ergonomics are rough. [tool-versioning.md](tool-versioning.md).

Unsanctioned MCP servers are addressed by architecture rather than by a feature.
If agent egress is required to traverse the gateway, an unapproved server is one
that egress policy refuses. If it is not required, the gateway never sees it.

## Reading order

If you are securing a deployment for the first time:

1. [threat-model.md](threat-model.md), to see the assumptions you are inheriting.
2. [api-security.md](api-security.md) or [mcp-security.md](mcp-security.md),
   depending on what you are putting behind it.
3. [audit-log.md](audit-log.md), because the controls are worth much less
   without somewhere to send what they record.
4. [`SECURITY.md`](../SECURITY.md), for release verification and how to report
   something.

If you are responding to a security review, the two topic pages are written to
be handed over directly. Each threat class states what the gateway does, the
configuration that does it, and what remains yours. The last part is there so
the review is with you rather than about you.
