# Security

*Last modified: 2026-08-18*

SBproxy sits between your clients and whatever they are calling, which makes it
a good place to enforce things the service behind it might have forgotten. This
page is the map: what the gateway is responsible for, what it is not, and where
to read next.

There are four surfaces worth keeping separate in your head, because they fail
differently and the controls do not transfer.

## The four surfaces

**Your API traffic.** Ordinary request and response governance: who is calling,
what they may reach, how much of it, and what comes back. Most of this is
familiar and most of it is solved by putting a policy in the path.
[api-security.md](api-security.md).

**Your AI model traffic.** Prompts, completions, and the spend attached to
them. The payload is conversation, the cost is metered per token, and the
provider on the other end is somebody else's computer. The controls that
matter are guardrails in the request path, budget enforcement that actually
denies, an inventory of every provider endpoint reached, and telemetry that
does not leak the traffic it audits.
[ai-gateway-security-coverage.md](ai-gateway-security-coverage.md).

**Your MCP and agent traffic.** Different, and harder, because the payload is
partly instruction. A tool description reaches a model that treats it as
something to act on, so integrity of the definition matters as much as
authorization of the call. [mcp-security.md](mcp-security.md).

**The proxy itself.** Its own attack surface, the assumptions it makes, and the
trust boundaries it draws. [threat-model.md](threat-model.md).

Separately from all four: reporting a vulnerability in SBproxy, verifying a
release signature, and checking build provenance live in
[`SECURITY.md`](../SECURITY.md) at the repository root.

## Identity and credential controls

These sit underneath more than one of the four surfaces above, so they get
their own list rather than a slot in any single one.

**Authenticating the caller.** [auth-oidc.md](auth-oidc.md) covers the
`oidc` provider: a full authorization-code-plus-PKCE login with a sealed
session cookie, for callers that are people. [web-bot-auth.md](web-bot-auth.md)
covers the `bot_auth` provider: RFC 9421 signature verification against a
published key directory, for callers that claim to be a known crawler and can
prove it rather than just assert it.

**Managing the credentials themselves.** [key-management.md](key-management.md)
covers minting, revoking, and rotating inbound virtual keys at runtime through
the admin API, hashed at rest. [secrets.md](secrets.md) covers the one
reference grammar every secret-bearing config value resolves through,
regardless of which field it sits in.

**Constraining outbound credentials.** [outbound-dpop.md](outbound-dpop.md)
covers RFC 9449 sender-constrained tokens on the credentials SBproxy presents
to an upstream, so a stolen bearer token by itself is not enough to replay.

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

## AI traffic, in brief

The coverage page carries the row-by-row detail, including an honest mapping
against the OWASP LLM Top 10 (2026 edition). The short version:

Request and response bodies run through configured guardrails, and a verdict on
a streamed response must equal the verdict the same bytes would get buffered
whole; a streaming mode that cannot keep that promise is refused at config
compile rather than approximated. A multipart Content-Type on a JSON-only AI
surface, chat completions for example, is refused outright, so a caller cannot
relabel a request past body inspection. [guardrails.md](guardrails.md),
[ai-gateway.md](ai-gateway.md).

The `pii:` block redacts AI request and response bodies. The `dlp` policy scans
the request URI, headers, and by default the first 16 KiB of the buffered
request body; it tags or blocks and never masks, and it never sees a response.
They cover different surfaces and should not be confused. [prompt-injection-v2.md](prompt-injection-v2.md) states the
detector's limits plainly: the default is a substring heuristic, and no
detection model ships in the binary.

Budgets deny at the cap across seven scopes, and denial of wallet is treated as
enforcement rather than observation. Counters are per replica unless a shared
store is configured, and when that store fails, enforcement degrades to
per-instance tracking with a metric and a warning rather than silence.
[ai-gateway.md](ai-gateway.md#budgets).

Every outbound destination the gateway reaches, across every wired egress
purpose and not just AI providers, is recorded with its authorization status,
allowed, denied, or ungated, and is readable at `GET /api/egress`. Outbound
dials pass a default-deny, DNS-pinned egress authorizer.

Serving-path request budgets key by tenant, and a panicking tenant policy now
denies that one request instead of crashing the process. Neither changes the
recommendation in [multi-tenant.md](multi-tenant.md): mutually untrusting
tenants get one process per trust boundary.

Prompt-linked audit records carry salted digests and lengths, never content.
Security, config, key-mutation, and admin-action records each append, when
opted in per channel, to their own hash-chained, signed file that `sbproxy
audit verify --channel` checks offline. [audit-log.md](audit-log.md).

## Defaults worth knowing

A few behaviors are on without configuration, which is usually what you want but
occasionally surprising.

Upstreams that resolve to private address space are refused unless allowed, so
an SSRF attempt against cloud metadata does not leave the gateway.

A multipart body on a JSON-only AI surface is refused before any budget,
guardrail, or upstream work happens, and the refusal emits a security audit
record.

MCP catalogs are scanned on every refresh for text that conceals content from a
reader and for static poisoning indicators. Both report; neither blocks.

Redaction runs before observability fan-out, so a value redacted from a response
does not reappear in a log or a trace. Prompt-linked audit lines carry digests,
not content.

Denials emit structured security audit records with stable event types and
closed reason labels, and never carry the offending header value.

## Where the gaps are

Stated plainly, because these are the ones people assume are covered.

Per-upstream certificate pinning is not implemented. TLS uses standard chain
validation. If your threat model requires pinning a specific key for a specific
upstream, that is not available here today.

`sbproxy mcp lock` generates the MCP tool-versioning baseline from the live
catalog, and `sbproxy mcp verify-lock` diffs against it and exits nonzero on
drift. Wiring `verify-lock` into your own CI, so drift actually blocks a
merge, is still on you. [tool-versioning.md](tool-versioning.md).

Unsanctioned MCP servers are addressed by architecture rather than by a feature.
If agent egress is required to traverse the gateway, an unapproved server is one
that egress policy refuses. If it is not required, the gateway never sees it.

GET and multipart AI surfaces do not debit token budgets, and DLP does not read
request bodies. Both limits are stated in the coverage page's rows rather than
smoothed over.

## Reading order

If you are securing a deployment for the first time:

1. [threat-model.md](threat-model.md), to see the assumptions you are inheriting.
2. [api-security.md](api-security.md), [mcp-security.md](mcp-security.md), or
   [ai-gateway-security-coverage.md](ai-gateway-security-coverage.md),
   depending on what you are putting behind it.
3. [policy.md](policy.md), once you know which threat class you are answering
   and need the actual policy, its fields, and a config example.
4. [audit-log.md](audit-log.md), because the controls are worth much less
   without somewhere to send what they record.
5. [`SECURITY.md`](../SECURITY.md), for release verification and how to report
   something.

If you are responding to a security review, the topic pages are written to
be handed over directly. Each threat class states what the gateway does, the
configuration that does it, and what remains yours. The last part is there so
the review is with you rather than about you.
