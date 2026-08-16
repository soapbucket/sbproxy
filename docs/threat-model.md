# SBproxy threat model

*Last modified: 2026-08-16*

This is the threat-model companion to [`operator-runbook.md`](operator-runbook.md).
It records the operator-facing assumptions that should be revisited at the end
of each implementation wave.

## Assets

- Proxy configuration (`sb.yml`, `SBProxyConfig`, Helm values).
- Traffic metadata, access logs, audit events, and traces.
- Customer credentials: API keys, JWKS material, webhook secrets, quote-token
  signing seeds, and vault references.
- Runtime policy decisions: auth, rate limit, WAF, AI crawl control, and
  content-shape transforms.

## Trust Boundaries

- Client to proxy: all request headers and bodies are untrusted.
- Proxy to upstream origin: only policy-filtered requests should cross.
- Proxy to admin API: protected by admin auth and network placement.
- Proxy to observability sinks: redaction must happen before fan-out.
- Proxy to external resolvers/providers: DNS, JWKS, ACME, AI providers, and
  webhook receivers may fail or return malformed data.

## Current Wave Notes

- **Observability and dashboards:** dashboard panels now link to the operator
  runbook so a red panel has a concrete action path instead of only a metric
  name.
- **Secrets:** quote-token signing seeds can move through the shared vault
  resolver shape instead of only inline/env-only config paths.
- **Agent identity:** live reverse-DNS verification depends on external DNS
  availability. DNS errors must degrade to a diagnostic verdict, not a silent
  allow.
- **Build supply chain:** the reproducible-build probe is informational until
  binary diffs are driven to zero.
- **Upstream TLS verification:** SBproxy relies on the rustls verifier
  defaults that ship with Pingora, validating upstream certificates against
  the system CA bundle in the runtime image. Pin-by-SPKI is not implemented.
  Operators who need stricter assurance for sensitive upstreams should
  compensate via network-egress allowlists, mTLS to the upstream, or a
  forward-proxy layer that performs the pinning itself.
- **Outbound egress DNS pinning (resolve-to-connect):** purpose-scoped
  egress authorization resolves a destination once and records the
  answer as a pin set. For OpenAPI-backed MCP tool calls, the path that
  dials a pinned destination today, the resolve-to-connect window is
  closed at the connector: immediately before each connect the dial
  addresses are re-verified against the pin set, and the HTTP client is
  handed only the verified addresses so it cannot re-resolve on its
  own. Every redirect hop is re-authorized as a new destination and
  gets the same per-hop verification. A DNS answer that changes between
  authorization and dial refuses the call with the closed
  `DnsPinMismatch` reason; it is never silently re-resolved. RAG
  provider and external guardrail clients close the same window by a
  different mechanism: they resolve and validate once at client build
  and their connectors dial only those addresses, so no second
  resolution exists to rebind. One opening remains by explicit choice:
  legacy allow-by-default MCP egress records no pins and dials
  unpinned; operators opt into pinning by switching the policy to
  enforce.
- **Outbound redirect re-authorization:** an allowlist checked once
  covers the first hop and nothing after it, so a destination that
  answers with a redirect used to be able to walk a credential to a
  host no gate had seen. Every consumer now disables its HTTP client's
  own redirect following and re-authorizes each `Location` before the
  next connect, capped at ten hops. AI provider dials, the webhook,
  Langfuse, and Datadog usage sinks, and both token-exchange paths
  refuse any hop that changes scheme, host, or port when no allowlist
  is configured: the operator named one host, so that is the only host
  the chain may reach. With an allowlist configured, each hop is
  authorized against it and credentials are stripped on a cross-origin
  hop, including credentials in vendor header names such as
  `x-api-key` and `DD-API-KEY` that an HTTP client's own stripping does
  not cover. Model and engine artifact downloads follow cross-origin
  hops, because a registry handing a download to object storage or a
  CDN is the normal case, but the source credential is dropped before
  the request leaves the origin it was minted for. Refusals are counted
  on `sbproxy_egress_refused_total{purpose, reason, tenant, origin}`.
- **DNS pinning exemption for the credential-bearing consumers:** the
  gates for AI providers, usage sinks and webhooks, token exchange, and
  artifact downloads now authorize against a live system resolver
  behind a 30-second cache, so a host that resolves onto private or
  link-local space is refused and a recorded pin describes DNS rather
  than a fixture. They are deliberately **not** dial-pinned: the
  authorizer records a pin set, but the address handed to the connector
  is not held to it.

  The reason is the shape of the client. Dial pinning works by building
  a client whose resolver override carries exactly the verified
  addresses, which means one client per destination. The OpenAPI tool
  path can afford that because it builds a client per call already. The
  four consumers here share one long-lived client each, and `AiClient`
  is the hottest outbound path in the proxy: a client per destination
  there would rebuild the TLS configuration and abandon the connection
  pool on every dial, turning a pooled keep-alive request into a fresh
  handshake. That is a latency regression on every AI request in
  exchange for closing a window that the resolver cache already narrows
  to its TTL.

  Residual risk: an attacker who controls DNS for an allowlisted host
  can rebind it between the gate's resolution and the connector's own,
  and reach an address the gate would have refused. The allowlist,
  scheme, and port checks still hold, so the attack requires already
  being on the operator's allowlist. Closing it needs a per-destination
  client cache keyed on host and pin set, or a connector-level resolver
  that consults the authorizer, so that one shared client can still
  dial only verified addresses. Either is a bounded change once
  operator-facing `proxy.egress` configuration exists and someone is
  actually running these gates in enforce mode; today no production
  configuration attaches an authorizer to any of the four.
- **Egress bypass detection:** the gateway enforces nothing on traffic
  that does not reach it. A caller with direct network access to an AI
  provider that skips the proxy entirely is invisible to every egress
  control above: the authorizer, the DNS pinning, the per-purpose
  inventory. None of it sees a request it was never handed. Closing
  that gap is a deployment decision, not something SBproxy configures
  for you, and three things help. A network egress policy (a
  Kubernetes NetworkPolicy, a cloud security group, a host firewall
  rule) that permits outbound HTTPS to AI provider hosts only from the
  gateway's own network identity, and refuses it from the workloads
  that are supposed to call the gateway instead, forces that traffic
  across a boundary the gateway can see. An outer forward proxy in
  front of the gateway, or any other independent egress choke point,
  adds a second control that does not share the gateway's own blind
  spots. Provider-side key restrictions, most AI providers let an API
  key be scoped to an origin IP or a project, mean a leaked credential
  or a bypassed network policy still cannot reach the provider from
  anywhere but the gateway's own address.

  What SBproxy adds is detection after the fact. `sbproxy ai ledger
  reconcile` compares the gateway's own usage ledger against a usage
  export downloaded directly from the provider, per day and model, and
  flags provider-billed usage the ledger never recorded, exactly the
  shape a bypass leaves behind. It proves nothing about traffic under a
  different provider organization, project, or key, and a ledger-only
  row is a lead rather than proof: clock-window edges between the
  export's bucket boundary and the ledger's own timestamp produce the
  same shape. See
  [ai-usage-ledger.md](ai-usage-ledger.md#reconciling-against-a-provider-export).
- **Agent Skills v0.2.0:** every artifact `GET` re-hashes the served
  body and compares to the manifest digest. A mismatch returns 503 with a
  generic "service unavailable" body and emits an `agent_skill.digest_mismatch`
  audit event so the operator notices a hot-swap or memory corruption.
  Archive entries (`type: archive`) are validated for path traversal,
  external symlinks, and decompression bombs at config-load time. The proxy
  never executes any pre-/post-hooks or scripts shipped inside an artifact;
  artifacts are served as opaque bytes. See [`agent-skills.md`](agent-skills.md)
  for the full integrity and archive-safety contract.

## Review Checklist

- New config fields document whether they are secret-bearing.
- New metrics have bounded labels or a documented cardinality cap.
- New outbound calls have timeouts and failure modes.
- New dashboards link to a runbook section.
- New closed-enum values use the fast-track ADR template when eligible.

## Examples in Practice

To explore SBproxy's security model in action, see the following examples:

| Example | What it is | How to use it | Outcome |
|---------|------------|---------------|---------|
| [`csrf`](../examples/csrf/) | Cross-Site Request Forgery protection. | Configure CSRF token validation policies. | Blocks unauthorized state-changing requests from browsers. |
| [`defense-in-depth`](../examples/defense-in-depth/) | Layered security. | Combine WAF, rate limits, and authentication. | Comprehensive, multi-tiered protection for sensitive endpoints. |
| [`dlp-catalog`](../examples/dlp-catalog/) | Data Loss Prevention. | Use `dlp` policies for PII detection. | Detects sensitive shapes in the request URI and headers, then tags or blocks. It does not read request bodies; use the `pii:` block on an `ai_proxy` origin for those. |
| [`hsts`](../examples/hsts/) | Strict Transport Security. | Set `hsts: true` in your server block. | Forces client browsers to use secure TLS connections. |
| [`page-shield`](../examples/page-shield/) | Monitor third-party scripts. | Inject Content Security Policy (CSP) rules. | Mitigates risks like Magecart attacks on frontend assets. |
| [`security-headers`](../examples/security-headers/) | Standard secure headers. | Apply the `security_headers` configuration preset. | Hardens browser interactions out-of-the-box. |
| [`sri`](../examples/sri/) | Subresource Integrity. | Inject SRI hashes into HTML bodies. | Ensures CDN assets haven't been maliciously altered. |
