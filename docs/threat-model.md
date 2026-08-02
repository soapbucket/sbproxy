# SBproxy threat model

*Last modified: 2026-08-02*

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
  resolution exists to rebind. Two openings remain by explicit choice.
  Legacy allow-by-default MCP egress records no pins and dials
  unpinned; operators opt into pinning by switching the policy to
  enforce. And the egress gates for AI providers, usage sinks and
  webhooks, token exchange, and model or engine artifact downloads
  enforce host, scheme, and port allowlists fail-closed but are not
  DNS-pinned: no production configuration attaches an authorizer to
  those paths yet, and their gate runs against a fixed synthetic
  resolver rather than a live DNS answer, so a pin check there would
  assert coverage that does not exist. Those gates also cover only the
  first hop, because their HTTP clients follow redirects internally.
  Real pins and per-hop re-authorization for those paths arrive
  together, when operator-facing egress configuration lands and wires a
  live resolver through them.
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
