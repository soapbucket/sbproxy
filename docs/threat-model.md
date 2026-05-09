# SBproxy threat model

This is the OSS threat-model companion to [`operator-runbook.md`](operator-runbook.md).
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
- **Upstream TLS verification:** the OSS build relies on the rustls verifier
  defaults that ship with Pingora, validating upstream certificates against
  the system CA bundle in the runtime image. Pin-by-SPKI is not implemented.
  Operators who need stricter assurance for sensitive upstreams should
  compensate via network-egress allowlists, mTLS to the upstream, or a
  forward-proxy layer that performs the pinning itself.

## Review Checklist

- New config fields document whether they are secret-bearing.
- New metrics have bounded labels or a documented cardinality cap.
- New outbound calls have timeouts and failure modes.
- New dashboards link to a runbook section.
- New closed-enum values use the fast-track ADR template when eligible.
