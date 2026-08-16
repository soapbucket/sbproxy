# SBproxy security

*Last modified: 2026-08-16*

SBproxy is an enforcement point in the traffic path: every request that reaches a model, an API origin, or an MCP tool passes through the gateway's enforcement code before it goes anywhere else. This page summarizes that enforcement. Every claim below links to the doc that carries its details and its limits, and nothing here states a claim more strongly than the doc it links to does.

## AI traffic security

[ai-gateway-security-coverage.md](ai-gateway-security-coverage.md) maps SBproxy's AI gateway path (providers, routing, guardrails, budgets, streaming) against the OWASP LLM Top 10 (2026 edition), plus the gateway-layer controls no published list covers, and states coverage honestly as full, partial, or out of scope. The sections below summarize that page; read it for the row-by-row detail.

**Input and output guardrails.** Request and response bodies run through configured guardrails before a request reaches the model or a response reaches the caller. A guardrail verdict on a streamed response must equal the verdict the same bytes would get if buffered whole; a streaming mode that cannot keep that promise is refused at config compile time instead of approximated. Guardrail inspection assumes a JSON body, which creates a gap a caller could try to exploit by relabeling a request: a multipart `Content-Type` on a JSON-only AI surface, chat completions for example, is refused outright. Image edits, image variations, audio transcription, and file uploads are the surfaces that legitimately carry multipart bodies; on those, built-in guardrail inspection is bypassed instead, because the body cannot be JSON-parsed, and every bypass is counted on a metric so a JSON surface taking this path stands out. See [ai-gateway.md](ai-gateway.md#guardrails) and [guardrails.md](guardrails.md#streaming-and-multipart-content).

**Prompt injection screening.** The `prompt_injection_v2` policy scores a prompt and maps the score to tag, block, or log. The default detector is a substring heuristic. SBproxy also ships an in-process ONNX detector and a sidecar detector as swappable alternatives, and uses a verified in-process model automatically when a complete artifact pair is staged, but no detection model ships in the binary by default. See [prompt-injection-v2.md](prompt-injection-v2.md).

**PII redaction and DLP.** These cover different surfaces and should not be confused. The `pii:` block on an `ai_proxy` origin redacts PII from AI request and response bodies. The `dlp` policy scans the request URI and headers only, against a detector catalog, and tags or blocks; it does not read request bodies and it never masks. Use `pii:` for body content and `dlp` for URI and header shapes like leaked keys or ticket IDs in a query string.

**Budgets and denial-of-wallet enforcement.** Budget policies deny a request at the cap rather than only log past it. By default budget counters are per-instance, so a cluster of N replicas enforces roughly N times a configured cap unless a shared Redis-backed key store is configured, in which case the fleet enforces one shared total. If that shared store is briefly unreachable, enforcement falls back to the per-instance tracker instead of blocking everything, and that degradation is visible on `sbproxy_budget_share_fail_open_total` and `sbproxy_budget_share_unavailable`. See [ai-gateway.md](ai-gateway.md#budgets).

**Provider egress control.** Upstream provider endpoints pass a default-deny, DNS-pinned egress authorizer: a destination is resolved once, the answer is pinned, and every dial is re-verified against that pin set immediately before connecting, closing the window where a DNS answer could change between authorization and dial. Every endpoint the gateway reaches is inventoried with its authorization status, allowed, denied, or ungated, readable from the admin API. Traffic that never crosses the gateway is invisible to this control. See [threat-model.md](threat-model.md).

**Tenant isolation.** Multi-tenant deployments get tenant-keyed serving-path budgets (the workspace rate-limit escalation ladder buckets by tenant, with per-tenant series on `sbproxy_rate_limit_total{workspace}`), and a policy that panics now denies that one request with a 500 and increments `sbproxy_policy_panic_total{policy}` instead of taking down the process. That narrows the blast radius of a tenant-triggered fault; it does not turn co-tenancy into hard isolation, since a fault outside policy evaluation can still reach every tenant. Production deployments running mutually untrusting tenants should still run one proxy process per trust boundary, the same recommendation as before. See [multi-tenant.md](multi-tenant.md).

**Telemetry hygiene.** Every log line and event runs through the same secret redactor before it leaves the process, and sensitive fields are matched by field key (`authorization`, `*_secret`, `*_token`, `*_key`, `prompt`, `messages`, and similar), not by guessing at values. Prompt-linked audit records carry salted digests and lengths of prompt content, never the content itself; verbatim capture is an explicit, off-by-default opt-in. See [observability.md](observability.md) and [access-log.md](access-log.md).

**Tamper-evident audit chains.** `audit.sink: chain` appends every `security_audit` event to a SHA-256 hash-chained, Ed25519-signed file whenever the chain sink is on; there is no separate opt-in for that channel. `config_audit` events chain too, but only when `audit.config_path` is also set, since its payload shape differs from the security trail and needs its own file. `key_audit` is deliberately not chainable yet: its before/after credential diff needs a content-based ruling before it goes into a file designed to be impossible to quietly amend. Verify a trail with `sbproxy audit verify --channel security` (the default) or `--channel config`; the command reads only the file and reports the first record that does not check out. See [audit-log.md](audit-log.md).

## API traffic security

**WAF.** SBproxy ships a built-in Web Application Firewall: a curated, CRS-derived baseline of sixteen rules total, against roughly 900 rules in the OWASP Core Rule Set. [waf-options.md](waf-options.md) says what the baseline does and does not catch, and gives followable recipes for the three ways to get more coverage: a CRS-capable WAF in front, the signed rule feed, and layering the policies already in the binary.

**Auth surfaces.** Endpoints can require any of seven built-in authentication types, including API keys, JWT with JWKS, mTLS, and OIDC, plus fine-grained access control through `object_authz`. See [auth-oidc.md](auth-oidc.md), [object-authz.md](object-authz.md), and [key-management.md](key-management.md).

**Rate limiting.** Token-bucket rate limiting and the budget escalation ladder cap request rate alongside the WAF's pattern-based blocking. See [policy.md](policy.md) and [agent-budget.md](agent-budget.md).

## Model hosting

The model host starts inference processes beside a gateway that may hold cloud provider credentials, so write access to `sb.yml`, the deployment revision store, engine paths, and the artifact cache is privileged operator access. [security-model-host.md](security-model-host.md) covers the trust boundaries in full: which inputs are operator-controlled supply chain and which are untrusted request callers, who may only select a public model the deployment already exposes.

## Reporting a vulnerability

To report a security vulnerability in SBproxy, do not file a public GitHub issue; see [SECURITY.md](../SECURITY.md) for the disclosure process, PGP key, and response timelines.
