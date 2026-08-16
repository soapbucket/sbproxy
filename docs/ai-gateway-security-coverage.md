# AI gateway security coverage

*Last modified: 2026-08-16*

What the gateway enforces against the OWASP LLM Top 10 (2026 edition,
published 2026-08-03), and the gateway-layer controls no published list
covers. Coverage levels are literal: **full** means the control is
enforced in the traffic path with tests, **partial** means enforced with
named gaps, **out of scope** means the risk lives in the application or
provider and a proxy cannot own it.

## OWASP LLM Top 10 (2026) mapping

| # | Risk | Gateway control | Coverage |
|---|---|---|---|
| LLM01 | Prompt Injection | Built-in and external input guardrails with streaming verdict parity; two-pass RAG screening; multipart requests are refused on JSON surfaces so a Content-Type cannot relabel past body inspection. The default detector is a substring heuristic; no injection model ships. | partial |
| LLM02 | Sensitive Information Disclosure | Secret-regex plus field-key redaction on structured logs, access log lines, and request-event sinks; audit events carry digests of prompt-linked content, never the content; PII redaction policies on request/response bodies. DLP scans URI and headers only and never masks. | partial |
| LLM03 | Excessive Agency | Tool scoping, entitlements, and per-credential model blocks are enforced at the MCP seam (see the MCP gateway docs); the model-call seam contributes credential containment and per-agent budgets. | partial |
| LLM04 | Supply Chain | Every outbound destination the gateway reaches, across every wired egress purpose (AI providers, the dual-LLM quarantine judge, OpenAPI-backed MCP tools, token exchange, webhooks, usage sinks, model and engine artifact downloads, and extension bundle hooks), passes a default-deny, DNS-pinned egress authorizer and is inventoried with its authorization status. Weights: none ship; the model runtime pins artifacts by SHA-256 and verifies signatures. | partial |
| LLM05 | Model & Data Poisoning | Out of scope for hosted providers: a proxy cannot attest what a vendor trained on. | out of scope |
| LLM06 | Misinformation | Out of scope as a correctness property. Shadow evaluation and judge-model routing exist but are not misinformation controls and are not claimed as such. | out of scope |
| LLM07 | Unbounded Consumption | Budgets across seven scopes with block, log, or downgrade; per-agent token consumption charged on buffered and streamed responses; tenant-keyed request budgets on the serving path. Per-instance counters multiply the cap by replica count unless a shared store is configured, and a store outage degrades to per-instance enforcement (visible on `sbproxy_budget_share_fail_open_total`). GET and multipart surfaces do not debit token budgets. | partial |
| LLM08 | Hidden Context Exposure | System prompts and injected RAG context are not echoed through error paths; cache keys carry no prompt, tenant, subject, or model text; prompt-linked audit lines carry salted digests. | partial |
| LLM09 | Vector & Embedding Weaknesses | RAG pipeline runs input guardrails before embedding (a rejected prompt causes no embedding egress) and again over the augmented request, so retrieved text gets the same screening as user text; vector search is tenant-scoped. | full |
| LLM10 | Improper Output Handling | Output guardrails with schema validation; streaming blocks withhold the violating chunk onward. Limit: headers may already be sent, so a blocked stream ends empty rather than re-statusing. | partial |

## Gateway-layer controls (no published list covers these)

The lists above describe risks to an application. A proxy in the AI
traffic path has failure modes of its own. This is the set we hold
ourselves to; it is written so that an operator of any gateway can apply
it.

1. **Credential custody.** Callers authenticate to the gateway; the
   gateway holds provider credentials. Inbound keys are peppered hashes,
   upstream credentials sit in an AEAD envelope, and no log line,
   metric label, or cache key carries either.
2. **Cross-tenant boundaries.** Cache keys bind tenant and credential
   scope with domain-separated digests; request budgets key by tenant;
   a panicking tenant policy denies that request instead of crashing the
   process. Co-tenancy is still soft isolation; run one process per
   trust boundary when tenants are mutually untrusting.
3. **Routing decisions leave a record.** Every route, retry, and
   fallback is a decision event with its trigger and result.
4. **Denial of wallet is enforcement, not observation.** Budgets deny at
   the cap. Degraded enforcement (store outage, replica-local counters)
   is alertable, because fail-open is a posture only when it is visible.
5. **Streaming parity.** A guardrail verdict on a streamed response must
   equal the verdict on the same bytes buffered. Modes that cannot keep
   that promise are refused at config compile, not approximated.
6. **Telemetry does not leak the traffic it audits.** Prompt-linked
   audit carries digests and lengths; sinks run secret and field-key
   redaction; verbatim content is an explicit opt-in.
7. **Egress is inventoried.** Every outbound destination the gateway
   reaches, across every wired egress purpose, is recorded with its
   authorization status (allowed, denied, or ungated) and last-seen
   time, and is readable from the admin API. Traffic that never
   crosses the gateway is invisible to it; the deployment recipe for
   making the gateway the only path is part of the control, not an
   afterthought.
8. **Change control is tamper-evident.** Security, config, key, and
   admin-action records each append, when the operator opts that
   channel in, to their own hash-chained, signed file that verifies
   offline; a chain that cannot open fails the boot; an append failure
   is a non-ok outcome on the emit metric, so a quiet alert means an
   intact trail rather than a broken sensor.

## Signals

| Control | Log target | Metric |
|---|---|---|
| Multipart surface refusal | `security_audit` (policy_denied via events sink) | `sbproxy_audit_emit_duration_seconds{channel="security"}` |
| Budget fail-open | `sbproxy::budget` WARN on transition | `sbproxy_budget_share_fail_open_total{op}`, `sbproxy_budget_share_unavailable` |
| Tenant throttle | decision events | `sbproxy_rate_limit_total{workspace}`, `sbproxy_rate_limit_decisions_total{policy}` |
| Policy panic | `security_audit` ERROR | `sbproxy_policy_panic_total{policy}` |
| Egress sightings | `sbproxy::egress` WARN on refusal | `sbproxy_egress_refused_total`, inventory at `GET /api/egress` |
| Audit chain health | `security_audit` / `config_audit` / `key_audit` / `sbproxy::admin::audit` | `sbproxy_audit_emit_duration_seconds{channel, outcome!="ok"}` |
