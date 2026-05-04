# Threat model
*Last modified: 2026-05-03*

This is the security threat model for the SBproxy AI Governance Gateway. Each row of the STRIDE table names a threat, the asset it targets, the mitigation in code or configuration, and the ADR that motivates the design.

Companion documents:

- `docs/operator-runbook.md` for the on-call procedures that respond when a mitigation fails in production.
- `docs/architecture.md` for the request-pipeline overview.
- The ADRs cited in the table for the design rationale behind each mitigation.

For the AI-discoverable capability catalog, see `docs/llms.txt`.

## Scope

In scope:

- The substrate pillars: tier-aware AI crawl pricing, the HTTP ledger client, the `agent_class` resolver, reverse-DNS verification, dynamic Web Bot Auth directory refresh, per-agent metric labels, structured logs with redaction, the OpenTelemetry tracer, the admin-action audit envelope, and the outbound webhook framework with the inbound verifier scaffold.
- The trust boundaries those pillars cross.
- The keys and secrets the substrate handles.

Out of scope:

- Payment-rail webhook handling and merchant settlement scenarios. These live in the commercial distribution.
- Wallet, agent registry, and signed-batch audit-log threat surface beyond the OSS structured-log sink.
- Identity and fingerprint privacy.
- SSO and license-leak detection.

## Trust boundaries

The substrate crosses six trust boundaries on a single inbound 402 request. Every row in the STRIDE table sits on at least one of these.

1. **Caller to proxy.** The inbound request from any client; the first surface where User-Agent claims, request signatures, and IPs are evaluated.
2. **Proxy to ledger.** Outbound HTTP from the proxy to the configured ledger endpoint, signed with the ledger HMAC key per ADR `adr-http-ledger-protocol.md`.
3. **Proxy to bot-auth directory.** Outbound HTTPS to a vendor's `/.well-known/http-message-signatures-directory` URL (resolved from `Signature-Agent` request header) per ADR `adr-bot-auth-directory.md`.
4. **Proxy to OTLP exporter.** Outbound gRPC to the configured collector endpoint, optionally over mTLS, per ADR `adr-observability.md`.
5. **Audit emitter to storage.** The audit emitter is the structured-log audit sink per ADR `adr-admin-action-audit.md`.
6. **Outbound webhook to customer.** Outbound HTTPS to a customer-supplied URL, signed per ADR `adr-webhook-security.md`.

## STRIDE table

| Category | Asset | Threat | Mitigation | ADR / code reference |
|---|---|---|---|---|
| Spoofing | `agent_class` | Forged User-Agent header claims to be GPTBot to access a discounted tier or a free-preview window. | UA match alone is non-authoritative; resolver chain demands reverse-DNS verify or Web Bot Auth keyid before assigning a privileged `agent_id`. Catalog distinguishes "claim-only" agents from verified ones via `verified: bool`. | `adr-agent-class-taxonomy.md`; `crates/sbproxy-modules/src/policy/agent_class.rs` |
| Spoofing | Ledger redeem request | Attacker posing as the proxy submits a forged redeem to the ledger to debit a victim agent or claim free quota. | Every ledger request is HMAC-SHA256 signed with the per-deployment ledger key; the ledger rejects unsigned and bad-MAC requests. The HMAC key never leaves the proxy's secret mount. | `adr-http-ledger-protocol.md`; `crates/sbproxy-modules/src/policy/ai_crawl.rs` |
| Spoofing | Outbound webhook | Attacker posts forged events to a customer-supplied URL claiming to be sbproxy. | Every outbound delivery is Ed25519-signed per ADR `adr-webhook-security.md`; the customer endpoint verifies the signature against the published public key. Per-tenant subscription means the signing surface is opt-in. | `adr-webhook-security.md`; `crates/sbproxy-observe/src/notify.rs` |
| Spoofing | Bot-auth directory anchor | Attacker on the network serves a malicious directory at the vendor's well-known URL. | HTTPS-only enforcement (no plain HTTP fetch); directory self-signature verification against the configured anchor PEM; HTTPS certificate verification against the system trust store. Directory cache holds the previously verified copy across transient failures. | `adr-bot-auth-directory.md`; `crates/sbproxy-modules/src/auth/bot_auth_directory.rs` |
| Tampering | Bot-auth directory cache | Attacker modifies the in-memory directory cache via a memory-safety bug to insert a bogus key. | Pure-Rust safe-code module; cache entries are immutable once verified; refresh atomically replaces the cache rather than mutating it. Negative caching prevents a single failed refresh from collapsing the cache to "trust anything." | `adr-bot-auth-directory.md`; `crates/sbproxy-modules/src/auth/bot_auth_directory.rs` |
| Tampering | Bot-auth directory in transit | Attacker tampers with directory bytes between the vendor and the proxy. | TLS terminates at the directory host; the directory's self-signature, verified against the configured anchor, makes any in-transit modification visible. Fail closed if the self-signature does not verify (the cache holds the prior verified copy until refresh succeeds). | `adr-bot-auth-directory.md`; `crates/sbproxy-modules/src/auth/bot_auth_directory.rs` |
| Repudiation | Admin-action audit trail | Operator denies having performed an action recorded in the audit log. | Every state-mutating endpoint emits an `AdminAuditEvent` with actor, action, target, before/after diff, reason, request_id, trace_id, ip, and user_agent. The audit sink emits through the same redaction-aware log pipeline as the access log. | `adr-admin-action-audit.md`; `crates/sbproxy-observe/src/audit.rs` |
| Repudiation | Per-agent attribution | A vendor disputes a per-agent revenue or crawl-count rollup. | Per-agent metric labels (`agent_id`, `agent_class`, `agent_vendor`, `payment_rail`, `content_shape`) are bounded by the cardinality budget so attribution series are reproducible from the access log. Exemplars on histograms link back to the trace that motivated each measurement. | `adr-metric-cardinality.md`, `adr-observability.md`; `crates/sbproxy-observe/src/agent_labels.rs` |
| Information disclosure | Authorization header in logs | A logged request line leaks an upstream API key or bearer token to a log sink. | Redaction middleware applies a denylist (Authorization, ledger HMAC, KYA tokens, raw prompt body, raw envelope) before any log record reaches a sink. Per-sink override allows stricter redaction on external sinks (customer Loki, third-party trace exporter) than on internal sinks. | `adr-log-schema-redaction.md`; `crates/sbproxy-observe/src/redact.rs` |
| Information disclosure | OTel trace export | A traced request leaks a redaction-class field as a span attribute to the OTLP collector. | The redaction pipeline runs on span attributes before export, with the same denylist as the structured-log sinks; per-sink overrides apply. The OTLP exporter is opt-in and disabled by default. | `adr-observability.md`, `adr-log-schema-redaction.md`; `e2e/tests/redaction.rs` |
| Information disclosure | OTLP exporter in transit | Attacker on the network reads spans containing trace context that names protected endpoints. | OTLP exporter ships with optional mTLS; the operator runbook recommends mTLS in production. The default is "exporter off"; an operator who enables it without TLS owns the disclosure. | `adr-observability.md`; `crates/sbproxy-observe/src/telemetry.rs` |
| Information disclosure | Cardinality demotion | A label-value explosion fingerprints a tenant by demotion patterns to the `__other__` bucket. | The cardinality limiter applies the cap per metric (not globally) and the demotion is to a fixed `__other__` sentinel that does not encode the demoted value. | `adr-metric-cardinality.md`; `crates/sbproxy-observe/src/cardinality.rs` |
| Denial of service | Bot-auth directory refresh | Attacker triggers high-frequency refresh of a malicious or unreachable directory, exhausting outbound connections. | Cache TTL bounds refresh frequency; negative caching bounds repeat fetches of an unreachable host; HTTPS-only blocks plain-HTTP redirect amplification; directory URL is allowlisted via the agent-class catalog so an arbitrary URL cannot be requested. | `adr-bot-auth-directory.md`; `crates/sbproxy-modules/src/auth/bot_auth_directory.rs` |
| Denial of service | Ledger client | Attacker drives the ledger endpoint into outage to cascade backpressure into the proxy request path. | Circuit breaker on the ledger client opens on sustained failure; the policy honours the configured fail-mode (closed by default) so the request path does not block on a dead ledger. Exponential-backoff retries bound retry storm. | `adr-http-ledger-protocol.md`; `crates/sbproxy-modules/src/policy/ai_crawl.rs` |
| Denial of service | Outbound webhook delivery | A misbehaving customer endpoint absorbs deliveries and exhausts the proxy's outbound queue. | Per-tenant subscription bounds the per-tenant queue depth; exponential-backoff retries cap retry frequency; deadletter queue absorbs sustained failure with a configurable capacity (`proxy.notify.deadletter_capacity`). The runbook covers deadletter triage. | `adr-webhook-security.md`; `crates/sbproxy-observe/src/notify.rs` |
| Denial of service | Metrics cardinality | An attacker generates synthetic per-agent traffic to inflate the cardinality of `sbproxy_requests_total` and OOM the metric scrape. | Per-metric, per-label cap with `__other__` demotion. Cardinality budget regression test gates PRs. The runbook flags sustained over-cap demotion as a re-budget signal, not a silence target. | `adr-metric-cardinality.md`; `crates/sbproxy-observe/src/cardinality.rs` |
| Denial of service | Per-tenant capacity exhaustion | A misbehaving tenant consumes the workspace's burst budget so a co-tenant on the same proxy sees 429s. | Per-(workspace, route) inner bucket caps any single route at 100 rps default; the workspace-level outer bucket is per-tenant, not shared; cardinality budget on the rate-limit metric prevents a hot tenant from exhausting the Prometheus series count. | `adr-capacity-rate-limits.md`, `adr-metric-cardinality.md`; `crates/sbproxy-modules/src/middleware/rate_limit.rs` |
| Elevation of privilege | Outbound webhook replay | Attacker replays a captured signed delivery to a customer endpoint to re-trigger an action. | Each outbound delivery carries a monotonically increasing nonce and a delivery timestamp; customer endpoints reject deliveries outside a configurable replay window. | `adr-webhook-security.md`; `crates/sbproxy-observe/src/notify.rs` |
| Elevation of privilege | Inbound webhook replay | Attacker replays a captured signed event to the inbound verifier. | Inbound verifier scaffold ships replay-protection cache (Redis-backed in production, in-memory for tests) and idempotency-key dedup. | `adr-webhook-security.md`; `crates/sbproxy-modules/src/auth/bot_auth.rs` |
| Elevation of privilege | Bot-auth keyid reuse | Attacker reuses a captured Web Bot Auth signature outside its valid context (different request, different proxy) to claim a vendor's `agent_id`. | Verifier checks the message-signature components scoped to the current request (`@authority`, `@target-uri`, `@method`, signing time, expiry) per `draft-meunier-http-message-signatures-directory-05`; signatures outside their valid window are rejected. | `adr-bot-auth-directory.md`; `crates/sbproxy-modules/src/auth/bot_auth.rs` |
| Elevation of privilege | Log injection | A request field controlled by the caller carries log-formatting characters or fake JSON that, when written to the log sink, fakes an admin-action audit entry. | Structured logs use a typed JSON-line schema; field values are escaped as JSON strings, not interpolated; the audit envelope is a typed Rust struct (`AdminAuditEvent`) emitted via `serde_json`, so a caller-controlled payload cannot impersonate the audit-log shape. | `adr-log-schema-redaction.md`, `adr-admin-action-audit.md`; `crates/sbproxy-observe/src/logging.rs` |
| Elevation of privilege | Redaction bypass | A field name is added in a follow-up PR without the corresponding redaction rule, leaking a secret to the next release. | The redaction policy is denylist-driven against a documented list (`adr-log-schema-redaction.md`); regression tests assert the contract on every PR; the operator runbook calls out rotation procedure for the secret types currently covered (ledger HMAC, outbound webhook signing key, bot-auth anchor). | `adr-log-schema-redaction.md`; `e2e/tests/redaction.rs` |

## Refresh checklist

Future revisions of this document should:

1. **Re-read** these ADRs and confirm no row above is invalidated: `adr-agent-class-taxonomy.md`, `adr-http-ledger-protocol.md`, `adr-bot-auth-directory.md`, `adr-observability.md`, `adr-log-schema-redaction.md`, `adr-admin-action-audit.md`, `adr-webhook-security.md`, `adr-metric-cardinality.md`, `adr-schema-versioning.md`, `adr-slo-alert-taxonomy.md`.
2. **Confirm** the redaction denylist still covers every secret type added since the last refresh.
3. **Update** the operator runbook secret-and-key inventory in parallel; the two documents share the rotation cadence and compromise procedure for each new key.
4. **Cross-check** every row against `docs/operator-runbook.md` so the mitigation in this table maps to a runbook section the on-call can act on.
