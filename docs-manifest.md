# OSS Docs Manifest (WOR-49)
*Last modified: 2026-05-03*

## Summary
- Total files: 78
- Keep: 52
- Scrub: 20
- Delete: 6

## Per-file verdict

| File | Verdict | Reason |
|------|---------|--------|
| access-log.md | keep | Core observability; pure OSS feature |
| adr-a2a-protocol-envelope.md | scrub | Contains Wave/planning codes (W1-W6, A codes); strip to keep core a2a spec |
| adr-admin-action-audit.md | scrub | Audit log schema is OSS, but dense with Wave 1-6 planning vocab and enterprise references (S3, Postgres batches, signed-log v0). Strip planning vocab, keep envelope shape |
| adr-agent-class-taxonomy.md | scrub | 31 Wave refs, mostly planning vocabulary. Core taxonomy is OSS-relevant; strip timeline refs |
| adr-agent-dcr.md | scrub | Dynamic client registration (OSS-relevant); heavy planning vocab. Strip Wave refs |
| adr-agent-registry-feed.md | scrub | Agent identity feed is OSS infrastructure. Strip Wave 2/G2.1 refs, keep spec |
| adr-audit-log-v0.md | **delete** | Exclusively about enterprise signed-batch audit log (Wave 2), S3 Object Lock, Postgres batches, KMS, HKDF daily rotation. Pure enterprise feature |
| adr-billing-hot-path-vs-async.md | scrub | Layering rule is architecture; strip enterprise rail references. Keep async layering pattern |
| adr-billing-rail-x402-mpp-mapping.md | **delete** | Exclusively x402 + MPP (commercial-only payment rails). Entire document is Wave 3 rail mapping |
| adr-bot-auth-directory.md | keep | Bot authentication is OSS feature; minimal planning vocab (8 Wave refs, mostly dates) |
| adr-capacity-rate-limits.md | scrub | Rate-limit schema is OSS; 23 planning refs. Strip timeline vocabulary |
| adr-content-negotiation-and-pricing.md | scrub | Content shape negotiation is OSS. Pricing and Wave 4 code (G4.1) are commercial; strip pricing-specific sections. Keep negotiation logic |
| adr-cross-rail-refund.md | **delete** | Exclusively about multi-rail refund/dispute model (x402, MPP, Stripe). Pure Wave 3 commercial feature |
| adr-custom-properties.md | keep | Custom headers/properties are core proxy feature; minimal planning vocab (1 ref) |
| adr-db-migration-policy.md | scrub | Schema migration is OSS concern. References Wave 1-6 timeline and enterprise features (Postgres audit log, S3). Strip timeline, keep migration pattern |
| adr-disaster-recovery-retention.md | scrub | Retention policy is relevant to any deployment. Heavy Wave refs (21); strip planning vocab |
| adr-end-to-end-idempotency.md | scrub | Idempotency across stack is OSS-relevant. 39 Wave refs and cross-rail orchestration. Strip rail-specific sections, keep idempotency-key pattern |
| adr-event-envelope.md | keep | Event envelope is core observability; minimal planning vocab (4 refs) |
| adr-evm-reorg-resistance.md | **delete** | Exclusively x402 on-chain reorg handling (Wave 3, A3.3). No OSS relevance; commercial chain settlement only |
| adr-http-ledger-protocol.md | scrub | Ledger protocol is OSS-relevant (the trait). 17 Wave refs. Strip planning timeline, keep wire spec |
| adr-json-envelope-schema.md | keep | JSON schema is core; 36 Wave refs all in context section. Strip context, keep schema |
| adr-log-schema-redaction.md | scrub | Log redaction is OSS feature. 20 Wave refs in timeline. Strip planning vocab |
| adr-metric-cardinality.md | keep | Metric cardinality management is core observability; 10 Wave refs in planning sections |
| adr-ml-agent-classifier.md | scrub | Classifier is OSS (ONNX-backed); 31 Wave refs, all timeline/planning. Strip planning vocab |
| adr-multi-rail-402-challenge.md | scrub | 402 challenge wire format appears OSS (multi-rail negotiation), but deeply tied to x402/MPP commercial rails. Strip to keep single-rail 402 baseline; mark for potential rewrite since Wave 3 focused |
| adr-observability.md | scrub | Core observability; 26 Wave refs but concentrated in timeline/roadmap. Strip roadmap, keep metrics schema |
| adr-policy-graph-projections.md | scrub | Projections (robots.txt, llms.txt, licenses.xml) are OSS; 27 Wave refs and 4 enterprise refs (PDF transform). Strip Wave/enterprise, keep projection contract |
| adr-quote-token-jws.md | scrub | Quote tokens are tied to commercial payment rails (Wave 3, A3.2). 27 Wave refs. Keep token schema as it's needed for the accept_payment policy, but strip rail-specific context |
| adr-schema-versioning.md | scrub | Schema versioning policy is OSS-relevant. 20 Wave refs, 6 enterprise refs. Strip timeline, keep versioning rules |
| adr-session-id.md | keep | Session ID is core request tracking; minimal planning vocab (1 ref) |
| adr-skyfire-kya-token.md | scrub | KYA (Know-Your-Agent) is OSS policy module. 38 Wave refs, 2 enterprise refs (attestation). Strip planning/enterprise refs |
| adr-slo-alert-taxonomy.md | keep | Observability alerting is core; 24 Wave refs but in roadmap context. Categorization is OSS-relevant |
| adr-tls-fingerprint-pipeline.md | keep | TLS fingerprinting is core security; 23 Wave refs in timeline |
| adr-user-id.md | keep | User identity is core auth; minimal planning vocab (1 ref) |
| adr-wallet-model.md | **delete** | Exclusively metered billing wallet (Wave 2, A2.1). Stripe integration, journaling for refunds/disputes. Pure enterprise commercial feature |
| adr-webhook-security.md | scrub | Webhook signature verification is OSS (for inbound webhooks). 14 Wave refs, 2 enterprise refs (Stripe webhook). Strip planning vocab and Stripe-specific sections |
| ai-crawl-control.md | scrub | The ai_crawl_control policy is partially OSS (token-based access control) and partially commercial (payment rail integration). Heavy planning vocab (9 Wave refs). Keep access-control sections; mark quote-token and rail sections for careful scrub |
| ai-gateway.md | keep | Core AI gateway feature; 200+ providers, routing, budgets, streaming. Minimal enterprise refs |
| architecture.md | keep | System architecture is OSS; 1 enterprise ref (merchant payment context) |
| audit-log.md | scrub | Audit log envelope is OSS (human-readable logs). 21 Wave refs, 3 enterprise refs (S3, Postgres, signed batches). Strip enterprise references; keep envelope schema |
| build.md | keep | Build instructions; no commercial content |
| bulk-redirects.md | keep | Feature documentation; no commercial content |
| cache-reserve.md | scrub | Cache reserve is OSS with enterprise extensions. 1 enterprise ref (S3+KMS backend). Keep OSS backends (memory, file, redis), reference trait for enterprise extension |
| codebase.md | keep | Codebase orientation; no commercial content |
| comparison.md | keep | Honest comparison with other proxies; 7 enterprise refs are context (BSL license, note). Keep as-is for transparency |
| config-stability.md | keep | Configuration stability guarantees; no commercial content |
| configuration.md | scrub | Core configuration schema is OSS. 2 enterprise refs (S3 backend, Stripe config). Strip enterprise sections, keep OSS schema |
| content-for-agents.md | scrub | AI crawler content shapes (Markdown, JSON, HTML) are OSS. 32 Wave refs, 4 enterprise refs (PDF transform, content licensing, Stripe cost tracking). Strip Wave refs and enterprise sections; keep shape negotiation |
| degradation.md | keep | Proxy degradation modes are relevant; 7 enterprise refs are merchant-context examples |
| events.md | keep | Event stream is core observability; no commercial content |
| exposed-credentials.md | keep | Secrets detection is core security; 3 enterprise refs are dashboard context |
| feature-flags.md | scrub | Feature flag mechanism is OSS; 2 enterprise refs (flag list examples). Strip enterprise flag examples |
| features.md | scrub | Feature overview is OSS. 1 enterprise ref (guardrail vendors); strip |
| kubernetes.md | keep | K8s operator and deployment are OSS; no commercial content |
| manual-testing-rails.md | scrub | Manual testing guide is heavy on commercial rails (x402, MPP, Stripe). 5 Wave refs (testing roadmap context). Could be kept as testing guide but OSS testing is minimal. Mark for potential deletion as it's primarily commercial-rail testing |
| manual.md | keep | Operator manual is OSS; no commercial content |
| metrics-stability.md | keep | Metric schema stability; no commercial content |
| observability.md | keep | Core observability guide; 15 Wave refs in roadmap. Keep |
| onnx-classifier.md | keep | ONNX classifier is OSS feature; no commercial content |
| openapi-emission.md | keep | OpenAPI spec generation is OSS; 1 enterprise ref is schema context |
| openapi-validation.md | keep | OpenAPI validation is OSS feature; no commercial content |
| operator-runbook.md | scrub | Operational runbooks are partially OSS (auth, rate limits, cache, TLS) and partially commercial (rails, wallet, audit batches, merchant merchant disputes). 88 Wave refs, 10 enterprise refs. Heavy filtering needed; extract OSS-only runbook sections or consider deletion |
| payment-rails.md | **delete** | Exclusively Wave 3 payment rails (x402, MPP, Stripe). 29 Wave refs, 7 enterprise refs. Entire document is commercial monetization platform |
| performance.md | keep | Performance tuning is OSS; no commercial content |
| prompt-injection-v2.md | keep | Security feature (guardrail); no commercial content |
| providers.md | keep | Provider support matrix is OSS; documents public integrations |
| rate-limits-and-budgets.md | scrub | Rate limiting is OSS; budgets are partially OSS (token/cost) and partially commercial. 18 Wave refs. Strip commercial budget-enforcement sections |
| README.md | keep | Top-level README; keep |
| routing-strategies.md | keep | Routing logic is OSS; no commercial content |
| rsl.md | keep | Responsible Supply License reference; 6 Wave refs in planning context. Keep |
| runbooks/synthetic-monitor.md | keep | Synthetic monitoring is OSS; no commercial content |
| scripting.md | keep | CEL/Lua/WASM scripting is OSS; no commercial content |
| threat-model.md | scrub | Threat model is relevant to any deployment. 49 Wave refs, 10 enterprise refs (merchant disputes, x402 settlement, audit log tampering). Strip enterprise threat scenarios, keep proxy threats |
| troubleshooting.md | keep | Troubleshooting guide is OSS; no commercial content |
| upgrade.md | keep | Upgrade guide documents Go->Rust cutover (ALLOWED per rule 4). No commercial content; pure migration docs |
| wasm-development.md | keep | WASM plugin development is OSS; no commercial content |
| web-bot-auth.md | keep | Bot authentication via headers is OSS; no commercial content |

## Files flagged for full rewrite

1. **adr-multi-rail-402-challenge.md** - Currently focused on Wave 3 multi-rail (x402 + MPP). OSS ships single-rail 402 only; this document needs comprehensive rewrite to document the single-rail baseline and clearly mark multi-rail as commercial-only future work.

2. **ai-crawl-control.md** - Deeply intertwined with quote-token (payment) and payment-rails logic. Document would need substantial restructuring to separate OSS access-control policy from commercial monetization features. Current structure makes this difficult.

3. **manual-testing-rails.md** - Primarily focused on commercial rail testing (x402, MPP, Stripe). OSS section (HTTP ledger) is minimal. Consider whether keeping as commercial-only runbook or deleting entirely is clearer.

4. **operator-runbook.md** - Heavily mixed OSS and enterprise. Merchant disputes, wallet settlement, audit batch DLQ, x402 reorg simulation dominate. Requires surgical extraction of OSS-only sections (auth, cache, TLS) or deletion.

## Cross-cutting issues found

1. **Wave/planning vocabulary saturation**: 35+ ADRs contain timeline references (Wave 1-6, codes like G3.1, A2.3, E6.3) that are internal planning artifacts. These add noise to OSS docs and confuse readers unfamiliar with Soap Bucket's release roadmap. Recommendation: blanket strip all Wave/code references from OSS docs on a per-file basis.

2. **Merchant/commercial context leakage**: Several docs (threat-model.md, degradation.md, comparison.md, operator-runbook.md, payment-rails.md, adr-wallet-model.md) assume a "SaaS Soap Bucket" merchant context (disputes, chargebacks, hosted ledger service, "Stripe outage pages on-call"). This vocabulary doesn't apply to OSS deployments. Recommend: strip merchant-specific examples and replace with self-hosted operator context.

3. **S3 + Postgres + KMS references**: Audit log, cache reserve, and disaster-recovery docs reference enterprise backends (S3 Object Lock, Postgres-backed non-store, KMS-wrapped keys) as primary. OSS alternatives (in-memory, filesystem) are documented but buried. Recommend: restructure to lead with OSS defaults; mark enterprise as optional extension.

4. **Quote-token and payment-rail entanglement**: Documents on multi-rail 402, quote tokens, and content negotiation are architecturally sound but tightly coupled to commercial payment rail implementations (x402 EIP-3009, MPP Stripe, Stripe dispute resolution). The *token schema itself* (JWS, nonce, TTL) is OSS-relevant (used by accept_payment policy), but all *usage context* is commercial. Current docs don't separate these layers clearly.

5. **Provider count and stale numbers**: `comparison.md` states "20+ native providers" and "200+ models"; `providers.md` should verify current count against `crates/sbproxy-ai/src/providers/`. If count has drifted, this will fail code-fit check.

6. **Schema lock (v1.0.x vs schema-v1) consistency**: Several ADRs and docs reference "schema-v1" (config schema version) alongside "v1.0.0" (binary version). Need to verify that references in adr-schema-versioning.md, configuration.md, and upgrade.md correctly distinguish the two; confusion here could break OSS config migrations.

## Recommended deletion order
1. adr-audit-log-v0.md
2. adr-billing-rail-x402-mpp-mapping.md
3. adr-cross-rail-refund.md
4. adr-evm-reorg-resistance.md
5. adr-wallet-model.md
6. payment-rails.md

**Rationale**: These six documents are entirely about Wave 2-3 commercial features (metered billing, wallet settlement, payment rails) with zero OSS relevance. Deletion unblocks OSS docs from commercial roadmap context.

## Recommended scrub order (by impact)
1. adr-admin-action-audit.md - Heavy Wave refs (55); strip timeline, keep envelope schema
2. operator-runbook.md - Heavy mixed (88 Wave, 10 enterprise); extract OSS sections or delete
3. adr-end-to-end-idempotency.md - Moderate Wave (39); idempotency pattern is OSS-relevant
4. adr-multi-rail-402-challenge.md - Moderate Wave (45); rewrite to focus on single-rail baseline
5. threat-model.md - Heavy enterprise context (10 refs); strip merchant/x402/audit tampering scenarios
6. All other ADRs with Wave refs - bulk strip Wave/code references while preserving decision/consequence text

## Files requiring code verification (code-fit check)

Before release, audit these against current Rust code:

- providers.md: Verify "20 native providers" and "200+ models" counts against `crates/sbproxy-ai/src/providers/`
- configuration.md: Sample config blocks against current schema in `crates/sbproxy-config/`
- build.md: Verify Cargo commands and feature flags against Cargo.toml
- examples: Spot-check 3-5 example configs in `examples/` directory match documented YAML syntax
- manual.md and scripting.md: Verify CEL/Lua policy examples execute against current binary

