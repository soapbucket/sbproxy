# Wave History
*Last modified: 2026-05-03*

A retroactive narrative of the seven roadmap waves that built SBproxy v1.0. Each section describes what shipped in plain language, points at the receipts (commits, file paths, test counts), and notes the dates the work merged to `main`.

For the code conventions used in commit subjects (G, A, R, B, S, Q, T, E prefixes), see [glossary.md](glossary.md).

## Wave 1: AI governance substrate

**Shipped:** Tier-aware Pay Per Crawl pricing, HTTP ledger redemption, typed agent class on every request, dynamic Web Bot Auth directory, OpenTelemetry tracing, structured access and audit logs, outbound webhook framework, `/healthz` and `/readyz` endpoints, Grafana dashboards, Prometheus alerts, the operator runbook scaffold, and the STRIDE threat model v1.

**Buyer-facing language:** SBproxy now knows what kind of agent is asking, charges them the right price for what they want, and ships the dashboards and runbooks an operator needs to keep it healthy.

**Dates:** Substrate landed late April 2026. The 2.1.0 release candidate was tagged on 2026-04-30 (CHANGELOG `[2.1.0-rc.1] - 2026-04-30`).

**Receipts:**
- Substrate ADRs: `docs/adr-http-ledger-protocol.md`, `docs/adr-agent-class-taxonomy.md`, `docs/adr-bot-auth-directory.md`, `docs/adr-observability.md`, `docs/adr-log-schema-redaction.md`, `docs/adr-webhook-security.md`, `docs/adr-metric-cardinality.md`, `docs/adr-slo-alert-taxonomy.md`.
- Tiered pricing + HTTP ledger: commit `2af6119` in `crates/sbproxy-modules/src/policy/ai_crawl.rs`.
- Agent class on context: commit `7299ee8` in `crates/sbproxy-core` (exposed to CEL, Lua, JS, WASM as `request.agent`).
- Reverse-DNS verification: commit `c4a6d92` in `crates/sbproxy-security/src/agent_verify.rs` (GPTBot, ClaudeBot, PerplexityBot, GoogleBot, BingBot, DuckDuckBot, AppleBot tables).
- Per-agent metric labels: commit `02f93bf`. Cardinality budget enforced by `.github/workflows/observability-budgets.yml`.
- Dynamic bot-auth directory: commit `19d1edb` (HTTPS-only fetch + JWKS verification + TTL cache).
- OTel + W3C TraceContext + exemplars: commit `bffb6ee` in `crates/sbproxy-observe`.
- Health endpoints: commit `4fe7557` (`/healthz`, `/readyz` with per-pillar dependency state).
- Outbound webhook framework: commit `15b4b7d` (HMAC-SHA256, key rotation, deadletter, per-tenant subscriptions).
- Reference observability stack: `examples/00-observability-stack/` (Compose: Prometheus, Grafana, Tempo, Loki, OTel collector).
- Doc CI runner: `scripts/docs-ci.sh` plus `.github/workflows/docs-ci.yml`.
- Synthetic-monitor harness: `sbproxy-bench/harness/synthetic/` plus `.github/workflows/synthetic-nightly.yml`.

## Wave 2: Billing foundation

**Shipped:** First production payment rail (Stripe / MPP path), wallet ledger backing, agent registry intake, signed-batch audit log v0, per-tenant rate-limit middleware with RFC 9239 headers, agent-aware tier resolution (`Tier.agent_id`), and the hot-path-vs-async-path layering rule that keeps billing latency-critical code synchronous.

**Buyer-facing language:** Operators can now bill agents through Stripe, with a per-tenant rate-limit ceiling that escalates from soft to throttle to auto-suspend, and a signed audit batch the compliance team can verify.

**Dates:** Wave 2 landed early May 2026. The 2.2.0 release candidate was tagged on 2026-05-01 (CHANGELOG `[2.2.0-rc.1] - 2026-05-01`).

**Receipts:**
- Substrate ADRs: `docs/adr-schema-versioning.md` (A1.8 amendment renaming `BillingProvider` to `BillingRail`), `docs/adr-billing-hot-path-vs-async.md`, `docs/adr-disaster-recovery-retention.md`, `docs/adr-capacity-rate-limits.md`, `docs/adr-db-migration-policy.md`.
- `Tier.agent_id` selector + agent-aware tier resolvers (`resolve_price_for(path, agent_id)`, `matched_tier_for(path, agent_id)`): part of the Wave 1 follow-up batch in `crates/sbproxy-modules/src/policy/ai_crawl.rs`.
- Per-tenant rate-limit middleware (R2.3): cardinality-bounded `sbproxy_rate_limit_total{tenant,route,result}` counter, soft / throttle / auto-suspend / manual-review escalation tiers.
- Hot-path / async-path layering invariant: enforced in CI by `scripts/check-crate-graph.sh` (commit `e52bea2`).
- Cargo-chef Dockerfile rewrite: commit `9cae84a`. Cold image build dropped from ~12 min to ~3.5-4 min.
- New OSS docs: `docs/rate-limits-and-budgets.md`, plus Wave 2 entries in `docs/operator-runbook.md` and `docs/threat-model.md`.
- Reference deployment: `examples/24-ai-crawl-tiered/`.
- Stripe SK redaction: `sk_live_*`, `sk_test_*`, `rk_live_*`, `rk_test_*`, `pk_live_*`, `pk_test_*` patterns redacted from access, error, and audit log sinks (Q1.9 regression).

## Wave 3: Multi-rail payments

**Shipped:** x402 plus MPP negotiation in a single 402 challenge, per-shape pricing matrix, signed quote-token JWS with replay protection, end-to-end idempotency keys, EVM reorg-aware two-phase settlement, clock-skew monitor with `/readyz` integration, JWKS endpoint at `/.well-known/sbproxy/quote-keys.json`, and a four-example rail walkthrough (`30-rail-x402-base-sepolia` through `33-quote-token-replay-jwks`).

**Buyer-facing language:** Agents now choose between stablecoin-on-chain (x402 v2) and card-on-Stripe (MPP) in one round trip. The proxy signs each quote so an agent cannot replay a stale price, and the on-chain path is reorg-aware so a settlement that disappears in a re-org gets re-charged correctly.

**Dates:** Wave 3 ADRs landed mid-April 2026; wave-closing examples + manual-testing-rails doc landed end of April 2026.

**Receipts:**
- Wave 3 substrate ADRs: `docs/adr-billing-rail-x402-mpp-mapping.md`, `docs/adr-multi-rail-402-challenge.md`, `docs/adr-quote-token-jws.md`.
- Wave 3 cross-cutting ADRs: `docs/adr-end-to-end-idempotency.md`, `docs/adr-evm-reorg-resistance.md`, `docs/adr-time-sync-requirements.md`.
- Multi-rail 402 challenge emission (G3.4): commit `23cc5e1` in `crates/sbproxy-modules/src/policy/ai_crawl.rs`.
- Per-shape pricing threading (G3.5): commit `379a4fe`. `ContentShape` flows end-to-end so a markdown request and an HTML request resolve to different tiers and emit different rail entries.
- Quote-token JWS signer + verifier + nonce store (G3.6): commit `4884ffb`.
- `Accept-Payment` header parser (R3.1): commit `71df7c4`.
- Idempotency cache with cached-retry semantics (R3.2): commit `0c344b8`.
- Clock-skew monitor + `/readyz` probe (R3.3): commit `93b15cb`.
- JWKS publication endpoint: commit `0bb1758` (admin route, `/.well-known/sbproxy/quote-keys.json`).
- Operator docs: `docs/payment-rails.md`, `docs/manual-testing-rails.md`.
- Examples: `examples/30-rail-x402-base-sepolia/` (mock facilitator + Base Sepolia opt-in), `examples/31-rail-mpp-stripe-test/` (Stripe test mode), `examples/32-multi-rail-accept-payment/` (x402 + MPP negotiation), `examples/33-quote-token-replay-jwks/` (JWKS endpoint + replay protection). Helper script: `examples/sign-x402.sh`.

## Wave 4: Content for agents

**Shipped:** Two-pass `Accept` content negotiation, per-shape pricing matrix, JSON envelope schema for agent-facing responses, citation-block and boilerplate-stripping transforms, well-known projection routes for `robots.txt`, `llms.txt`, RSL `licenses.xml`, TDMRep `tdmrep.json`, the Content-Signal response header, the `aipref` request-side preference signal, and the `x-markdown-tokens` response header.

**Buyer-facing language:** SBproxy now serves the right shape of an article (Markdown for an agent, HTML for a browser) at the right price, surfaces a token-count header so agents can size their context window, and exposes the publisher's licence terms at standardised URLs that crawlers already know how to read.

**Dates:** Wave 4 substrate landed end of April through early May 2026. Day-6 close-out (Content-Signal + `token_bytes_ratio` overrides + projection data-plane routes + `aipref`) merged 2026-05-01.

**Receipts:**
- Substrate ADRs: `docs/adr-content-negotiation-and-pricing.md` (G4.1), `docs/adr-policy-graph-projections.md` (A4.1), `docs/adr-json-envelope-schema.md` (A4.2).
- `RequestContext` substrate (G4.2 - G4.4): commit `df155da`. New fields, refactored MarkdownProjection.
- Content-negotiate action with two-pass `Accept` resolution (G4.2): commit `6e2670e`.
- JSON envelope transform v1 (G4.4): commit `2d05409`.
- Citation-block transform (G4.10 part 1): commit `da38cba`.
- Boilerplate-stripping transform (G4.10 part 2): commit `4d232ed` (with `stripped_bytes` metric).
- Policy-graph projections (G4.5 - G4.8): commit `1a40698`. Adds `robots.txt`, `llms.txt`, RSL `licenses.xml`, TDMRep `tdmrep.json`, ArcSwap cache, CLI `render` subcommand, AuditAction amendment.
- `aipref` preference parser (G4.9): commit `e193ded`.
- Content-Signal response header (G4.5 closeout): commit `f28d3d2`.
- Per-origin `token_bytes_ratio` override (A4.2 follow-up): commit `6529872`.
- New OSS docs: `docs/content-for-agents.md` (G4.12), `docs/rsl.md` (S4.1).
- Operator runbook playbooks (S4.4): shape-rollout and licensing-edit playbooks.
- Examples: `examples/17-markdown-for-agents/`, `examples/18-rsl-licensing/`, `examples/19-robots-llms-txt/`.
- Test footprint: Q4.1 - Q4.14 cover content negotiation, envelope, Content-Signal, projections, RSL / TDMRep fixtures, boilerplate, fuzz, bench, and cross-pillar.

## Wave 5: Identity differentiator

**Shipped:** RFC 8693 outbound credential resolver, Vault-backed Personal Access Tokens, stored OAuth grants under one delegation-aware interface, JA3 / JA4 / JA4H TLS fingerprinting, headless-browser detection, Skyfire KYA token verification, ML agent classifier hook surface, header-mutating CEL transform, `features.*` to `proxy.extensions.*` config migration, and a SIGHUP re-bootstrap handler.

**Buyer-facing language:** SBproxy now exchanges an inbound identity for an upstream credential the way a real auth gateway does, fingerprints the TLS handshake to flag bots that lie about being browsers, and reloads its config on SIGHUP without dropping connections.

**Dates:** Wave 5 architect ADRs landed mid-April 2026. Day-3 through day-6 implementation merged 2026-05-01 through 2026-05-02.

**Receipts:**
- Substrate ADRs: `docs/adr-skyfire-kya-token.md` (G5.1), `docs/adr-tls-fingerprint-pipeline.md` (A5.1), `docs/adr-ml-agent-classifier.md` (A5.2).
- KYA verifier substrate: commit `ed7e72a` (adds `AgentIdSource::Kya` resolver step).
- JA3 / JA4 / JA4H ClientHello fingerprinting (G5.3 / A5.1): commit `0993d7e` in `crates/sbproxy-tls/`.
- Headless detection (G5.4): commit `eecc45c` (security crate, with CEL / Lua TLS bindings in `crates/sbproxy-extension/`).
- ML classifier types (G5.5): commit `b1bd0aa` (`MlClass`, `MlClassification`, `G1.4` ML override).
- Identity / ML / anomaly hook trait surfaces (day-4 substrate): commit `3b9cc06`.
- Async hooks for KYA JWKS fetch: commit `43581db`.
- Day-5 batch (config + boot + CEL + harness): merge `966652e`. Adds `auth.type=kya` config, exposes `request.kya` and `request.ml_classification` to CEL / Lua / JS, ships the cel-script transform module, and trusts loopback for TLS fingerprint sidecar headers in the e2e harness.
- Day-6 batch: merge `85e7cda`. Header-mutating CEL transform, `features.*` to `proxy.extensions[...]` migration, TLS fingerprint config threaded onto `CompiledPipeline`, SIGHUP re-bootstrap handler.
- Test footprint: Q5.x e2e suite (TLS fingerprint capture, headless detection, KYA token round trip, ML classification override).
<!-- TODO: verify Wave 5 enterprise outbound-credential-resolver crate path against the OSS surface. -->

## Wave 6: Operational substrate

**Shipped:** Hash-chained Merkle audit log v1, access log v1 schema, CAP token verifier, revenue rollups, compliance crate scaffold, `sbproxy-audit-migrate` and `sbproxy-evidence-verify` CLIs, Open Licensing Protocol (OLP) issuer wiring, Crawler Authorization Protocol (CAP) issuer.

**Buyer-facing language:** Every request now lands in a tamper-evident audit log a compliance team can verify with a single CLI, and publishers can issue per-crawler licence and capability tokens without owning a billing pipeline.

**Dates:** Wave 6 shipped to `origin/main` on 2026-05-02. This wave closes the public commitment that all six waves are visible evidence on `main`.

**Receipts (OSS):**
- CAP token verifier: `crates/sbproxy-modules/src/auth/cap.rs` (R6.1).
- Access log v1: `crates/sbproxy-observe/src/access_log.rs` (G6.2). Schema and builder, with Wave 6 fields for quote / licence / CAP token IDs and on-chain settlement hash.
- Dispatch wiring: `crates/sbproxy-core/src/{server.rs,dispatch.rs}` plus end-to-end test at `e2e/tests/cap_verifier.rs`.
- OSS commit set: `b550cde` (CAP verifier), `5cfcdf1` (dispatch wiring + e2e), `623950d` (access log builder), `964ecfc` (fmt). Merge: `f4a7cdb`.
- ADRs: `docs/adr-licensing-olp.md` (A6.1, Open Licensing Protocol four-step flow), `docs/adr-licensing-cap.md` (A6.2, CAP token format), `docs/adr-audit-log-v0.md` (Wave 5 baseline that v1 builds on). <!-- TODO: confirm A6.1 / A6.2 ADR file paths land in OSS docs/ rather than enterprise repo. -->
- OSS implementation footprint: 4 commits, ~1,770 lines (CAP verifier + access log + dispatch wiring + e2e).

**Open follow-ups (load-bearing, deferred deliberately):**
- A6.3 IAB CoMP marketplace endpoints (deferred per ADR; original scaffold removed during the licensing crate cut).
- OLP discovery handler (served from OSS projection cache, not yet wired in licensing crate).
- OLP `payment` acquisition method (delegates to existing Wave 3 multi-rail; not yet glued).
- CAP audit-table writes, per-agent-class policy, token renewal, anonymous-cap path.

## Wave 7: Bonus enterprise scope

**Shipped:** Employee-bound agent identity (with SCIM webhook receiver and per-employee chargeback), Agent-to-Agent (A2A) protocol envelope with depth cap and cycle detection, license-leak guardrail (corpus + outbound transform), Lightning rail (CLN production adapter, LND stub, spot-rate oracle).

**Buyer-facing language:** A laptop-issued employee identity now flows all the way through to a per-employee invoice line, agents can call other agents through SBproxy without producing infinite call graphs, the proxy refuses to leak licensed content downstream even when a model regurgitates it, and Bitcoin Lightning joins x402 and MPP as a third payment rail.

**Dates:** Wave 7 shipped 2026-05-02 (same multi-agent session as Wave 6). Wave 7 is bonus scope beyond the public "all six waves shipped" commitment.

**Receipts (OSS):**
- A2A protocol envelope: `crates/sbproxy-modules/src/auth/a2a/` (Anthropic and Google parsers), `crates/sbproxy-modules/src/policy/a2a.rs` (depth cap + cycle detection), `e2e/tests/a2a_policy_e2e.rs` (Q7.3 conformance test).
- A2A merge: `0fcb65c` (G7.3 + Q7.3); ~1,953 lines added.
- A2A ADR: `docs/adr-a2a-protocol-envelope.md` (A7.2).
- Lightning rail enum on the OSS side: `Rail::Lightning` variant added in `crates/sbproxy-modules/src/policy/ai_crawl.rs` (followup #6, commit `358a279`, merge `7d71241`). Production node adapter ships enterprise-side under cargo feature `lightning-cln`.
- Cargo features added (default OFF on OSS, opt-in per spec instability): `a2a-anthropic`, `a2a-google`, `a2a` umbrella in `sbproxy-modules`.

**Open follow-ups shipped 2026-05-03:**
- LND production adapter via tonic-build (vendored `lightning.proto`, full LightningClient with macaroon interceptor + TLS pinning).
- Phoenixd HTTP adapter for hobbyist publishers.
- ONNX cosine-similarity license-leak detector (replacing the bag-of-words baseline).

## See also

- [glossary.md](glossary.md) for the work-stream prefixes (G, A, R, B, S, Q, T, E) and the general SBproxy vocabulary.
- [config-reference.md](config-reference.md) for the field-by-field configuration schema.
- The [CHANGELOG.md](../CHANGELOG.md) at the workspace root for the formal release log.
- The [operator-runbook.md](operator-runbook.md) for runbooks per wave.
