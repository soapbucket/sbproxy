# Glossary
*Last modified: 2026-05-03*

A plain-English mapping of the codes and acronyms that appear in SBproxy commits, ADRs, the CHANGELOG, and the operator runbook. If you have ever seen a commit titled `feat(modules): G3.4 multi-rail challenge emission` and wondered which knob that turns, this is the page.

The terminology is split into four groups:

1. Wave codes (the seven roadmap waves that built v1.0)
2. Work-stream prefixes (G, A, R, B, S, Q, T, E) used inside each wave
3. Q-codes used for QA gates and quarterly markers
4. General SBproxy vocabulary (OLP, CAP, MCP, x402, MPP, DPoP, RFC 9421, RSL, and so on)

## Wave codes

Each wave delivered one cross-cutting capability. They are sequential and additive: Wave 2 builds on Wave 1, Wave 3 on Wave 2, and so on. Every commit subject in the repository carries the wave it belongs to so the audit trail stays legible.

| Code   | Theme                              | What it shipped (buyer-facing)                                                                                                                       |
|--------|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| Wave 1 | AI governance substrate            | Tier-aware Pay Per Crawl pricing, HTTP ledger redemption, typed agent class on every request, dynamic Web Bot Auth directory, OpenTelemetry tracing, structured access and audit logs, outbound webhook framework, `/healthz` and `/readyz` endpoints, Grafana dashboards, Prometheus alerts. |
| Wave 2 | Billing foundation                 | First production payment rail (Stripe / MPP path), wallet ledger, agent registry intake, signed-batch audit log v0, per-tenant rate-limit middleware with RFC 9239 headers, agent-aware tier resolution, hot-path vs async-path layering rule. |
| Wave 3 | Multi-rail payments                | x402 plus MPP negotiation in a single 402 challenge, per-shape pricing, signed quote-token JWS, end-to-end idempotency keys, EVM reorg-aware two-phase settlement, clock-skew monitor, JWKS endpoint at `/.well-known/sbproxy/quote-keys.json`. |
| Wave 4 | Content for agents                 | Two-pass `Accept` content negotiation, per-shape pricing matrix, JSON envelope schema, citation-block + boilerplate-stripping transforms, well-known projection routes for `robots.txt`, `llms.txt`, RSL `licenses.xml`, TDMRep `tdmrep.json`, Content-Signal response header, `aipref` preference signal, `x-markdown-tokens` header. |
| Wave 5 | Identity differentiator            | RFC 8693 outbound credential resolver, Vault-backed PATs, stored OAuth grants under one delegation-aware interface, JA3 / JA4 / JA4H TLS fingerprinting, headless-browser detection, Skyfire KYA token verification, ML agent classifier hook surface, header-mutating CEL transform, SIGHUP re-bootstrap. |
| Wave 6 | Operational substrate              | Hash-chained Merkle audit log v1, access log v1, CAP token verifier, revenue rollups, compliance crate scaffold, evidence-verify and audit-migrate CLIs, Open Licensing Protocol (OLP) issuer wiring, Crawler Authorization Protocol (CAP) issuer.                        |
| Wave 7 | Bonus enterprise scope             | Employee-bound agent identity (SCIM webhook receiver + chargeback), Agent-to-Agent (A2A) protocol envelope with depth cap and cycle detection, license-leak guardrail (corpus + outbound transform), Lightning rail (CLN production adapter, LND stub, spot-rate oracle).         |

Wave 6 closes the public commitment "all six waves shipped." Wave 7 is bonus scope.

## Work-stream prefixes

Inside each wave, individual deliverables are tagged with a single-letter stream prefix and a sub-number. The streams describe who owns the work, not what it does:

| Prefix | Stream                | What it covers                                                                                                                       |
|--------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| G      | Governance / feature  | Customer-visible feature behaviour. New policy modules, new tier resolvers, new pricing matrices, new request-context fields.        |
| A      | Architect / ADR       | Architecture decision records. Each `A<wave>.<n>` corresponds to an `adr-*.md` file under `docs/`. ADRs are merged before their G work.|
| R      | Reliability / runtime | Cross-cutting runtime behaviour. Rate limits, idempotency, clock skew, timing, observability wiring, OTel exporters, structured logs.|
| B      | Builder / packaging   | Build, packaging, CI, deploy. Cargo features, Helm values, Grafana dashboards, Prometheus alerts, Dockerfiles, signed releases.       |
| S      | Scribe / documentation| Operator-facing documentation. CHANGELOG entries, operator runbook playbooks, threat-model entries, llms.txt updates.                 |
| Q      | Quality / QA gates    | End-to-end and conformance tests. Fuzz harnesses. Bench fixtures. Each `Q<wave>.<n>` is a single test fixture or harness.             |
| T      | Telemetry envelope    | Wave 8 P0 work on the request envelope. Custom properties, sessions, users, RequestEvent emission. (Telemetry layer.)                |
| E      | Enterprise            | Enterprise-only deliverables, called out in OSS docs only when they cross the public boundary (e.g. CAP issuer paired with R6.1 verifier). |

A label such as `G3.4` reads as "Wave 3, governance / feature stream item 4," and corresponds to a single PR or merge. Numbers within a stream are not contiguous; gaps mean the item was renumbered or moved to a follow-up.

## Q codes

Q codes have two meanings depending on context:

- **Inside a wave** (e.g. `Q1.1`, `Q3.6`): a quality / QA gate. Each Q item is one e2e or conformance test, a fuzz harness, a synthetic-monitor fixture, or a bench scenario. Q items are merged after the G items they exercise.
- **In product-strategy notes** (e.g. "Q15", "the Q5 narrative"): a question number on the YC application. These do not correspond to wave work and are unrelated to the engineering Q codes.

When a commit references `Q4.2` it is a Wave 4 QA gate. When a planning doc references "the Q5 commitment" it is a YC application question.

## General SBproxy vocabulary

| Term                | Stands for / source                                  | What it means in SBproxy                                                                                                                                          |
|---------------------|------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| OLP                 | Open Licensing Protocol                              | A four-step flow for publishers to advertise a licence catalogue, agents to discover it, and the gateway to issue licence tokens (`jti` claims) bound to a licence row. The verifier ships in OSS via the AI crawl control policy; the issuer is enterprise-side. |
| CAP                 | Crawler Authorization Protocol                       | A JWT-based capability-token format that an agent presents in `CAP-Token:` or `Authorization: CAP <jwt>`. The OSS verifier checks signature, claims, audience, glob-allowed paths, and (optionally) per-token rate limits. The issuer ships enterprise-side. |
| MCP                 | Model Context Protocol                               | The Anthropic-originated tool-and-resource catalogue protocol. SBproxy ships an MCP federation action that aggregates tool catalogues across upstream MCP servers and routes `tools/call` per tool. |
| x402                | x402 protocol (Coinbase et al.)                      | A stablecoin-on-chain payment rail riding HTTP 402. SBproxy emits x402 challenge entries in multi-rail 402 responses and verifies redemption tokens via the x402 facilitator. v2 is supported; v1 is rejected with a typed error.                                |
| MPP                 | Merchant Payment Protocol                            | The card-and-stablecoin-on-Stripe payment rail. SBproxy emits MPP challenge entries that carry a Stripe `payment_intent` id; redemption confirms against Stripe.                                                                                                  |
| DPoP                | Demonstration of Proof-of-Possession (RFC 9449)      | A JWS that proves the presenter holds the private key bound to an access token. SBproxy uses DPoP on outbound credential resolution so a stolen access token alone is insufficient to call an upstream.                                                          |
| RFC 8693            | OAuth 2.0 Token Exchange                             | The token-exchange grant that powers SBproxy's outbound credential resolver. Wave 5 uses RFC 8693 to swap an inbound identity for an upstream access token under one delegation-aware interface.                                                                  |
| RFC 9421            | HTTP Message Signatures                              | The IETF spec for signing HTTP messages. SBproxy implements per-origin message-signature configuration plus the Web Bot Auth directory (RFC 9421-style signatures with a JWKS feed).                                                                              |
| RFC 9239            | RateLimit headers                                    | The IETF spec for `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, and `Retry-After`. SBproxy emits these on every throttled response.                                                                                                                |
| RSL                 | Really Simple Licensing                              | A licence-advertisement standard served as `licenses.xml`. Wave 4 added a projection route at `/licenses.xml` keyed off the live config and the per-origin Content-Signal value.                                                                                  |
| TDMRep              | Text and Data Mining Reservation Protocol (W3C)      | A licence-reservation standard served as `tdmrep.json`. Wave 4 added a projection route at `/.well-known/tdmrep.json`. When `content_signal` is unset on an origin, the proxy stamps `TDM-Reservation: 1` instead of asserting a positive Content-Signal.         |
| llms.txt            | llms.txt convention                                  | A plain-text capability index for AI crawlers. SBproxy serves both a static `llms.txt` per origin (Wave 4 projection) and a top-level `/llms.txt` describing the gateway itself.                                                                                  |
| robots.txt          | Robots Exclusion Protocol                            | A projection route that derives the live robots.txt from each origin's policy graph (Wave 4). The proxy never serves a static robots.txt; it composes one on every reload.                                                                                        |
| aipref              | AI Preferences Working Group draft                   | A request-side preference signal an agent can carry to declare training, search, or input intent. Parsed at request entry into `RequestContext.aipref` and exposed to CEL, Lua, JavaScript, and WASM.                                                              |
| Content-Signal      | IAB Tech Lab Content-Signal header                   | A response header carrying one of `ai-train`, `search`, `ai-input`. SBproxy stamps it on 200 responses per origin and reflects the same value into the licensing projections.                                                                                     |
| Pay Per Crawl       | Cloudflare-coined term, SBproxy implementation       | The pattern of charging an AI crawler with HTTP 402 plus a `Crawler-Payment` token. Implemented by the `ai_crawl_control` policy.                                                                                                                                |
| Web Bot Auth        | IETF draft (HTTP message signatures + key directory) | The signed-bot-traffic standard. SBproxy fetches `/.well-known/http-message-signatures-directory` from a vendor, caches the JWKS with TTL, and verifies signatures on inbound bot requests.                                                                       |
| KYA                 | Know-Your-Agent (Skyfire)                            | A token format for verified agent identity. Wave 5 added a KYA verifier and exposed `request.kya` to scripting.                                                                                                                                                   |
| JA3 / JA4 / JA4H    | TLS fingerprinting algorithms                        | ClientHello fingerprints captured at the TLS layer and stamped onto the request context. Wave 5 ships JA3 plus the JA4 family for headless-detection signals.                                                                                                     |
| schema-v1           | Internal config schema label                         | The `sb.yml` schema shared by the archived Go `v0.1.x` line and the Rust `v1.x` line. Schema-v1 is independent of binary version and is pinned by `v1_compat::v1_fixtures_compile_unmodified` in `crates/sbproxy-config/`.                                          |
| BSL 1.1             | Business Source License 1.1                          | The licence under which SBproxy v1.0 is published. Source-available; production use allowed for everything except offering SBproxy as a competing hosted or managed service. See [LICENSE](../LICENSE).                                                            |
| Pingora             | Cloudflare's Rust proxy framework                    | The async runtime SBproxy is built on. The `sbproxy-core` crate plugs into Pingora's `request_filter`, `response_filter`, and `response_body_filter` lifecycle.                                                                                                  |
| CEL                 | Common Expression Language                           | Google's expression language. Used for per-origin policy rules, request modifiers, and response transforms. Powered by `cel-rust`.                                                                                                                                |
| Lua / Luau          | Lua and Roblox's Luau dialect                        | The scripting hook surface for request modifiers and transforms, sandboxed via `mlua`. Configured under `lua_script:` blocks.                                                                                                                                     |
| QuickJS             | Bellard's QuickJS engine, via `rquickjs`             | The JavaScript hook surface for request and response modifiers. Configured under `js_script:` blocks.                                                                                                                                                             |
| WASM / wasmtime     | WebAssembly + Bytecode Alliance runtime              | The WebAssembly hook surface (WASI). Configured under `wasm:` blocks. Ship custom modules in any language that compiles to WASI.                                                                                                                                  |
| L2 cache            | Layer-2 cache backend                                | A shared-state backend (Redis today) that turns rate-limit counters and response-cache entries into cluster-wide state. Configured under `proxy.l2_cache_settings`.                                                                                                |
| Cache Reserve       | Long-tail cold cache tier                            | A second cache tier sitting under the per-origin response cache. Sample-rate driven mirroring; admission gate by min TTL and size; promotion-on-hit. Configured under `proxy.cache_reserve`.                                                                       |
| Hot path / async path | Layering rule                                      | The pin that keeps OSS billing latency-critical code on the synchronous request path and pushes per-rail accounting to async workers. Enforced by `scripts/check-crate-graph.sh` in CI.                                                                            |

## See also

- [config-reference.md](config-reference.md) for the field-by-field configuration schema.
- [wave-history.md](wave-history.md) for a narrative walk through what each wave shipped, when, and where to find the receipts.
- [openapi-emission.md](openapi-emission.md) for how SBproxy emits an OpenAPI document from the live config.
- [features.md](features.md) for the buyer-facing tour of every feature with copy-paste configs.
