# SBproxy documentation
*Last modified: 2026-06-18*

The AI gateway built like a real proxy. One binary, built on Pingora.

## Where to start

New here? Read [manual.md](manual.md) for install and CLI, then [configuration.md](configuration.md) for the schema. The [examples](../examples/) folder has runnable configs you can point the binary at right away.

## Documentation index

### Getting started
- [manual.md](manual.md) - install, CLI, runtime, TLS, deployment patterns.
- [getting-started-api-estate.md](getting-started-api-estate.md) - put SBproxy in front of existing APIs with auth, rate limits, and header rewrites.
- [getting-started-content-estate.md](getting-started-content-estate.md) - HTML-to-markdown and content transformation for agents.
- [getting-started-ai-estate.md](getting-started-ai-estate.md) - run SBproxy as the LLM gateway in front of model providers.
- [getting-started-agent-identity.md](getting-started-agent-identity.md) - issue and enforce agent identity at the edge.
- [getting-started-sovereign-multicloud.md](getting-started-sovereign-multicloud.md) - Kubernetes, sidecar, and secret-backend deployment.
- [configuration.md](configuration.md) - every `sb.yml` field with examples.
- [json-schema.md](json-schema.md) - JSON Schema for editor autocomplete + validation of `sb.yml`.
- [mcp-schema-drift.md](mcp-schema-drift.md) - CI-friendly schema-drift detection for converted MCP servers (the `sbproxy-mcp-drift` CLI).
- [features.md](features.md) - tour of every feature with copy-paste configs.
- [troubleshooting.md](troubleshooting.md) - common failure modes and fixes.
- [faq.md](faq.md) - quick answers to the questions operators hit most often.

### AI gateway
- [ai-gateway.md](ai-gateway.md) - providers, routing strategies, guardrails, budgets, streaming.
- [ai-usage-ledger.md](ai-usage-ledger.md) - the verifiable usage ledger: hash-chained, Ed25519-signed spend receipts you can re-derive and verify.
- [ai-policy-cel.md](ai-policy-cel.md) - the unified CEL policy plane: one sandboxed expression over guardrails, budgets, routing, and principal that emits a closed action set.
- [ai-guardrail-mesh.md](ai-guardrail-mesh.md) - the guardrail mesh: collect every verdict, fuse on a quorum, redact-and-continue, latency-budgeted cascade with a verdict cache.
- [ai-outcome-aware-routing.md](ai-outcome-aware-routing.md) - the `outcome_aware` strategy: route by realized cost-per-success fed back from completed requests.
- [ai-predictive-budget.md](ai-predictive-budget.md) - predictive budgets with soft-landing: warn, then downgrade, then block as a scope approaches its cap.
- [local-inference.md](local-inference.md) - run embeddings (semantic cache) and prompt-injection classify on local ONNX models via the sidecar or in-process.
- [ai-lb-benchmark.md](ai-lb-benchmark.md) - P50/P95/P99/P99.9 latency comparison across AI router strategies under skewed load.
- [providers.md](providers.md) - the catalog of supported LLM providers.
- [scripting.md](scripting.md) - CEL, Lua, JavaScript, and WASM scripting reference.
- [wasm-development.md](wasm-development.md) - writing WebAssembly modules for the `wasm` transform against the WASI preview-1 contract.
- [mcp.md](mcp.md) - the MCP gateway: wire shape, capabilities, and `experimental.agentSkillsUrl` advertising.
- [a2a-gateway.md](a2a-gateway.md) - the `a2a` action: typed AgentCard, capability discovery, and modality negotiation helpers.
- [agent-skills.md](agent-skills.md) - Agent Skills v0.2.0 well-known projection: schema, integrity, archive safety, no-script-execution contract.
- [cloudflare-code-mode.md](cloudflare-code-mode.md) - typed TypeScript module emission for Cloudflare Code Mode agents over the MCP federation registry.
- [ai-crawl-control.md](ai-crawl-control.md) - the `ai_crawl_control` policy: Pay Per Crawl token challenge, ledger trait, OSS-advertises / enterprise-settles split.
- [content-for-agents.md](content-for-agents.md) - operator guide to agent-aware content delivery: shape negotiation, body transforms, well-known license posture.
- [rsl.md](rsl.md) - RSL 1.0 licensing cookbook: expressing license stance via YAML and the resulting `/licenses.xml` projection.
- [web-bot-auth.md](web-bot-auth.md) - the `bot_auth` provider: verifying RFC 9421-signed AI crawlers against a published key directory.
- [auth-oidc.md](auth-oidc.md) - the `oidc` auth provider: OpenID Connect Relying-Party login flow (authorization-code + PKCE, sealed session cookie, optional userinfo trust-header projection, RP-initiated logout).
- [prompt-injection-v2.md](prompt-injection-v2.md) - the v2 guardrail: swappable detector returning score + label, with score-to-action mapping.

### Operations
- [access-log.md](access-log.md) - structured JSON access log: filters, sampling, header capture, redaction.
- [audit-log.md](audit-log.md) - tamper-evident audit log of admin actions.
- [observability.md](observability.md) - metrics, logs, traces, and the bundled dashboards.
- [clickhouse-attribution.md](clickhouse-attribution.md) - access-log schema, pre-aggregations, and sample attribution queries.
- [migration-credentials.md](migration-credentials.md) - migrating the legacy `virtual_keys:` shape to the unified `credentials:` block.
- [migration-mcp-rbac.md](migration-mcp-rbac.md) - upgrading MCP `ToolAccessPolicy` to the principal-aware ACL and the default-deny flip.
- [migration-litellm.md](migration-litellm.md) - moving a LiteLLM proxy to SBproxy with `config import-litellm` and the field-by-field mapping.
- [secrets.md](secrets.md) - vault backend setup for HashiCorp Vault, AWS Secrets Manager, and Kubernetes Secrets.
- [multi-tenant.md](multi-tenant.md) - when to use the multi-tenant shape, the three scopes, isolation guarantees, the synthetic `__default__` tenant.
- [operator-runbook.md](operator-runbook.md) - dashboard triage and rollback actions.
- [threat-model.md](threat-model.md) - OSS trust boundaries and per-wave review checklist.
- [events.md](events.md) - the event bus, callback hooks, and emitted event types.
- [openapi-emission.md](openapi-emission.md) - publishing an OpenAPI 3.0 document from the live config.
- [policy.md](policy.md) - the policy engine: `semantic_constraint`, the NL linter L001-L009, and the OSS / enterprise capability boundary.
- [object-authz.md](object-authz.md) - `object_authz` policy: BOLA + BFLA enforcement with tenant-isolation and enumeration detection.
- [headless-detection.md](headless-detection.md) - header-only headless / stealth-browser indicator heuristics surfaced under `request.agent.headless_*`.
- [content-digest.md](content-digest.md) - `content_digest` policy: RFC 9530 request-body verification for integrity-critical inboxes.
- [agent-budget.md](agent-budget.md) - `agent_budget` policy: semantic rate-limit primitive keyed on resolved agent identity.
- [performance.md](performance.md) - tuning guide, benchmark methodology, profiling.
- [degradation.md](degradation.md) - failure modes and graceful degradation behavior.
- [upgrade.md](upgrade.md) - migration notes between releases.
- [quickstart-operator.md](quickstart-operator.md) - first 24 hours running the Kubernetes operator.
- [kubernetes.md](kubernetes.md) - the OSS Kubernetes operator and its CRDs.
- [sidecar-deployment.md](sidecar-deployment.md) - running sbproxy as a per-pod sidecar: traffic capture (iptables / eBPF), service-mesh integration (Istio, Linkerd), and the kustomize overlay under `deploy/k8s/sidecar/`.

### Reference
- [402-challenge.md](402-challenge.md) - wire-format contract for the `402 Payment Required` body, including the OSS-advertises / enterprise-settles split.
- [l402.md](l402.md) - L402 (Lightning HTTP 402) macaroon bearer credential surface: issuer, verifier, attenuation, payment-hash binding.
- [outbound-peer-pricing.md](outbound-peer-pricing.md) - the `peer_pricing_preflight` policy: parse a peer's `llms.txt`, gate egress on budget, return a structured 402 to the agent on overflow.
- [admin-api-reference.md](admin-api-reference.md) - per-route schema for the embedded admin server (`/api/*`, `/admin/*`, and the unauthenticated probe routes).
- [config-stability.md](config-stability.md) - field stability guarantees and versioning.
- [listings.md](listings.md) - the repo-native `Listing` primitive: schema, loader, three pinning modes, plan-validation rules.
- [bulk-redirects.md](bulk-redirects.md) - the `redirect` action's source-to-destination row list, compiled at load time into an O(1) path lookup.
- [cache-reserve.md](cache-reserve.md) - long-tail cold tier under the response cache: backends (memory, filesystem, Redis) and admission sampling.
- [exposed-credentials.md](exposed-credentials.md) - the `exposed_credentials` policy: detect known-leaked basic-auth passwords and tag or block.
- [feature-flags.md](feature-flags.md) - the sticky-bucketing flag store plus the `flag_enabled(name, key)` CEL helper.
- [routing-strategies.md](routing-strategies.md) - the `RoutingStrategy` trait: opt-in extension point for custom upstream selection inside `load_balancer`.
- [openapi-validation.md](openapi-validation.md) - the `openapi_validation` policy: validating request bodies against an OpenAPI 3.0 document at startup.
- [enterprise.md](enterprise.md) - what the enterprise tier adds on top of the OSS data plane and how to request access.
- [glossary.md](glossary.md) - vocabulary used in this documentation set.
- [headers-reference.md](headers-reference.md) - every response header the proxy can emit, with the config that triggers it.
- [metrics-stability.md](metrics-stability.md) - Prometheus metric naming and stability.
- [model-pinning.md](model-pinning.md) - how SHA-256 hashes get computed and pinned for the classifier known-model registry.
- [adr-ai-hub-format.md](adr-ai-hub-format.md) - hub `ChatFormat` trait and the canonical `ChatRequest` / `ChatResponse` shape that backs `/v1/chat/completions`, `/v1/messages`, and `/v1/responses`.
- [adr-outbound-credential-resolver.md](adr-outbound-credential-resolver.md) - the OSS vs enterprise line for the outbound credential resolver (RFC 8693 exchange, client-credentials, and vault resolution in OSS).
- [adr-vault-reference-schemes.md](adr-vault-reference-schemes.md) - per-provider secret reference schemes and the migration path away from the `vault://` umbrella form.
- [comparison.md](comparison.md) - how SBproxy compares to other proxies and AI gateways.

### Contributing
- [architecture.md](architecture.md) - internals: pipeline, hot reload, plugin system.
- [build.md](build.md) - building from source, supported platforms, optional features.
- [CONTRIBUTING.md](../CONTRIBUTING.md) - how to set up a dev environment and submit changes.

### AI-discoverable corpora
- [llms.txt](llms.txt) - flat capability catalog (one line per shipped feature), per the [llmstxt.org](https://llmstxt.org/) convention. The small index AI tools fetch first.
- [llms-full.txt](llms-full.txt) - the entire docs corpus (this directory + the top-level `README.md`, `MIGRATION.md`, `CHANGELOG.md`) flattened into one file so AI tools that want the full set get it in one HTTP request. Generated; do not hand-edit. Regenerate with `scripts/regen-llms-full.sh` after any docs change. Mirrored live at <https://sbproxy.dev/llms-full.txt>.

## Quick start

```bash
# Build
make build-release

# Run with a config
make run CONFIG=examples/basic-proxy/sb.yml
```

Minimal `sb.yml`:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: http://backend:3000
```

## What's in the box

- Reverse proxy: HTTP/1.1, HTTP/2, WebSocket, gRPC, connection pooling, hot reload.
- AI gateway: 200+ LLM models, 15 routing strategies, OpenAI-compatible API, guardrails, budgets, virtual keys, MCP server.
- Authentication: API key, basic, bearer, JWT, digest, forward auth, noop.
- Policies: rate limiting, IP filter, CEL expressions, WAF, DDoS, CSRF, security headers.
- Transforms: 18 request and response transforms (JSON, HTML, Markdown, CSS, Lua, JavaScript, encoding, and more).
- Scripting: CEL via cel-rust, Lua via mlua/Luau, JavaScript via QuickJS, WebAssembly via wasmtime.
- Caching: response cache with pluggable backends (memory, file, Redis).
- Load balancing: 7 algorithms with sticky sessions and health checks.
- Observability: Prometheus metrics, structured logging, typed event bus, OpenTelemetry tracing.
- Hot reload: config changes apply with no dropped connections.
