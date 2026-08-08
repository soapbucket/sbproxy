# SBproxy documentation

*Last modified: 2026-08-08*

SBproxy is an open source Enterprise AI Gateway for API, MCP and agent, and AI model traffic. Every feature in this repository ships under Apache-2.0.

## Start and learn

- [core-concepts.md](core-concepts.md) - request pipeline, traffic types, data plane, admin plane, and reload.
- [getting-started.md](getting-started.md) - install, run your first config, and where to go next. Start here.
- [quickstart-serve.md](quickstart-serve.md) - run one local model with `sbproxy run`.
- [manual.md](manual.md) - install, CLI, runtime, TLS, deployment patterns.
- [configuration.md](configuration.md) - every `sb.yml` field with examples.
- [json-schema.md](json-schema.md) - JSON Schema for editor autocomplete + validation of `sb.yml`.
- [features.md](features.md) - tour of every feature with copy-paste configs.
- [admin.md](admin.md) - the admin server: enable it, TLS, the built-in web UI, and the control-plane endpoints (keys, config, metrics, logs, prompts).
- [admin-api-guide.md](admin-api-guide.md) - task-oriented admin API walkthrough: login/CSRF, roles, and a curl cookbook.
- [admin-ui.md](admin-ui.md) - the built-in admin dashboard, page by page: what each view shows, mutates, and calls.
- [troubleshooting.md](troubleshooting.md) - common failure modes and fixes.
- [faq.md](faq.md) - quick answers to the questions operators hit most often.

## Choose a focused guide

<a id="solve-a-problem"></a>

- [getting-started-api-estate.md](getting-started-api-estate.md) - put SBproxy in front of an existing API.
- [getting-started-content-estate.md](getting-started-content-estate.md) - transform content for agents.
- [getting-started-ai-estate.md](getting-started-ai-estate.md) - route requests to model providers.
- [getting-started-agent-identity.md](getting-started-agent-identity.md) - verify agent identity and publish discovery metadata.
- [getting-started-sovereign-multicloud.md](getting-started-sovereign-multicloud.md) - use Kubernetes, sidecars, and secret backends.
- [use-case-own-openrouter.md](use-case-own-openrouter.md) - run a provider gateway on your own credentials.
- [use-case-coding-assistant.md](use-case-coding-assistant.md) - point a coding assistant at a local model.
- [use-case-connect-codex.md](use-case-connect-codex.md) - connect Codex CLI to a governed gateway.
- [use-case-connect-cursor.md](use-case-connect-cursor.md) - connect Cursor to a governed gateway.
- [use-case-connect-cline.md](use-case-connect-cline.md) - connect Cline to a governed gateway.
- [use-case-connect-copilot.md](use-case-connect-copilot.md) - connect GitHub Copilot BYOK to a governed gateway.
- [use-case-production-ops.md](use-case-production-ops.md) - move from a laptop deployment to operational ownership.
- [use-case-local-first.md](use-case-local-first.md) - prove a GPU you already bought pays for itself.
- [use-case-serve-on-l4.md](use-case-serve-on-l4.md) - serve Qwen, GLM, or Gemma on a single cloud L4.
- [use-case-air-gapped.md](use-case-air-gapped.md) - keep weights, prompts, and verdicts inside your network.
- [use-case-guardrails-everywhere.md](use-case-guardrails-everywhere.md) - one guardrail mesh over local and hosted models alike.
- [use-case-mcp-federation.md](use-case-mcp-federation.md) - federate sprawling internal MCP servers behind one governed gateway.
- [use-case-meter-crawlers.md](use-case-meter-crawlers.md) - charge AI crawlers for the content they read.

## Route AI, APIs, and tools

Govern the AI you call, the AI that calls you, and the AI you run.

- [ai-gateway.md](ai-gateway.md) - providers, routing strategies, guardrails, budgets, streaming.
- [guardrails.md](guardrails.md) - external guardrail adapters, response contract, failure policy, and a local tested walkthrough.
- [quickstart-serve.md](quickstart-serve.md) - run your first model in 60 seconds: `curl | sh`, then `sbproxy run <model>`, on a Linux GPU, a Mac, or a CPU box.
- [self-hosting.md](self-hosting.md) - single binary to self-host: install, the serve-only quickstart, the model manifest, aliases, spill-to-cloud, and the OpenRouter parity map.
- [model-host.md](model-host.md) - canonical `proxy.model_host` deployments, verified artifacts, managed engines, admission, reload, and lifecycle CLI for one node.
- [model-host-capabilities.md](model-host-capabilities.md) - generated stable, preview, config-only, and unsupported contracts for model-host features and configuration fields.
- [gpu-fit-planning.md](gpu-fit-planning.md) - how the fit planner picks a quant for your GPU: capability tiers, the weights + KV math, throughput, and why it refuses an impossible config.
- [model-host-certification.md](model-host-certification.md) - the hardware evidence ledger: CPU contracts run in CI, Apple Silicon Metal and local multi-process gates have passed, and NVIDIA CUDA plus live GCP multi-node certification remain pending.
- [serving-engine-benchmark.md](serving-engine-benchmark.md) - vLLM vs SGLang head-to-head on one L4: throughput, prefix-cache behavior, and how the gateway picks an engine.
- [security-model-host.md](security-model-host.md) - trusted config, verified artifacts, typed process launch, engine acquisition, containers, credentials, and remaining isolation work.
- [custom-engines.md](custom-engines.md) - why there is no bring-your-own-image command template: the typed-driver seam, the OpenAI-compatible provider escape hatch, and the bar a signed engine descriptor would have to clear.
- [ai-usage-ledger.md](ai-usage-ledger.md) - the verifiable usage ledger: hash-chained, Ed25519-signed spend receipts you can re-derive and verify.
- [value-ledger-economics.md](value-ledger-economics.md) - the Value Ledger: local-vs-cloud lane split, reference prices, and the savings report at `/admin/model-host/value`.
- [key-management.md](key-management.md) - dynamic virtual keys: mint, revoke, and rotate at runtime through the admin API, hashed at rest, with a fail-closed policy cache.
- [ai-policy-cel.md](ai-policy-cel.md) - the unified CEL policy plane: one sandboxed expression over guardrails, budgets, routing, and principal that emits a closed action set.
- [ai-guardrail-mesh.md](ai-guardrail-mesh.md) - the guardrail mesh: collect every verdict, fuse on a quorum, redact-and-continue, latency-budgeted cascade with a verdict cache.
- [ai-default-centroids-evaluation.md](ai-default-centroids-evaluation.md) - pinned classifier safety centroid artifact, held-out precision and recall, false-positive budget, and deterministic regeneration.
- [ai-outcome-aware-routing.md](ai-outcome-aware-routing.md) - the `outcome_aware` strategy: route by realized cost-per-success fed back from completed requests.
- [ai-predictive-budget.md](ai-predictive-budget.md) - predictive budgets with soft-landing: warn, then downgrade, then block as a scope approaches its cap.
- [ai-llm-aware-resilience.md](ai-llm-aware-resilience.md) - classify upstream failures (timeout, rate-limit, context-window, content-policy) and set per-error retry counts.
- [ai-context-compression.md](ai-context-compression.md) - selectable compression profiles, explicit input budgets, Redis summary state, value accounting, evaluation, metrics, and logs.
- [rag.md](rag.md) - SBproxy in front of a RAG pipeline: gateway-side retrieval from five vector stores, plus marked-context governance, guardrails, and metering.
- [local-inference.md](local-inference.md) - run embeddings (semantic cache) and prompt-injection classify on local ONNX models via the sidecar or in-process.
- [ai-lb-benchmark.md](ai-lb-benchmark.md) - P50/P95/P99/P99.9 latency comparison across AI router strategies under skewed load.
- [providers.md](providers.md) - the catalog of supported LLM providers.
- [scripting.md](scripting.md) - CEL, Lua, JavaScript, and WASM scripting reference.
- [wasm-development.md](wasm-development.md) - writing WebAssembly modules for the `wasm` transform against the WASI preview-1 contract.
- [mcp.md](mcp.md) - the MCP gateway: wire shape, capabilities, and `experimental.agentSkillsUrl` advertising.
- [mcp-gateway-guardrails.md](mcp-gateway-guardrails.md) - MCP gateway guardrails: egress, session risk, quarantine, stdio, run-as-user, and compaction.
- [admin-mcp.md](admin-mcp.md) - manage SBproxy from an MCP client: the gateway's own admin API as governed, read-only-by-default MCP tools for Claude Code or Cursor.
- [tool-versioning.md](tool-versioning.md) - the rollout plane (publish several versions of one tool, resolve per consumer, adapt, sunset) plus the compatibility oracle: a contract digest and a semver grade per tool, with a version-bump linter that fails an under-bump.
- [a2a-gateway.md](a2a-gateway.md) - the `a2a` action and policy: envelope trust, per-hop chain limits, push-notification target validation, typed AgentCard, and modality negotiation helpers.
- [agent-skills.md](agent-skills.md) - Agent Skills v0.2.0 well-known projection: schema, integrity, archive safety, no-script-execution contract.
- [cloudflare-code-mode.md](cloudflare-code-mode.md) - typed TypeScript module emission for Cloudflare Code Mode agents over the MCP federation registry.
- [ai-crawl-control.md](ai-crawl-control.md) - the `ai_crawl_control` policy: Pay Per Crawl token challenge and ledger trait.
- [payment-settlement.md](payment-settlement.md) - `proxy.payments`: charge for a request and prove it was paid before the origin is called.
- [metering.md](metering.md) - attested metering: signed, hash-chained consumption receipts, the operator surface that reads and verifies the chain, and buyer-side verification against the published key set.
- [content-for-agents.md](content-for-agents.md) - operator guide to agent-aware content delivery: shape negotiation, body transforms, well-known license posture.
- [rsl.md](rsl.md) - RSL 1.0 licensing cookbook: expressing license stance via YAML and the resulting `/licenses.xml` projection.
- [web-bot-auth.md](web-bot-auth.md) - the `bot_auth` provider: verifying RFC 9421-signed AI crawlers against a published key directory.
- [outbound-dpop.md](outbound-dpop.md) - RFC 9449 sender-constrained OAuth credentials and per-request proof minting for upstream calls.
- [auth-oidc.md](auth-oidc.md) - the `oidc` auth provider: OpenID Connect Relying-Party login flow (authorization-code + PKCE, sealed session cookie, optional userinfo trust-header projection, RP-initiated logout).
- [prompt-injection-v2.md](prompt-injection-v2.md) - the v2 guardrail: swappable detector returning score + label, with score-to-action mapping and a delegation-depth-aware action at the agent boundary.

## Connect clients

Point a framework you already run at the gateway: chat completions through the OpenAI-compatible endpoint, tools through the MCP gateway. Every snippet on these pages was validated against a running proxy.

- [langchain.md](langchain.md) - LangChain (python): any provider through ChatOpenAI at the gateway, native ChatAnthropic on `/v1/messages`, MCP tools via langchain-mcp-adapters.
- [vercel-ai-sdk.md](vercel-ai-sdk.md) - Vercel AI SDK (typescript): the openai-compatible provider, MCP tools via the AI SDK's MCP client.
- [pydantic-ai.md](pydantic-ai.md) - Pydantic AI (python): OpenAIChatModel through the gateway, MCP toolsets on an Agent.
- [mastra.md](mastra.md) - Mastra (typescript): agents on a gateway-backed model, tools from the MCP client.
- [n8n.md](n8n.md) - n8n: the OpenAI credential's base URL, the MCP Client Tool node, and federating n8n's own MCP trigger.

## Operate and change safely

- [access-log.md](access-log.md) - structured JSON access log: filters, sampling, header capture, redaction.
- [audit-log.md](audit-log.md) - tamper-evident audit log of admin actions.
- [observability.md](observability.md) - metrics, logs, traces, and the bundled dashboards.
- [clickhouse-attribution.md](clickhouse-attribution.md) - access-log schema, pre-aggregations, and sample attribution queries.
- [migration-credentials.md](migration-credentials.md) - migrating the legacy `virtual_keys:` shape to the unified `credentials:` block.
- [migration-mcp-rbac.md](migration-mcp-rbac.md) - upgrading MCP `ToolAccessPolicy` to the principal-aware ACL and the default-deny flip.
- [migration-litellm.md](migration-litellm.md) - moving a LiteLLM proxy to SBproxy with `config import-litellm` and the field-by-field mapping.
- [secrets.md](secrets.md) - the secret-reference vocabulary (env vars, files, provider URIs) resolved everywhere in config, plus backend setup for HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Kubernetes Secrets.
- [multi-tenant.md](multi-tenant.md) - when to use the multi-tenant shape, the three scopes, isolation guarantees, the synthetic `__default__` tenant.
- [operator-runbook.md](operator-runbook.md) - dashboard triage and rollback actions.
- [threat-model.md](threat-model.md) - trust boundaries and per-wave review checklist.
- [events.md](events.md) - the event bus, callback hooks, and emitted event types.
- [openapi-emission.md](openapi-emission.md) - publishing an OpenAPI 3.0 document from the live config.
- [policy.md](policy.md) - the policy engine, the `semantic_constraint` policy, and the `request_validator`, `concurrent_limit`, `rate_limit_budget`, `http_framing`, and `a2a` policy reference.
- [object-authz.md](object-authz.md) - `object_authz` policy: BOLA + BFLA enforcement with tenant-isolation and enumeration detection.
- [headless-detection.md](headless-detection.md) - header-only headless / stealth-browser indicator heuristics surfaced under `request.agent.headless_*`.
- [content-digest.md](content-digest.md) - `content_digest` policy: RFC 9530 request-body verification for integrity-critical inboxes.
- [agent-budget.md](agent-budget.md) - `agent_budget` policy: semantic rate-limit primitive keyed on resolved agent identity.
- [performance.md](performance.md) - tuning guide, benchmark methodology, profiling.
- [degradation.md](degradation.md) - failure modes and graceful degradation behavior.
- [upgrade.md](upgrade.md) - migration notes between releases.
- [mesh-replication.md](mesh-replication.md) - the replicated cluster-state substrate: replication factor, read/write consistency, durable restart, handoff, anti-entropy, and the tombstone deletion protocol.
- [quickstart-operator.md](quickstart-operator.md) - first 24 hours running the Kubernetes operator.
- [kubernetes.md](kubernetes.md) - the Kubernetes operator and its CRDs.
- [sidecar-deployment.md](sidecar-deployment.md) - running sbproxy as a per-pod sidecar: traffic capture (iptables / eBPF), service-mesh integration (Istio, Linkerd), and the kustomize overlay under `deploy/k8s/sidecar/`.

## Reference

- [payment-settlement.md](payment-settlement.md) - `proxy.payments`: rails, durable intents, the state table that gates origin access, timeouts, reconciliation, and the exact unsupported boundaries.
- [402-challenge.md](402-challenge.md) - the exact bytes of every payment challenge, credential, problem document, and receipt.
- [l402.md](l402.md) - L402 (Lightning HTTP 402) design notes: the protocol shape SBproxy would implement. None of it ships in the current binary; [402-challenge.md](402-challenge.md) covers the payment surface that does.
- [admin-api-reference.md](admin-api-reference.md) - per-route schema for the embedded admin server (`/api/*`, `/admin/*`, and the unauthenticated probe routes).
- [config-stability.md](config-stability.md) - field stability guarantees and versioning.
- [config-authority-drills.md](config-authority-drills.md) - two-process certification drills for signed config distribution.
- [listings.md](listings.md) - the repo-native `Listing` primitive: schema, loader, three pinning modes, plan-validation rules.
- [bulk-redirects.md](bulk-redirects.md) - the `redirect` action's source-to-destination row list, compiled at load time into an O(1) path lookup.
- [cache-reserve.md](cache-reserve.md) - long-tail cold tier under the response cache: backends (memory, filesystem, Redis) and admission sampling.
- [exposed-credentials.md](exposed-credentials.md) - the `exposed_credentials` policy: detect known-leaked basic-auth passwords and tag or block.
- [feature-flags.md](feature-flags.md) - the sticky-bucketing flag store plus the `flag_enabled(name, key)` CEL helper.
- [routing-strategies.md](routing-strategies.md) - the `RoutingStrategy` trait: opt-in extension point for custom upstream selection inside `load_balancer`.
- [openapi-validation.md](openapi-validation.md) - the `openapi_validation` policy: validating request bodies against an OpenAPI 3.0 document at startup.
- [glossary.md](glossary.md) - vocabulary used in this documentation set.
- [headers-reference.md](headers-reference.md) - every response header the proxy can emit, with the config that triggers it.
- [metrics-stability.md](metrics-stability.md) - Prometheus metric naming and stability.
- [model-pinning.md](model-pinning.md) - how SHA-256 hashes get computed and pinned for the classifier known-model registry.
- [comparison.md](comparison.md) - how SBproxy compares to other proxies and AI gateways.

## Contribute

- [architecture.md](architecture.md) - internals: pipeline, hot reload, plugin system.
- [build.md](build.md) - building from source, supported platforms, optional features.
- [CONTRIBUTING.md](../CONTRIBUTING.md) - how to set up a dev environment and submit changes.

## Machine-readable documentation

- [llms.txt](llms.txt) - flat capability catalog (one line per shipped feature), per the [llmstxt.org](https://llmstxt.org/) convention. The small index AI tools fetch first.
- [llms-full.txt](llms-full.txt) - the entire docs corpus (this directory + the top-level `README.md`, `MIGRATION.md`, `CHANGELOG.md`) flattened into one file so AI tools that want the full set get it in one HTTP request. Generated; do not hand-edit and do not commit it on a branch. CI regenerates it on `main` after a docs change merges. Mirrored live at <https://sbproxy.dev/llms-full.txt>.
