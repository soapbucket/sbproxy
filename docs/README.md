# SBproxy documentation

*Last modified: 2026-08-29*

SBproxy is an open source Enterprise AI Gateway for API, MCP and agent, and AI model traffic. Every feature in this repository ships under Apache-2.0.

[overview.html](overview.html) is the one-page product overview: the five
classes of AI traffic the proxy governs, the request path, and where we
stand against the specialists in each class. It renders in any browser
with no dependencies.

## Which path is yours?

- **New to SBproxy?** Start at [Start here](#start-here), then [Guides by use case](#guides-by-use-case).
- **Configuring something specific?** Jump straight to the category: [API gateway](#api-gateway-and-traffic-management), [AI gateway](#ai-gateway), [MCP and agents](#mcp-and-agents), [Payments](#payments-and-metering), [Policies](#policies), [Security](#security).
- **Operating this in production?** [Observability and operations](#observability-and-operations), [Deployment](#deployment), [Migration and upgrading](#migration-and-upgrading).
- **Building on top of an AI stack?** [AI gateway](#ai-gateway), [MCP and agents](#mcp-and-agents), [Connect clients](#connect-clients).
- **Extending SBproxy?** [Scripting and extensibility](#scripting-and-extensibility), [Contribute](#contribute).
- **Deciding whether to upgrade?** [Release notes](#release-notes) has what changed, grouped by the categories above.

## Start here

Four walkthroughs, one per traffic shape:

- [all-traffic-gateway.md](all-traffic-gateway.md) - API, MCP, and AI on one listener. Commands: [getting-started.md](getting-started.md).
- [getting-started-ai-estate.md](getting-started-ai-estate.md) - apps calling model providers.
- [getting-started-inbound.md](getting-started-inbound.md) - agents and crawlers calling you (content shaping + agent identity).
- [quickstart-serve.md](quickstart-serve.md) - run one local model with `sbproxy run`.

Then the maps:

- [core-concepts.md](core-concepts.md) - request pipeline, traffic types, data plane, admin plane, and reload.
- [request-flow.md](request-flow.md) - the request pipeline stage by stage, with every point where a hook, script, transform, or plugin can attach.
- [manual.md](manual.md) - install, CLI, runtime, TLS, deployment patterns.
- [configuration.md](configuration.md) - every `sb.yml` field with examples.
- [json-schema.md](json-schema.md) - JSON Schema for editor autocomplete + validation of `sb.yml`.
- [features.md](features.md) - stub pointing at the hubs above, plus the action / policy / scripting catalogs.
- [admin.md](admin.md) - the admin server: enable it, TLS, the built-in web UI, and the control-plane endpoints (keys, config, metrics, logs, prompts).
- [admin-api-guide.md](admin-api-guide.md) - task-oriented admin API walkthrough: login/CSRF, roles, and a curl cookbook.
- [admin-ui.md](admin-ui.md) - the built-in admin dashboard, page by page: what each view shows, mutates, and calls.
- [troubleshooting.md](troubleshooting.md) - common failure modes and fixes.
- [faq.md](faq.md) - quick answers to the questions operators hit most often.

## Guides by use case

<a id="solve-a-problem"></a>

- [getting-started-api-estate.md](getting-started-api-estate.md) - put SBproxy in front of an existing API.
- [getting-started-inbound.md](getting-started-inbound.md) - stitch of content-for-agents and agent identity (AI that calls you).
- [getting-started-content-estate.md](getting-started-content-estate.md) - transform content for agents.
- [getting-started-ai-estate.md](getting-started-ai-estate.md) - route requests to model providers.
- [getting-started-agent-identity.md](getting-started-agent-identity.md) - verify agent identity and publish discovery metadata.
- [getting-started-sovereign-multicloud.md](getting-started-sovereign-multicloud.md) - use Kubernetes, sidecars, and secret backends.
- [use-case-own-openrouter.md](use-case-own-openrouter.md) - run a provider gateway on your own credentials.
- [use-case-coding-assistant.md](use-case-coding-assistant.md) - point a coding assistant at a local model.
- [use-case-connect-coding-agents.md](use-case-connect-coding-agents.md) - point Codex, Claude Code, Cursor, Cline, and Copilot at a governed gateway with `sbproxy connect`.
- [use-case-production-ops.md](use-case-production-ops.md) - move from a laptop deployment to operational ownership.
- [use-case-local-first.md](use-case-local-first.md) - prove a GPU you already bought pays for itself.
- [use-case-serve-on-l4.md](use-case-serve-on-l4.md) - serve Qwen, GLM, or Gemma on a single cloud L4.
- [use-case-air-gapped.md](use-case-air-gapped.md) - keep weights, prompts, and verdicts inside your network.
- [use-case-guardrails-everywhere.md](use-case-guardrails-everywhere.md) - one guardrail mesh over local and hosted models alike.
- [use-case-mcp-federation.md](use-case-mcp-federation.md) - federate sprawling internal MCP servers behind one governed gateway.
- [use-case-meter-crawlers.md](use-case-meter-crawlers.md) - charge AI crawlers for the content they read.

## API gateway and traffic management

SBproxy's traditional reverse-proxy pillar: routing, load balancing, transforms, and the traffic-shaping layer underneath the AI and MCP features.

- [api-gateway.md](api-gateway.md) - the entry point for the traditional reverse-proxy pillar: routing, auth, rate limiting, WAF, load balancing, protocols, and OpenAPI, independent of any AI functionality. Start here if you're replacing Nginx, Envoy, or Kong.
- [routing.md](routing.md) - the hub for how a request gets matched to an upstream: hostname matching, forward rules, load balancing algorithms, protocol-specific actions (GraphQL, gRPC, gRPC-Web, WebSocket), and failover.
- [websocket.md](websocket.md) - the `websocket` action: config keys, upgrade semantics, what runs before the upgrade, `max_message_size` enforcement on the tunnel, and `subprotocols` negotiation.
- [grpc.md](grpc.md) - the `grpc` action: h2c and TLS listeners, passthrough, `grpc_web`, REST `transcode`, and the body-reading-policy stall. Offline example: [`examples/grpc-h2c/`](../examples/grpc-h2c/).
- [graphql.md](graphql.md) - the `graphql` action: transparent by default, fail-closed syntax validation (depth, introspection, batches) when enabled, and where in the pipeline it runs.
- [storage.md](storage.md) - the `storage` action (serve objects from S3, GCS, Azure, or local disk), plus the map of where the gateway persists its own state and which backends hold what.
- [routing-strategies.md](routing-strategies.md) - the `RoutingStrategy` trait: opt-in extension point for custom upstream selection inside `load_balancer`.
- [transforms.md](transforms.md) - what a transform is, the common transform fields, chaining and order, and one section per shipped transform kind (JSON shaping, text/encoding, HTML/Markdown, scripting transforms, WASM, agent content-shaping).
- [openapi-emission.md](openapi-emission.md) - publishing an OpenAPI 3.0.3 document (3.1 on request) from the live config.
- [openapi-validation.md](openapi-validation.md) - the `openapi_validation` policy: validating request bodies against an OpenAPI 3.0 document at startup.

## AI gateway

Route AI, govern the AI that calls you, and run AI models yourself.

- [ai-gateway.md](ai-gateway.md) - providers, routing strategies, guardrails, budgets, streaming.
- [guardrails.md](guardrails.md) - external guardrail adapters, response contract, failure policy, and a local tested walkthrough.
- [ai-policy-cel.md](ai-policy-cel.md) - the unified CEL policy plane: one sandboxed expression over guardrails, budgets, routing, and principal that emits a closed action set.
- [ai-guardrail-mesh.md](ai-guardrail-mesh.md) - the guardrail mesh: collect every verdict, fuse on a quorum, redact-and-continue, latency-budgeted cascade with a verdict cache.
- [ai-default-centroids-evaluation.md](ai-default-centroids-evaluation.md) - pinned classifier safety centroid artifact, held-out precision and recall, false-positive budget, and deterministic regeneration.
- [prompt-injection-v2.md](prompt-injection-v2.md) - the v2 guardrail: swappable detector returning score + label, with score-to-action mapping and a delegation-depth-aware action at the agent boundary.
- [classifier-sidecar.md](classifier-sidecar.md) - running the ONNX classifier as a sidecar instead of in-process, and when that trade is worth it.
- [ai-outcome-aware-routing.md](ai-outcome-aware-routing.md) - the `outcome_aware` strategy: route by realized cost-per-success fed back from completed requests.
- [intent-detection.md](intent-detection.md) - configure stock classifier-backed prompt intent and quality-based provider routing, including fail-open state visibility.
- [prompt-versioning.md](prompt-versioning.md) - live, scoped, stable weighted prompt rollouts with a config, admin, CLI, event, and metric contract.
- [ai-evaluation-harness.md](ai-evaluation-harness.md) - immutable dataset registration and offline evaluation of recorded responses through the live authenticated toolkit runtime.
- [ai-predictive-budget.md](ai-predictive-budget.md) - predictive budgets with soft-landing: warn, then downgrade, then block as a scope approaches its cap.
- [ai-llm-aware-resilience.md](ai-llm-aware-resilience.md) - classify upstream failures (timeout, rate-limit, context-window, content-policy) and set per-error retry counts.
- [ai-context-compression.md](ai-context-compression.md) - selectable compression profiles, explicit input budgets, Redis summary state, value accounting, evaluation, metrics, and logs.
- [rag.md](rag.md) - SBproxy in front of a RAG pipeline: gateway-side retrieval from five vector stores, plus marked-context governance, guardrails, and metering.
- [local-inference.md](local-inference.md) - run embeddings (semantic cache) and prompt-injection classify on local ONNX models via the sidecar or in-process.
- [ai-lb-benchmark.md](ai-lb-benchmark.md) - P50/P95/P99/P99.9 latency comparison across AI router strategies under skewed load.
- [providers.md](providers.md) - the catalog of supported LLM providers.

### Model hosting and self-hosting

- [self-hosting.md](self-hosting.md) - single binary to self-host: install, the serve-only quickstart, the model manifest, aliases, spill-to-cloud, and the OpenRouter parity map.
- [model-host.md](model-host.md) - canonical `proxy.model_host` deployments, verified artifacts, managed engines, admission, reload, and lifecycle CLI for one node.
- [model-host-capabilities.md](model-host-capabilities.md) - generated stable, preview, config-only, and unsupported contracts for model-host features and configuration fields.
- [gpu-fit-planning.md](gpu-fit-planning.md) - how the fit planner picks a quant for your GPU: capability tiers, the weights + KV math, throughput, and why it refuses an impossible config.
- [model-host-certification.md](model-host-certification.md) - the hardware evidence ledger: CPU contracts run in CI, Apple Silicon Metal and local multi-process gates have passed, and NVIDIA CUDA plus live GCP multi-node certification remain pending.
- [serving-engine-benchmark.md](serving-engine-benchmark.md) - vLLM vs SGLang head-to-head on one L4: throughput, prefix-cache behavior, and how the gateway picks an engine.
- [security-model-host.md](security-model-host.md) - trusted config, verified artifacts, typed process launch, engine acquisition, containers, credentials, and remaining isolation work.
- [custom-engines.md](custom-engines.md) - why there is no bring-your-own-image command template: the typed-driver seam, the OpenAI-compatible provider escape hatch, and the bar a signed engine descriptor would have to clear.

## MCP and agents

- [mcp-and-agents.md](mcp-and-agents.md) - the map across MCP (tool calling) and A2A (agent-to-agent) traffic: which doc covers which layer.
- [mcp.md](mcp.md) - the MCP gateway: wire shape, capabilities, and `experimental.agentSkillsUrl` advertising.
- [mcp-oauth-gateway.md](mcp-oauth-gateway.md) - standalone OAuth 2.1 broker (PKCE, DPoP, mTLS-bound tokens, device-code, CIMD, token exchange) for an MCP server not fronted by `sbproxy`, plus the resource-server companion that verifies the tokens it issues.
- [mcp-compose.md](mcp-compose.md) - `type: local` servers: config-declared tools (static, HTTP, or a step DAG), the interpolation vocabulary, DAG semantics, and template/JS/Lua response shaping.
- [mcp-gateway-guardrails.md](mcp-gateway-guardrails.md) - MCP gateway guardrails: egress, session risk, quarantine, stdio, run-as-user, and compaction.
- [mcp-security.md](mcp-security.md) - MCP and agent threat classes: tool poisoning, definition tampering, prompt injection in tool output, and tenant isolation.
- [mcp-security-coverage.md](mcp-security-coverage.md) - see [Security](#security).
- [admin-mcp.md](admin-mcp.md) - manage SBproxy from an MCP client: the gateway's own admin API as governed, read-only-by-default MCP tools for Claude Code or Cursor.
- [tool-versioning.md](tool-versioning.md) - the rollout plane (publish several versions of one tool, resolve per consumer, adapt, sunset) plus the compatibility oracle: a contract digest and a semver grade per tool, with a version-bump linter that fails an under-bump.
- [a2a-gateway.md](a2a-gateway.md) - the `a2a` action and policy: envelope trust, per-hop chain limits, push-notification target validation, typed AgentCard, and modality negotiation helpers.
- [agent-orchestration.md](agent-orchestration.md) - governed agent discovery and bounded finite-state workflows through the live authenticated toolkit runtime; not the same A2A as the entry above.
- [agent-skills.md](agent-skills.md) - Agent Skills v0.2.0 well-known projection: schema, integrity, archive safety, no-script-execution contract.
- [agent-registry.md](agent-registry.md) - agent identity: a signed catalog of known agents plus an owner-approval queue for agents that register themselves, both on one embedded store with no database behind it.
- [cloudflare-code-mode.md](cloudflare-code-mode.md) - typed TypeScript module emission for Cloudflare Code Mode agents over the MCP federation registry.
- [content-for-agents.md](content-for-agents.md) - operator guide to agent-aware content delivery: shape negotiation, body transforms, well-known license posture.
- [rsl.md](rsl.md) - RSL 1.0 licensing cookbook: expressing license stance via YAML and the resulting `/licenses.xml` projection.

## Payments and metering

- [payments.md](payments.md) - the map across three things that are easy to conflate: getting paid before serving a request, proving how much was consumed, and pricing AI crawler traffic.
- [payment-settlement.md](payment-settlement.md) - `proxy.payments`: charge for a request and prove it was paid before the origin is called.
- [payment-clustering.md](payment-clustering.md) - why a node running both `proxy.payments` and `proxy.cluster` refuses to start, and the staged path to a shared transactional store.
- [402-challenge.md](402-challenge.md) - the exact bytes of every payment challenge, credential, problem document, and receipt.
- [l402.md](l402.md) - L402 (Lightning HTTP 402) design notes: the protocol shape SBproxy would implement. None of it ships in the current binary.
- [ai-crawl-control.md](ai-crawl-control.md) - the `ai_crawl_control` policy: Pay Per Crawl token challenge and ledger trait.
- [comp-marketplace.md](comp-marketplace.md) - the `sbproxy-licensing` crate: IAB CoMP marketplace bridge (manifest, signed quote, redeem), bridging into the OSS OLP license-token wire format on redeem.
- [ai-usage-ledger.md](ai-usage-ledger.md) - the verifiable usage ledger: hash-chained, Ed25519-signed spend receipts you can re-derive and verify.
- [metering.md](metering.md) - attested metering: signed, hash-chained consumption receipts, the operator surface that reads and verifies the chain, and buyer-side verification against the published key set.
- [value-ledger-economics.md](value-ledger-economics.md) - the Value Ledger: local-vs-cloud lane split, reference prices, and the savings report at `/admin/model-host/value`.
- [ai-chargeback.md](ai-chargeback.md) - per-event usage attribution, team/workspace chargeback rollups, unified bill generation, and spend forecasting, layered onto the existing usage-sink seam.

## Scripting and extensibility

- [plugins.md](plugins.md) - the entry point for extending SBproxy: the five config-level surfaces (CEL, Rego, Lua, JavaScript, WASM), extension bundles, the four hook kinds, and the advanced linked-Rust-plugin path.
- [scripting.md](scripting.md) - CEL, Rego, Lua, JavaScript, and WASM scripting reference, including the offline `sbproxy rego test` loop.
- [opa-rego-policies.md](opa-rego-policies.md) - OPA-compatible policies (Rego): the Regorus interpreter in process, the input document, and when to choose Rego over CEL.
- [extension-bundles.md](extension-bundles.md) - adding policies, transforms, actions, HTTP filters, and event hooks as loadable bundles, from a local directory or a verified git checkout, without linking a new proxy binary.
- [wasm-development.md](wasm-development.md) - writing WebAssembly modules for the `wasm` transform against the WASI preview-1 contract.
- [key-management.md](key-management.md) - dynamic virtual keys: mint, revoke, and rotate at runtime through the admin API, hashed at rest, with a fail-closed policy cache.

## Connect clients

Point a framework you already run at the gateway: chat completions through the OpenAI-compatible endpoint, tools through the MCP gateway. Every snippet on these pages was validated against a running proxy.

- [langchain.md](langchain.md) - LangChain (python): any provider through ChatOpenAI at the gateway, native ChatAnthropic on `/v1/messages`, MCP tools via langchain-mcp-adapters.
- [vercel-ai-sdk.md](vercel-ai-sdk.md) - Vercel AI SDK (typescript): the openai-compatible provider, MCP tools via the AI SDK's MCP client.
- [pydantic-ai.md](pydantic-ai.md) - Pydantic AI (python): OpenAIChatModel through the gateway, MCP toolsets on an Agent.
- [mastra.md](mastra.md) - Mastra (typescript): agents on a gateway-backed model, tools from the MCP client.
- [n8n.md](n8n.md) - n8n: the OpenAI credential's base URL, the MCP Client Tool node, and federating n8n's own MCP trigger.

## Policies

- [policy.md](policy.md) - the policy catalog: all 30 policy types grouped as traffic-shape/abuse, identity/access, content/input safety, AI-specific, enrichment, and scripting-driven, each linked to wherever it's documented.
- [cedar-policy.md](cedar-policy.md) - Cedar ABAC on MCP `tools/call`: compile-at-load, empty entity store, `sbproxy cedar replay`, Confirm park plus admin queue. Runnable: [`examples/cedar-mcp-full/`](../examples/cedar-mcp-full/), [`examples/cedar-confirm-flow/`](../examples/cedar-confirm-flow/), [`examples/cedar-replay/`](../examples/cedar-replay/).
- [object-authz.md](object-authz.md) - `object_authz` policy: BOLA + BFLA enforcement with tenant-isolation and enumeration detection.
- [waf-options.md](waf-options.md) - what the 16-rule WAF baseline catches and what it does not, and the three alternatives when you need more.
- [exposed-credentials.md](exposed-credentials.md) - the `exposed_credentials` policy: detect known-leaked basic-auth passwords and tag or block.
- [agent-budget.md](agent-budget.md) - `agent_budget` policy: semantic rate-limit primitive keyed on resolved agent identity.
- [content-digest.md](content-digest.md) - `content_digest` policy: RFC 9530 request-body verification for integrity-critical inboxes.
- [anomaly-detection.md](anomaly-detection.md) - the rolling per-agent-class histogram that flags long-tail TLS fingerprints, headless libraries, and per-address rate spikes, and the reputation score it feeds.
- [headless-detection.md](headless-detection.md) - header-only headless / stealth-browser indicator heuristics surfaced under `request.agent.headless_*`.
- [request-enrichment.md](request-enrichment.md) - the `geoip` and `user_agent_parser` policies: typed GeoIP and User-Agent producers for identity and anomaly hooks, never denying traffic.
- [feature-flags.md](feature-flags.md) - the sticky-bucketing flag store plus the `flag_enabled(name, key)` CEL helper.

## Security

- [security.md](security.md) - the security map: what the gateway enforces, what stays with your services, and which gaps are real.
- [threat-model.md](threat-model.md) - trust boundaries and per-wave review checklist.
- [api-security.md](api-security.md) - API threat classes and the policy configuration for each, from object-level authorization to bot traffic.
- [owasp-api-top10.md](owasp-api-top10.md) - the `owasp_api_top10` policy pack: what each of the ten OWASP API Security Top 10 (2023) items synthesizes, its default posture and why, the report_only-to-enforce path, what an operator still has to supply, and the honest not-covered items.
- [ai-gateway-security-coverage.md](ai-gateway-security-coverage.md) - the eight gateway-layer controls no published list covers, and a row-by-row OWASP LLM Top 10 (2026) mapping, each claim backed by a named test or signal and every limit paired with its rationale.
- [mcp-security-coverage.md](mcp-security-coverage.md) - a row-by-row OWASP MCP Top 10 mapping, coverage stated as full, partial, or out of gateway scope, each claim backed by a named test or config example.
- [mcp-security.md](mcp-security.md) - see [MCP and agents](#mcp-and-agents).
- [authentication.md](authentication.md) - the chooser over all twelve inbound auth providers: which fits which caller, accepting several on one origin (credential migrations), and what the gateway does with the resulting identity.
- [auth-oidc.md](auth-oidc.md) - the `oidc` auth provider: OpenID Connect Relying-Party login flow (authorization-code + PKCE, sealed session cookie, optional userinfo trust-header projection, RP-initiated logout).
- [federation.md](federation.md) - `proxy.federation`: the OpenID Federation 1.0 entity statement this proxy publishes, and `peer_trust`, which walks a caller's claimed entity to a pinned anchor on the request path. Also the `sbproxy-federation` crate behind it (JWS sign/verify, RFC 7638 key thumbprints, metadata policy, trust marks, trust-chain resolution) for establishing trust between independently-operated gateways.
- [web-bot-auth.md](web-bot-auth.md) - the `bot_auth` provider: verifying RFC 9421-signed AI crawlers against a published key directory.
- [cap.md](cap.md) - the `cap` provider: verifying Crawler Authorization Protocol capability tokens (path globs, rate grants, agent binding) against an issuer's JWKS.
- [trust-tiers.md](trust-tiers.md) - the four-value trust tier every request gets (`suspicious`, `strong`, `named`, `anonymous`), what earns each, and how policies and dashboards consume it.
- [outbound-dpop.md](outbound-dpop.md) - RFC 9449 sender-constrained OAuth credentials and per-request proof minting for upstream calls.
- [secrets.md](secrets.md) - the secret-reference vocabulary (env vars, files, provider URIs) resolved everywhere in config, plus backend setup for HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Kubernetes Secrets.

## Observability and operations

- [access-log.md](access-log.md) - structured JSON access log: filters, sampling, header capture, redaction.
- [audit-log.md](audit-log.md) - tamper-evident audit log of admin actions.
- [observability.md](observability.md) - metrics, logs, traces, and the bundled dashboards.
- [clickhouse-attribution.md](clickhouse-attribution.md) - access-log schema, pre-aggregations, and sample attribution queries.
- [events.md](events.md) - the twenty-three typed events, the `events:` file and webhook sinks, decision-audit, and how the pieces fit into a SIEM integration.
- [notifications.md](notifications.md) - outbound webhook subscriptions for the customer-facing side of the same events: many destinations with their own filters and signing keys, bounded retries, and a deadletter queue with replay.
- [event-ingest.md](event-ingest.md) - the two optional destinations for the request-event stream, a NATS subject tree and a ClickHouse table, plus the delivery watermark that replaces a reconciliation table.
- [metrics-stability.md](metrics-stability.md) - Prometheus metric naming and stability.
- [decision-records.md](decision-records.md) - what a SIEM consumer may rely on from the decision-audit feed.
- [operator-runbook.md](operator-runbook.md) - the `runbook_id` index every paging alert resolves through, a response section per id, plus dashboard triage and rollback actions.
- [performance.md](performance.md) - tuning guide, benchmark methodology, profiling.
- [capacity-planning.md](capacity-planning.md) - how big a pod: what memory is and is not measured, the commands that fill the gaps, a `resources:` starting point with its arithmetic shown, and OOM triage.
- [degradation.md](degradation.md) - failure modes and graceful degradation behavior.

## Deployment

- [multi-tenant.md](multi-tenant.md) - when to use the multi-tenant shape, the three scopes, isolation guarantees, the synthetic `__default__` tenant.
- [mesh-replication.md](mesh-replication.md) - the replicated cluster-state substrate: replication factor, read/write consistency, durable restart, handoff, anti-entropy, and the tombstone deletion protocol.
- [quickstart-operator.md](quickstart-operator.md) - first 24 hours running the Kubernetes operator.
- [kubernetes.md](kubernetes.md) - the Kubernetes operator and its CRDs.
- [gateway-api.md](gateway-api.md) - the Gateway API controller: which `gateway.networking.k8s.io/v1` fields it translates, the status conditions it writes, and the explicit list of what it does not support.
- [sidecar-deployment.md](sidecar-deployment.md) - running sbproxy as a per-pod sidecar: traffic capture (iptables / eBPF), service-mesh integration (Istio, Linkerd), and the kustomize overlay under `deploy/k8s/sidecar/`.
- [upgrade.md](upgrade.md) - migration notes between releases.

## Migration and upgrading

- [migration-credentials.md](migration-credentials.md) - migrating the legacy `virtual_keys:` shape to the unified `credentials:` block.
- [migration-mcp-rbac.md](migration-mcp-rbac.md) - upgrading MCP `ToolAccessPolicy` to the principal-aware ACL and the default-deny flip.
- [migration-litellm.md](migration-litellm.md) - moving a LiteLLM proxy to SBproxy with `config import-litellm` and the field-by-field mapping.
- [comparison.md](comparison.md) - pinned capability rows (clustering, rate limiting, PROXY protocol). The long competitor matrix is retired; start from [architecture.md](architecture.md).

## Release notes

- [release-notes.md](release-notes.md) - what changed recently, grouped by category (API gateway, routing, transforms, plugins, policies, security, AI gateway, MCP and agents, payments, observability, deployment, reference) instead of by date.
- [CHANGELOG.md](../CHANGELOG.md) - the complete chronological record with exact version boundaries.

## Reference

- [admin-api-reference.md](admin-api-reference.md) - per-route schema for the embedded admin server (`/api/*`, `/admin/*`, and the unauthenticated probe routes).
- [config-stability.md](config-stability.md) - field stability guarantees and versioning.
- [config-authority-drills.md](config-authority-drills.md) - two-process certification drills for signed config distribution.
- [listings.md](listings.md) - the repo-native `Listing` primitive: schema, loader, three pinning modes, plan-validation rules.
- [bulk-redirects.md](bulk-redirects.md) - the `redirect` action's source-to-destination row list, compiled at load time into an O(1) path lookup.
- [cache-reserve.md](cache-reserve.md) - long-tail cold tier under the response cache: backends (memory, filesystem, Redis, object storage) and admission sampling.
- [glossary.md](glossary.md) - vocabulary used in this documentation set.
- [headers-reference.md](headers-reference.md) - every response header the proxy can emit, with the config that triggers it.
- [model-pinning.md](model-pinning.md) - how SHA-256 hashes get computed and pinned for the classifier known-model registry.

## Contribute

- [architecture.md](architecture.md) - internals: pipeline, hot reload, plugin system.
- [build.md](build.md) - building from source, supported platforms, optional features.
- [CONTRIBUTING.md](../CONTRIBUTING.md) - how to set up a dev environment and submit changes.

## Machine-readable documentation

- [llms.txt](llms.txt) - flat capability catalog (one line per shipped feature), per the [llmstxt.org](https://llmstxt.org/) convention. The small index AI tools fetch first.
- [llms-full.txt](llms-full.txt) - the entire docs corpus (this directory + the top-level `README.md`, `MIGRATION.md`, `CHANGELOG.md`) flattened into one file so AI tools that want the full set get it in one HTTP request. Generated; do not hand-edit and do not commit it on a branch. CI regenerates it on `main` after a docs change merges. Mirrored live at <https://sbproxy.dev/llms-full.txt>.
