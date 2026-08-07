# SBproxy Features Hub

SBproxy is a high-performance reverse proxy and AI gateway built on Cloudflare's Pingora framework. It unifies traditional API proxying, AI model routing, Agent-to-Agent (A2A) communication, Model Context Protocol (MCP) tool integration, and Agent-specific workflows into a single binary.

This document breaks down SBproxy's capabilities into five core domains: **API**, **AI**, **MCP**, **A2A**, and **Agent**. For each area, you'll find a discussion of what the codebase does and links to the relevant deep-dive documentation and runnable examples.

---

## 1. API: Traditional Reverse Proxy & Gateway

At its core, SBproxy is an extremely capable reverse proxy with advanced traffic shaping and zero-downtime configuration reload: a candidate config is validated, constructed with rollback on failure, and committed atomically, while in-flight requests finish on the config snapshot they started with. Binary upgrades use rolling restarts; see [Upgrade](upgrade.md).

### Core Proxy & Routing
SBproxy routes traffic based on exact hostnames and dynamic forward rules. It supports complex deployment patterns like blue-green and canary rollouts.
* **Docs:** [Configuration Schema](configuration.md), [Routing & Fallback](routing-strategies.md)
* **Examples:** [Basic Proxy](../examples/basic-proxy/), [Forward Rules](../examples/forward-rules/), [Host Override](../examples/host-override/), [gRPC H2C](../examples/grpc-h2c/), [Error Pages](../examples/error-pages/), [Headers & CORS](../examples/headers-and-cors/), [Compression](../examples/compression/)

### Load Balancing & Health Checks
Traffic can be distributed across upstream targets using 7 algorithms (including round-robin, least connections, and consistent hashing). Active health checks proactively remove failing targets from the pool.
* **Docs:** [Performance & Load Balancing](performance.md), [Architecture](architecture.md)
* **Examples:** [Load Balancer](../examples/load-balancer/), [Active Health Checks](../examples/active-health-checks/), [Circuit Breaker](../examples/circuit-breaker/), [LB Deployment](../examples/load-balancer-deployment/)

### Authentication & Authorization
Protect your endpoints with 7 built-in authentication types: API Keys, Basic Auth, Bearer tokens, JWT (with JWKS), Forward Auth, Digest, and mTLS. You can also enforce fine-grained access control.
* **Docs:** [OIDC Auth](auth-oidc.md), [Object Authz](object-authz.md), [Key Management](key-management.md), [Web Bot Auth](web-bot-auth.md)
* **Examples:** [Auth JWT](../examples/auth-jwt/), [Auth Forward](../examples/auth-forward/), [mTLS Client Auth](../examples/mtls-client-auth/), [API Key](../examples/auth-api-key/), [Basic Auth](../examples/auth-basic/), [Bearer Token](../examples/auth-bearer/), [Bearer DPoP](../examples/auth-bearer-dpop/), [CAP Auth](../examples/auth-cap/), [Inbound Keys](../examples/keys-inbound-headers/), [Sessions](../examples/sessions/)

### Security & Guardrails
A built-in Web Application Firewall (WAF) screens requests before they hit your upstream. It ships a curated, CRS-derived baseline of 16 rules: 4 built-in patterns plus a 12-rule managed bundle with CRS-style IDs and paranoia levels. The rule set extends through a signed remote rule feed, verified with HMAC-SHA256, cached on disk, and rejected when older than a configured staleness bound, and repeat offenders can be blocked persistently through strike-based blocking. Operators who need full OWASP CRS coverage (anomaly scoring, transformation pipelines, body processors) should put ModSecurity, Coraza, or a CDN WAF in front and keep SBproxy's WAF as a baseline layer. SBproxy also mitigates DDoS attacks and HTTP request smuggling, and enforces token-bucket rate limiting.
* **Docs:** [Threat Model](threat-model.md), [Exposed Credentials](exposed-credentials.md), [Security Model Host](security-model-host.md)
* **Examples:** [WAF](../examples/waf/), [DDoS Protection](../examples/ddos-protection/), [Rate Limiting](../examples/rate-limiting/), [IP Filter](../examples/ip-filter/), [CSRF](../examples/csrf/), [Defense in Depth](../examples/defense-in-depth/), [DLP Catalog](../examples/dlp-catalog/), [HSTS](../examples/hsts/), [Page Shield](../examples/page-shield/), [Security Headers](../examples/security-headers/), [SRI](../examples/sri/), [Request Limit](../examples/request-limit/)

### Scripting & Custom Transforms
When declarative config isn't enough, inject custom logic via Lua, JavaScript, WebAssembly (WASM), or CEL expressions. You can rewrite headers, transform payloads, and implement bespoke policies. Package complex behaviors with Extension Bundles.
* **Docs:** [Scripting Guide](scripting.md), [Extension Bundles](extension-bundles.md), [Custom Engines](custom-engines.md), [WASM Development](wasm-development.md)
* **Examples:** [CEL Policy](../examples/cel-policy/), [Transform Lua](../examples/transform-lua/), [WASM Transform](../examples/wasm-transform/), [Javascript](../examples/transform-javascript/), [JSON](../examples/transform-json/), [JSON Projection](../examples/transform-json-projection/), [JSON Schema](../examples/transform-json-schema/), [Markdown](../examples/transform-markdown/), [Payload Limit](../examples/transform-payload-limit/), [Replace Strings](../examples/transform-replace-strings/), [Template](../examples/transform-template/), [Variables](../examples/variables-template/), [Encoding](../examples/transform-encoding/), [Storage Action](../examples/storage-action/)

### OpenAPI & Admin APIs
Dynamically emit OpenAPI specs for your routes, and validate incoming traffic against them. The Admin API allows real-time metric querying and configuration updates.
* **Docs:** [Admin API Guide](admin-api-guide.md), [OpenAPI Emission](openapi-emission.md), [OpenAPI Validation](openapi-validation.md)
* **Examples:** [OpenAPI Emission](../examples/openapi-emission/), [OpenAPI Validation](../examples/openapi-validation/)

---

## 2. AI: Advanced Model Gateway

The `ai_proxy` action turns SBproxy into an OpenAI-compatible API gateway capable of routing requests to 72 native providers and over 200 models.

### Provider Integration & Model Routing
Send standard chat completion requests to the proxy, and it routes them based on the model name. You can configure multiple providers and utilize fallback chains to ensure high availability.
* **Docs:** [AI Gateway](ai-gateway.md), [Providers List](providers.md), [Local Inference](local-inference.md), [Model Host](model-host.md)
* **Examples:** [AI Multi-Provider](../examples/ai-multi-provider/), [AI OpenRouter](../examples/ai-openrouter/), [AI Local Serving](../examples/ai-local-serving/), [Bedrock Direct](../examples/ai-bedrock-direct/), [Gemini Direct](../examples/ai-gemini-direct/), [Model Group](../examples/ai-model-group/), [Streaming](../examples/ai-streaming/)

### Smart Routing & Resilience
Go beyond round-robin with LLM-aware routing strategies like lowest latency, least token usage, cost-optimized, cascade, or outcome-aware routing. The gateway categorizes upstream failures and retries intelligently.
* **Docs:** [AI LLM Aware Resilience](ai-llm-aware-resilience.md), [AI Outcome Aware Routing](ai-outcome-aware-routing.md), [AI Load Balancer Benchmark](ai-lb-benchmark.md)
* **Examples:** [AI Cascade Routing](../examples/ai-cascade-routing/), [AI Outcome Aware Routing](../examples/ai-outcome-aware-routing/), [AI Resilience](../examples/ai-resilience/), [Cost Optimized](../examples/ai-cost-optimized/), [Routing Fallback](../examples/ai-routing-fallback/)

### Budgets & Metering
Enforce hard or soft budgets on AI spend by workspace, user, or key. SBproxy calculates token counts and USD costs locally, emitting metrics for attribution and saving tamper-evident logs.
* **Docs:** [AI Predictive Budget](ai-predictive-budget.md), [AI Usage Ledger](ai-usage-ledger.md), [Value Ledger Economics](value-ledger-economics.md), [Metering](metering.md)
* **Examples:** [AI Budget](../examples/ai-budget/), [AI Usage Ledger](../examples/ai-usage-ledger/), [Metering Verify](../examples/metering-verify/), [Model Rate Limits](../examples/ai-model-rate-limits/), [Surface Rate Limits](../examples/ai-per-surface-rate-limits/), [Waste Signals](../examples/ai-waste-signals/), [Attribution Tags](../examples/ai-attribution-tags/)

### Guardrails & Policy
Apply input/output guardrails using local classifiers or external APIs to detect toxicity, jailbreaks, and PII. You can use the Guardrail Mesh to fuse multiple safety verdicts and write complex rules with the AI CEL policy plane.
* **Docs:** [Guardrails](guardrails.md), [AI Guardrail Mesh](ai-guardrail-mesh.md), [AI Policy CEL](ai-policy-cel.md), [Prompt Injection](prompt-injection-v2.md), [Classifier Sidecar](classifier-sidecar.md)
* **Examples:** [AI Guardrails](../examples/ai-guardrails/), [AI Safety Classifiers](../examples/ai-safety-classifiers/), [AI Regex DLP](../examples/ai-regex-dlp/)

### Context Compression & Caching
Reduce token costs and latency by stripping redundant context from prompts or using semantic caching to serve identical queries directly from the proxy edge.
* **Docs:** [AI Context Compression](ai-context-compression.md), [Cache Reserve](cache-reserve.md)
* **Examples:** [AI Context Compression Redis](../examples/ai-context-compression-redis/), [Semantic Cache Local](../examples/semantic-cache-local/), [Response Caching](../examples/response-caching/), [Context Compression Mesh](../examples/ai-context-compression-mesh/), [Origin Keys Cache](../examples/response-cache-per-origin-keys/)

---

## 3. MCP: Model Context Protocol

SBproxy acts as an MCP gateway, allowing AI models and agents to securely discover and execute tools within your infrastructure.

### MCP Federation & Routing
Federate multiple MCP servers behind a single SBproxy endpoint. Agents can seamlessly discover capabilities across your microservices while SBproxy handles authentication and routing.
* **Docs:** [MCP Overview](mcp.md), [Use Case: MCP Federation](use-case-mcp-federation.md)
* **Examples:** [MCP Federation](../examples/mcp-federation/), [MCP Code Mode](../examples/mcp-code-mode/)

### Security & RBAC
Restrict which agents can call which tools. SBproxy's MCP implementation includes robust Role-Based Access Control (RBAC), quotas, and guardrails specifically designed for tool execution.
* **Docs:** [Migration: MCP RBAC](migration-mcp-rbac.md), [MCP Gateway Guardrails](mcp-gateway-guardrails.md)
* **Examples:** [MCP RBAC Quotas](../examples/mcp-rbac-quotas/)

### Tool Versioning & Discovery
Manage the lifecycle of your MCP tools with progressive discovery and strict tool versioning, ensuring that agents always interact with compatible tool schemas.
* **Docs:** [Tool Versioning](tool-versioning.md)
* **Examples:** [MCP Tool Versioning](../examples/mcp-tool-versioning/), [MCP Tool Rollout](../examples/mcp-tool-rollout/), [MCP Progressive Discovery](../examples/mcp-progressive-discovery/)

---

## 4. A2A: Agent-to-Agent Communication

As multi-agent systems grow, SBproxy facilitates the complex web of communication between autonomous agents.

### A2A Gateway
SBproxy provides a dedicated gateway layer for Agent-to-Agent interactions. It normalizes protocols, handles identity verification between agents, and ensures that asynchronous messages and capability handoffs occur reliably.
* **Docs:** [A2A Gateway](a2a-gateway.md)
* **Examples:** [A2A Protocol](../examples/a2a-protocol/), [A2A Prompt Injection](../examples/a2a-prompt-injection/)

---

## 5. Agent: Dedicated Agent Workflows

Beyond standard API and AI proxying, SBproxy ships with features tailored explicitly for the needs of autonomous agents navigating the web and consuming APIs.

### Agent Identity & Skills
Provision unique identities for your agents and equip them with specific skills. SBproxy tracks agent behavior and authorizes actions based on their assigned identities.
* **Docs:** [Getting Started: Agent Identity](getting-started-agent-identity.md), [Agent Skills](agent-skills.md)
* **Examples:** [Agent Skills](../examples/agent-skills/)

### Agent Budgets & Crawl Control
Agents can operate autonomously, which means they can rack up costs or aggressively scrape resources. Enforce strict agent-specific budgets and utilize crawl control mechanisms to throttle autonomous scraping behavior.
* **Docs:** [Agent Budget](agent-budget.md), [AI Crawl Control](ai-crawl-control.md), [Use Case: Meter Crawlers](use-case-meter-crawlers.md)
* **Examples:** [Agent Budget](../examples/agent-budget/), [AI Crawl Control](../examples/ai-crawl-control/)

### Content for Agents
Serve content formatted specifically for LLM consumption. SBproxy can dynamically strip heavy HTML, inject markdown, or serve `llms.txt` files to optimize the context window for visiting agents.
* **Docs:** [Content for Agents](content-for-agents.md)
* **Examples:** [Markdown for Agents](../examples/markdown-for-agents/), [Transform HTML to Markdown](../examples/transform-html-to-markdown/), [Robots LLMs txt](../examples/robots-llms-txt/)
