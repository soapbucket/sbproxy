# SBproxy examples
*Last modified: 2026-04-26*


Runnable sample configurations covering every major feature. Each example is a self-contained `sb.yml` you can point the binary at directly, with curl commands in the file header showing how to exercise it.

## Prerequisites

Build the binary once from the repo root:

```bash
make build           # debug build
make build-release   # optimised
```

`make run CONFIG=<path>` launches the proxy with whichever config you specify. All examples bind to `127.0.0.1:8080` and use a fictional `*.local` Host header so multiple examples can coexist on the same port without DNS.

## Running an example

```bash
make run CONFIG=examples/basic-proxy/sb.yml          # default
make run CONFIG=examples/transform-json/sb.yml LOG_LEVEL=debug
```

Each `sb.yml` opens with a comment block listing the curl commands to drive it.

## Catalog

Auto-generated index of every example. Each row links to the example's
directory (with its `sb.yml` and README). Regenerated from `examples/` on 2026-05-31.

| Example | Description |
|---|---|
| [a2a-protocol](a2a-protocol/) | The `a2a` policy enforces per-route safety on agent-to-agent traffic. Detection runs once per request and matches three signals: `Content-Type: applic |
| [access-log](access-log/) | Structured JSON access log on stdout, ready for Fluent Bit / Vector / any stdout-tailing log shipper. Exercises every commonly-used knob on the top-level `access_log:` block: status and method filters, sampling, request and response header capture with the PII redactor, and the always-on secret redactor. |
| [active-health-checks](active-health-checks/) | A round-robin load balancer with two targets: `test.sbproxy.dev` and `test.sbproxy.dev/status/503` (an always-503 alias on the same host so the example shows the proxy detecting and routing around the unhealthy upstream). Each target has a `health_check` block, so the proxy runs a backgroun |
| [agent-budget](agent-budget/) | Demonstrates the `agent_budget` policy. Per-agent rate-limit primitive keyed on the resolved `agent_id` (from the agent-class resolver). One bucket pe |
| [agent-skills](agent-skills/) | Demonstrates the Agent Skills v0.2.0 well-known projection. SBproxy |
| [ai-agent-alignment](ai-agent-alignment/) | The `agent_alignment` guardrail audits the assistant's `tool_calls` array against an operator-declared ruleset (allow + deny lists, forbidden-substring matchers, argument validators). Catches an off-policy tool selection before it leaves the gateway. |
| [ai-attribution-tags](ai-attribution-tags/) | Tokenomics: tag every AI request with the operator's project / feature / team / customer / env / agent_type / risk_tier / trace_id so the spend record lands on the right dashboard row and the downstream Token-to-Value Ledger can join token spend to business outcomes. Per-credential `attrs:` defaults compose with per-request `SB-Attr-<Key>` headers. |
| [ai-bedrock-direct](ai-bedrock-direct/) | Direct integration with AWS Bedrock's model-agnostic Converse API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to the |
| [ai-budget](ai-budget/) | Two stacked budget limits with `on_exceed: downgrade`. The workspace-wide cap allows up to USD 500 of spend per month and downgrades to `claude-3-5-ha |
| [ai-cascade-routing](ai-cascade-routing/) | The `cascade` strategy walks an ordered list of `(provider, model)` tiers from cheapest to most expensive. Each tier's response is graded against a `q |
| [ai-cel-tenant-gate](ai-cel-tenant-gate/) | A proxy-native pattern: a CEL expression runs at the network layer before any AI provider is contacted. Pure AI gateway libraries cannot reject a requ |
| [ai-claude](ai-claude/) | Direct integration with the Anthropic Messages API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to Anthropic's `/v1/m |
| [ai-context-poisoning](ai-context-poisoning/) | A single Anthropic origin with the `context_poisoning` input guardrail enabled. The guardrail inspects the full input, including any retrieved content |
| [ai-cost-optimized](ai-cost-optimized/) | The `cost_optimized` strategy scores each provider as `in_flight_requests * 1000 + weight` and routes to the lowest score. Cheaper providers get a low |
| [ai-crawl-control](ai-crawl-control/) | The `ai_crawl_control` policy returns HTTP 402 Payment Required to known AI crawler User-Agents that arrive without a `Crawler-Payment` token. The 402 |
| [ai-crawl-tiered](ai-crawl-tiered/) | Demonstrates a three-tier paywall in front of an article-publishing |
| [ai-gemini-direct](ai-gemini-direct/) | Direct integration with the Google Gemini API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to Gemini's `:generateCont |
| [ai-guardrails](ai-guardrails/) | A full guardrail stack on a single Anthropic origin. Three input guardrails inspect the prompt before any upstream call: `injection` uses the built-in |
| [ai-mixed-traffic](ai-mixed-traffic/) | Pure AI gateway libraries assume the host is "the AI gateway" and that everything that lands on it should hit a model. A real proxy can do more: serve |
| [ai-model-rate-limits](ai-model-rate-limits/) | Different models cost and behave differently, so they each need their own rate cap. The `model_rate_limits` map keys by model name and applies sliding |
| [ai-multi-provider](ai-multi-provider/) | A two-provider AI gateway with input guardrails and a soft budget cap. The `fallback_chain` strategy tries Anthropic first (priority 1) and falls back |
| [ai-openrouter](ai-openrouter/) | Routes OpenAI-compatible chat completion requests through OpenRouter. Clients speak the OpenAI protocol; SBproxy injects the OpenRouter API key, forwa |
| [ai-per-surface-rate-limits](ai-per-surface-rate-limits/) | Different OpenAI surfaces have different cost and capacity profiles. Chat completions are cheap and high volume; image generation is slow and expensiv |
| [ai-race](ai-race/) | Race strategy fans out the request to every eligible provider in parallel, returns the first 2xx response, and cancels the losers. Trade-off: race min |
| [ai-regex-dlp](ai-regex-dlp/) | Built-in PII detection covers the obvious patterns (email, phone, SSN, credit card). Real organisations have their own confidential vocabulary: projec |
| [ai-resilience](ai-resilience/) | Three independent resilience signals run on the AI provider pool. Any one can eject a provider from the routing list. (1) `circuit_breaker` is the cla |
| [ai-routing-fallback](ai-routing-fallback/) | Three providers in priority order. Provider 1 (`broken-anthropic`) is intentionally configured with an invalid API key so it always returns 401. The r |
| [ai-shadow](ai-shadow/) | Each request is forwarded to the primary provider as usual; a copy is also sent to the shadow provider concurrently. The shadow response is drained an |
| [ai-streaming](ai-streaming/) | Streaming is on by default in the AI gateway. The minimal Anthropic origin in this example handles `"stream": true` requests end-to-end: sbproxy opens |
| [ai-virtual-keys](ai-virtual-keys/) | Two virtual keys, two teams, two budgets. The frontend team's key is allowlisted to `claude-3-5-haiku-latest` only, capped at 30 RPM and 60,000 TPM, w |
| [ai-waste-signals](ai-waste-signals/) | Tokenomics: Prometheus counters for tokens spent with no outcome, partitioned by waste class (`duplicate_request`, `abandoned_stream`, `validation_failed`, `context_bloat`) and attribution (project, team). Observational only; pair with `ai-budget` for enforcement and `ai-attribution-tags` for the grouping labels. |
| [audit-log](audit-log/) | Every state-mutating admin call emits a typed `AdminAuditEvent` envelope on the structured-log stream. Pairs with `access-log` to see both streams side by side. Bound on the admin server's loopback `:9090` with basic-auth; `/admin/reload` is the canonical mutation to trigger. |
| [auth-api-key](auth-api-key/) | Enforces an API key check before any upstream call. The `api_key` authentication provider compares the value of the configured header (`X-Api-Key`) ag |
| [auth-basic](auth-basic/) | Two-user HTTP Basic auth with a custom realm (`"sbproxy demo"`). Useful for quick admin panels and small internal tools. Requests without credentials  |
| [auth-bearer](auth-bearer/) | Accepts a fixed allowlist of opaque service tokens in the `Authorization: Bearer <token>` header. Pick this when callers are services that already man |
| [auth-bearer-dpop](auth-bearer-dpop/) | RFC 9449 DPoP-bound Bearer tokens. A stolen token alone is not enough: the request must come with a valid DPoP proof whose JWK thumbprint matches the operator-stamped `dpop_jkt` on the matched token entry. |
| [auth-cap](auth-cap/) | Validates Crawler Authorization Protocol (CAP) tokens on every request. CAP tokens are EdDSA-signed JWTs bound to an agent identity (`sub`), a request |
| [auth-forward](auth-forward/) | Delegates the authentication decision to an external HTTP service. For each inbound request, sbproxy issues a sub-request to the configured URL (`http |
| [auth-jwt](auth-jwt/) | Validates HS256 JWTs against a static HMAC secret (`dev-secret-change-me`). The JWT must carry the configured issuer (`https://issuer.local`) and audi |
| [basic-proxy](basic-proxy/) | The simplest possible sbproxy configuration. A single origin keyed on `myapp.example.com` forwards every inbound request to `https://test.sbproxy.dev` |
| [bulk-redirects](bulk-redirects/) | Each origin owns its own redirect list, compiled at config-load into an O(1) lookup keyed on the request path. Three sources are supported: inline `ro |
| [cel-policy](cel-policy/) | Demonstrates the `expression` policy, which evaluates a CEL expression per request and decides whether to allow it. This config admits requests only w |
| [circuit-breaker](circuit-breaker/) | Demonstrates the `circuit_breaker` block on a `load_balancer` action. The breaker is a formal Closed -> Open -> HalfOpen state machine, one instance p |
| [compression](compression/) | Enables response compression on `api.local` for brotli, gzip, and zstd. The first algorithm in `algorithms` that the client advertises in `Accept-Enco |
| [concurrent-limit](concurrent-limit/) | Demonstrates the `concurrent_limit` policy. The limiter caps the number of in-flight requests per key, distinct from the requests-per-second `rate_lim |
| [connection-pool](connection-pool/) | The `connection_pool` block on `api.local` sizes the proxy's outbound HTTP client for this origin. `max_connections: 32` caps concurrent in-flight ups |
| [content-digest](content-digest/) | Demonstrates the `content_digest` policy on a webhook receiver. The proxy hashes every inbound body and compares the result to the `Content-Digest:` h |
| [content-shape-negotiation](content-shape-negotiation/) | Same URL, three response shapes. The proxy reads the agent's `Accept` header on the way in, resolves a single content shape per request, and the respo |
| [correlation-id](correlation-id/) | The proxy mints a per-request correlation ID early in the request lifecycle. With the default policy, an inbound `X-Request-Id` is adopted as-is so up |
| [csrf](csrf/) | Demonstrates the `csrf` policy. Safe methods (`GET`, `HEAD`, `OPTIONS`) are exempt and serve as the channel through which the proxy issues the `csrf_t |
| [ddos-protection](ddos-protection/) | Demonstrates the `ddos_protection` policy. The proxy tracks a sliding 1-second window per source IP. When the rate exceeds `request_rate_threshold: 10 |
| [defense-in-depth](defense-in-depth/) | Layered authentication, authorisation, and inspection on a single origin. The chain answers a different question at each layer: `ip_filter` (is this s |
| [dlp-catalog](dlp-catalog/) | The `dlp` policy scans the request URI and headers for matches against the configured detector set, then either tags the upstream request with a `dlp- |
| [error-pages](error-pages/) | The origin on `api.local` is protected by API key authentication (`X-Api-Key: secret-key`). Requests that miss the key get a 401 from the proxy, which |
| [exposed-credentials](exposed-credentials/) | When a request carries `Authorization: Basic <base64>` whose password matches the configured exposure list, the proxy stamps the upstream request with |
| [fallback-origin](fallback-origin/) | The primary action proxies to `test.sbproxy.dev/status/503`, which always returns 503. The `fallback_origin` block defines a backup origin served when the  |
| [forward-rules](forward-rules/) | A single origin on `gateway.local` dispatches incoming requests to three different inline child origins based on path. Requests to `/api/*` proxy to ` |
| [forwarding-headers](forwarding-headers/) | The proxy injects a standard set of forwarding headers on every upstream request: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Pro |
| [grpc-h2c](grpc-h2c/) | Proxies plaintext gRPC traffic to an upstream gRPC server. gRPC requires HTTP/2 end-to-end, so the proxy's plain HTTP listener must speak HTTP/2 clear |
| [headers-and-cors](headers-and-cors/) | Combines three sibling blocks on one origin: `request_modifiers` injects `X-Forwarded-By: sbproxy` and a freshly generated `X-Trace-Id` (from the `uui |
| [host-override](host-override/) | By default the proxy sends the upstream URL's hostname in the upstream `Host` header (so vhost-routed services like Vercel, Cloudflare-fronted origins |
| [hsts](hsts/) | The `hsts` block on `secure.local` injects a `Strict-Transport-Security` header on every response. `max_age: 31536000` is one year, `include_subdomain |
| [idempotency](idempotency/) | The origin on `api.local` opts in to RFC 8594-style idempotency for |
| [ip-filter](ip-filter/) | Demonstrates the `ip_filter` policy. Only requests from the loopback range `127.0.0.0/8` and the private LAN range `10.0.0.0/8` are accepted; everythi |
| [json-schema](json-schema/) | Demonstrates the `# yaml-language-server: $schema=...` opt-in for editor autocomplete + validation against the generated JSON Schema for `sb.yml`. See [`docs/json-schema.md`](../docs/json-schema.md) for the editor walkthrough. |
| [k8s-gateway](k8s-gateway/) | Realistic config when SBproxy runs behind a Kubernetes Ingress (or any cluster-edge load balancer) and proxies to backend Pods that scale up and down  |
| [listing-primitive](listing-primitive/) | A minimal example of the repo-native `Listing` primitive. |
| [load-balancer](load-balancer/) | The `load_balancer` action dispatches each request across a pool of upstream targets using the `round_robin` algorithm. Two targets are configured wit |
| [load-balancer-deployment](load-balancer-deployment/) | A blue-green deployment split across two LB targets. The targets carry `group: blue` and `group: green` tags. With `deployment_mode.mode: blue_green`  |
| [local-models](local-models/) | Routes cheap traffic to a locally-hosted model (Ollama, vLLM, LM Studio, Hugging Face TGI, or llama.cpp) and the long tail or tougher prompts to a hos |
| [lora-aware-routing](lora-aware-routing/) | Wires the `lora-aware` `RoutingStrategy` onto a three-target load balancer pool. The strategy walks each target's `metadata` map, looks for a `loaded_ |
| [markdown-for-agents](markdown-for-agents/) | Demonstrates the Wave 4 content negotiation surface end-to-end. A |
| [mcp-federation](mcp-federation/) | The `mcp` action turns SBproxy into a Model Context Protocol gateway. It speaks JSON-RPC 2.0 on a configured origin, aggregates the tool catalogues of |
| [mtls-client-auth](mtls-client-auth/) | Demonstrates mutual TLS at the listener. Incoming HTTPS clients must present a certificate signed by the configured CA bundle. Failed handshakes never |
| [multi-rail-accept-payment](multi-rail-accept-payment/) | Both rails (x402 + MPP) configured at once. The example demonstrates |
| [object-authz](object-authz/) | Demonstrates the `object_authz` policy. The gateway enforces a declarative ownership rule (`{owner}` path segment must equal the JWT `sub`) so a reque |
| [observability-stack](observability-stack/) | A single `docker compose` command boots a complete metrics, logs, and traces stack pre-wired for SBproxy: Prometheus for metrics, Grafana for visualiz |
| [oidc](oidc/) | OpenID Connect Relying-Party login flow. Puts SSO in front of an upstream that has no auth of its own: an unauthenticated browser is redirected to the IdP, completes the auth-code + PKCE flow, and is served with a sealed session cookie. See `docs/auth-oidc.md` for the full field reference. |
| [openapi-emission](openapi-emission/) | The gateway publishes an OpenAPI 3.0 document describing the routes it exposes, derived from the live config. Three things land together: rich path ma |
| [openapi-validation](openapi-validation/) | The `openapi_validation` policy loads an inline OpenAPI document at startup and validates each request body against the matching operation's `requestB |
| [outbound-peer-pricing](outbound-peer-pricing/) | Demonstrates the `peer_pricing_preflight` policy: when an internal |
| [outlier-detection](outlier-detection/) | A round-robin load balancer with two targets: `test.sbproxy.dev` and `test.sbproxy.dev/status/503` (an always-503 alias on the same host so the example shows the proxy detecting and routing around the unhealthy upstream). The `outlier_detection` block tracks each target's success/failure ra |
| [page-shield](page-shield/) | Client-side script monitoring via Content Security Policy report intake. The `page_shield` policy stamps a `Content-Security-Policy-Report-Only` (or e |
| [pii-redaction](pii-redaction/) | When `pii.enabled: true` is set on an AI proxy origin, the gateway redacts well-known PII shapes from the parsed JSON request body before forwarding t |
| [problem-details](problem-details/) | The origin on `api.local` is protected by API key authentication. The |
| [prompt-injection-sidecar](prompt-injection-sidecar/) | Two origins demonstrating the `prompt_injection_v2` policy with the out-of-process `sidecar` detector. Detection runs in a separate process instead of |
| [prompt-injection-v2](prompt-injection-v2/) | The successor to the v1 `prompt_injection` heuristic guardrail. The v2 policy splits detection from enforcement: a swappable detector returns a numeri |
| [quote-token-replay-jwks](quote-token-replay-jwks/) | Demonstrates the quote-token JWKS endpoint, end-to-end JWS |
| [rail-lightning](rail-lightning/) | Lightning rail in the `Accept-Payment` negotiation contract alongside |
| [rail-mpp-stripe-test](rail-mpp-stripe-test/) | Stripe MPP (Merchant Payment Protocol) paywall in front of a markdown |
| [rail-x402-base-sepolia](rail-x402-base-sepolia/) | x402 v2 paywall in front of an article origin, wired against a local |
| [rate-limiting](rate-limiting/) | A token-bucket rate limit attached to a `proxy` action. The `rate_limiting` policy caps each client IP at 5 requests per second with a burst capacity  |
| [ratelimit-by-claim](ratelimit-by-claim/) | Per-tenant rate limiting keyed on a JWT claim. The `rate_limiting` policy on `api.local` accepts a `key:` CEL expression that runs against the request |
| [request-limit](request-limit/) | Demonstrates the `request_limit` policy. Caps the request body at `1024` bytes, the header count at `20`, and the URL length at `256` characters befor |
| [request-mirror](request-mirror/) | Every request matched by `localhost` is forwarded to the primary upstream `test.sbproxy.dev` as normal AND a copy is fired at `https://test.sbproxy.dev/echo` (the  |
| [request-modifiers](request-modifiers/) | Demonstrates the full typed shape of `request_modifiers`. On the way to the upstream, the proxy sets `X-Source: sbproxy` and `Content-Type: applicatio |
| [request-validator](request-validator/) | The `request_validator` policy on `localhost` validates inbound JSON request bodies against a JSON Schema before they reach the upstream. The schema i |
| [resilience-stack](resilience-stack/) | Composes four signals on a single load balancer so a flaky backend gets isolated quickly and recovers automatically without operator intervention. Act |
| [response-caching](response-caching/) | Demonstrates the per-origin `response_cache` block. Successful responses are stored in the in-memory cache for 60 seconds, keyed on the request method |
| [response-modifiers](response-modifiers/) | Demonstrates the full typed shape of `response_modifiers` across two origins on `127.0.0.1:8080`. `api.local` keeps the upstream `200`, sets `X-Served |
| [robots-llms-txt](robots-llms-txt/) | Demonstrates the Wave 4 text-format policy-graph projections. |
| [rsl-licensing](rsl-licensing/) | Demonstrates the Wave 4 policy-graph projections. A single |
| [security-headers](security-headers/) | Demonstrates the `security_headers` policy. Every response from the `test.sbproxy.dev` upstream gains the standard browser hardening set: `Strict-Transport |
| [semantic-cache-local](semantic-cache-local/) | The AI gateway's embedding semantic cache, vectorizing prompts on-box via the local classifier sidecar (`source: sidecar`) instead of a paid provider embedding API. No per-call cost, no prompt egress, low loopback latency. |
| [semantic-cache-openai](semantic-cache-openai/) | The embedding semantic cache vectorizing prompts via any OpenAI-compatible `/v1/embeddings` endpoint (`source: openai`), decoupled from the origin's chat providers: point it at another sbproxy, OpenRouter, or a hosted provider, with its own URL and auth (Bearer, `api-key`, or custom headers). |
| [semantic-constraint](semantic-constraint/) | A natural-language policy enforced by an LLM-as-judge backend. The `semantic_constraint` policy renders a prompt template against the request envelope |
| [service-discovery](service-discovery/) | Demonstrates `service_discovery` on a `proxy` action. Without service discovery, Pingora resolves the upstream hostname once when a connection is esta |
| [sessions](sessions/) | The `session` block on `app.local` configures the encrypted cookie used to carry session state across requests. Cookie name is `sb_session`, max age i |
| [sidecar](sidecar/) | Sidecar-tuned `sbproxy` config for the per-pod fanout case: small RSS, fast cold start, no required external dependencies. Runs on loopback in the pod's network namespace; an init container DNATs outbound TCP onto it. See `docs/sidecar-deployment.md` + `deploy/k8s/sidecar/` for the Kubernetes wire-up. |
| [sni-resolve-override](sni-resolve-override/) | Two siblings of `action.url` change how the proxy reaches the upstream without touching the URL itself. `sni_override: cdn.provider.net` sends that na |
| [sri](sri/) | Demonstrates the `sri` policy in observation mode. The proxy walks `text/html` responses, inspects every `<script src="https://...">` and `<link rel=" |
| [static-and-mock](static-and-mock/) | Three origins demonstrating the two upstream-free actions. `hello.local` uses the `static` action to return a fixed plain-text body. `api.local` uses  |
| [storage-action](storage-action/) | The `storage` action serves files from object storage backends. It is backed by the `object_store` crate and supports S3, GCS, Azure Blob, and the loc |
| [transform-encoding](transform-encoding/) | Demonstrates the `encoding` transform. A `static` action returns a small JSON document; the transform converts the bytes to standard base64 via `encod |
| [transform-html](transform-html/) | Demonstrates the `html` transform on a real upstream. The proxy fetches `https://test.sbproxy.dev/html` (a public Moby-Dick excerpt page) and rewrites the  |
| [transform-html-to-markdown](transform-html-to-markdown/) | Demonstrates the `html_to_markdown` transform. The proxy fetches `https://test.sbproxy.dev/html` (a public Moby-Dick excerpt page) and converts the HTML bo |
| [transform-javascript](transform-javascript/) | Demonstrates the `javascript` transform via QuickJS. The entrypoint is `function transform(body)` where `body` is the raw upstream body as a string. T |
| [transform-json](transform-json/) | Demonstrates the `json` transform. The upstream is a `static` action that returns a canned post document, so the example runs offline. The transform r |
| [transform-json-projection](transform-json-projection/) | Demonstrates the `json_projection` transform in whitelist mode. Only the listed fields (`id`, `title`) survive in the response; everything else is dro |
| [transform-json-schema](transform-json-schema/) | Demonstrates the `json_schema` transform. The upstream JSON response body is validated against a JSON Schema compiled once at config-load time (remote |
| [transform-lua](transform-lua/) | Demonstrates the `lua_json` transform. The script entrypoint is `function modify_json(data, ctx)` where `data` is the decoded JSON value (a Lua table) |
| [transform-markdown](transform-markdown/) | Demonstrates the `markdown` transform. A `static` action returns a Markdown release-notes document; the transform converts it to HTML using pulldown-c |
| [transform-payload-limit](transform-payload-limit/) | Demonstrates the `payload_limit` transform. The proxy fetches `https://test.sbproxy.dev/bytes/4096`, which returns 4096 random bytes, and clips the respons |
| [transform-replace-strings](transform-replace-strings/) | Demonstrates the `replace_strings` transform. Two find-and-replace rules run against the upstream body: a literal substring swap that rewrites every o |
| [transform-template](transform-template/) | Demonstrates the `template` transform. A `static` action emits a JSON document describing an order; the `template` transform parses that JSON as the i |
| [trusted-proxies](trusted-proxies/) | When SBproxy sits behind another LB or CDN (Cloudflare, AWS ALB, Fly.io edge, internal LB), the immediate TCP peer is the LB, not the real client. The |
| [upstream-retries](upstream-retries/) | When the proxy cannot establish a TCP/TLS connection to the upstream (DNS failure, refused, unreachable, TLS handshake fail), Pingora calls back into  |
| [variables-template](variables-template/) | The `variables` block declares static, per-origin key-value pairs that the template engine exposes as `{{ variables.<name> }}`. Environment variables  |
| [vault-reference](vault-reference/) | Provider-specific secret reference schemes for YAML secrets. Demonstrates `vault://`, `awssm://`, `gcpsm://`, `k8ssecret://`, `secretfile://`, `${...}` env-var interpolation, and the resolution order. Pair with the vault backend examples for end-to-end secret loading. |
| [waf](waf/) | Demonstrates the `waf` policy with the OWASP Core Rule Set enabled. Each request is screened for common attack signatures (SQL injection, cross-site s |
| [wasm](wasm/) | Reference modules for the SBproxy WASM transform. A WASM transform is a sandboxed module loaded by the `wasm` transform action; SBproxy invokes it onc |
| [wasm-transform](wasm-transform/) | Demonstrates the `wasm` response-body transform. The upstream response body is piped through a sandboxed wasm32-wasi module: the body goes in on stdin |
| [web-bot-auth](web-bot-auth/) | Cryptographic agent verification under RFC 9421 HTTP Message Signatures and the IETF Web Bot Auth draft. AI agents (crawlers, indexers, research bots) |
| [web-bot-auth-publish](web-bot-auth-publish/) | Demonstrates the `web_bot_auth_publish` per-origin config. SBproxy serves its own JWKS-shaped signing-key directory at `/.well-known/http-message-sign |
| [webhook-signing](webhook-signing/) | Every lifecycle webhook the proxy fires (`on_request`, `on_response`) carries a structured envelope and, when `secret` is set on the callback, an HMAC |

_133 examples on disk._
