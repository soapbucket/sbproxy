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
directory (with its `sb.yml` and README). Generated from `examples/` on 2026-05-10; the 15 entries below the original alphabetical block were appended on 2026-05-31 to cover examples that landed after the original sweep.

| Example | Description |
|---|---|
| [active-health-checks](active-health-checks/) | A round-robin load balancer with two targets: `httpbin.org` and `httpbingo.org`. Each target has a `health_check` block, so the proxy runs a |
| [ai-budget](ai-budget/) | Two stacked budget limits with `on_exceed: downgrade`. The workspace-wide cap allows up to USD 500 of spend per month and downgrades to `cla |
| [ai-cel-tenant-gate](ai-cel-tenant-gate/) | A proxy-native pattern: a CEL expression runs at the network layer before any AI provider is contacted. Pure AI gateway libraries cannot rej |
| [ai-claude](ai-claude/) | Direct integration with the Anthropic Messages API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to Anthropi |
| [ai-cost-optimized](ai-cost-optimized/) | The `cost_optimized` strategy scores each provider as `in_flight_requests * 1000 + weight` and routes to the lowest score. Cheaper providers |
| [ai-crawl-control](ai-crawl-control/) | The `ai_crawl_control` policy returns HTTP 402 Payment Required to known AI crawler User-Agents that arrive without a `Crawler-Payment` toke |
| [ai-crawl-tiered](ai-crawl-tiered/) | Demonstrates a three-tier paywall in front of an article-publishing |
| [ai-guardrails](ai-guardrails/) | A full guardrail stack on a single Anthropic origin. Three input guardrails inspect the prompt before any upstream call: `injection` uses th |
| [ai-mixed-traffic](ai-mixed-traffic/) | Pure AI gateway libraries assume the host is "the AI gateway" and that everything that lands on it should hit a model. A real proxy can do m |
| [ai-model-rate-limits](ai-model-rate-limits/) | Different models cost and behave differently, so they each need their own rate cap. The `model_rate_limits` map keys by model name and appli |
| [ai-multi-provider](ai-multi-provider/) | A two-provider AI gateway with input guardrails and a soft budget cap. The `fallback_chain` strategy tries Anthropic first (priority 1) and  |
| [ai-openrouter](ai-openrouter/) | Routes OpenAI-compatible chat completion requests through OpenRouter. Clients speak the OpenAI protocol; SBproxy injects the OpenRouter API  |
| [ai-race](ai-race/) | Race strategy fans out the request to every eligible provider in parallel, returns the first 2xx response, and cancels the losers. Trade-off |
| [ai-regex-dlp](ai-regex-dlp/) | Built-in PII detection covers the obvious patterns (email, phone, SSN, credit card). Real organisations have their own confidential vocabula |
| [ai-resilience](ai-resilience/) | Three independent resilience signals run on the AI provider pool. Any one can eject a provider from the routing list. (1) `circuit_breaker`  |
| [ai-routing-fallback](ai-routing-fallback/) | Three providers in priority order. Provider 1 (`broken-anthropic`) is intentionally configured with an invalid API key so it always returns  |
| [ai-shadow](ai-shadow/) | Each request is forwarded to the primary provider as usual; a copy is also sent to the shadow provider concurrently. The shadow response is  |
| [ai-streaming](ai-streaming/) | Streaming is on by default in the AI gateway. The minimal Anthropic origin in this example handles `"stream": true` requests end-to-end: sbp |
| [ai-virtual-keys](ai-virtual-keys/) | Two virtual keys, two teams, two budgets. The frontend team's key is allowlisted to `claude-3-5-haiku-latest` only, capped at 30 RPM and 60, |
| [auth-api-key](auth-api-key/) | Enforces an API key check before any upstream call. The `api_key` authentication provider compares the value of the configured header (`X-Ap |
| [auth-basic](auth-basic/) | Two-user HTTP Basic auth with a custom realm (`"sbproxy demo"`). Useful for quick admin panels and small internal tools. Requests without cr |
| [auth-bearer](auth-bearer/) | Accepts a fixed allowlist of opaque service tokens in the `Authorization: Bearer <token>` header. Pick this when callers are services that a |
| [auth-forward](auth-forward/) | Delegates the authentication decision to an external HTTP service. For each inbound request, sbproxy issues a sub-request to the configured  |
| [auth-jwt](auth-jwt/) | Validates HS256 JWTs against a static HMAC secret (`dev-secret-change-me`). The JWT must carry the configured issuer (`https://issuer.local` |
| [basic-proxy](basic-proxy/) | The simplest possible sbproxy configuration. A single origin keyed on `myapp.example.com` forwards every inbound request to `https://test.sb |
| [bulk-redirects](bulk-redirects/) | Each origin owns its own redirect list, compiled at config-load into an O(1) lookup keyed on the request path. Three sources are supported:  |
| [cel-policy](cel-policy/) | Demonstrates the `expression` policy, which evaluates a CEL expression per request and decides whether to allow it. This config admits reque |
| [circuit-breaker](circuit-breaker/) | Demonstrates the `circuit_breaker` block on a `load_balancer` action. The breaker is a formal Closed -> Open -> HalfOpen state machine, one  |
| [compression](compression/) | Enables response compression on `api.local` for brotli, gzip, and zstd. The first algorithm in `algorithms` that the client advertises in `A |
| [concurrent-limit](concurrent-limit/) | Demonstrates the `concurrent_limit` policy. The limiter caps the number of in-flight requests per key, distinct from the requests-per-second |
| [connection-pool](connection-pool/) | The `connection_pool` block on `api.local` sizes the proxy's outbound HTTP client for this origin. `max_connections: 32` caps concurrent in- |
| [correlation-id](correlation-id/) | The proxy mints a per-request correlation ID early in the request lifecycle. With the default policy, an inbound `X-Request-Id` is adopted a |
| [csrf](csrf/) | Demonstrates the `csrf` policy. Safe methods (`GET`, `HEAD`, `OPTIONS`) are exempt and serve as the channel through which the proxy issues t |
| [ddos-protection](ddos-protection/) | Demonstrates the `ddos_protection` policy. The proxy tracks a sliding 1-second window per source IP. When the rate exceeds `request_rate_thr |
| [defense-in-depth](defense-in-depth/) | Layered authentication, authorisation, and inspection on a single origin. The chain answers a different question at each layer: `ip_filter`  |
| [dlp-catalog](dlp-catalog/) | The `dlp` policy scans the request URI and headers for matches against the configured detector set, then either tags the upstream request wi |
| [error-pages](error-pages/) | The origin on `api.local` is protected by API key authentication (`X-Api-Key: secret-key`). Requests that miss the key get a 401 from the pr |
| [exposed-credentials](exposed-credentials/) | When a request carries `Authorization: Basic <base64>` whose password matches the configured exposure list, the proxy stamps the upstream re |
| [fallback-origin](fallback-origin/) | The primary action proxies to `httpbin.org/status/503`, which always returns 503. The `fallback_origin` block defines a backup origin served |
| [forward-rules](forward-rules/) | A single origin on `gateway.local` dispatches incoming requests to three different inline child origins based on path. Requests to `/api/*`  |
| [forwarding-headers](forwarding-headers/) | The proxy injects a standard set of forwarding headers on every upstream request: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, `X-For |
| [grpc-h2c](grpc-h2c/) | Proxies plaintext gRPC traffic to an upstream gRPC server. gRPC requires HTTP/2 end-to-end, so the proxy's plain HTTP listener must speak HT |
| [headers-and-cors](headers-and-cors/) | Combines three sibling blocks on one origin: `request_modifiers` injects `X-Forwarded-By: sbproxy` and a freshly generated `X-Trace-Id` (fro |
| [host-override](host-override/) | By default the proxy sends the upstream URL's hostname in the upstream `Host` header (so vhost-routed services like Vercel, Cloudflare-front |
| [hsts](hsts/) | The `hsts` block on `secure.local` injects a `Strict-Transport-Security` header on every response. `max_age: 31536000` is one year, `include |
| [ip-filter](ip-filter/) | Demonstrates the `ip_filter` policy. Only requests from the loopback range `127.0.0.0/8` and the private LAN range `10.0.0.0/8` are accepted |
| [k8s-gateway](k8s-gateway/) | Realistic config when SBproxy runs behind a Kubernetes Ingress (or any cluster-edge load balancer) and proxies to backend Pods that scale up |
| [load-balancer-deployment](load-balancer-deployment/) | A blue-green deployment split across two LB targets. The targets carry `group: blue` and `group: green` tags. With `deployment_mode.mode: bl |
| [load-balancer](load-balancer/) | The `load_balancer` action dispatches each request across a pool of upstream targets using the `round_robin` algorithm. Two targets are conf |
| [local-models](local-models/) | Routes cheap traffic to a locally-hosted model (Ollama, vLLM, LM Studio, Hugging Face TGI, or llama.cpp) and the long tail or tougher prompt |
| [lora-aware-routing](lora-aware-routing/) | Wires the `lora-aware` `RoutingStrategy` onto a three-target load balancer pool. The strategy walks each target's `metadata` map, looks for  |
| [markdown-for-agents](markdown-for-agents/) | Demonstrates the Wave 4 content negotiation surface end-to-end. A |
| [mcp-federation](mcp-federation/) | The `mcp` action turns SBproxy into a Model Context Protocol gateway. It speaks JSON-RPC 2.0 on a configured origin, aggregates the tool cat |
| [mtls-client-auth](mtls-client-auth/) | Demonstrates mutual TLS at the listener. Incoming HTTPS clients must present a certificate signed by the configured CA bundle. Failed handsh |
| [multi-rail-accept-payment](multi-rail-accept-payment/) | Both rails (x402 + MPP) configured at once. The example demonstrates |
| [observability-stack](observability-stack/) | A single `docker compose` command boots a complete metrics, logs, and traces stack pre-wired for SBproxy: Prometheus for metrics, Grafana fo |
| [openapi-emission](openapi-emission/) | The gateway publishes an OpenAPI 3.0 document describing the routes it exposes, derived from the live config. Three things land together: ri |
| [openapi-validation](openapi-validation/) | The `openapi_validation` policy loads an inline OpenAPI document at startup and validates each request body against the matching operation's |
| [outlier-detection](outlier-detection/) | A round-robin load balancer with two targets: `httpbin.org` and `httpbingo.org`. The `outlier_detection` block tracks each target's success/ |
| [page-shield](page-shield/) | Client-side script monitoring via Content Security Policy report intake. The `page_shield` policy stamps a `Content-Security-Policy-Report-O |
| [pii-redaction](pii-redaction/) | When `pii.enabled: true` is set on an AI proxy origin, the gateway redacts well-known PII shapes from the parsed JSON request body before fo |
| [prompt-injection-sidecar](prompt-injection-sidecar/) | Two origins demonstrating the `prompt_injection_v2` policy with the out-of-process `sidecar` detector: inference runs in a separate process over gRPC instead of in the proxy, isolating the model runtime. Shows `fail_closed` allow-vs-deny and `tag` vs `block`. |
| [prompt-injection-v2](prompt-injection-v2/) | The successor to the v1 `prompt_injection` heuristic guardrail. The v2 policy splits detection from enforcement: a swappable detector return |
| [quote-token-replay-jwks](quote-token-replay-jwks/) | Demonstrates the quote-token JWKS endpoint, end-to-end JWS |
| [rail-mpp-stripe-test](rail-mpp-stripe-test/) | Stripe MPP (Merchant Payment Protocol) paywall in front of a markdown |
| [rail-x402-base-sepolia](rail-x402-base-sepolia/) | x402 v2 paywall in front of an article origin, wired against a local |
| [rate-limiting](rate-limiting/) | A token-bucket rate limit attached to a `proxy` action. The `rate_limiting` policy caps each client IP at 5 requests per second with a burst |
| [ratelimit-by-claim](ratelimit-by-claim/) | Per-tenant rate limiting keyed on a JWT claim. The `rate_limiting` policy on `api.local` accepts a `key:` CEL expression that runs against t |
| [request-limit](request-limit/) | Demonstrates the `request_limit` policy. Caps the request body at `1024` bytes, the header count at `20`, and the URL length at `256` charac |
| [request-mirror](request-mirror/) | Every request matched by `localhost` is forwarded to the primary upstream `httpbin.org` as normal AND a copy is fired at `https://httpbingo. |
| [request-modifiers](request-modifiers/) | Demonstrates the full typed shape of `request_modifiers`. On the way to the upstream, the proxy sets `X-Source: sbproxy` and `Content-Type:  |
| [request-validator](request-validator/) | The `request_validator` policy on `localhost` validates inbound JSON request bodies against a JSON Schema before they reach the upstream. Th |
| [resilience-stack](resilience-stack/) | Composes four signals on a single load balancer so a flaky backend gets isolated quickly and recovers automatically without operator interve |
| [response-caching](response-caching/) | Demonstrates the per-origin `response_cache` block. Successful responses are stored in the in-memory cache for 60 seconds, keyed on the requ |
| [response-modifiers](response-modifiers/) | Demonstrates the full typed shape of `response_modifiers` across two origins on `127.0.0.1:8080`. `api.local` keeps the upstream `200`, sets |
| [robots-llms-txt](robots-llms-txt/) | Demonstrates the Wave 4 text-format policy-graph projections. |
| [rsl-licensing](rsl-licensing/) | Demonstrates the Wave 4 policy-graph projections. A single |
| [security-headers](security-headers/) | Demonstrates the `security_headers` policy. Every response from the `httpbin.org` upstream gains the standard browser hardening set: `Strict |
| [service-discovery](service-discovery/) | Demonstrates `service_discovery` on a `proxy` action. Without service discovery, Pingora resolves the upstream hostname once when a connecti |
| [sessions](sessions/) | The `session` block on `app.local` configures the encrypted cookie used to carry session state across requests. Cookie name is `sb_session`, |
| [sni-resolve-override](sni-resolve-override/) | Two siblings of `action.url` change how the proxy reaches the upstream without touching the URL itself. `sni_override: cdn.provider.net` sen |
| [sri](sri/) | Demonstrates the `sri` policy in observation mode. The proxy walks `text/html` responses, inspects every `<script src="https://...">` and `< |
| [static-and-mock](static-and-mock/) | Three origins demonstrating the two upstream-free actions. `hello.local` uses the `static` action to return a fixed plain-text body. `api.lo |
| [storage-action](storage-action/) | The `storage` action serves files from object storage backends. It is backed by the `object_store` crate and supports S3, GCS, Azure Blob, a |
| [transform-encoding](transform-encoding/) | Demonstrates the `encoding` transform. A `static` action returns a small JSON document; the transform converts the bytes to standard base64  |
| [transform-html-to-markdown](transform-html-to-markdown/) | Demonstrates the `html_to_markdown` transform. The proxy fetches `https://httpbin.org/html` (a public Moby-Dick excerpt page) and converts t |
| [transform-html](transform-html/) | Demonstrates the `html` transform on a real upstream. The proxy fetches `https://httpbin.org/html` (a public Moby-Dick excerpt page) and rew |
| [transform-javascript](transform-javascript/) | Demonstrates the `javascript` transform via QuickJS. The entrypoint is `function transform(body)` where `body` is the raw upstream body as a |
| [transform-json-projection](transform-json-projection/) | Demonstrates the `json_projection` transform in whitelist mode. Only the listed fields (`id`, `title`) survive in the response; everything e |
| [transform-json-schema](transform-json-schema/) | Demonstrates the `json_schema` transform. The upstream JSON response body is validated against a JSON Schema compiled once at config-load ti |
| [transform-json](transform-json/) | Demonstrates the `json` transform. The upstream is a `static` action that returns a canned post document, so the example runs offline. The t |
| [transform-lua](transform-lua/) | Demonstrates the `lua_json` transform. The script entrypoint is `function modify_json(data, ctx)` where `data` is the decoded JSON value (a  |
| [transform-markdown](transform-markdown/) | Demonstrates the `markdown` transform. A `static` action returns a Markdown release-notes document; the transform converts it to HTML using  |
| [transform-payload-limit](transform-payload-limit/) | Demonstrates the `payload_limit` transform. The proxy fetches `https://httpbin.org/bytes/4096`, which returns 4096 random bytes, and clips t |
| [transform-replace-strings](transform-replace-strings/) | Demonstrates the `replace_strings` transform. Two find-and-replace rules run against the upstream body: a literal substring swap that rewrit |
| [transform-template](transform-template/) | Demonstrates the `template` transform. A `static` action emits a JSON document describing an order; the `template` transform parses that JSO |
| [trusted-proxies](trusted-proxies/) | When SBproxy sits behind another LB or CDN (Cloudflare, AWS ALB, Fly.io edge, internal LB), the immediate TCP peer is the LB, not the real c |
| [upstream-retries](upstream-retries/) | When the proxy cannot establish a TCP/TLS connection to the upstream (DNS failure, refused, unreachable, TLS handshake fail), Pingora calls  |
| [variables-template](variables-template/) | The `variables` block declares static, per-origin key-value pairs that the template engine exposes as `{{ variables.<name> }}`. Environment  |
| [waf](waf/) | Demonstrates the `waf` policy with the OWASP Core Rule Set enabled. Each request is screened for common attack signatures (SQL injection, cr |
| [wasm-transform](wasm-transform/) | Demonstrates the `wasm` response-body transform. The upstream response body is piped through a sandboxed wasm32-wasi module: the body goes i |
| [wasm](wasm/) | Reference modules for the SBproxy WASM transform. A WASM transform is a sandboxed module loaded by the `wasm` transform action; SBproxy invo |
| [web-bot-auth](web-bot-auth/) | Cryptographic agent verification under RFC 9421 HTTP Message Signatures and the IETF Web Bot Auth draft. AI agents (crawlers, indexers, rese |
| [webhook-signing](webhook-signing/) | Every lifecycle webhook the proxy fires (`on_request`, `on_response`) carries a structured envelope and, when `secret` is set on the callbac |
| [a2a-protocol](a2a-protocol/) | The `a2a` policy enforces per-route safety on agent-to-agent traffic. Detection runs once per request and matches three signals: `Content-Type: applic |
| [agent-skills](agent-skills/) | Demonstrates the Agent Skills v0.2.0 well-known projection. SBproxy stamps `/.well-known/agent-skills/manifest.json` plus per-skill artifacts so MCP cl |
| [ai-bedrock-direct](ai-bedrock-direct/) | Direct integration with AWS Bedrock's model-agnostic Converse API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to the |
| [ai-cascade-routing](ai-cascade-routing/) | The `cascade` strategy walks an ordered list of `(provider, model)` tiers from cheapest to most expensive. Each tier's response is graded against a `q |
| [ai-context-poisoning](ai-context-poisoning/) | A single Anthropic origin with the `context_poisoning` input guardrail enabled. The guardrail inspects the full input, including any retrieved content |
| [ai-gemini-direct](ai-gemini-direct/) | Direct integration with the Google Gemini API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to Gemini's `:generateCont |
| [ai-per-surface-rate-limits](ai-per-surface-rate-limits/) | Different OpenAI surfaces have different cost and capacity profiles. Chat completions are cheap and high volume; image generation is slow and expensiv |
| [auth-cap](auth-cap/) | Validates Crawler Authorization Protocol (CAP) tokens on every request. CAP tokens are EdDSA-signed JWTs bound to an agent identity (`sub`), a request |
| [content-shape-negotiation](content-shape-negotiation/) | Same URL, three response shapes. The proxy reads the agent's `Accept` header on the way in, resolves a single content shape per request, and the respo |
| [idempotency](idempotency/) | The origin on `api.local` opts in to RFC 8594-style idempotency: every request carrying an `Idempotency-Key` header is cached against that key for a c |
| [listing-primitive](listing-primitive/) | A minimal example of the repo-native `Listing` primitive: a per-origin descriptor that names the routes, payment rails, and quotas a hosted Catalog wo |
| [outbound-peer-pricing](outbound-peer-pricing/) | Demonstrates the `peer_pricing_preflight` policy: when an internal request fans out to a paid peer, the proxy pre-fetches the price quote and asserts  |
| [problem-details](problem-details/) | The origin on `api.local` is protected by API key authentication. The `problem_details` middleware reshapes the proxy's error responses to RFC 9457 Pr |
| [rail-lightning](rail-lightning/) | Lightning rail in the `Accept-Payment` negotiation contract alongside the existing on-chain L1 rails. Demonstrates the LNURL-pay quote flow, the BOLT- |
| [semantic-constraint](semantic-constraint/) | A natural-language policy enforced by an LLM-as-judge backend. The `semantic_constraint` policy renders a prompt template against the request envelope |

_119 examples on disk._
