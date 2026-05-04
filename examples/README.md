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
make run CONFIG=examples/00-basic-proxy/sb.yml          # default
make run CONFIG=examples/40-transform-json/sb.yml LOG_LEVEL=debug
```

Each `sb.yml` opens with a comment block listing the curl commands to drive it.

## Catalog

Auto-generated index of every example. Each row links to the example's
directory (with its `sb.yml` and README). Generated from `examples/` on 2026-05-04.

| Example | Description |
|---|---|
| [00-basic-proxy](00-basic-proxy/) | The simplest possible sbproxy configuration. A single origin keyed on `myapp.example.com` forwards every inbound request to `https://test.sb |
| [00-observability-stack](00-observability-stack/) | A single `docker compose` command boots a complete metrics, logs, and traces stack pre-wired for SBproxy: Prometheus for metrics, Grafana fo |
| [01-static-and-mock](01-static-and-mock/) | Three origins demonstrating the two upstream-free actions. `hello.local` uses the `static` action to return a fixed plain-text body. `api.lo |
| [02-rate-limiting](02-rate-limiting/) | A token-bucket rate limit attached to a `proxy` action. The `rate_limiting` policy caps each client IP at 5 requests per second with a burst |
| [03-response-caching](03-response-caching/) | Demonstrates the per-origin `response_cache` block. Successful responses are stored in the in-memory cache for 60 seconds, keyed on the requ |
| [04-load-balancer](04-load-balancer/) | The `load_balancer` action dispatches each request across a pool of upstream targets using the `round_robin` algorithm. Two targets are conf |
| [05-headers-and-cors](05-headers-and-cors/) | Combines three sibling blocks on one origin: `request_modifiers` injects `X-Forwarded-By: sbproxy` and a freshly generated `X-Trace-Id` (fro |
| [06-auth-api-key](06-auth-api-key/) | Enforces an API key check before any upstream call. The `api_key` authentication provider compares the value of the configured header (`X-Ap |
| [10-ai-openrouter](10-ai-openrouter/) | Routes OpenAI-compatible chat completion requests through OpenRouter. Clients speak the OpenAI protocol; SBproxy injects the OpenRouter API  |
| [100-prompt-injection-onnx](100-prompt-injection-onnx/) | Two origins demonstrating the `prompt_injection_v2` policy with an ONNX-backed neural classifier. The `tag.local` origin runs in `tag` mode  |
| [11-ai-claude](11-ai-claude/) | Direct integration with the Anthropic Messages API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to Anthropi |
| [12-ai-multi-provider](12-ai-multi-provider/) | A two-provider AI gateway with input guardrails and a soft budget cap. The `fallback_chain` strategy tries Anthropic first (priority 1) and  |
| [13-ai-budget](13-ai-budget/) | Two stacked budget limits with `on_exceed: downgrade`. The workspace-wide cap allows up to USD 500 of spend per month and downgrades to `cla |
| [14-ai-virtual-keys](14-ai-virtual-keys/) | Two virtual keys, two teams, two budgets. The frontend team's key is allowlisted to `claude-3-5-haiku-latest` only, capped at 30 RPM and 60, |
| [15-ai-guardrails](15-ai-guardrails/) | A full guardrail stack on a single Anthropic origin. Three input guardrails inspect the prompt before any upstream call: `injection` uses th |
| [16-ai-streaming](16-ai-streaming/) | Streaming is on by default in the AI gateway. The minimal Anthropic origin in this example handles `"stream": true` requests end-to-end: sbp |
| [17-ai-routing-fallback](17-ai-routing-fallback/) | Three providers in priority order. Provider 1 (`broken-anthropic`) is intentionally configured with an invalid API key so it always returns  |
| [17-markdown-for-agents](17-markdown-for-agents/) | Demonstrates the Wave 4 content negotiation surface end-to-end. A |
| [18-ai-cost-optimized](18-ai-cost-optimized/) | The `cost_optimized` strategy scores each provider as `in_flight_requests * 1000 + weight` and routes to the lowest score. Cheaper providers |
| [18-rsl-licensing](18-rsl-licensing/) | Demonstrates the Wave 4 policy-graph projections. A single |
| [19-ai-model-rate-limits](19-ai-model-rate-limits/) | Different models cost and behave differently, so they each need their own rate cap. The `model_rate_limits` map keys by model name and appli |
| [19-robots-llms-txt](19-robots-llms-txt/) | Demonstrates the Wave 4 text-format policy-graph projections. |
| [20-auth-jwt](20-auth-jwt/) | Validates HS256 JWTs against a static HMAC secret (`dev-secret-change-me`). The JWT must carry the configured issuer (`https://issuer.local` |
| [21-auth-bearer](21-auth-bearer/) | Accepts a fixed allowlist of opaque service tokens in the `Authorization: Bearer <token>` header. Pick this when callers are services that a |
| [22-auth-basic](22-auth-basic/) | Two-user HTTP Basic auth with a custom realm (`"sbproxy demo"`). Useful for quick admin panels and small internal tools. Requests without cr |
| [23-auth-forward](23-auth-forward/) | Delegates the authentication decision to an external HTTP service. For each inbound request, sbproxy issues a sub-request to the configured  |
| [24-ai-crawl-tiered](24-ai-crawl-tiered/) | Demonstrates a three-tier paywall in front of an article-publishing |
| [30-ip-filter](30-ip-filter/) | Demonstrates the `ip_filter` policy. Only requests from the loopback range `127.0.0.0/8` and the private LAN range `10.0.0.0/8` are accepted |
| [30-rail-x402-base-sepolia](30-rail-x402-base-sepolia/) | x402 v2 paywall in front of an article origin, wired against a local |
| [31-rail-mpp-stripe-test](31-rail-mpp-stripe-test/) | Stripe MPP (Merchant Payment Protocol) paywall in front of a markdown |
| [31-waf](31-waf/) | Demonstrates the `waf` policy with the OWASP Core Rule Set enabled. Each request is screened for common attack signatures (SQL injection, cr |
| [32-csrf](32-csrf/) | Demonstrates the `csrf` policy. Safe methods (`GET`, `HEAD`, `OPTIONS`) are exempt and serve as the channel through which the proxy issues t |
| [32-multi-rail-accept-payment](32-multi-rail-accept-payment/) | Both rails (x402 + MPP) configured at once. The example demonstrates |
| [33-quote-token-replay-jwks](33-quote-token-replay-jwks/) | Demonstrates the quote-token JWKS endpoint, end-to-end JWS |
| [33-security-headers](33-security-headers/) | Demonstrates the `security_headers` policy. Every response from the `httpbin.org` upstream gains the standard browser hardening set: `Strict |
| [34-request-limit](34-request-limit/) | Demonstrates the `request_limit` policy. Caps the request body at `1024` bytes, the header count at `20`, and the URL length at `256` charac |
| [35-cel-policy](35-cel-policy/) | Demonstrates the `expression` policy, which evaluates a CEL expression per request and decides whether to allow it. This config admits reque |
| [36-ddos-protection](36-ddos-protection/) | Demonstrates the `ddos_protection` policy. The proxy tracks a sliding 1-second window per source IP. When the rate exceeds `request_rate_thr |
| [37-sri](37-sri/) | Demonstrates the `sri` policy in observation mode. The proxy walks `text/html` responses, inspects every `<script src="https://...">` and `< |
| [38-wasm-transform](38-wasm-transform/) | Demonstrates the `wasm` response-body transform. The upstream response body is piped through a sandboxed wasm32-wasi module: the body goes i |
| [40-transform-json](40-transform-json/) | Demonstrates the `json` transform. The upstream is a `static` action that returns a canned post document, so the example runs offline. The t |
| [41-transform-json-projection](41-transform-json-projection/) | Demonstrates the `json_projection` transform in whitelist mode. Only the listed fields (`id`, `title`) survive in the response; everything e |
| [42-transform-json-schema](42-transform-json-schema/) | Demonstrates the `json_schema` transform. The upstream JSON response body is validated against a JSON Schema compiled once at config-load ti |
| [43-transform-html](43-transform-html/) | Demonstrates the `html` transform on a real upstream. The proxy fetches `https://httpbin.org/html` (a public Moby-Dick excerpt page) and rew |
| [44-transform-markdown](44-transform-markdown/) | Demonstrates the `markdown` transform. A `static` action returns a Markdown release-notes document; the transform converts it to HTML using  |
| [45-transform-html-to-markdown](45-transform-html-to-markdown/) | Demonstrates the `html_to_markdown` transform. The proxy fetches `https://httpbin.org/html` (a public Moby-Dick excerpt page) and converts t |
| [46-transform-template](46-transform-template/) | Demonstrates the `template` transform. A `static` action emits a JSON document describing an order; the `template` transform parses that JSO |
| [47-transform-replace-strings](47-transform-replace-strings/) | Demonstrates the `replace_strings` transform. Two find-and-replace rules run against the upstream body: a literal substring swap that rewrit |
| [48-transform-encoding](48-transform-encoding/) | Demonstrates the `encoding` transform. A `static` action returns a small JSON document; the transform converts the bytes to standard base64  |
| [49-transform-lua](49-transform-lua/) | Demonstrates the `lua_json` transform. The script entrypoint is `function modify_json(data, ctx)` where `data` is the decoded JSON value (a  |
| [50-transform-javascript](50-transform-javascript/) | Demonstrates the `javascript` transform via QuickJS. The entrypoint is `function transform(body)` where `body` is the raw upstream body as a |
| [51-transform-payload-limit](51-transform-payload-limit/) | Demonstrates the `payload_limit` transform. The proxy fetches `https://httpbin.org/bytes/4096`, which returns 4096 random bytes, and clips t |
| [52-grpc-h2c](52-grpc-h2c/) | Proxies plaintext gRPC traffic to an upstream gRPC server. gRPC requires HTTP/2 end-to-end, so the proxy's plain HTTP listener must speak HT |
| [60-request-modifiers](60-request-modifiers/) | Demonstrates the full typed shape of `request_modifiers`. On the way to the upstream, the proxy sets `X-Source: sbproxy` and `Content-Type:  |
| [61-response-modifiers](61-response-modifiers/) | Demonstrates the full typed shape of `response_modifiers` across two origins on `127.0.0.1:8080`. `api.local` keeps the upstream `200`, sets |
| [62-forward-rules](62-forward-rules/) | A single origin on `gateway.local` dispatches incoming requests to three different inline child origins based on path. Requests to `/api/*`  |
| [63-fallback-origin](63-fallback-origin/) | The primary action proxies to `httpbin.org/status/503`, which always returns 503. The `fallback_origin` block defines a backup origin served |
| [64-error-pages](64-error-pages/) | The origin on `api.local` is protected by API key authentication (`X-Api-Key: secret-key`). Requests that miss the key get a 401 from the pr |
| [65-sessions](65-sessions/) | The `session` block on `app.local` configures the encrypted cookie used to carry session state across requests. Cookie name is `sb_session`, |
| [66-variables-template](66-variables-template/) | The `variables` block declares static, per-origin key-value pairs that the template engine exposes as `{{ variables.<name> }}`. Environment  |
| [67-compression](67-compression/) | Enables response compression on `api.local` for brotli, gzip, and zstd. The first algorithm in `algorithms` that the client advertises in `A |
| [68-hsts](68-hsts/) | The `hsts` block on `secure.local` injects a `Strict-Transport-Security` header on every response. `max_age: 31536000` is one year, `include |
| [69-connection-pool](69-connection-pool/) | The `connection_pool` block on `api.local` sizes the proxy's outbound HTTP client for this origin. `max_connections: 32` caps concurrent in- |
| [71-load-balancer-deployment](71-load-balancer-deployment/) | A blue-green deployment split across two LB targets. The targets carry `group: blue` and `group: green` tags. With `deployment_mode.mode: bl |
| [72-host-override](72-host-override/) | By default the proxy sends the upstream URL's hostname in the upstream `Host` header (so vhost-routed services like Vercel, Cloudflare-front |
| [72-sni-resolve-override](72-sni-resolve-override/) | Two siblings of `action.url` change how the proxy reaches the upstream without touching the URL itself. `sni_override: cdn.provider.net` sen |
| [73-trusted-proxies](73-trusted-proxies/) | When sbproxy sits behind another LB or CDN (Cloudflare, AWS ALB, Fly.io edge, internal LB), the immediate TCP peer is the LB, not the real c |
| [74-bulk-redirects](74-bulk-redirects/) | Each origin owns its own redirect list, compiled at config-load into an O(1) lookup keyed on the request path. Three sources are supported:  |
| [74-forwarding-headers](74-forwarding-headers/) | The proxy injects a standard set of forwarding headers on every upstream request: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, `X-For |
| [75-request-mirror](75-request-mirror/) | Every request matched by `localhost` is forwarded to the primary upstream `httpbin.org` as normal AND a copy is fired at `https://httpbingo. |
| [76-dlp-catalog](76-dlp-catalog/) | The `dlp` policy scans the request URI and headers for matches against the configured detector set, then either tags the upstream request wi |
| [76-upstream-retries](76-upstream-retries/) | When the proxy cannot establish a TCP/TLS connection to the upstream (DNS failure, refused, unreachable, TLS handshake fail), Pingora calls  |
| [77-active-health-checks](77-active-health-checks/) | A round-robin load balancer with two targets: `httpbin.org` and `httpbingo.org`. Each target has a `health_check` block, so the proxy runs a |
| [77-exposed-credentials](77-exposed-credentials/) | When a request carries `Authorization: Basic <base64>` whose password matches the configured exposure list, the proxy stamps the upstream re |
| [78-outlier-detection](78-outlier-detection/) | A round-robin load balancer with two targets: `httpbin.org` and `httpbingo.org`. The `outlier_detection` block tracks each target's success/ |
| [79-ratelimit-by-claim](79-ratelimit-by-claim/) | Per-tenant rate limiting keyed on a JWT claim. The `rate_limiting` policy on `api.local` accepts a `key:` CEL expression that runs against t |
| [79-webhook-signing](79-webhook-signing/) | Every lifecycle webhook the proxy fires (`on_request`, `on_response`) carries a structured envelope and, when `secret` is set on the callbac |
| [80-correlation-id](80-correlation-id/) | The proxy mints a per-request correlation ID early in the request lifecycle. With the default policy, an inbound `X-Request-Id` is adopted a |
| [81-request-validator](81-request-validator/) | The `request_validator` policy on `localhost` validates inbound JSON request bodies against a JSON Schema before they reach the upstream. Th |
| [82-concurrent-limit](82-concurrent-limit/) | Demonstrates the `concurrent_limit` policy. The limiter caps the number of in-flight requests per key, distinct from the requests-per-second |
| [83-service-discovery](83-service-discovery/) | Demonstrates `service_discovery` on a `proxy` action. Without service discovery, Pingora resolves the upstream hostname once when a connecti |
| [84-circuit-breaker](84-circuit-breaker/) | Demonstrates the `circuit_breaker` block on a `load_balancer` action. The breaker is a formal Closed -> Open -> HalfOpen state machine, one  |
| [85-mtls-client-auth](85-mtls-client-auth/) | Demonstrates mutual TLS at the listener. Incoming HTTPS clients must present a certificate signed by the configured CA bundle. Failed handsh |
| [86-local-models](86-local-models/) | Routes cheap traffic to a locally-hosted model (Ollama, vLLM, LM Studio, Hugging Face TGI, or llama.cpp) and the long tail or tougher prompt |
| [87-ai-resilience](87-ai-resilience/) | Three independent resilience signals run on the AI provider pool. Any one can eject a provider from the routing list. (1) `circuit_breaker`  |
| [88-ai-shadow](88-ai-shadow/) | Each request is forwarded to the primary provider as usual; a copy is also sent to the shadow provider concurrently. The shadow response is  |
| [89-ai-race](89-ai-race/) | Race strategy fans out the request to every eligible provider in parallel, returns the first 2xx response, and cancels the losers. Trade-off |
| [90-resilience-stack](90-resilience-stack/) | Composes four signals on a single load balancer so a flaky backend gets isolated quickly and recovers automatically without operator interve |
| [91-defense-in-depth](91-defense-in-depth/) | Layered authentication, authorisation, and inspection on a single origin. The chain answers a different question at each layer: `ip_filter`  |
| [91-web-bot-auth](91-web-bot-auth/) | Cryptographic agent verification under RFC 9421 HTTP Message Signatures and the IETF Web Bot Auth draft. AI agents (crawlers, indexers, rese |
| [92-k8s-gateway](92-k8s-gateway/) | Realistic config when SBproxy runs behind a Kubernetes Ingress (or any cluster-edge load balancer) and proxies to backend Pods that scale up |
| [93-ai-cel-tenant-gate](93-ai-cel-tenant-gate/) | A proxy-native pattern: a CEL expression runs at the network layer before any AI provider is contacted. Pure AI gateway libraries cannot rej |
| [93-page-shield](93-page-shield/) | Client-side script monitoring via Content Security Policy report intake. The `page_shield` policy stamps a `Content-Security-Policy-Report-O |
| [94-ai-mixed-traffic](94-ai-mixed-traffic/) | Pure AI gateway libraries assume the host is "the AI gateway" and that everything that lands on it should hit a model. A real proxy can do m |
| [95-ai-crawl-control](95-ai-crawl-control/) | The `ai_crawl_control` policy returns HTTP 402 Payment Required to known AI crawler User-Agents that arrive without a `Crawler-Payment` toke |
| [95-ai-regex-dlp](95-ai-regex-dlp/) | Built-in PII detection covers the obvious patterns (email, phone, SSN, credit card). Real organisations have their own confidential vocabula |
| [96-openapi-emission](96-openapi-emission/) | The gateway publishes an OpenAPI 3.0 document describing the routes it exposes, derived from the live config. Three things land together: ri |
| [97-mcp-federation](97-mcp-federation/) | The `mcp` action turns SBproxy into a Model Context Protocol gateway. It speaks JSON-RPC 2.0 on a configured origin, aggregates the tool cat |
| [97-openapi-validation](97-openapi-validation/) | The `openapi_validation` policy loads an inline OpenAPI document at startup and validates each request body against the matching operation's |
| [97-pii-redaction](97-pii-redaction/) | When `pii.enabled: true` is set on an AI proxy origin, the gateway redacts well-known PII shapes from the parsed JSON request body before fo |
| [98-prompt-injection-v2](98-prompt-injection-v2/) | The successor to the v1 `prompt_injection` heuristic guardrail. The v2 policy splits detection from enforcement: a swappable detector return |
| [98-storage-action](98-storage-action/) | The `storage` action serves files from object storage backends. It is backed by the `object_store` crate and supports S3, GCS, Azure Blob, a |
| [99-lora-aware-routing](99-lora-aware-routing/) | Wires the `lora-aware` `RoutingStrategy` onto a three-target load balancer pool. The strategy walks each target's `metadata` map, looks for  |
| [wasm](wasm/) | Reference modules for the SBproxy WASM transform. A WASM transform is a sandboxed module loaded by the `wasm` transform action; SBproxy invo |

_104 examples on disk._
