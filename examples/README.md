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

### Getting started

| Path | What it shows |
|------|---------------|
| [00-basic-proxy](00-basic-proxy/sb.yml) | Reverse proxy to a public upstream (httpbin.org). |
| [01-static-and-mock](01-static-and-mock/sb.yml) | `static` and `mock` actions for stubbing without an upstream. |

### Policies

| Path | What it shows |
|------|---------------|
| [02-rate-limiting](02-rate-limiting/sb.yml) | Per-IP token bucket rate limit on a public REST API. |
| [30-ip-filter](30-ip-filter/sb.yml) | CIDR-based whitelist + blacklist. |
| [31-waf](31-waf/sb.yml) | OWASP CRS WAF policy. |
| [32-csrf](32-csrf/sb.yml) | CSRF token policy with safe-method exemption. |
| [33-security-headers](33-security-headers/sb.yml) | HSTS, X-Frame-Options, structured CSP. |
| [34-request-limit](34-request-limit/sb.yml) | Body size, header count, URL length caps. |
| [35-cel-policy](35-cel-policy/sb.yml) | Custom access control via a CEL expression. |

### Caching and load balancing

| Path | What it shows |
|------|---------------|
| [03-response-caching](03-response-caching/sb.yml) | TTL cache for upstream responses. |
| [04-load-balancer](04-load-balancer/sb.yml) | Round-robin across two public JSON endpoints. |
| [71-load-balancer-deployment](71-load-balancer-deployment/sb.yml) | Blue-green deployment mode with target group tagging. |

### Authentication

| Path | What it shows |
|------|---------------|
| [06-auth-api-key](06-auth-api-key/sb.yml) | `X-Api-Key` enforcement before the upstream is reached. |
| [20-auth-jwt](20-auth-jwt/sb.yml) | JWT validation with a static HS256 secret. |
| [21-auth-bearer](21-auth-bearer/sb.yml) | Bearer token allowlist. |
| [22-auth-basic](22-auth-basic/sb.yml) | HTTP Basic auth with a custom realm. |
| [23-auth-forward](23-auth-forward/sb.yml) | Delegated auth via an external decision endpoint. |

### Modifiers and transforms

| Path | What it shows |
|------|---------------|
| [05-headers-and-cors](05-headers-and-cors/sb.yml) | Header rewrites and CORS preflight. |
| [60-request-modifiers](60-request-modifiers/sb.yml) | All typed request modifier shapes (headers, URL, query, method, body). |
| [61-response-modifiers](61-response-modifiers/sb.yml) | Status / body / header overrides on the response side. |
| [40-transform-json](40-transform-json/sb.yml) | `json` transform: set, remove, rename fields. |
| [41-transform-json-projection](41-transform-json-projection/sb.yml) | Whitelist or blacklist fields via projection. |
| [42-transform-json-schema](42-transform-json-schema/sb.yml) | JSON Schema validation of upstream responses. |
| [43-transform-html](43-transform-html/sb.yml) | HTML rewriting: inject, remove, attribute changes. |
| [44-transform-markdown](44-transform-markdown/sb.yml) | Render Markdown to HTML. |
| [45-transform-html-to-markdown](45-transform-html-to-markdown/sb.yml) | Convert HTML to Markdown (good for LLM input). |
| [46-transform-template](46-transform-template/sb.yml) | minijinja templating over upstream response. |
| [47-transform-replace-strings](47-transform-replace-strings/sb.yml) | Literal and regex find-and-replace. |
| [48-transform-encoding](48-transform-encoding/sb.yml) | Base64-encode the response body. |
| [49-transform-lua](49-transform-lua/sb.yml) | `lua_json` script with the real `modify_json(data, ctx)` entrypoint. |
| [50-transform-javascript](50-transform-javascript/sb.yml) | JavaScript via QuickJS with `function transform(body)`. |
| [51-transform-payload-limit](51-transform-payload-limit/sb.yml) | Cap response body size with truncation. |

### Routing

| Path | What it shows |
|------|---------------|
| [62-forward-rules](62-forward-rules/sb.yml) | Path-based dispatch to inline child origins. |
| [63-fallback-origin](63-fallback-origin/sb.yml) | Serve a degraded response when the upstream returns 5xx. |
| [64-error-pages](64-error-pages/sb.yml) | Custom error responses with content negotiation. |

### Operations

| Path | What it shows |
|------|---------------|
| [65-sessions](65-sessions/sb.yml) | Cookie-based session config. |
| [66-variables-template](66-variables-template/sb.yml) | Origin-level `variables` and `{{ env.* }}` interpolation. |
| [67-compression](67-compression/sb.yml) | Brotli, gzip, zstd negotiated via `Accept-Encoding`. |
| [68-hsts](68-hsts/sb.yml) | Strict-Transport-Security header policy. |
| [69-connection-pool](69-connection-pool/sb.yml) | Upstream connection pool tuning. |

### Forwarding, resilience, observability

| Path | What it shows |
|------|---------------|
| [72-host-override](72-host-override/sb.yml) | Override the upstream `Host`; auto-set `X-Forwarded-Host`. |
| [73-trusted-proxies](73-trusted-proxies/sb.yml) | Trust XFF from upstream LBs only; strip elsewhere. IPv6 supported. |
| [74-forwarding-headers](74-forwarding-headers/sb.yml) | Per-action `disable_*_header` opt-outs (XFF, X-Real-IP, Forwarded, Via, ...). |
| [75-request-mirror](75-request-mirror/sb.yml) | Shadow traffic via `mirror: { url, sample_rate, timeout_ms }`. |
| [76-upstream-retries](76-upstream-retries/sb.yml) | `retry: { max_attempts, retry_on, backoff_ms }` on connect errors / timeouts. |
| [77-active-health-checks](77-active-health-checks/sb.yml) | Background probes per LB target with configurable probe period. |
| [78-outlier-detection](78-outlier-detection/sb.yml) | Passive ejection from LB rotation on sliding-window error rate. |
| [79-webhook-signing](79-webhook-signing/sb.yml) | Identity envelope + HMAC-SHA256 signed `on_request`/`on_response` webhooks. |
| [80-correlation-id](80-correlation-id/sb.yml) | Honour inbound `X-Request-Id`, generate when absent, propagate to upstream and echo on the response. |
| [81-request-validator](81-request-validator/sb.yml) | Reject malformed JSON request bodies at the edge using a JSON Schema. |
| [82-concurrent-limit](82-concurrent-limit/sb.yml) | Cap in-flight requests per route / IP / API key (distinct from RPS rate limit). |
| [83-service-discovery](83-service-discovery/sb.yml) | DNS-based service discovery: re-resolve the upstream hostname on a TTL and rotate through its A/AAAA set. |
| [84-circuit-breaker](84-circuit-breaker/sb.yml) | Formal Closed/Open/HalfOpen breaker per LB target with consecutive-failure and consecutive-success thresholds. |
| [85-mtls-client-auth](85-mtls-client-auth/sb.yml) | Verify client TLS certs against a CA bundle; forward CN, SAN, and other cert metadata to the upstream. Run `bash examples/85-mtls-client-auth/generate-certs.sh` once before starting the proxy. |

### Production patterns (cross-cutting)

| Path | What it shows |
|------|---------------|
| [90-resilience-stack](90-resilience-stack/sb.yml) | Connect-error retries + outlier detection + circuit breaker + active health checks composed on one load balancer. Self-healing upstream pool. |
| [91-defense-in-depth](91-defense-in-depth/sb.yml) | Layered IP filter, WAF, rate limit, concurrent limit, JWT auth, request body schema validation, security headers, and CORS on a single origin. |
| [92-k8s-gateway](92-k8s-gateway/sb.yml) | Behind a K8s Ingress: trusted_proxies + service_discovery + correlation_id + concurrent_limit + host_override on a Service hostname. |
| [86-local-models](86-local-models/sb.yml) | Hybrid local + cloud routing across Ollama / vLLM / LM Studio / TGI / llama.cpp with cloud fallback. |
| [87-ai-resilience](87-ai-resilience/sb.yml) | Per-provider circuit breaker, outlier detection, and active /models health probes. |
| [88-ai-shadow](88-ai-shadow/sb.yml) | Side-by-side eval: mirror traffic to a shadow provider and log latency, tokens, and finish_reason. |
| [89-ai-race](89-ai-race/sb.yml) | Race strategy: fan out across providers, take the first 2xx, cancel the losers. |
| [93-ai-cel-tenant-gate](93-ai-cel-tenant-gate/sb.yml) | CEL access policy gating AI requests by tenant header before any provider is contacted. |
| [94-ai-mixed-traffic](94-ai-mixed-traffic/sb.yml) | Forward rules mixing AI proxy, static health probe, model catalog, and a docs reverse proxy on one hostname. |
| [95-ai-regex-dlp](95-ai-regex-dlp/sb.yml) | Regex guardrails layered on PII: block project codenames and ticket IDs, allow only on-topic prompts. |
| [96-openapi-emission](96-openapi-emission/sb.yml) | Emit an OpenAPI 3.0 spec from gateway config. Templated paths, parameter declarations, admin and per-host `/.well-known/openapi.json` endpoints. |
| [97-pii-redaction](97-pii-redaction/sb.yml) | Pattern-aware PII redaction at the AI request boundary: email, SSN, credit card with Luhn, phone, IPv4, common API key shapes, plus custom regex rules. |
| [98-storage-action](98-storage-action/sb.yml) | Serve files from S3 / GCS / Azure / local via the `storage` action. Range requests, index_file fallback, etag, last-modified. |

### AI gateway: basics

| Path | What it shows |
|------|---------------|
| [10-ai-openrouter](10-ai-openrouter/sb.yml) | AI gateway routing to OpenRouter (200+ models, single key). |
| [11-ai-claude](11-ai-claude/sb.yml) | AI gateway routing directly to Anthropic Claude. |
| [12-ai-multi-provider](12-ai-multi-provider/sb.yml) | Anthropic primary, OpenRouter fallback, with input guardrails. |

### AI gateway: deep features

| Path | What it shows |
|------|---------------|
| [13-ai-budget](13-ai-budget/sb.yml) | Hierarchical budget with workspace + api_key scopes, downgrade on exceed. |
| [14-ai-virtual-keys](14-ai-virtual-keys/sb.yml) | Per-team API keys with allowed providers, models, RPM caps, tags. |
| [15-ai-guardrails](15-ai-guardrails/sb.yml) | Input (injection / pii / jailbreak) + output (toxicity / schema) guardrails. |
| [16-ai-streaming](16-ai-streaming/sb.yml) | SSE streaming via the OpenAI-compatible interface. |
| [17-ai-routing-fallback](17-ai-routing-fallback/sb.yml) | `fallback_chain` strategy with priority ordering. |
| [18-ai-cost-optimized](18-ai-cost-optimized/sb.yml) | `cost_optimized` strategy and weight-driven scoring. |
| [19-ai-model-rate-limits](19-ai-model-rate-limits/sb.yml) | Per-model RPM and TPM caps. |

## AI examples

The AI examples expect API keys in the environment:

| Example | Variables |
|---------|-----------|
| `10-ai-openrouter`, `18-ai-cost-optimized`, `19-ai-model-rate-limits` | `OPENROUTER_API_KEY` |
| `11-ai-claude`, `13-ai-budget`, `15-ai-guardrails`, `16-ai-streaming`, `17-ai-routing-fallback` | `ANTHROPIC_API_KEY` |
| `12-ai-multi-provider`, `13-ai-budget`, `18-ai-cost-optimized` | both above |
| `14-ai-virtual-keys` | `ANTHROPIC_API_KEY`, `TEAM_FRONTEND_KEY`, `TEAM_DATA_KEY` |

The proxy presents an OpenAI-compatible interface to clients regardless of which provider answers, so any OpenAI SDK works without modification.

## Public endpoints used

Free, well-known services that don't require an account:

| Service | Notes |
|---------|-------|
| `httpbin.org` | Echoes request data, supports `/delay/N` and `/status/<code>` for failure tests. |
| `jsonplaceholder.typicode.com` | Static fake REST API; great for JSON transforms. |
| `dummyjson.com` | Alternate fake REST API for the load balancer demo. |
| `test.sbproxy.dev` | SBproxy project's own test endpoint. |
| `openrouter.ai` | Aggregated LLM gateway. |
| `api.anthropic.com` | Anthropic Claude. |

Be a good neighbour: keep traffic to these public APIs at a sensible rate when experimenting.
