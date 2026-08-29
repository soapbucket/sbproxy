# SBproxy Features Hub

*Last modified: 2026-08-28*

This page used to be a five-domain tour of the binary. That tour duplicated [api-gateway.md](api-gateway.md), [ai-gateway.md](ai-gateway.md), [mcp-and-agents.md](mcp-and-agents.md), [a2a-gateway.md](a2a-gateway.md), and [policy.md](policy.md), and it went stale whenever one of those pages moved. Start from the walkthrough that matches the traffic you have, then use the catalogs below when you need every `action:` or `policies:` type in one list.

## Start here

| You want | Page |
|---|---|
| API + MCP + AI on one listener | [all-traffic-gateway.md](all-traffic-gateway.md) |
| Apps calling models | [getting-started-ai-estate.md](getting-started-ai-estate.md) |
| Agents and crawlers calling you | [getting-started-inbound.md](getting-started-inbound.md) |
| A model you run locally | [quickstart-serve.md](quickstart-serve.md) |

Domain hubs: [api-gateway.md](api-gateway.md), [ai-gateway.md](ai-gateway.md) and [providers.md](providers.md), [mcp-and-agents.md](mcp-and-agents.md), [a2a-gateway.md](a2a-gateway.md), [policy.md](policy.md), [scripting.md](scripting.md), [architecture.md](architecture.md). Field tables: [configuration.md](configuration.md).

The rest of this page is the action, policy, and scripting catalogs inbound links still point at. They will move next to those hubs; until they do, this is the address.

---

## 6. Reference: every action type

An origin's `action:` decides what serves the request, and forward rules can pick a different action per matched rule. These seventeen types are the complete set the config compiler accepts, mirrored from its dispatch table; any other `type:` string is a linked plugin, an extension-bundle hook, or a config error. [architecture.md](architecture.md#3-request-pipeline) shows where dispatch happens in the pipeline; [request-flow.md](request-flow.md) walks everything around it.

* **`proxy`** reverse-proxies to a single upstream URL. It carries the classic knobs: base-path stripping, query preservation, `Host` and SNI overrides, forwarding-header controls, retries with backoff, DNS-based service discovery for upstreams whose IPs churn, and IP pinning for reaching a backend without traversing its public CDN entry. Docs: [routing.md](routing.md), [configuration.md](configuration.md).
* **`load_balancer`** spreads traffic across a target pool: eight algorithms (round-robin, weighted random, least connections, IP/URI/header/cookie hash, and ketama-style `ring_hash`), five named custom strategies (`first-healthy`, `gpu-aware`, `lora`, `lora-aware`, `bandit`), three health layers (active probes, passive outlier ejection, per-target circuit breakers), and blue-green and canary deployment modes with backup targets and priority tiers. Docs: [routing.md](routing.md), [routing-strategies.md](routing-strategies.md).
* **`static`** serves a fixed response straight from config: status, body, content type, extra headers. Maintenance pages, stubs, well-known files.
* **`redirect`** issues HTTP redirects (301, 302, 307, 308), including bulk source-to-destination lists compiled at load time into an O(1) path lookup. Docs: [bulk-redirects.md](bulk-redirects.md).
* **`echo`** reflects the request back as JSON: method, path, headers, body. The debugging and smoke-test action.
* **`mock`** returns a configured JSON document, for standing up an API's shape before the real upstream exists.
* **`beacon`** answers with a one-pixel transparent GIF, so an analytics or tracking pixel needs no upstream at all.
* **`noop`** accepts the request and returns an empty 200. A placeholder for scaffolding a config before its real action lands.
* **`websocket`** proxies WebSocket upgrades, with subprotocol negotiation, message-size limits, and host override; auth and policies run before the upgrade like on any other action. Docs: [websocket.md](websocket.md).
* **`grpc`** passes gRPC through on HTTP/2 for every RPC cardinality, unary through bidirectional streaming, with opt-in gRPC-Web translation for browser clients and descriptor-driven REST-to-gRPC transcoding routes. Both translation modes are unary or server-streaming only, and a body-reading policy on the origin stalls streaming calls. Docs: [grpc.md](grpc.md), [routing.md](routing.md#grpc-limits).
* **`graphql`** proxies GraphQL with a query-depth cap, an introspection toggle, and optional query validation before anything reaches the upstream. Docs: [graphql.md](graphql.md).
* **`storage`** serves objects from S3, Google Cloud Storage, Azure Blob, or a local directory. Example: [Storage Action](../examples/storage-action/).
* **`ai_proxy`** is the AI gateway in one action: the OpenAI-compatible surface, the provider catalog, model aliases, LLM-aware routing, guardrails, budgets, semantic caching, and local model hosting. [ai-gateway.md](ai-gateway.md) is the reference; [providers.md](providers.md) is the catalog.
* **`mcp`** is the MCP gateway: federates real MCP servers, OpenAPI-derived tools, and config-defined local tools behind one endpoint, with RBAC, tool versioning, quotas, and content filters. [mcp.md](mcp.md) and [mcp-compose.md](mcp-compose.md) are the references. Cedar on `tools/call`: [cedar-policy.md](cedar-policy.md).
* **`a2a`** proxies agent-to-agent JSON-RPC with envelope trust rules, delegation-depth caps, cycle detection, and caller and callee lists. Docs: [a2a-gateway.md](a2a-gateway.md).
* **`abtest`** splits traffic across weighted backend variants for an A/B test. A first request takes a weighted roll and gets a sticky cookie back; every request after it that returns the cookie reaches the same variant. Docs: [configuration.md](configuration.md#abtest), example: [A/B Test Routing](../examples/ab-test-routing/).
* **`https_proxy`** is a guarded TLS reverse-proxy relay to the request's resolved host rather than a URL fixed in config, allow-listed by `allowed_hosts`. It is not an HTTP CONNECT tunnel. The narrow case: a wildcard origin that wants to relay only a named subset of the hosts it would otherwise match. Docs: [configuration.md](configuration.md#https_proxy), example: [HTTPS Relay](../examples/https-forward-proxy/).

## 7. Reference: every policy type

[policy.md](policy.md) is the catalog, with a one-line job description for each of the thirty `policies:` types and a link to its full documentation. The names, grouped by the job you are hiring for:

* **Rate, volume, and budget:** `rate_limiting`, `rate_limit_budget`, `concurrent_limit`, `request_limit`, `ddos`, `ip_filter`, `agent_budget`.
* **Identity and access:** `object_authz` (BOLA and BFLA enforcement, plus enumeration detection), `agent_class`, `a2a`, `csrf`, `security_headers`.
* **Content, validation, and DLP:** `request_validator`, `openapi_validation`, `body_threat_protection`, `waf`, `http_framing`, `sri`, `content_digest`, `page_shield`, `dlp`, `exposed_credentials`.
* **AI-specific:** `ai_crawl_control`, `prompt_injection_v2`, `semantic_constraint`.
* **Enrichment:** `geoip`, `user_agent_parser`. Neither denies traffic; both annotate the request for downstream identity/anomaly hooks and, optionally, the upstream request. Docs: [request-enrichment.md](request-enrichment.md).
* **Scripting-driven:** `expression` (CEL), `rego`, `assertion`.
* **Packs:** `owasp_api_top10` is not a twenty-ninth type. The compiler expands it into entries from the groups above, backs off per item when you author the type yourself, and reports each of the ten items in a five-state manifest, including the ones it does not cover. Docs: [owasp-api-top10.md](owasp-api-top10.md).

Authentication is a separate axis, configured on an origin's `auth:` block rather than in `policies:`: `api_key`, `basic_auth`, `bearer`, `jwt`, `digest`, `forward_auth`, `ldap_auth`, `oidc`, `bot_auth` (Web Bot Auth), and `cap`, plus mTLS client verification at the listener. Chooser: [authentication.md](authentication.md). Digest example: [`examples/auth-digest/`](../examples/auth-digest/).

## 8. Reference: where custom logic attaches

Five engines run operator-supplied logic, all loaded from config and all hot-reloadable. The per-site contract (what the script receives, what it may return, the sandbox limits) is in [scripting.md](scripting.md); the pipeline placement of every attachment point is in [request-flow.md](request-flow.md).

| Engine | Available at |
|---|---|
| **CEL** | `expression` and `assertion` policies; rate-limit bucket keys and WAF persistent-block keys; forward-rule `when:` predicates; access-log custom fields; the `cel` response transform; the AI policy plane (`ai_policy.expression`); MCP argument and result policies; MCP local-tool step conditions |
| **Rego** | `rego` policies; request and response modifiers; MCP argument and result policies; extension-bundle policy hooks with `runtime: rego` |
| **Lua** | Request and response modifiers (returned headers); `lua` raw-body and `lua_json` transforms; WAF custom rules; access-log custom fields; response-cache key and admit events; MCP local-tool response shaping |
| **JavaScript** | Request and response modifiers (returned headers); `javascript` and `js_json` transforms; WAF custom rules; access-log custom fields; response-cache key and admit events; extension bundles (JS or TypeScript); MCP tool-version adapters; MCP local-tool response shaping |
| **WASM** | The `wasm` body transform (WASI preview 1, with opt-in per-request context); envelope-WASM extension-bundle hooks, including `ai_routing`; Proxy-Wasm HTTP filter chains via `origins.<host>.filters[]` |

Beyond inline scripts, an extension bundle packages logic as a versioned directory (JavaScript, TypeScript, or compiled WASM) loaded from disk or from a digest-pinned git source, with no rebuild and no partial loads: auth, policy, action, and transform hooks in the core pipeline, plus AI guardrail, tool-call, and routing hooks, Proxy-Wasm streaming filters, and payment lifecycle hooks. [plugins.md](plugins.md) is the map of all of it; [extension-bundles.md](extension-bundles.md) is the reference. Organizations that build their own binary can also compile logic in directly; that path and its costs are covered in [plugins.md](plugins.md) and [architecture.md](architecture.md#4-plugin-system).
