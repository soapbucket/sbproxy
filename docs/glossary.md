# Glossary

*Last modified: 2026-08-30*

A plain-English mapping of the terms that appear in SBproxy configuration and documentation. Start with the gateway words below, then use the longer protocol list when you meet an acronym.

| Term | What it means in SBproxy |
|---|---|
| Origin | A client-facing hostname and the configuration that handles requests for it. An `origins:` entry selects an action, policy, authentication, and transforms. |
| Action | The work an origin performs after SBproxy accepts a request. Common actions proxy an HTTP API, serve an MCP endpoint, or route an AI completion. |
| Upstream | The service SBproxy calls on the other side of an action. It can be an application backend, an MCP server, or an OpenAI-compatible inference service. |
| Provider | An AI source configured under an `ai_proxy` action. A provider can be hosted or local and may expose one or more model names. |
| Data plane | The listener that serves client traffic through origins and actions. Local examples use port 8080. |
| Admin plane | Authenticated endpoints and UI that inspect or change a running proxy, including health, keys, config, and reload. |
| Configuration compilation | The startup and validation step that parses `sb.yml` and constructs the request pipeline before the proxy accepts traffic. |
| Reload | Recompiling a candidate config in a running process, then swapping it in only when compilation succeeds. The old pipeline keeps serving when it fails. |
| MCP | A JSON-RPC protocol for clients to discover and call tools. MCP does not generate model completions. |
| OpenAI-compatible | An HTTP API shape that accepts endpoints such as `/v1/chat/completions` and returns the corresponding response format. Compatibility describes the wire protocol, not the model itself. |

See [core-concepts.md](core-concepts.md) for the request flow and [configuration.md](configuration.md) for configuration fields.

| Term                | Stands for / source                                  | What it means in SBproxy                                                                                                                                          |
|---------------------|------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| OLP                 | Open Licensing Protocol                              | A four-step flow for publishers to advertise a license catalog, agents to discover it, and the gateway to issue license tokens (`jti` claims) bound to a license row. SBproxy is both ends of it: the AI crawl control policy verifies tokens, and the origin-level `olp` block runs the issuer, minting at `POST /.well-known/olp/token` and publishing its JWK set at `GET /.well-known/olp/key`. |
| CAP                 | Crawler Authorization Protocol                       | A JWT-based capability-token format that an agent presents in `CAP-Token:` or `Authorization: CAP <jwt>`. SBproxy verifies signature, claims, audience, glob-allowed paths, and (optionally) per-token rate limits. Tokens are minted by whichever CAP issuer the deployment trusts, named by `jwks_url` or pinned inline with `jwks_static`. |
| MCP                 | Model Context Protocol                               | The Anthropic-originated tool-and-resource catalog protocol. SBproxy ships an MCP federation action that aggregates tool catalogs across upstream MCP servers and routes `tools/call` per tool. |
| x402                | x402 protocol (Linux Foundation x402 Foundation)     | A stablecoin-on-chain payment rail riding HTTP 402. x402 moved to a Linux Foundation project on 2026-04-02. SBproxy emits x402 challenge entries in multi-rail 402 responses and verifies redemption tokens via the x402 facilitator. v2 is the emitted and accepted version. |
| MPP                 | Merchant Payment Protocol                            | The card-and-stablecoin-on-Stripe payment rail. SBproxy emits MPP challenge entries that carry a Stripe `payment_intent` id; redemption confirms against Stripe. |
| DPoP                | Demonstration of Proof-of-Possession (RFC 9449)      | A JWS that proves the presenter holds the private key bound to an access token. SBproxy uses DPoP on outbound credential resolution so a stolen access token alone is insufficient to call an upstream. |
| RFC 8693            | OAuth 2.0 Token Exchange                             | The token-exchange grant that powers SBproxy's outbound credential resolver. SBproxy uses RFC 8693 to swap an inbound identity for an upstream access token under one delegation-aware interface. |
| RFC 9421            | HTTP Message Signatures                              | The IETF spec for signing HTTP messages. SBproxy implements per-origin message-signature configuration plus the Web Bot Auth directory (RFC 9421-style signatures with a JWKS feed). |
| RateLimit headers   | draft-ietf-httpapi-ratelimit-headers                 | The IETF draft for `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, and `Retry-After`. SBproxy emits these on throttled responses when the rate-limit policy opts in via its `headers` block; they are off by default. |
| RSL                 | Really Simple Licensing                              | A license-advertisement standard served as `licenses.xml`. SBproxy serves it from `/licenses.xml` keyed off the live config and the per-origin Content-Signal value. |
| TDMRep              | Text and Data Mining Reservation Protocol (W3C)      | A license-reservation standard served as `tdmrep.json`. SBproxy serves it from `/.well-known/tdmrep.json`. When `content_signal` is unset on an origin, the proxy stamps `TDM-Reservation: 1` instead of asserting a positive Content-Signal. |
| llms.txt            | llms.txt convention                                  | A plain-text capability index for AI crawlers. SBproxy serves one live `llms.txt` projection per origin, derived from the compiled policy graph and regenerated on every config reload; nothing is served from a static file. |
| robots.txt          | Robots Exclusion Protocol                            | A projection route that derives the live robots.txt from each origin's policy graph. The proxy never serves a static robots.txt; it composes one on every reload. |
| aipref              | AI Preferences Working Group draft                   | A request-side preference signal an agent can carry to declare training, search, or input intent. Parsed at request entry into `RequestContext.aipref` and exposed to CEL, Lua, JavaScript, and WASM. |
| Content-Signal      | IAB Tech Lab Content-Signal header                   | A response header carrying one of `ai-train`, `search`, `ai-input`. SBproxy stamps it on 200 responses per origin and reflects the same value into the licensing projections. |
| Pay Per Crawl       | Cloudflare-coined term, SBproxy implementation       | The pattern of charging an AI crawler with HTTP 402 plus a `Crawler-Payment` token. Implemented by the `ai_crawl_control` policy. |
| Web Bot Auth        | IETF draft (HTTP message signatures + key directory) | The signed-bot-traffic standard. SBproxy fetches `/.well-known/http-message-signatures-directory` from a vendor, caches the JWKS with TTL, and verifies signatures on inbound bot requests. |
| KYA                 | Know-Your-Agent (Skyfire)                            | A token format for verified agent identity. The proxy verifies KYA tokens and exposes `request.kya` to scripting. |
| JA3 / JA4 / JA4H    | TLS fingerprinting algorithms                        | ClientHello fingerprints supplied by a trusted TLS-terminating sidecar via `x-sbproxy-tls-*` request headers (accepted only from peers in `proxy.trusted_proxies`) and stamped onto the request context. JA3 plus the JA4 family power the headless-detection signals. |
| schema-v1           | Internal config schema label                         | The label for the `sb.yml` schema, independent of binary version. Key names and their meanings carry over from the [archived Go `v0.1.x` line](https://github.com/soapbucket/sbproxy-go); the file's shape does not. Go compatibility is deprecated: a flat single-origin file from that line is refused rather than translated, and the Rust line reads origin behavior only from `origins.<hostname>:`. See [MIGRATION.md](../MIGRATION.md). |
| Apache 2.0          | Apache License, Version 2.0                          | The open source license under which SBproxy is published. Free for any use, including production and commercial, with no field-of-use restriction. See [LICENSE](../LICENSE). |
| Pingora             | Cloudflare's Rust proxy framework                    | The async runtime SBproxy is built on. The `sbproxy-core` crate plugs into Pingora's `request_filter`, `response_filter`, and `response_body_filter` lifecycle. |
| CEL                 | Common Expression Language                           | Google's expression language. Used for per-origin policy rules, request modifiers, and response transforms. Powered by `cel-rust`. |
| Lua / Luau          | Lua and Roblox's Luau dialect                        | The scripting hook surface for request modifiers and transforms, sandboxed via `mlua`. Configured under `lua_script:` blocks. |
| QuickJS             | Bellard's QuickJS engine, via `rquickjs`             | The JavaScript hook surface for request and response modifiers. Configured under `js_script:` blocks. |
| WASM / wasmtime     | WebAssembly + Bytecode Alliance runtime              | The WebAssembly hook surface (WASI). Configured as a transforms entry with `type: wasm`. Ship custom modules in any language that compiles to WASI. |
| L2 cache            | Layer-2 cache backend                                | A shared-state backend (Redis today) that turns rate-limit counters and response-cache entries into cluster-wide state. Configured under `proxy.l2_cache_settings`. |
| Cache Reserve       | Long-tail cold cache tier                            | A second cache tier sitting under the per-origin response cache. Sample-rate driven mirroring; admission gate by min TTL and size; promotion-on-hit. Configured under `proxy.cache_reserve`. |

## See also

- [configuration.md](configuration.md) for the field-by-field configuration schema.
- [features.md](features.md) for the buyer-facing tour of every feature with copy-paste configs.
- [openapi-emission.md](openapi-emission.md) for how SBproxy emits an OpenAPI document from the live config.
