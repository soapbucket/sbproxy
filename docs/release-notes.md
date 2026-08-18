# Release notes

*Last modified: 2026-08-18*

A category view of recent SBproxy changes, for readers who want to know
what changed in an area they care about rather than read a chronological
diff. Covers versions 1.8.0 through 1.12.0.

[`CHANGELOG.md`](../CHANGELOG.md) stays the canonical, chronological,
Keep-a-Changelog-style record with full detail and exact version
boundaries. This page re-sorts the same material by category and
compresses each entry to one line; check the matching version's entry
in `CHANGELOG.md` before you upgrade anything flagged **Breaking**.

## Security

**Breaking / needs attention:**

- **A matched virtual key no longer erases the inbound principal's roles and claims.** (1.11.0) `roles` and `claims` now carry forward from the JWT principal instead of being wiped by a virtual-key match; role-scoped MCP ACL rules and claim-based CEL policies that silently stopped matching now match again.
- **`require_mtls_bound: true` no longer rejects every request in production.** (1.11.0) The production auth path hardcoded a missing client-certificate thumbprint; any origin using `require_mtls_bound` was rejecting all of its traffic until this fix.
- **`GET /admin/config` and `GET /admin/config/effective` no longer return inlined secrets in plaintext.** (1.11.0) Both now redact secrets like the log pipeline does; a config with an inlined secret can no longer round-trip through GET, edit, PUT (move the value to `env:` or a secrets backend).
- **A secret reference in `message_signatures.key` is now resolved instead of being used as the key itself.** (1.11.0) Previously the reference text (e.g. `vault://prod/signing-key`) stood in for the actual RFC 9421 signing key, so anyone who read the config could forge an accepted signature.
- **RFC 9421 signature verification can now actually check a covered body.** (1.11.0) A signature claiming to cover `content-digest` was verified against an empty body, so a forged or tampered body could pass verification. Also adds ECDSA-P256 support.
- **A federated MCP server with no `rbac:` label no longer defaults to allow-all.** (1.11.0) Config compile now rejects a `federated_servers` entry with `rbac_policies` configured elsewhere but no `rbac:` label, closing a silent default-deny bypass.
- **An `ai_proxy` origin's `credentials:` block now enforces something even without `require_governed_key: true`.** (1.11.0) Eight of nine shipped examples, including the flagship `ai-virtual-keys` example, shipped the vulnerable unenforced shape; config compile now fails loud instead.
- **Admin operator passwords are now hashed at rest [BREAKING].** (1.9.0) A plaintext `password` under `operators:` no longer parses; compute `password_hash` with the new `sbproxy admin hash-password` CLI helper. The default pepper is a fixed public constant shared by every install, so pin `key_management.crypto.pepper` in production, or a leaked hash is offline-crackable.
- **The admin server no longer boots wide open on default credentials.** (1.8.0)
- **`sbproxy run` and `sbproxy service install` no longer publish the local model gateway to the network.** (1.10.0) Both now generate `bind_address: 127.0.0.1` instead of the previous hardcoded `0.0.0.0` with no authentication in front of it. If you relied on `sbproxy run` being reachable from another machine, it no longer is: write a config, set `proxy.bind_address` explicitly, and put authentication in front of it.
- **Outbound HTTP no longer follows a redirect without re-authorizing it.** (1.9.0) Every hop is now re-authorized against the egress allowlist, not just the first one. A provider base URL that depended on a 301 to add a trailing slash now fails instead of silently working; point the config at the URL the provider actually serves.
- **Egress authorization resolves DNS for real.** (1.9.0)

**Also shipped:**

- A tamper-evident security audit trail behind `audit.sink: chain`: SHA-256 hash-chained, Ed25519-signed, independently verifiable with `sbproxy audit verify`. (1.11.0)
- OCSP stapling now builds a real RFC 6960 request and validates the response; a staple no client could verify is no longer sent. (1.11.0)
- Four fixes from a security inventory of the auth path: async JWKS refresh, constant-time comparators via `subtle`, malformed CIDR now fails config compile. (1.11.0)
- `key_management.crypto.pepper`/`master_key` and `cluster.security.shared_key` can now resolve through any configured secrets backend, not just env or file. (1.11.0)
- Boot and every SIGHUP reload now warn when `key_management.inbound.provider_hints` recognizes a native provider credential that no `inbound.native_key_policy` admits, surfacing a gap that previously refused those keys with a silent 403. (1.11.0)
- A bulk credential purge (`invalidate_all`) now reaches every node in a cluster instead of only the local shard. (1.10.0)
- A clustered node running the embedded per-node keystore now warns, or refuses to start, when its cache tier can't actually propagate key state the way the deployment implies. (1.10.0)
- Outbound credentials can use DPoP-bound tokens. (1.9.0)
- Encryption at rest for cached responses. (1.8.0)
- Trust tier is now live policy input. (1.8.0)
- Pingora updated to upstream 0.8.1. (1.8.0)
- Saving config from the admin console no longer leaks health probes. (1.8.0)
- The admin console's read-only Users page lists who can sign in and their role. (1.8.0)

## AI Gateway

**Breaking / needs attention:**

- **`timeout_ms` on an AI provider is now enforced.** (1.12.0) The key previously validated and did nothing; a forgotten low value starts cutting requests off on upgrade.
- **A broken `ai_policy.expression` now refuses the config instead of disabling itself.** (1.12.0) If your config stops loading on upgrade, the expression was never actually running.
- **`model_aliases` now actually does something.** (1.11.0) The key previously parsed and was silently ignored; a second bug also closed credential model-gate bypass via alias.
- **The in-process embedded engine (`engine: embedded`) is removed.** (1.10.0)
- **The AI gateway's `context_overflow:` block is removed.** (1.11.0) It parsed and was never wired to anything; an authored key now fails config compile naming the compression settings (`window_fit`) that actually fit a prompt to the model's window.
- **A multipart AI request's `prompt` field now goes through input guardrails.** (1.11.0) Multipart was a documented way to bypass prompt-injection scanning entirely.
- **The AI gateway's circuit breaker and outlier detection now actually run.** (1.10.0) Both blocks parsed and validated but were never attached to a router. If you have either configured, providers will now start leaving the routing pool on real failures (five consecutive failures, or a 50% failure rate over at least five requests in 60 seconds); with every provider ejected, dispatch falls back to the full permitted set rather than refusing the request.

**Also shipped:**

- Anthropic multi-tool-call streams now close every content block correctly. (1.12.0)
- Gemini empty `generateContent` bodies now surface as an error instead of a fake empty success. (1.12.0)
- `sbproxy ai ledger report` reads the AI value ledger offline. (1.11.0)
- Ollama's NDJSON streaming responses now stay on the streaming relay instead of being buffered whole, so their usage is recorded and workspace budgets enforce correctly again. (1.10.0)
- [`GET /v1/key/usage`](admin-api-guide.md) lets a caller read its own governance snapshot (requests, tokens, spend, remaining budget), scoped to its own key. (1.9.0)
- `kv_quant: int4` now books the same KV cache size vLLM and SGLang actually allocate, instead of under-sizing it and risking a first-token failure under a tight long-context config. (1.9.0)
- Model Host gains a mistral.rs subprocess engine, admin API job tracking for load/evict operations, and fleet-wide VRAM aggregation in the admin console. (1.9.0 / 1.10.0)
- AI routing learns live locality and shares caller quota across the mesh. (1.10.0)
- External AI guardrails now use hardened vendor contracts. (1.10.0)
- AI routing and state now carry production authority end to end. (1.9.0)
- Classifier safety guardrails ship calibrated default centroids. (1.9.0)
- Six new AI providers, including AI21 Labs (Jamba), Clarifai, and Inception Labs. (1.9.0)
- vLLM prefix caching is now a config flag; opt-in Xet-aware weight transport. (1.9.0)
- Killed engines auto-recover on the next request. (1.9.0)
- Local classifier-based routing (`type: classifier` input guardrail). (1.8.0)
- Admin console reports context compression, and spend links through to the requests behind it. (1.8.0)
- `sbproxy_ai_multipart_inspection_skipped_total` makes the multipart guardrail gap visible. (1.11.0)

## Policies

**Breaking / needs attention:**

- **`agent_budget`'s `tokens_per_hour` limit is now actually enforced.** (1.11.0) The request-rate half worked; the token half never charged usage after a response completed until this fix.
- **Every `config_only` key now has a real disposition.** (1.11.0) Most visibly, `cors.enable: false` was silently ignored and CORS stayed enabled; it's now refused at config compile with a message naming the fix.

**Also shipped:**

- `policy: rego` and the AI gateway's Rego engine can load a module from a file (`module_path`) and accept pre-OPA-1.0 syntax (`rego_v0: true`); request and response modifiers gained a Rego form, and signed extension bundles can ship a `.rego` policy module. (1.12.0)
- `sbproxy rego test` runs Rego fixtures offline with per-module line coverage and a `--min-coverage` gate. (1.12.0)
- Rate limits converge across a gossip mesh with no Redis required. (1.10.0)
- Workspace rate-budget behavior now has one owner. (1.8.0)
- A rate-limit `key:` expression that fails to evaluate has corrected behavior. (1.9.0)

## Routing & traffic management

**Breaking / needs attention:**

- **`routing.strategy: token_rate` is now refused at config load instead of silently behaving like a different strategy.** (1.10.0) It scored providers against a per-provider limit no config field ever declared, so it was actually running `least_token_usage` under another name. If you have `token_rate` set, change it to `least_token_usage` (what you were already running) or to `headroom`/`reset_aware`, which score real rate-limit headers.
- **A `sticky:` block on the load balancer is now a hard config-compile refusal, not just a boot warning.** (1.11.0) It never issued an affinity cookie; use the new `algorithm: ring_hash` for session or cache affinity that survives a pool resize.

**Also shipped:**

- Forward rules can match on a field inside the JSON request body (RFC 6901 JSON Pointer), ANDed with path/header/query matchers. (1.11.0)
- Forward rules can match on HTTP method. (1.11.0)
- Origin hostnames can start with `*.` for wildcard, longest-suffix routing. (1.11.0)
- `origins.*.timeouts` makes all five upstream deadlines configurable per origin. (1.11.0)
- `algorithm: ring_hash` adds ketama-style consistent hashing to the load balancer, so a pool resize only moves the keys owned by the target that joined or left. (1.11.0)
- `request_modifiers[].js_script` now actually runs (previously only its Lua twin executed). (1.11.0)

## API Gateway / core proxy

**Breaking / needs attention:**

- **A configured origin now owns `/health` on the data plane.** (1.12.0) A load balancer probing `/health` with a configured origin's Host header now reaches your upstream instead of the proxy's built-in `{"status":"ok"}`. An upstream with no `/health` route now answers 404 there, which a health checker reads as unhealthy; point such probes at the admin listener's health route, or make sure the upstream serves the path.
- **The response cache now stores the transform chain's output.** (1.12.0) All existing response-cache entries are retired on upgrade (one cold start per key).

**Also shipped:**

- `compression.level` is now applied to the response encoders instead of being parsed and dropped. (1.11.0)
- `response_modifiers[].status.text` is now emitted as the HTTP/1.x reason phrase. (1.11.0)
- Config compile now warns when `invalidate_on_mutation` is combined with the `file` or `memcached` response-cache store, since neither backend can purge by key prefix and mutations were silently invalidating nothing. (1.11.0)
- A response-cache store you can pick, plus memcached key hashing and 30-day TTL clamping, and file-cache entries/concurrent writes no longer torn. (1.8.0)
- `proxy.bind_address` now correctly makes the public listener's interface configurable. (1.10.0)

## Transforms

**Breaking / needs attention:**

- **`allowed_hosts:` on the `wasm` transform is removed.** (1.11.0) It parsed and was never enforced (no networking exists at that boundary); an authored key now fails config compile.
- **`on_request:` on the `cel` transform is removed.** (1.11.0) Transforms are response-side only; the key was compiled and never evaluated.

**Also shipped:**

- The `a2a_agent_card_rewrite` transform now actually runs; a configured rewrite previously silently passed agent-card bodies through unchanged, leaking the real upstream URL. (1.11.0)
- `proxy.scripting.javascript.sandbox` now tunes the live QuickJS engines used by response modifiers, `javascript`/`js_json` transforms, and WAF custom rules. (1.11.0)

## Plugins & extensibility

**Also shipped:**

- Extension bundle manifests can declare `secret_vars` and `masked_vars` on a hook, resolved through the standard secret-reference forms. (1.11.0)
- Bundles can make granted outbound HTTP calls via a declared `net:outbound=` permission and the sandboxed `sbproxy_fetch` host function. (1.12.0)
- `ai_tool_call` hooks can rewrite tool calls in-flight, gated by `execution.mutates: true`. (1.12.0)
- `digest_scope: bundle_v1` covers a whole extension bundle's digest, including `bundle.yaml`, not just the entry file. (1.11.0)
- Extension bundles: install TypeScript, JavaScript, or WebAssembly directly. (1.10.0)
- A bundle's declared `failure_posture` is now the posture the pipeline actually uses, and a bundle hook can no longer end a request with a non-HTTP status. (1.10.0)
- `sbproxy-plugin` is 0.3.0, with `ActionOutcome` as the headline change. (1.10.0)

## MCP & Agents

**Breaking / needs attention:**

- **A federated MCP server with no `rbac:` label no longer defaults to allow-all.** (1.11.0) See also under Security.

**Also shipped:**

- The full MCP surface is governed: `content_filters` runs the shared secret and PII detector catalog over tool-call arguments and results (`off | warn | redact | block` per category), sessions are tenant-bound with fail-closed caps, `result_policies[]` runs CEL/Rego over tool results, and `federated_servers[].status` stages a draft / approved / deprecated review lifecycle. (1.12.0)
- Every dispatched MCP `tools/call` emits an `mcp_governance_decision` evidence event; `events.fail_closed` can refuse a call rather than serve it un-evidenced, and tool-definition changes and registry status transitions emit their own records. (1.12.0)
- Federated MCP servers resist a silent protocol or auth downgrade: `federated_servers[].protocol` pins an era, and `downgrade: warn | block` acts on a peer answering weaker than it ever has. (1.12.0)
- `argument_policies[]` authorizes an MCP tool call on its arguments with CEL or Rego after RBAC and schema validation; a rule can only narrow an allow, and a rule that cannot be evaluated fails closed. (1.12.0)
- An `mcp` action's `flow` block adds deterministic session-flow enforcement (Meta's Rule of Two): a session that read something untrusted and touched something sensitive is warned or blocked on its next outbound call. (1.12.0)
- The base MCP connect is egress-gated and inventoried at `GET /api/egress` under purpose `mcp_upstream`. (1.12.0)
- A prefix-namespaced federated tool call now reaches its upstream instead of being refused as unknown. (1.12.0)
- The MCP gateway now federates `prompts/list` and `prompts/get`. (1.11.0)
- The configured A2A agent card is now served at its well-known path (`/.well-known/agent-card.json`). (1.11.0)
- `examples/admin-mcp` lets an agent client (Claude Code, Cursor) manage a running proxy over MCP. (1.11.0)
- The `a2a` policy no longer decides on inputs the caller controls, and `sbproxy_a2a_hops_total` distinguishes verified allows from unverified ones. (1.10.0)

## Payments

**Breaking / needs attention:**

- **`usage_reporters.stripe_meter` gains two required fields, `source` and `unit` [BREAKING].** (1.10.0) A config with a `stripe_meter` block and no `source` no longer parses. Set `source` to `http`, `ai`, or `mcp`, and `unit` to the unit that meter bills. There is deliberately no default: one request can produce a request receipt, an AI usage record, and an MCP tool-call record, and billing more than one of those against the same meter double-charges the customer.

**Also shipped:**

- A configured usage reporter (`proxy.payments.usage_reporters.stripe_meter`) now actually receives live proxy traffic instead of billing nothing; the call to the provider happens off the request path, so no request waits on Stripe. (1.10.0)
- A payment stuck in reconciliation now withholds fresh 402 challenges from the payer it belongs to, not every payer of the route. (1.11.0)
- The served-quote nonce ledger for x402 payments is now SQLite-durable; previously a client re-presenting a settled quote token got served twice per restart. (1.11.0)
- A stranded payment intent with no identifiable payer now stops withholding challenges after a bounded window. (1.11.0)
- A plain "not paid yet" read from a Lightning invoice no longer poisons the settlement intent. (1.11.0)
- Meter receipts now fold extra attempts under `billable.retry: collapse`. (1.12.0)

## Observability & operations

**Breaking / needs attention:**

- **The `outcome` label value `auth_denied` split in two.** (1.12.0) Dashboards keyed on `outcome="auth_denied"` need updating; usage rollups keep the legacy mapping.
- **Single-tenant traffic now reports workspace `__default__`, not `default`.** (1.12.0) Dashboards or alerts matching `workspace="default"` need updating.
- **The in-process burn-rate rule now reads the hour it is named for.** (1.11.0) A slow burn under 14.4x over the last hour no longer opens an in-process incident; alert labels changed from `scope`+`objectives` to `scope`+`objective`+`window`, which changes the PagerDuty dedup key.
- **Unsupported `telemetry.propagation` values now fail boot.** (1.9.0)

**Also shipped:**

- A new `egress_refused` typed event carries every purpose-scoped outbound-dial refusal to the `events:` sink; all six config-reload paths write `config_audit` records, mTLS handshake rejections and circuit-breaker transitions get structured records, and boot warns when `events.types:` names a type nothing publishes. (1.12.0)
- Trace spans now cover the ordinary proxied request, not only the AI gateway (`sbproxy.intake.accept`, `.authenticate`, `sbproxy.policy.enforce`, `sbproxy.transform.shape`). (1.11.0)
- A top-level `request_events:` block lets request events leave the process (`logging` or `file` NDJSON sinks). (1.11.0)
- `proxy.observability.log.level` and `.format` now actually reach the process logger. (1.11.0)
- Seven more outbound helper call sites inject W3C trace context (ledger redeem, Web Bot Auth directory, webhooks, OAuth/OIDC token exchange, forward auth). (1.11.0)
- A credential's `attrs.team` now reaches the request principal across all attribution surfaces. (1.11.0)
- OTLP metrics export actually exports; OTLP spans are flushed on graceful shutdown and join the caller's trace. (1.9.0 / 1.10.0)
- The metering-divergence health sweep no longer alerts on every tenant with billable traffic; the `ledger` health component is renamed `usage_ledger`. (1.11.0)
- Six new self-host observability metrics cover artifact-acquisition failures, model-directory and replica-selection exclusions, placement rejections, and the key-policy budget fail-closed path, each with alerts and dashboard panels. (1.9.0)

## Deployment

**Also shipped:**

- The Kubernetes Gateway API controller ships in OSS for the first time, rendering `sb.yml` from `Gateway`/`HTTPRoute`/`GRPCRoute` resources. (1.11.0)
- cert-manager is now the recommended TLS path on Kubernetes; the operator refuses multi-replica pod-local ACME configurations that can't work. (1.11.0)
- ACME HTTP-01 challenge validation now works behind a load balancer (shared `KVStore` instead of a process-local map). (1.11.0)
- ACME issuance now retries a `badNonce` rejection with the nonce the server actually returned, instead of failing outright. (1.11.0)
- The Helm chart, the operator crate, and the workspace version now agree instead of reporting three different numbers; a stock `helm install` no longer lands the operator pod in `ImagePullBackOff`. (1.11.0)
- Self-host certification writes a complete `record.json` (macOS version, chip, memory, engine version, digest, time to ready). (1.12.0)
- The Kubernetes operator image now builds inside Docker instead of copying a host-compiled, wrong-platform binary. (1.12.0)
- llama.cpp and mistral.rs Model Host provisioning works on the official distroless Docker image: engine archives unpack in-process instead of shelling out to a `tar` the image does not contain. (1.12.0)
- `sbproxy doctor --strict` runs startup checks (GPU visibility, `/dev/shm` sizing, weight-cache mount, cluster identity) so a managed worker refuses to boot into a configuration it can't serve, instead of joining the cluster and failing every dispatch. (1.10.0)
- See also under Security: `sbproxy run` and `sbproxy service install` no longer bind to `0.0.0.0` by default. (1.10.0)
- The self-host matrix has a runner and an evidence ledger; the macOS launchd agent has an environment file. (1.10.0)
- Worker and gateway container images are split, with a generic cloud image. (1.9.0)
- `sbproxy service install|uninstall|status` runs a model as a background service. (1.9.0)
- Operate a config authority from the command line; preview a configuration before it lands; subscribe to signed configuration from an upstream authority. (1.8.0)

## Reference / configuration

**Breaking / needs attention:**

- **Five config keys that parsed, warned, and governed nothing are now removed.** (1.11.0) `origins.*.connection_pool.max_connections`, `.max_lifetime_secs`, `origins.*.traffic_capture`, `origins.*.sessions.ttl_seconds`, `proxy.device_parser_file`; each now fails config compile naming a real replacement.
- **`audit.sink: tracing` and the origin-level `rate_limit_headers:` block are removed.** (1.11.0) Both were accepted and did nothing.
- **`proxy.messenger_settings` names the deleted bus defects and must be removed.** (1.12.0) Config distribution is `proxy.config_authority`, and cache invalidation is `POST /admin/cache/purge`.
- **A CEL syntax error is now a config error everywhere CEL comes from.** (1.9.0) A config with a CEL typo that used to boot fine will now refuse to start; run `sbproxy validate` against your config before upgrading.
- **A reload that fails now really does change nothing.** (1.8.0)
- **Changing `proxy.secrets` on a reload is now refused instead of silently ignored.** (1.8.0) The secret resolver holds live backend connections and is only ever built at startup, so a reload never actually picked up the change; it now fails outright with a message saying a restart is required. Rotating a secret's value inside your backend still needs no restart, only changing where SBproxy looks does.

**Also shipped:**

- `localsecret://` replaces the overloaded `secret://` scheme name (old spelling still works, with a deprecation warning). (1.11.0)
- `env:NAME` now resolves through the same secret resolver as every other secret-bearing field. (1.11.0)
- Config compile now enforces GraphQL depth/introspection/syntax limits before upstream dispatch, keys concurrent-limit policies by client/API key/header/route, and refuses the reserved HTTP/3 listener at compile time instead of logging and continuing without QUIC. (1.8.0)
- NOTICE now names the 27 Apache-2.0-only crates it previously omitted, and a CI gate keeps it that way. (1.12.0)
