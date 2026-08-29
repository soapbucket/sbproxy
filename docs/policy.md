# Policy engine
*Last modified: 2026-08-29*

The policy engine evaluates a list of policies on every request. Each policy returns one of four verdicts: `Allow`, `Deny`, `AllowWithHeaders`, or `Confirm`. The dispatcher folds the per-policy results into a single decision and applies it before the request reaches the upstream.

SBproxy ships thirty `policies:` list types. This page is the map: every policy, grouped by what it is for, linking to wherever it is actually documented. Some get their own dedicated page; some are documented here; others are a subsection of a broader page such as [api-security.md](api-security.md) or [scripting.md](scripting.md). Two more checks that behave like policies but are not `policies:` list entries are covered separately at the bottom of this page.

If you are deciding which policy stops which threat, start with the group headings below and [security.md](security.md). If you already know which policy you want and just need the field list, follow its link directly.

## The policy catalog

**Traffic-shape and abuse.** Limits keyed on volume, concurrency, or request shape rather than content.

- `rate_limiting`: token-bucket request-rate limiting per key. [api-security.md](api-security.md#no-limit-on-what-one-caller-can-consume).
- `rate_limit_budget`: opts an origin into the workspace-wide `rate_limits:` ceiling and its `Normal` -> `Soft` -> `Throttle` -> `AutoSuspend` escalation. [This page](#rate_limit_budget).
- `concurrent_limit`: caps in-flight requests per key, distinct from a per-second rate limit. [This page](#concurrent_limit).
- `request_limit`: bounds body size, header count and size, and URL length, the shapes that never reach a rate limiter. [api-security.md](api-security.md#no-limit-on-what-one-caller-can-consume).
- `ddos`: per-IP request-rate blocking with a cooldown window. [api-security.md](api-security.md#no-limit-on-what-one-caller-can-consume).
- `ip_filter`: allow or deny by CIDR or address. [api-security.md](api-security.md#automated-traffic-you-cannot-distinguish).
- `agent_budget`: semantic rate limit keyed on the resolved `agent_id` rather than IP, for LLM-driven callers that do not pause between requests. [agent-budget.md](agent-budget.md).

**Identity and access.** Who is calling, and what they are allowed to reach.

- `object_authz` (alias `bola`): object- and function-level authorization, catching BOLA and BFLA. [object-authz.md](object-authz.md).
- `agent_class`: stamps the resolved agent-identity verdict onto the upstream request. [This page](#agent_class).
- `a2a`: depth, cycle, and allowlist enforcement for agent-to-agent hops. [This page](#a2a) and [a2a-gateway.md](a2a-gateway.md).
- `csrf`: signed-cookie CSRF token verification for state-changing browser requests. [api-security.md](api-security.md#browser-facing-misconfiguration).
- `security_headers`: sets baseline security response headers. [api-security.md](api-security.md#browser-facing-misconfiguration).

**Content and input safety.** Validating or constraining what a request or response actually carries.

- `request_validator`: validates request bodies against a JSON Schema at the edge. [This page](#request_validator).
- `openapi_validation`: validates request bodies against an OpenAPI 3.0 document. [openapi-validation.md](openapi-validation.md).
- `body_threat_protection`: structural JSON/XML body threat limits (nesting depth, container sizes, key/string lengths) with an unconditional XML DTD refusal, in block or observe-only tap mode. [api-security.md](api-security.md#structural-body-threat-limits).
- `waf`: a curated signature ruleset against common web-application attack payloads. [waf-options.md](waf-options.md).
- `http_framing`: refuses request-smuggling and desync primitives. [This page](#http_framing).
- `sri`: enforces Subresource Integrity on scripts the origin serves. [api-security.md](api-security.md#browser-facing-misconfiguration).
- `content_digest`: verifies an inbound body against its RFC 9530 `Content-Digest` header. [content-digest.md](content-digest.md).
- `page_shield`: watches for third-party script drift on pages the origin serves. [api-security.md](api-security.md#browser-facing-misconfiguration).
- `dlp`: scans the request URI and headers for regulated-data shapes and tags or blocks. `scan_body` defaults true, but the live request-filter chain snapshots an empty body, so a secret that appears only in the POST body is not seen. Requests only, and it detects rather than masks. [api-security.md](api-security.md#data-leaving-that-should-not).
- `exposed_credentials` (alias `leaked_credentials`): detects a known-leaked basic-auth password and tags or blocks. [exposed-credentials.md](exposed-credentials.md).

**AI-specific.** Policies with no equivalent in an ordinary API gateway.

- `ai_crawl_control` (alias `pay_per_crawl`): the Pay Per Crawl 402 challenge and token ledger for AI crawlers. [ai-crawl-control.md](ai-crawl-control.md).
- `prompt_injection_v2`: a swappable detector plus an enforcer that maps a score onto an action. [prompt-injection-v2.md](prompt-injection-v2.md).
- `semantic_constraint`: routes a request through an LLM-as-judge backend for a natural-language rule. [This page](#semantic_constraint).

**Enrichment.** Producers that annotate a request for downstream identity and anomaly hooks; neither denies traffic.

- `geoip`: resolves the client IP to country / continent / city / ASN via a MaxMind-compatible MMDB. [request-enrichment.md](request-enrichment.md).
- `user_agent_parser`: parses the `User-Agent` header into browser / OS / device-type plus a headless-automation-library signal. [request-enrichment.md](request-enrichment.md).

**Scripting-driven.** Policies whose logic is an expression or module you author rather than a fixed field set.

- `expression`: a CEL boolean predicate; `false` denies. [This page](#calling-it) has a worked example; [scripting.md](scripting.md) has the full surface. Often paired with the headless-browser score from [headless-detection.md](headless-detection.md).
- `rego`: a Rego/OPA module evaluated against the same request context as `expression`, for teams that already have Rego. [scripting.md](scripting.md#3a-rego-policies).
- `assertion` (alias `response_assertion`): an observational CEL check against the response; a false assertion is logged and never blocks traffic. [scripting.md](scripting.md#response-assertions).

**One pack, not a twenty-ninth type.** `owasp_api_top10` is a policy-pack entry the compiler expands into concrete types from the groups above (`object_authz`, `rate_limiting`, `ddos_protection`, `request_limit`, `concurrent_limit`, `security_headers`, `http_framing`, and a `json_projection` transform) before any policy parses. It backs off per item when the origin already authors that type, and reports every enabled item in a five-state manifest (`enforced`, `report_only`, `needs_operator_input`, `operator_authored`, `not_covered`) at plan time and at `GET /admin/owasp-api-pack`. [owasp-api-top10.md](owasp-api-top10.md).

## Calling it

Three examples carry a policy this page touches. The one used here is
[`examples/cel-policy/`](../examples/cel-policy/), because it is the only one
that demonstrates the *engine* described above: a policy returning `Deny` and
the dispatcher turning that verdict into a response. The other two,
[`ai-policy-cel`](../examples/ai-policy-cel/) and
[`ai-content-policy-fallback`](../examples/ai-content-policy-fallback/),
exercise the AI policy plane, which is a different evaluator documented in
[ai-policy-cel.md](ai-policy-cel.md).

That example runs one `expression` policy admitting a request only when the
`X-Tenant` header is `acme`, with `deny_status: 403` and
`deny_message: "tenant not allowed"`:

```bash
make run CONFIG=examples/cel-policy/sb.yml
```

A request that satisfies the expression is forwarded and the policy is
invisible:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: cel.local' \
  -H 'X-Tenant: acme' http://127.0.0.1:8080/get
# 200
```

One that does not is denied by the dispatcher before the upstream is reached:

```bash
curl -sS -i -H 'Host: cel.local' http://127.0.0.1:8080/get
```

```http
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 30

{"error":"tenant not allowed"}
```

The configured `deny_message` becomes the value of a single `error` field in a
JSON body; it is not returned as plain text. `deny_status` sets the status.
A wrong header value and a missing header produce the identical response,
because the expression evaluates to false either way rather than erroring.

This is the shape every `Deny` verdict on this page takes. What differs
between the policies is how the verdict is reached: `semantic_constraint` asks
a judge backend, `request_validator` checks a body, `concurrent_limit` and
`rate_limit_budget` check counters, and `expression` evaluates CEL. The
dispatcher's handling of the result is the same.

`semantic_constraint` is not demonstrated here because it requires a
configured LLM judge backend to reach a verdict at all.

## semantic_constraint

`semantic_constraint` routes the request through an LLM-as-judge backend and turns the verdict into an allow or deny. The prompt template is rendered against the request envelope before the call, so the same policy can express different rules per route, per method, or per host without re-deploying.

### Config shape

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://backend:3000
    policies:
      - type: semantic_constraint
        prompt_template: |
          Return verdict=allow when the request is routine API traffic
          and verdict=deny when the path looks like a sensitive admin
          route. Request: {{ request.method }} {{ request.path }}
        violations_block: true
        judge:
          endpoint: https://judge.internal/v1/chat/completions
          api_key_env: SBPROXY_JUDGE_API_KEY
          timeout_ms: 2000
          cache_capacity: 1000
          budget_tokens: 100000
```

### Fields

- `prompt_template`: a [minijinja](https://docs.rs/minijinja) template rendered against the request context. Available keys are `request.method`, `request.path`, `request.host`, and `request.query`. The rendered prompt is sent to the judge as the system message.
- `violations_block`: when `true`, a judge `deny` verdict surfaces as the configured HTTP status (default 403). When `false`, a `deny` is logged and the request is allowed; this is the monitor mode used during rollout.
- `judge.endpoint`: upstream chat-completions URL. The judge backend speaks an OpenAI-compatible body shape and accepts either a direct verdict body (`{"verdict": "allow" | "deny", ...}`) or a `choices[0].message.content` JSON envelope.
- `judge.api_key_env`: the name of the environment variable holding the bearer token. The proxy never stores the token in config (BYOK).
- `judge.timeout_ms`, `judge.cache_capacity`, `judge.budget_tokens`: per-policy bounds on round-trip latency, in-memory cache size, and per-process token budget. Defaults are 2000 ms, 10000 entries, and 100000 tokens.

### Verdict mapping

| Judge return | Enforcer return |
|---|---|
| `allow` | proxy continues to the upstream |
| `deny` and `violations_block: true` | proxy returns the configured status |
| `deny` and `violations_block: false` | proxy logs and continues |
| `BudgetExhausted` | proxy returns 429 with `judge_budget_exhausted` |
| any other error | proxy returns 500 with `semantic_constraint_judge_failure` (fail-closed) |

The fail-closed contract is deliberate: a misconfigured or unreachable judge cannot silently allow traffic. The 500 body is generic; structured detail goes to logs and metrics.

## Scope

`semantic_constraint` evaluates the configured prompt template directly against its judge. It does not compile natural-language rules into another policy language, store compiled policy records, or evaluate Cedar. Operators who need deterministic policy logic should use the built-in deterministic policies or a CEL expression.

## NL-to-Cedar decision

SBproxy does not offer natural-language-to-Cedar compilation: nothing turns a prose rule into Cedar policy text, and the inactive NL components that once attempted it had no runtime consumer and were removed. That is a different thing from the Cedar engine itself, which does ship: an `mcp` action's `cedar_policies` block hands Cedar source to `sbproxy-extension`'s compiler, which turns it into a schema-validated policy set, and its evaluator maps verdicts onto allow, deny, and confirm on the built-in MCP `tools/call` hook. Write Cedar under `cedar_policies`; the gateway compiles and enforces it at config load. A Cedar-only edit shows in `sbproxy plan` as Reload; `sbproxy cedar replay` previews the same source against a JSONL traffic sample. Confirm without `approval:` is a labelled refusal; with `approval:` the call parks until an operator acts in `/admin/ui/mcp-approvals`. The engine's embedded policy store (redb, stateless by default) is in the tree but is not yet wired to that hook; policies come from the config block. Dedicated page: [cedar-policy.md](cedar-policy.md). Runnable: [`examples/cedar-mcp-full/`](../examples/cedar-mcp-full/), [`examples/cedar-confirm-flow/`](../examples/cedar-confirm-flow/), [`examples/cedar-replay/`](../examples/cedar-replay/).

## request_validator

![a JSON body with the required field accepted, then one missing name rejected with the failure's JSON path](assets/request-validator.gif)

Validation happens at the edge before the upstream sees the body ([config](../examples/request-validator/)).

Validates request bodies against a JSON Schema at the edge. The schema is compiled at config-load time, so each request is a cheap dispatch. Source: `crates/sbproxy-modules/src/policy/request_validator.rs`. Only requests whose `Content-Type` matches one of `content_types` (default `application/json`) are validated; other media types pass through. Remote `$ref` resolution is disabled at the workspace level so a malicious schema cannot become an SSRF primitive. Rejection responses report the failure location (JSON path) without echoing the attacker-controlled payload.

```yaml
policies:
  - type: request_validator
    content_types:
      - application/json
    status: 400
    error_content_type: application/json
    schema:
      type: object
      required: [name, age]
      properties:
        name: {type: string, minLength: 1, maxLength: 100}
        age:  {type: integer, minimum: 0, maximum: 150}
      additionalProperties: false
```

Runnable example: `examples/request-validator/sb.yml`.

## concurrent_limit

![five parallel 3-second requests: three take permits, the other two are rejected 503 immediately](assets/concurrent-limit.gif)

`max: 3` caps in-flight requests per key ([config](../examples/concurrent-limit/)).

Caps in-flight requests per key. Distinct from `rate_limiting`, which throttles requests per second. Concurrent limits protect backends with low concurrency budgets: legacy SOAP services, DB-bound endpoints, GPU inference workers. Source: `crates/sbproxy-modules/src/policy/concurrent_limit.rs`. Each accepted request takes a permit; the permit releases when the request finishes. When `max` permits are already issued for a key, new requests are rejected immediately with `status` (default 503).

Key strategies:

- `global` (default): one counter for the policy mount.
- `ip`: one counter per client IP.
- `api_key`: one counter per `X-Api-Key` header (or `Authorization: Bearer` when no api-key auth is configured).
- `route`: one counter per request path. Query strings do not create separate buckets.
- `header:<name>`: one counter per value of the named request header.

The former `key` field and its `origin` value remain accepted for schema-v1
compatibility. New configuration should use `key_by`.

```yaml
policies:
  - type: concurrent_limit
    max: 3
    key_by: ip
    status: 503
    error_body: '{"error":"too many concurrent requests, retry shortly"}'
```

Runnable example: `examples/concurrent-limit/sb.yml`.

## rate_limit_budget

`rate_limit_budget` opts an origin into the workspace ceiling configured by the
top-level `rate_limits:` block. Its module owns the token buckets and the full
`Normal` → `Soft` → `Throttle` → `AutoSuspend` state machine; the proxy core
only turns a denied decision into HTTP 429.

```yaml
rate_limits:
  workspace_default:
    http_rps_sustained: 100
    http_rps_burst: 200
    soft_threshold_rps: 80
  escalation:
    abuse_threshold_throttle_to_suspend: 1000
    auto_suspend_cooldown_secs: 3600

origins:
  "api.example.com":
    action:
      type: proxy
      url: http://backend:3000
    policies:
      - type: rate_limit_budget
        headers:
          enabled: true
          include_retry_after: true
          include_ratelimit_policy: true
```

`per_route_rps` is not implemented and is rejected during config compilation
instead of being silently ignored. Use a separate `rate_limiting` policy for
per-route RPS control. The three header switches above are all enforced on the
429 response.

## http_framing

Detects HTTP request-smuggling and desync primitives before they reach the upstream. Source: `crates/sbproxy-modules/src/policy/http_framing.rs`. Pingora's parser catches the wire-level malformed input; this policy adds the semantic-ambiguity layer. Every violation returns 400 and increments `sbproxy_http_framing_blocks_total{reason}` so operators can track attack rates independently of `policy_denied`.

Violations rejected:

| Reason | What it catches |
|---|---|
| `dual_cl_te` | Both `Content-Length` and `Transfer-Encoding` headers present (RFC 9112 §6.1). |
| `duplicate_cl` | Multiple `Content-Length` headers, even when values match. |
| `malformed_te` | `Transfer-Encoding` value that is not exactly `chunked` after trim and lowercase. Catches `xchunked`, leading whitespace, `gzip, chunked` chains. |
| `duplicate_te` | Multiple `Transfer-Encoding` headers (TE.TE primitive). |
| `control_chars` | CR, LF, or NUL in header values that survived parsing. |

```yaml
policies:
  - type: http_framing
```

The policy has no tunable knobs today; the defense set is hard-coded because each violation maps to a known smuggling primitive.

## a2a

![an A2A invoke passing at chain depth 1, then rejected with 429 when the declared depth exceeds the cap](assets/a2a-protocol.gif)

Depth, cycles, and caller and callee lists are all enforced before the upstream ([config](../examples/a2a-protocol/)).

Per-route enforcement for agent-to-agent calls. Source: `crates/sbproxy-modules/src/policy/a2a.rs`. The policy fires after authentication and after the resolver chain has populated `caller_agent_id`. Detection runs automatically on two header signals (`Content-Type: application/a2a+json` and `MCP-Method: agents.invoke`); `route_glob` is the operator escape hatch.

Both header signals are the caller's to send or withhold, and an undetected request is allowed, so **set `route_glob` on any route you intend to govern**. Likewise the envelope these checks read is only trusted when it comes from a signed token's RFC 8693 `act` chain or from a peer in `proxy.trusted_proxies`; from anyone else it is discarded and the policy evaluates an empty envelope that trips nothing. [A2A gateway](a2a-gateway.md) covers both in full. It is worth reading before relying on the knobs below.

Knobs:

- `max_chain_depth`: hard ceiling on hops. Capped at 32 regardless of the configured value. Exceeding it returns 429.
- `cycle_detection`: `strict` (exact `agent_id` + `request_id` pair must not repeat; the request id checked is the parent request's, so a peer that omits it is not checked for cycles), `by_agent_id` (default; callee `agent_id` must not appear earlier in the chain), or `by_callable_endpoint` (`agent_id` + endpoint must not repeat). Cycles return 409.
- `allow_cycles`: when true, the cycle check is skipped.
- `callee_allowlist`: when non-empty, only listed callees pass. Off-list callees return 403.
- `caller_denylist`: agents on this list never get past the policy. Returns 403.
- `bill_caller_only`: true (default) bills the caller's wallet. Setting false flips to callee-billed semantics; the audit log stamps `pricing_anomaly: callee_billed` on each such transaction.
- `route_glob`: any request whose path matches is treated as A2A traffic even when the protocol-detection headers are absent.
- `push_target_allowlist`: hosts permitted as A2A 1.0 push-notification webhook targets even when they resolve to private address space. A2A lets a caller register a URL the upstream agent POSTs task artifacts to, so the default posture refuses private targets and non-HTTP schemes; internal callbacks are legitimate, but the operator names the host rather than getting it implicitly. Refusals return 403 with `a2a_push_target_blocked`.

```yaml
policies:
  - type: a2a
    max_chain_depth: 5
    cycle_detection: by_agent_id
    callee_allowlist:
      - "agent:openai:gpt-5"
      - "agent:anthropic:claude-4"
    caller_denylist:
      - "agent:bad:actor"
    route_glob: "/agents/**"
    push_target_allowlist:
      - "callbacks.internal.example"
```

On detected A2A 1.0 routes the proxy buffers the request body so the push-notification target can be validated before it reaches the agent. The v0 drafts have no push-notification surface and are not buffered.

Composing `prompt_injection_v2` on the same origin additionally scans the message the hop carries, with the action chosen by delegation depth. See [prompt-injection-v2.md](prompt-injection-v2.md#the-agent-boundary).

Runnable examples: `examples/a2a-protocol/sb.yml` for the hop policy on its own, `examples/a2a-prompt-injection/sb.yml` for the two composed.

## agent_class

The `agent_class` policy stamps the process-wide agent-identity resolver's verdict onto the upstream request. The resolver itself runs earlier in the pipeline, built at startup from the top-level `agent_classes:` block (catalog plus reverse-DNS and Web Bot Auth keyid tuning; see [configuration.md](configuration.md#agent-classes)). This policy is the per-origin knob that decides whether the resolved identity crosses to the origin as headers; the identity is already available without it, since `agent_id`, `agent_class`, and `agent_vendor` land on `sbproxy_requests_total` and the access log regardless.

Ships on by default in the released `sbproxy` binary, behind the `agent-class` cargo feature. Library consumers building `sbproxy-modules` or `sbproxy-core` directly opt in per crate.

```yaml
policies:
  - type: agent_class
    forward_to_upstream: true
    header_name: X-Forwarded-Agent-Class
    vendor_header_name: X-Forwarded-Agent-Vendor
    verified_header_name: X-Forwarded-Agent-Verified
```

Fields:

- `forward_to_upstream`: default `false`. Most operators want resolution without forwarding; sending the verdict to the upstream is opt-in so an origin server does not silently start depending on a taxonomy that can still change.
- `header_name`: header carrying the resolved `agent_id` (a catalog id or one of the sentinels `human`, `unknown`, `anonymous`). Defaults to `X-Forwarded-Agent-Class`.
- `vendor_header_name`: header carrying the resolved vendor display string. Defaults to `X-Forwarded-Agent-Vendor`.
- `verified_header_name`: header carrying `true` or `false` for whether the resolution came from a verified signal (a Web Bot Auth keyid or forward-confirmed reverse DNS) rather than an advisory User-Agent match. Defaults to `X-Forwarded-Agent-Verified`; an empty string disables it.
- `verify_reverse_dns`: intended as a per-origin override of the global `agent_classes.resolver.rdns_enabled`. It is accepted at config load, but the current wiring builds one resolver process-wide, so the override has no effect yet. Set the global `agent_classes.resolver.rdns_enabled` instead.

The resolver chain that produces the verdict (Web Bot Auth keyid, then forward-confirmed reverse DNS, then User-Agent regex, then a generic-crawler heuristic, then a `human` fallthrough) is documented alongside the top-level catalog in [configuration.md](configuration.md#agent-classes).

## Two checks outside the policy list

`bot_detection` and `threat_protection` behave like policies, denying a request before or during the pipeline, but they are not `policies:` list entries. Both are top-level keys directly under an origin, and both ship at `alpha` stability ([config-stability.md](config-stability.md#alpha)): the field name, shape, or behavior may change without notice.

- `bot_detection`: blocks by `User-Agent` substring match against a deny list, with an allow-list override, before authentication runs. The `mode` field is accepted but not consulted by the enforcement path today; the runtime always blocks a denied agent regardless of its value.
- `threat_protection`: bounds JSON request-body shape, nesting depth, key count, string length, array size, and total size, once the body is fully buffered. Any tripped limit returns 413, including a depth or key-count violation that a different service might call a 400. The `body_threat_protection` *policy* ([api-security.md](api-security.md#structural-body-threat-limits)) is the successor surface: JSON and XML, a 400 naming the violated limit, and a tap mode. Prefer it for new configs, with one caveat: the policy has no body-size knob, so move `json.max_total_size` to `request_limit.max_body_size` before dropping `threat_protection:` or the effective cap widens to the proxy's 8 MiB buffering bound.

Full field tables and examples for both are in [configuration.md](configuration.md#bot-detection) and [configuration.md](configuration.md#threat-protection).

## See also

- [examples/semantic-constraint/sb.yml](../examples/semantic-constraint/sb.yml): runnable config exercising the YAML surface.
- [configuration.md](configuration.md): the full field reference for every policy on this page, including defaults this page does not repeat.
- [security.md](security.md): which threat class each policy answers, read as a hub across the whole gateway rather than one policy at a time.
