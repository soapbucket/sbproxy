# Policy engine
*Last modified: 2026-07-26*

The policy engine evaluates a list of policies on every request. Each policy returns one of four verdicts: `Allow`, `Deny`, `AllowWithHeaders`, or `Confirm`. The dispatcher folds the per-policy results into a single decision and applies it before the request reaches the upstream.

This page covers the `semantic_constraint` policy. The full set of built-in policies is listed in [features.md](features.md).

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

SBproxy does not offer NL-to-Cedar compilation or a compiled-policy store. The inactive components had no runtime consumer and were removed in WOR-1986. `semantic_constraint` remains supported because it evaluates its configured judge directly. Reintroduce a compiler only with a concrete runtime consumer, evaluator or durable-store contract, and an explicit configuration lifecycle.

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
- `cycle_detection`: `strict` (exact `agent_id` + `request_id` pair must not repeat), `by_agent_id` (default; callee `agent_id` must not appear earlier in the chain), or `by_callable_endpoint` (`agent_id` + endpoint must not repeat). Cycles return 409.
- `allow_cycles`: when true, the cycle check is skipped.
- `callee_allowlist`: when non-empty, only listed callees pass. Off-list callees return 403.
- `caller_denylist`: agents on this list never get past the policy. Returns 403.
- `bill_caller_only`: true (default) bills the caller's wallet. Setting false flips to callee-billed semantics; the audit log stamps `pricing_anomaly: callee_billed` on each such transaction.
- `route_glob`: any request whose path matches is treated as A2A traffic even when the protocol-detection headers are absent.

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
```

Runnable example: `examples/a2a-protocol/sb.yml`.

## See also

- [examples/semantic-constraint/sb.yml](../examples/semantic-constraint/sb.yml): runnable config exercising the YAML surface.
