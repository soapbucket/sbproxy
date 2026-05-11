# Policy engine
*Last modified: 2026-05-10*

The policy engine evaluates a list of policies on every request. Each policy returns one of four verdicts: `Allow`, `Deny`, `AllowWithHeaders`, or `Confirm`. The dispatcher folds the per-policy results into a single decision and applies it before the request reaches the upstream.

This page covers the `semantic_constraint` policy and the natural-language linter that supports it. The full set of built-in policies is listed in [features.md](features.md).

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
- `policy_id`: optional UUID-shaped reference to a pinned compiled policy. Recorded on the audit event but not consulted at evaluation time in the OSS build.
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

## NL linter (L001-L009)

Authors who want to express a policy in plain English use the same backend through the NL compiler. The compiler runs a fixed linter before issuing the LLM compile call. Each rule catches a class of underspecified or dangerous NL input that, if fed through the compiler unchecked, produces Cedar that looks plausible but is wrong.

| Rule | What it catches |
|---|---|
| L001 | Resource type referenced but not declared in the workspace schema. |
| L002 | Temporal constraint without a timezone or UTC marker. |
| L003 | Rate constraint missing its time unit (per second, per minute, ...). |
| L004 | Implicit deny-all or allow-all phrasing. The author must spell it out. |
| L005 | Conflicting polarity: the same input implies both allow and deny on overlapping actions. |
| L006 | Model name token that is not in the configured model schema. |
| L007 | User-attribute reference whose left-hand side is not a known principal type. |
| L008 | Monetary amount without a currency code or symbol. |
| L009 | Bare predicate that names no principal, action, or resource. |

A non-empty linter output blocks compilation. The author resolves the violations and re-submits.

## OSS vs enterprise capability boundary

OSS ships:

- The `semantic_constraint` policy module.
- The `NlLinter` rule set (L001-L009).
- The `NlCompiler` that wraps the linter and the judge backend and emits a `CompiledPolicy` candidate with a SHA-256 `content_hash`.
- An in-memory `CompiledPolicyStore` keyed by `policy_id`.
- A single-provider `JudgeClient` with an LRU verdict cache and a per-process token budget tracker.

OSS does not ship:

- A Cedar evaluator. The compiled Cedar source is stored verbatim and used for audit replay; the OSS build does not enforce Cedar policies at the request path.
- Multi-provider judge routing or the calibration tracker. The OSS judge is single-provider; the enterprise router adds failover, weighted blending, and a calibration delta metric.
- A durable compiled-policy store. The in-memory store is OSS scope; the enterprise tier wraps the same struct shape with a durable backing store.
- The hold-pending `Confirm` parking queue. The OSS dispatcher bridges `Confirm` to `AllowWithHeaders` with an `X-Policy-Confirm` header; the enterprise interceptor parks the request, posts to the configured webhook, and resumes on approval.

The enterprise tier reads the same `CompiledPolicy` struct shape produced by the OSS compiler, so policies authored under OSS upgrade cleanly when the enterprise evaluator is wired in.

## request_validator

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

Runnable example: `examples/81-request-validator/sb.yml`.

## concurrent_limit

Caps in-flight requests per key. Distinct from `rate_limiting`, which throttles requests per second. Concurrent limits protect backends with low concurrency budgets: legacy SOAP services, DB-bound endpoints, GPU inference workers. Source: `crates/sbproxy-modules/src/policy/concurrent_limit.rs`. Each accepted request takes a permit; the permit releases when the request finishes. When `max` permits are already issued for a key, new requests are rejected immediately with `status` (default 503).

Key strategies:

- `origin` (default): one global counter for the route.
- `ip`: one counter per client IP.
- `api_key`: one counter per `X-Api-Key` header (or `Authorization: Bearer` when no api-key auth is configured).

```yaml
policies:
  - type: concurrent_limit
    max: 3
    key: ip
    status: 503
    error_body: '{"error":"too many concurrent requests, retry shortly"}'
```

Runnable example: `examples/82-concurrent-limit/sb.yml`.

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

Per-route enforcement for agent-to-agent calls. Source: `crates/sbproxy-modules/src/policy/a2a.rs`. The policy fires after authentication and after the resolver chain has populated `caller_agent_id`. Detection runs automatically on two header signals (`Content-Type: application/a2a+json` and `MCP-Method: agents.invoke`); `route_glob` is the operator escape hatch.

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

Runnable example: `examples/40-a2a-protocol/sb.yml`.

## See also

- `docs/adr-policy-compilation.md`: design rationale for the linter, the compiler, and the pinning contract.
- `docs/adr-judge-trait.md`: contract the judge backend implements.
- `docs/adr-policy-verdict-shape.md`: full design of the four-verdict `PolicyDecision` enum and the dispatcher resolution rules.
- `docs/adr-policy-audit-binding.md`: shape of the `PolicyVerdictEvent` carried on the audit pipeline.
- `docs/adr-policy-engine-unification.md`: long-term plan for the runtime that evaluates pinned Cedar policies.
- [examples/semantic-constraint/sb.yml](../examples/semantic-constraint/sb.yml): runnable config exercising the YAML surface.
