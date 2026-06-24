# A2A protocol envelope and policy

*Last modified: 2026-05-07*

![A2A protocol envelope and policy](../../docs/assets/a2a-protocol.gif)

The `a2a` policy enforces per-route safety on agent-to-agent traffic. Detection runs once per request and matches three signals: `Content-Type: application/a2a+json` (Google A2A), `MCP-Method: agents.invoke` (Anthropic A2A), and an optional operator route glob. When a request is detected as A2A, the policy applies a chain-depth cap, a cycle check, a callee allowlist, and a caller denylist before the request reaches the upstream. Off-list callers and callees get `403`, depth violations get `429`, and cycles get `409` with structured JSON error bodies.

The runtime always builds an `A2AContext` once detection fires, even when the optional body parsers are off. That means the policy enforces route limits in the OSS default build with no extra cargo features set; the parser features add envelope-aware fields the policy can use, but the safety floor does not depend on them.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# 200 - allowed callee, depth 1, no cycle. The Content-Type signal
# triggers Google detection and the policy passes.
$ curl -i -H 'Host: a2a.local' \
       -H 'Content-Type: application/a2a+json' \
       -H 'X-A2A-Caller-Agent-Id: agent:caller' \
       -H 'X-A2A-Callee-Agent-Id: agent:openai:gpt-5' \
       -H 'X-A2A-Task-Id: task-1' \
       -H 'X-A2A-Chain-Depth: 1' \
       http://127.0.0.1:8080/agents/invoke
HTTP/1.1 200 OK
```

```bash
# 429 - chain depth 7 exceeds the configured limit of 3.
$ curl -i -H 'Host: a2a.local' \
       -H 'Content-Type: application/a2a+json' \
       -H 'X-A2A-Caller-Agent-Id: agent:caller' \
       -H 'X-A2A-Callee-Agent-Id: agent:openai:gpt-5' \
       -H 'X-A2A-Chain-Depth: 7' \
       http://127.0.0.1:8080/agents/invoke
HTTP/1.1 429 Too Many Requests
retry-after: 0
content-type: application/json

{"error":"a2a_chain_depth_exceeded","limit":3,"depth":7}
```

```bash
# 403 - caller is on the denylist; runs before depth and cycle checks.
$ curl -i -H 'Host: a2a.local' \
       -H 'Content-Type: application/a2a+json' \
       -H 'X-A2A-Caller-Agent-Id: agent:bad:actor' \
       -H 'X-A2A-Callee-Agent-Id: agent:openai:gpt-5' \
       -H 'X-A2A-Chain-Depth: 1' \
       http://127.0.0.1:8080/agents/invoke
HTTP/1.1 403 Forbidden

{"error":"a2a_caller_denied","caller":"agent:bad:actor"}
```

```bash
# 403 - callee is not on the allowlist.
$ curl -i -H 'Host: a2a.local' \
       -H 'Content-Type: application/a2a+json' \
       -H 'X-A2A-Caller-Agent-Id: agent:caller' \
       -H 'X-A2A-Callee-Agent-Id: agent:unknown' \
       -H 'X-A2A-Chain-Depth: 1' \
       http://127.0.0.1:8080/agents/invoke
HTTP/1.1 403 Forbidden

{"error":"a2a_callee_not_allowed","callee":"agent:unknown"}
```

```bash
# 200 via the operator escape hatch. No A2A protocol headers, but
# the path matches the configured route_glob, so detection still
# fires and the policy applies.
$ curl -i -H 'Host: a2a.local' http://127.0.0.1:8080/agents/ping
HTTP/1.1 200 OK
```

## When to enable the parser features

The policy block on this example works in the default OSS build. The two cargo features add deeper envelope parsing on top:

- `a2a-anthropic` - parse the Anthropic A2A draft. Pulls `caller_agent_id`, `callee_agent_id`, `chain_depth`, and the chain history out of the request body when `MCP-Method: agents.invoke` is set, instead of relying on `X-A2A-*` request headers.
- `a2a-google` - parse the Google A2A draft. Same idea, but for `Content-Type: application/a2a+json` requests.
- `a2a` - convenience flag that enables both.

Operators who only need route-level limits (the case this example demonstrates) can leave all three off. Turn one or both on when the upstream agents speak the spec on the wire and you want the policy to read envelope fields directly from the body rather than from forwarded headers.

## v0 spec instability caveat

Both A2A drafts are pre-1.0 and still moving. Field names, header names, and detection signals can change between draft revisions, and the policy module follows whichever revision the parsers were built against at compile time. If you depend on the parser features in production, pin the SBproxy minor version so a routine upgrade does not silently change envelope semantics under you. The policy's route-level surface (`max_chain_depth`, `cycle_detection`, `callee_allowlist`, `caller_denylist`) is stable across draft churn; the body-shape coupling is not.

## What this exercises

- `policies[].type: a2a` - the A2A policy module
- `max_chain_depth` - hard cap on hop count, clamped to the policy's hard ceiling at compile time
- `cycle_detection: by_agent_id` - the default cycle mode (other modes: `strict`, `by_callable_endpoint`)
- `callee_allowlist` / `caller_denylist` - per-route allow and deny surfaces with stable error bodies
- `route_glob` - operator escape hatch that extends detection beyond the two protocol headers

## See also

- [docs/configuration.md](../../docs/configuration.md)
- The policy implementation at `crates/sbproxy-modules/src/policy/a2a.rs`
- The detection logic at `crates/sbproxy-modules/src/auth/a2a/mod.rs`
