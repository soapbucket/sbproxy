# Routing and traffic management
*Last modified: 2026-08-18*

How SBproxy decides which upstream serves a request: hostname matching, forward rules, load balancing, protocol-specific actions, failover, and the extension point for custom selection logic. This page is the hub; [configuration.md](configuration.md) is the field-by-field source of truth for every block below.

![The same hostname routed to different backends by request body content](assets/body-routing.gif)

## How a request finds an origin

Each key under `origins:` is a hostname. SBproxy matches the inbound `Host` header (or `:authority` on HTTP/2+) against those keys and runs that origin's configuration.

- Exact match beats wildcard. Between wildcards, the longest matching suffix wins.
- A wildcard's `*` must be the complete first label (`*.example.com`, not `a*.example.com`).
- Matching is byte-for-byte on lowercase ASCII after the port is stripped; internationalized domains must be keyed in punycode.

Every origin has one required `action` (proxy, load balancer, static, redirect, websocket, grpc, graphql, storage, ai_proxy, mcp, and more) plus optional auth, policies, transforms, and forward rules that sit alongside it as siblings, not nested inside it. See [Origins](configuration.md#origins) and [Origin architecture](configuration.md#origin-architecture).

For the request lifecycle this fits into (auth, policies, transforms, action, response work), see [core-concepts.md](core-concepts.md) and [architecture.md](architecture.md#3-request-pipeline).

## Routing within an origin: forward rules

`forward_rules` route specific requests to a different inline child origin based on method, path, header, query, or JSON body, evaluated in order with first-match-wins. Common uses: path-based microservice routing, version routing, sending writes to a different backend than reads, and dispatching AI traffic by the request body's `model` field.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://default-backend.internal:8080
    forward_rules:
      - rules:
          - path: { prefix: /api/v2/ }
        origin:
          id: v2-backend
          action: { type: proxy, url: https://v2-backend.internal:8080 }
```

Matchers: `path` (`prefix`, `exact`, `template` with named/catch-all/regex-constrained segments, or `regex`), `header`, `query`, `body` (an RFC 6901 JSON Pointer into the request body, e.g. `/model`), and `method`. Every matcher present in one entry is ANDed; multiple entries in a rule are ORed. A `when` CEL predicate runs last, after the structured matchers pass; see [scripting.md](scripting.md).

Body matching buffers up to `max_bytes` (default 65536, also the hard ceiling) and replays it unchanged upstream, so routing on the body never consumes it. A body larger than the limit, non-JSON, or a pointer that misses is a match miss, not a request failure. Full field tables and the buffering contract are in [Forward rules](configuration.md#forward-rules).

Runnable: [`examples/forward-rules/`](../examples/forward-rules/), [`examples/body-routing/`](../examples/body-routing/).

## Distributing traffic: the load balancer action

`type: load_balancer` spreads requests across weighted targets.

| Algorithm | Behavior |
|---|---|
| `round_robin` (default) | Cycle through active targets. |
| `weighted_random` | Probability proportional to weight. |
| `least_connections` | Fewest in-flight requests. |
| `ip_hash` / `uri_hash` / `header_hash` / `cookie_hash` | Sticky by client IP, path, a named header, or a named cookie. |
| `ring_hash` | Ketama-style consistent hashing; removing one of N targets remaps roughly 1/N of keys instead of reshuffling most of them. |

The `sticky:` block from older configs was removed (it never issued an affinity cookie); use `ring_hash` keyed on a cookie your application already sets instead.

**Health, failure, and resilience signals** apply per target and compose:

- **Active health checks**: background GET probes on an interval; targets failing `unhealthy_threshold` consecutive probes are excluded until `healthy_threshold` consecutive successes. See [Active health checks](configuration.md#active-health-checks); runnable at [`examples/active-health-checks/`](../examples/active-health-checks/).
- **Circuit breaker**: a Closed → Open → HalfOpen → Closed state machine per target; trips on `failure_threshold` consecutive failures, immediate isolation. See [Circuit breaker](configuration.md#circuit-breaker); runnable at [`examples/circuit-breaker/`](../examples/circuit-breaker/).
- **Outlier detection**: ejects a target whose error *rate* crosses `threshold` over a sliding `window_secs`, complementary to the breaker's consecutive-failure trigger. See [Outlier detection](configuration.md#outlier-detection); runnable at [`examples/outlier-detection/`](../examples/outlier-detection/).

When every target is filtered by these signals, the load balancer falls back to the unfiltered list rather than returning 502 to the client.

**Deployment patterns:** blue-green (`deployment_mode: { mode: blue_green, active: green }`, targets tagged `group: blue`/`green`) and canary (`deployment_mode: { mode: canary, weight: 10 }`, a `group: canary` subset). See [Blue-green deployments](configuration.md#blue-green-deployments) and [Canary deployments](configuration.md#canary-deployments); runnable at [`examples/load-balancer/`](../examples/load-balancer/) and [`examples/load-balancer-deployment/`](../examples/load-balancer-deployment/).

**Service discovery:** `service_discovery: { enabled: true, refresh_secs: 30 }` on a `proxy` action re-resolves the hostname periodically and rotates across the current A/AAAA set, instead of pinning to whatever IP the first connection resolved. Runnable at [`examples/service-discovery/`](../examples/service-discovery/).

## Custom routing logic: the RoutingStrategy extension point

The eight built-in algorithms above are fallback selectors. Setting `strategy: <name>` on a `load_balancer` action runs a registered `RoutingStrategy` implementation first; it sees only the already health/circuit-breaker/outlier-filtered eligible targets and can return `None` to defer to `algorithm`.

Production strategies: `first-healthy`, `lora`, `lora-aware` (routes to a target advertising a warm `X-LoRA-Adapter`), `gpu-aware` (routes by configured `metadata.gpu_utilization`, never polled), and `bandit` (learns a latency-sensitive reward from real completed outcomes). None of them fabricate cost, token-price, or GPU telemetry that wasn't configured or observed.

Registering a new strategy is a Rust `inventory::submit!` call in an out-of-tree crate linked into the proxy binary; see [routing-strategies.md](routing-strategies.md) for the trait shape and a worked registration. Runnable, with a docker-compose harness that shows which target actually answered: [`examples/routing-strategies/`](../examples/routing-strategies/), [`examples/lora-aware-routing/`](../examples/lora-aware-routing/).

## Protocol-specific routing

Beyond plain HTTP `proxy`, dedicated actions route other transports through the same origin/policy/transform pipeline:

- **WebSocket** (`type: websocket`): proxies `ws://`/`wss://`. The `subprotocols` and `max_message_size` fields are accepted by config but not currently enforced; see [websocket.md](websocket.md) for what actually runs before and after the upgrade. Runnable at [`examples/websocket-proxy/`](../examples/websocket-proxy/).
- **gRPC** (`type: grpc`): proxies `grpc://`/`grpcs://`, with `grpc_web: true` letting browser gRPC-Web clients reach a native gRPC upstream, and optional REST-to-gRPC `transcode` bindings from an OpenAPI-style HTTP route to a unary gRPC call. Runnable at [`examples/grpc-h2c/`](../examples/grpc-h2c/).
- **GraphQL** (`type: graphql`): transparent by default; setting `max_depth`, `allow_introspection: false`, or `validate_queries: true` turns on fail-closed parsing (syntax only, not schema-aware) ahead of the upstream, including a 64 KiB validated-body limit and whole-batch rejection. Runnable at [`examples/graphql-gateway/`](../examples/graphql-gateway/).

Field tables for each: [configuration.md#websocket](configuration.md#websocket), [configuration.md#grpc](configuration.md#grpc), [configuration.md#graphql](configuration.md#graphql). WebSocket and GraphQL also have their own dedicated pages, [websocket.md](websocket.md) and [graphql.md](graphql.md), covering upgrade semantics, validation placement, and honest limits in more depth than the field tables alone.

## Routing AI traffic

`type: ai_proxy` origins pick a provider using a distinct set of strategies (`fallback_chain`, `weighted`, `cost_optimized`, `outcome_aware`, `race`, `cascade`, and more) that read AI-specific signals like realized cost-per-success and content-policy fallback, not the eight `load_balancer` algorithms above. This is a different routing surface with its own guardrail, budget, and resilience configuration; see [ai-gateway.md](ai-gateway.md#routing-strategies) for the full reference rather than duplicating it here.

When none of the built-in strategies fit, `ai_routing_policy` hands the
decision itself to a sandboxed CEL expression over the same `ai.*` signals;
see [ai-policy-cel.md](ai-policy-cel.md) and
[`examples/ai-routing-policy/`](../examples/ai-routing-policy/) for a
complete working config.

## Failing over: fallback origin

`fallback_origin` swaps in a backup action (static, redirect, mock, proxy, anything) when the primary errors (`on_error: true`) or returns a listed status (`on_status: [502, 503, 504]`). It runs only the fallback action, not the origin's own auth/policies/transforms; point it at another `proxy` origin if you need the full chain. See [Fallback origin](configuration.md#fallback-origin); runnable at [`examples/fallback-origin/`](../examples/fallback-origin/).

## Where an SRE lead goes next

Everything above that reacts to failure (health checks, circuit breaker, outlier detection, fallback origin) is the routing-layer half of resilience. For the operational half, deployment topology, alert-to-runbook mapping, and capacity math, see [degradation.md](degradation.md), [operator-runbook.md](operator-runbook.md), and [capacity-planning.md](capacity-planning.md).

## Examples

| Example | Covers |
|---|---|
| [`forward-rules`](../examples/forward-rules/) | Path/header/method-based forward rules |
| [`body-routing`](../examples/body-routing/) | Routing on a JSON request-body field |
| [`load-balancer`](../examples/load-balancer/) | Basic algorithm selection |
| [`load-balancer-deployment`](../examples/load-balancer-deployment/) | Blue-green and canary |
| [`active-health-checks`](../examples/active-health-checks/) | Active probes |
| [`circuit-breaker`](../examples/circuit-breaker/) | Consecutive-failure isolation |
| [`outlier-detection`](../examples/outlier-detection/) | Error-rate ejection |
| [`service-discovery`](../examples/service-discovery/) | DNS re-resolution and IP rotation |
| [`routing-strategies`](../examples/routing-strategies/) | gpu-aware and lora-aware strategies side by side |
| [`lora-aware-routing`](../examples/lora-aware-routing/) | Adapter-aware target selection |
| [`fallback-origin`](../examples/fallback-origin/) | Degraded-backend failover |
| [`grpc-h2c`](../examples/grpc-h2c/) | gRPC over cleartext HTTP/2 |
| [`graphql-gateway`](../examples/graphql-gateway/) | Fail-closed GraphQL validation: depth, introspection, batches, and the 64 KiB body limit |
| [`websocket-proxy`](../examples/websocket-proxy/) | Upgrade handshake, an auth gate before it, and what post-upgrade traffic is not inspected |
| [`correlation-id`](../examples/correlation-id/) | Request-ID propagation across a routed hop |
| [`ai-routing-policy`](../examples/ai-routing-policy/) | Operator-authored CEL routing decision over AI-specific signals |
