# LoRA-aware routing

*Last modified: 2026-04-27*

Wires the `lora-aware` `RoutingStrategy` onto a three-target load balancer pool. The strategy walks each target's `metadata` map, looks for a `loaded_adapters` array, and prefers a healthy target that already has the requested adapter warm. If none does, it returns `None` and the configured `lb_method` (here `least_connections`) gets to pick. The route key extracts the LoRA adapter name from the request (typically the `?adapter=...` query parameter or a header) and dispatches to whichever replica advertises that adapter in its metadata. The strategy is fail-soft: missing or malformed `loaded_adapters` metadata is treated as "no adapters loaded" rather than an error, so a single misconfigured target cannot poison the pool.

Forward-looking config notes: `lb_method: plugin` and `strategy: lora-aware` are how `LoadBalancerAction` will dispatch into the trait once the wiring follow-up lands. The Fail-6 trait scaffold parses, registers, and unit-tests the strategy today; the load balancer does not yet consult `RoutingStrategy::select` on the request hot path. Until then, this example exercises the config schema and strategy registration; selection still runs through `least_connections` (the configured `algorithm`).

## Run

```bash
sb run -c sb.yml
```

No setup required. The targets in this example are illustrative URLs (`upstream-{0,1,2}.ai.internal:8443`); swap them for your real model-serving replicas. The `metadata.loaded_adapters` arrays are hand-pinned in this YAML; the production live-feed path that populates them from a sidecar's adapter inventory is GPU-aware's sibling work.

## Try it

```bash
# Once the wiring follow-up is in: requests for adapter=alice-tone
# prefer replica 0 or replica 2 (both warm) and the strategy picks
# whichever has fewer in-flight requests.
curl -sS -H 'Host: ai.local' \
     'http://127.0.0.1:8080/v1/chat?adapter=alice-tone' \
     -d '{"prompt":"hello"}'
```

```bash
# adapter=carol-voice - only replica 1 has it warm, so it routes there
# regardless of in-flight count.
curl -sS -H 'Host: ai.local' \
     'http://127.0.0.1:8080/v1/chat?adapter=carol-voice' \
     -d '{"prompt":"hello"}'
```

```bash
# adapter=unknown-name - no replica is warm; the strategy returns None
# and least_connections picks across the pool.
curl -sS -H 'Host: ai.local' \
     'http://127.0.0.1:8080/v1/chat?adapter=unknown-name' \
     -d '{"prompt":"hello"}'
```

## What this exercises

- `load_balancer` action with `algorithm: least_connections` as the fallback selector
- `lb_method: plugin` + `strategy: lora-aware` opt-in for the trait dispatcher
- Per-target `metadata.loaded_adapters` arrays read by the strategy
- Fail-soft handling of missing or malformed metadata so one bad target does not poison the pool

## See also

- [docs/routing-strategies.md](../../docs/routing-strategies.md)
- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
