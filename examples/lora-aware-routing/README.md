# LoRA-aware routing

*Last modified: 2026-07-26*

![LoRA-aware routing](../../docs/assets/lora-aware-routing.gif)

Wires the production `lora-aware` `RoutingStrategy` onto a three-target load balancer pool. The strategy reads each target's `metadata.loaded_adapters` array and prefers an eligible target that already has the requested adapter warm. If none does, it returns `None` and `algorithm: least_connections` picks the target. The adapter comes from `X-LoRA-Adapter` or `?adapter=`; empty values and values over 256 bytes are ignored.

`strategy: lora-aware` compiles and runs the registered strategy on the production request path. `lb_method: plugin` is the compatibility marker used by this example, and `algorithm` remains the explicit fallback. Missing or malformed `loaded_adapters` metadata is treated as an empty inventory so one target cannot poison the pool.

## Run

```bash
sbproxy serve -f sb.yml
```

No setup is required to start the example. Its targets use the repository-standard `test.sbproxy.dev` placeholder; replace them with your model-serving replicas before production use. The example pins `metadata.loaded_adapters` in YAML. SBproxy does not poll replicas for adapter inventories, so generate and hot-reload these values from your own source of truth when inventories change.

## Try it

```bash
# Requests for adapter=alice-tone prefer replica 0 or replica 2
# (both warm), and the strategy picks
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
- `lb_method: plugin` plus `strategy: lora-aware` on the production action
- Per-target `metadata.loaded_adapters` arrays copied into the routing projection
- Fail-soft handling of missing or malformed metadata so one bad target does not poison the pool

## See also

- [docs/routing-strategies.md](../../docs/routing-strategies.md)
- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
