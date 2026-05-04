# Edge feature flags
*Last modified: 2026-04-27*

`sbproxy-extension` ships a small, sticky-bucketing feature-flag store and a `flag_enabled(name, key)` CEL helper. Flags are evaluated against a per-request bucketing key (user id, tenant id, JWT subject) so a request that lands inside a 25% rollout stays inside it across calls. The OSS implementation is config-driven; the enterprise build will layer a Redis Streams update channel for sub-second propagation across replicas.

## Rule grammar

Each flag carries a `default` plus an ordered rule set:

| Rule | Effect |
|------|--------|
| `block_list` | Keys in this set always evaluate `false`. Wins over everything. |
| `allow_list` | Keys in this set always evaluate `true`. |
| `segments` | When the request's segment label is in this set, the flag is `true`. |
| `rollout_percent` | Sticky `hash(name + key) % 100 < rollout_percent`. |

Order: `block_list` → `allow_list` → `segments` → `rollout_percent` → `default`. The first match wins. The block list winning over the allow list is deliberate: a key that ends up on both lists (typically a config typo) defaults to safe.

## Configuring flags

Today the OSS path seeds flags from code in the embedding binary:

```rust
use std::sync::Arc;
use sbproxy_extension::flags::{set_global_store, FlagConfig, FlagRule, FlagStore};

let store = FlagStore::from_configs(vec![
    FlagConfig {
        name: "new-checkout".into(),
        default: false,
        rules: FlagRule {
            allow_list: ["alice@acme.io".to_string()].into_iter().collect(),
            rollout_percent: 25,
            segments: ["beta".to_string()].into_iter().collect(),
            ..FlagRule::default()
        },
    },
]);
set_global_store(Arc::new(store));
```

A follow-up wires a top-level `flags:` block in `sb.yml` so operators can declare flags in YAML without writing Rust. The schema is identical:

```yaml
flags:
  - name: new-checkout
    default: false
    rules:
      allow_list:
        - alice@acme.io
      segments:
        - beta
      rollout_percent: 25
```

## CEL helper

The `flag_enabled(name, key)` CEL function reads the global store. The most common idiom keys flags on the JWT subject:

```
flag_enabled("new-checkout", jwt.claims.sub)
```

Use it in any CEL surface (forward rules, expression policies, request modifiers, AI selectors). Unknown flags evaluate to `false`. The function ignores segments today; add a per-request segment label by extending the helper or using a `segments`-only rule.

## Sticky bucketing

The bucket function is FNV-1a 64-bit over `flag_name | key`, mod 100. Properties:

- **Deterministic.** The same `(name, key)` pair always maps to the same bucket regardless of process restart.
- **Independent across flags.** A user that lands in 30% of `flag-a` is not biased into the same bucket of `flag-b` because the flag name salts the hash.
- **Smooth at edges.** A 1k-key sample of a 50% rollout gives ~500 hits ±50 (95% CI). For tighter than that, run a real bucketed experiment.

## Hot reloading

Calls to `FlagStore::upsert(flag)` and `FlagStore::remove(name)` rewrite the global store under an `RwLock`. Reads are cheap (`RwLock::read`); writes are the dominant cost only during config swaps. Embedders that need cross-replica propagation should layer a small consumer that reads from their control plane and calls `upsert` / `remove` accordingly. The enterprise build ships exactly that consumer with Redis Streams.

## Counters and observability

The store does not currently emit metrics. Wire a metric of your choice around the call site (a request modifier or policy that calls `flag_enabled` is the right place). Counters worth recording:

- `flag_eval_total{flag, result}` - how often each flag fires which way.
- `flag_eval_duration` - latency, to detect runaway lookup costs (the store reads through a `RwLock` so contention should be negligible).

## See also

- `crates/sbproxy-extension/src/flags.rs` - source.
- [scripting.md](scripting.md#cel-functions) - full CEL surface.
