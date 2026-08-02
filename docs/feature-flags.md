# Edge feature flags
*Last modified: 2026-07-22*

`sbproxy-extension` ships a small, sticky-bucketing feature-flag store and a `flag_enabled(name, key)` CEL helper. Flags are evaluated against a per-request bucketing key (user id, tenant id, JWT subject) so a request that lands inside a 25% rollout stays inside it across calls. The running proxy seeds the process-wide store from the top-level `flags:` block at boot and atomically replaces the complete set after each successful config reload.

## Rule grammar

Each flag carries a `default` plus an ordered rule set:

| Rule | Effect |
|------|--------|
| `block_list` | Keys in this set always evaluate `false`. Wins over everything. |
| `allow_list` | Keys in this set always evaluate `true`. |
| `rollout_percent` | Sticky `hash(name + key) % 100 < rollout_percent`. |

Order: `block_list` → `allow_list` → `rollout_percent` → `default`. The first match wins. The block list winning over the allow list is deliberate: a key that ends up on both lists (typically a config typo) defaults to safe.

The underlying Rust `FlagStore` also supports an optional segment argument for direct embedders. The shipped CEL helper deliberately has only `name` and `key` arguments, so top-level YAML rejects a `segments` rule instead of accepting configuration that no request could exercise.

## Configuring flags

Declare process-wide flags at the top level of `sb.yml`:

```yaml
flags:
  - name: new-checkout
    default: false
    rules:
      allow_list:
        - alice@acme.io
      rollout_percent: 25
```

Flag names must be unique and non-empty, and `rollout_percent` must be between 0 and 100. Invalid declarations fail config compilation, so a duplicate or impossible rollout cannot silently replace another flag.

An absent `flags:` block is an explicit empty set. Removing the block on reload clears previously configured flags after the candidate config and pipeline have both compiled successfully.

## CEL helper

The `flag_enabled(name, key)` CEL function reads the global store. The most common idiom keys flags on the JWT subject:

```
flag_enabled("new-checkout", jwt.claims.sub)
```

Use it in any CEL surface (forward rules, expression policies, request modifiers, AI selectors). Unknown flags evaluate to `false`. Segment rules are not part of the YAML surface because this helper has no segment argument.

## Sticky bucketing

The bucket function is FNV-1a 64-bit over `flag_name | key`, mod 100. Properties:

- **Deterministic.** The same `(name, key)` pair always maps to the same bucket regardless of process restart.
- **Independent across flags.** A user that lands in 30% of `flag-a` is not biased into the same bucket of `flag-b` because the flag name salts the hash.
- **Smooth at edges.** A 1k-key sample of a 50% rollout gives ~500 hits ±50 (95% CI). For tighter than that, run a real bucketed experiment.

## Hot reloading

The proxy builds a fresh store from each compiled config and publishes it by replacing one process-wide `Arc`. A reader therefore observes either the complete previous flag set or the complete new set, never an incrementally updated mixture. A reload that fails validation or pipeline construction leaves the previous store installed.

Direct embedders can still call `FlagStore::upsert(flag)` and `FlagStore::remove(name)`; those operations rewrite one store under an `RwLock`.

## Counters and observability

The store does not currently emit metrics. Wire a metric of your choice around the call site (a request modifier or policy that calls `flag_enabled` is the right place). Counters worth recording:

- `flag_eval_total{flag, result}` - how often each flag fires which way.
- `flag_eval_duration` - latency, to detect runaway lookup costs (the store reads through a `RwLock` so contention should be negligible).

## See also

- `crates/sbproxy-extension/src/flags.rs` - source.
- [scripting.md](scripting.md#3-cel-expressions) - full CEL surface.
