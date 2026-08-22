# Weighted prompt versioning
*Last modified: 2026-08-22*

`sbproxy_ai::prompt_versioning` (WOR-2672) lets an embedder maintain
several versions of a prompt template under one name and draw one by
weighted random selection, for a gradual percentage rollout or an A/B
experiment. It is fully self-contained and in-memory: no config surface,
no request-path wiring, no template rendering.

## Not `sbproxy_ai::prompts`

This crate already ships a config-declared, request-path-wired prompt
store: `sbproxy_ai::prompts` (WOR-800) resolves `"name@version"` from
`proxy.*` config, renders with minijinja, and supports a runtime overlay
that *pins* one version live (`pin_runtime_prompt`). That is the
system a request actually reads a stored prompt through; see the
"Stored prompts and offline optimization" section of
[ai-gateway.md](ai-gateway.md).

This module's types are deliberately named `WeightedPromptVersion` and
`WeightedPromptStore`, not `PromptVersion` / `PromptStore`, specifically
so they cannot be confused with `sbproxy_ai::prompts`'s types of almost
the same name. The distinction that matters: `prompts`'s pin is
deterministic, one version live at a time. This module instead answers
"which version should THIS caller get" from a weighted random draw,
which is what a percentage rollout needs and `prompts` does not provide.
Wiring this module's weights into `prompts:` config as a rollout option
is a separate, unscheduled follow-up; today it ships standalone.

## Usage

```rust,ignore
use sbproxy_ai::prompt_versioning::{WeightedPromptStore, WeightedPromptVersion};

let store = WeightedPromptStore::new();
store.add_version("support-system-prompt", WeightedPromptVersion::new(
    "support-system-prompt", 1, "You are a helpful support agent.", 90.0,
));
store.add_version("support-system-prompt", WeightedPromptVersion::new(
    "support-system-prompt", 2, "You are a concise, action-oriented support agent.", 10.0,
));

// Deterministic: always the highest version number.
let latest = store.get_latest("support-system-prompt").unwrap();
assert_eq!(latest.version, 2);

// Weighted random: ~90% of calls draw version 1, ~10% draw version 2.
let picked = store.select_by_weight("support-system-prompt").unwrap();
```

`select_by_weight` returns `None` only when the name has no versions or
every version's weight is non-positive; a single version with a positive
weight is always selected. `list_versions` returns every version sorted
ascending, and `list_names` returns every registered prompt name sorted,
for an operator-facing listing.

## Runnable example

[`crates/sbproxy-ai/examples/prompt_versioning_rollout.rs`](../crates/sbproxy-ai/examples/prompt_versioning_rollout.rs)
runs 1,000 draws against a 90/10 split and reports the observed ratio:

```bash
cargo run -p sbproxy-ai --example prompt_versioning_rollout
```
