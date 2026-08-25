# Weighted prompt versioning
*Last modified: 2026-08-25*

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
use sbproxy_ai::prompt_versioning::{
    PromptSelectionError, WeightedPromptStore, WeightedPromptVersion,
};

let store = WeightedPromptStore::new();
store.replace_versions(
    "support-system-prompt",
    vec![
        WeightedPromptVersion::new(
            "support-system-prompt",
            1,
            "You are a helpful support agent.",
            90.0,
        )?,
        WeightedPromptVersion::new(
            "support-system-prompt",
            2,
            "You are a concise, action-oriented support agent.",
            10.0,
        )?,
    ],
)?;

// Deterministic: always the highest version number.
let latest = store.get_latest("support-system-prompt").unwrap();
assert_eq!(latest.version, 2);

// Weighted random: ~90% of calls draw version 1, ~10% draw version 2.
let picked = match store.select_for_cohort_typed(
    "support-system-prompt",
    "customer-42",
    "rollout-1",
) {
    Ok(version) => version,
    Err(PromptSelectionError::MissingRollout { .. }) => unreachable!(),
    Err(PromptSelectionError::InvalidTotalWeight { .. }) => unreachable!(),
};
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `replace_versions` when installing or replacing a rollout as one
validated snapshot. `select_for_cohort_typed` returns a typed
`MissingRollout` versus `InvalidTotalWeight` error instead of collapsing
both cases into `None`. The compatibility `add_version` /
`select_for_cohort` pair remains available, but the batch + typed path is
the primary API.

### Stable cohort contract

`replace_versions` sorts members by numeric version before publication,
so input order cannot change cohort assignment. A rollout is accepted
only when every weight is finite and non-negative and their exact
mathematical sum is positive and no greater than `f64::MAX`; a refused
replacement leaves the prior snapshot live.

Selection hashes the UTF-8 bytes of `name`, `cohort`, and `salt`, in that
order. Each component is framed by its eight-byte big-endian byte length
and the framed stream is hashed with SHA-256. The first eight digest
bytes form a big-endian unsigned draw. Selection compares that draw
against exact cumulative binary-weight units in canonical version order,
using a half-open range, so a zero-weight version is never selected.

The same `(name, cohort, salt)` and rollout snapshot therefore produce
the same version across processes and platforms. Changing the salt
intentionally creates an independent assignment; changing versions or
weights may remap cohorts.

`list_versions` returns every version sorted ascending, and `list_names`
returns every registered prompt name sorted, for an operator-facing
listing.

## Runnable example

[`crates/sbproxy-ai/examples/prompt_versioning_rollout.rs`](../crates/sbproxy-ai/examples/prompt_versioning_rollout.rs)
runs 1,000 draws against a 90/10 split and reports the observed ratio:

```bash
cargo run -p sbproxy-ai --example prompt_versioning_rollout
```
