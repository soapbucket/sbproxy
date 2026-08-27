# AI Groups E/F API contract audit

Date: 2026-08-25

Status: read-only contract extraction. No Cargo or Rust command was run. This is a preflight API-shell map, not semantic implementation approval.

Current files matched the final report hashes at audit time, including F R4.

## E-owned shell

### `agent_orchestration/fsm.rs`

Required public vocabulary:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmLimitDimension {
    Steps,
    States,
    Edges,
    WorkflowNameBytes,
    InitialStateBytes,
    StateNameBytes,
    ActionBytes,
    OutcomeBytes,
    TransitionTargetBytes,
    GraphBytes,
    HistoryBytes,
}
```

Add to both existing public error enums:

```rust
LimitExceeded {
    dimension: FsmLimitDimension,
    limit: usize,
    observed: usize,
}
```

Both errors must retain `Debug + Clone + PartialEq + Eq + thiserror::Error`. `FsmLimitDimension` needs an error-display representation because deserializer tests construct the typed error and search for its `Display` text.

Test-build-only probe seam:

```rust
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum FsmCallsiteEvent {
    GraphIndexAllocated { requested_capacity: usize },
    TransitionTargetCloned { bytes: usize },
    OutcomeCloned { bytes: usize },
    HistoryPushed { retained_bytes: usize },
}

#[cfg(test)]
struct FsmCallsiteProbe { /* current-thread scoped */ }

#[cfg(test)]
impl FsmCallsiteProbe {
    fn install_for_current_thread() -> Self;
    fn events(&self) -> Vec<FsmCallsiteEvent>;
}
```

`events()` is not uniquely pinned as `Vec` versus slice, but returning an owned `Vec` is the least awkward contract and requires `Clone` on the event. The probe must be thread-local, observational, cleared/scoped by its guard, and connected to the real callsites. No release-build branch or alternate constructor/transition is permitted.

Compatibility work:

- Re-export `FsmLimitDimension` from `agent_orchestration/mod.rs`.
- Preserve all existing error variants and `FsmWorkflow::new` / `FsmExecution::transition` signatures.
- The current eager `RawWorkflow` compiles after the shell but will be semantic RED; later bounded deserialization must replace it with an incremental visitor.
- Probe event placement must ultimately be at the actual graph allocation, target/result ownership, and history commit. The valid transition expects exactly three events.

### `prompt_versioning.rs`

Add:

```rust
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PromptSelectionError {
    MissingRollout { name: String },
    InvalidTotalWeight { name: String, total: f64 },
}
```

Extend `PromptVersionError`:

```rust
InvalidTotalWeight { total: f64 }
```

Required methods:

```rust
pub fn replace_versions(
    &self,
    name: &str,
    versions: Vec<WeightedPromptVersion>,
) -> Result<(), PromptVersionError>;

pub fn select_for_cohort_typed(
    &self,
    name: &str,
    cohort: &str,
    salt: &str,
) -> Result<WeightedPromptVersion, PromptSelectionError>;
```

Compatibility work:

- Keep `add_version`, including its ability to build zero/non-finite aggregate legacy state; two tests deliberately use it to exercise typed defensive selection.
- Keep `select_for_cohort(...) -> Option<WeightedPromptVersion>` as a compatibility wrapper.
- Preserve `list_versions` canonical ascending order.
- Later migrate the CLI and example from repeated `add_version` calls to grouped `replace_versions`; the CLI may contain multiple names, so group batches by embedded name rather than treating the input as one rollout.

## F-owned shell

### Closed enums

```rust
pub enum ChargebackOverflowScope {
    Tracker,
    Workspace,
    Team,
}

pub enum ChargebackOverflowField {
    RecordedEntries,
    RequestCount,
    Tokens,
    Cost,
}

pub enum ChargebackRecordError {
    InvalidCost,
    InvalidTimestamp,
    ArithmeticOverflow {
        scope: ChargebackOverflowScope,
        field: ChargebackOverflowField,
    },
}
```

These need at least `Debug + Clone + PartialEq + Eq + Ord` because tests compare them and the private state inserts errors as ordered-map keys. `Copy`, `Hash`, `Serialize`, and `Deserialize` are sensible. `ChargebackRecordError` should implement `Error`.

### Typed snapshot model

Exact named types pinned by tests:

```rust
pub const CHARGEBACK_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DimensionKey {
    Value(String),
    Missing,
    Overflow,
}

pub struct ChargebackSnapshotEntry {
    pub workspace: DimensionKey,
    pub team: DimensionKey,
    pub project: String,
    pub provider: String,
    pub model: String,
    pub tokens: u64,
    pub cost: f64,
    pub timestamp: String,
}
```

`DimensionKey` needs `Debug + Clone + PartialEq + Eq + Ord + Hash + Serialize + Deserialize`. The entry needs `Debug + Clone + PartialEq + Serialize + Deserialize`.

The following element type names are not pinned, but their public shapes are:

```rust
pub struct ChargebackRollup {
    pub dimension: DimensionKey,
    pub totals: WorkspaceTotals,
}

pub struct ChargebackRefusalCount {
    pub reason: ChargebackRecordError,
    pub count: u64,
}

pub struct ChargebackEvictionWatermark {
    pub min_timestamp: Option<String>,
    pub max_timestamp: Option<String>,
    pub poisoned: bool,
}
```

Use public documented types because they occur in public `ChargebackSnapshot` fields and `missing_docs` becomes gate-visible.

`ChargebackSnapshot` must expose:

```rust
pub schema_version: u32,
pub max_entries: usize,
pub max_workspaces: usize,
pub max_teams: usize,
pub entries: Vec<ChargebackSnapshotEntry>,
pub workspace_rollups: Vec<ChargebackRollup>,
pub team_rollups: Vec<ChargebackRollup>,
pub recorded_entries: u64,
pub evicted_entries: u64,
pub collapsed_workspace_events: u64,
pub collapsed_team_events: u64,
pub complete: bool,
pub refused_entries: u64,
pub refusal_counts: Vec<ChargebackRefusalCount>,
pub earliest_retained_timestamp: Option<String>,
pub latest_retained_timestamp: Option<String>,
pub eviction_watermark: ChargebackEvictionWatermark,
```

It must serialize as v2 without `workspace_totals` or `team_totals`.

Private `ChargebackState` must change concurrently or the tests still will not compile:

```rust
entries: VecDeque<ChargebackSnapshotEntry>,
workspace_totals: BTreeMap<DimensionKey, WorkspaceTotals>,
team_totals: BTreeMap<DimensionKey, WorkspaceTotals>,
recorded_entries: u64,
evicted_entries: u64,
collapsed_workspace_events: u64,
collapsed_team_events: u64,
complete: bool, // custom Default = true
refused_entries: u64,
refusal_counts: BTreeMap<ChargebackRecordError, u64>,
earliest_retained_timestamp: Option<String>,
latest_retained_timestamp: Option<String>,
eviction_watermark: ChargebackEvictionWatermark,
```

Required ingestion signature:

```rust
pub fn try_record(
    &self,
    workspace: Option<&str>,
    entry: ChargebackEntry,
) -> Result<(), ChargebackRecordError>;
```

Keep these compatibility APIs:

- `record(ChargebackEntry) -> ()` as an infallible adapter.
- Object-safe `UsageSink::record(&LlmUsageEvent) -> ()`, delegating to the same fallible transaction and swallowing only the returned error.
- `entries_snapshot() -> Vec<ChargebackEntry>`.
- `workspace_totals_snapshot() -> HashMap<String, WorkspaceTotals>`.
- `total_by_team() -> HashMap<String, f64>`.

A private attributed ingestion helper is needed: `ChargebackEntry.team: String` cannot distinguish `None` from literal `"unattributed"`, while live `UsageSink` tests require `None -> DimensionKey::Missing` and literal text -> Value. Do not pre-normalize the live event through `UNATTRIBUTED` before creating the typed key.

### `billing/unified.rs`

Add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialPeriodReason {
    IncompleteSnapshot,
    EvictedRange,
    PoisonedEvictionWatermark,
}
```

Extend `BillError`:

```rust
PartialPeriod { reason: PartialPeriodReason }
```

Required function:

```rust
pub fn generate_bill_from_snapshot(
    snapshot: &ChargebackSnapshot,
    period_start: &str,
    period_end: &str,
) -> Result<UnifiedBill, BillError>;
```

Keep lower-level `generate_bill(&[ChargebackEntry], ...)` unchanged. Export the new function/reason and all externally useful typed snapshot/error types through `billing/mod.rs`.

## F compatibility boundary outside the library

Changing `ChargebackSnapshot` breaks `sbproxy-core/src/admin.rs`, which directly reads legacy maps. Avoid maintaining two mutable financial representations. Add an explicit v1 serialization/view conversion:

- Default `/admin/ai-chargeback` remains outer schema 1.
- Each v1 tracker has exactly the old entry/map/counter fields—no inner schema, typed fields, refusal fields, or watermarks.
- Convert `Missing -> "unattributed"`, `Overflow -> "__other__"`, and `Value(x) -> x` only in the legacy view.
- CSV must use the same legacy conversion.
- `?schema_version=2` serializes the actual v2 snapshots under outer schema 2.
- Route dispatch must pass the full request target, not `path_only`, to the schema parser.
- Unsupported numeric values echo as JSON numbers; bounded nonnumeric values as strings; never echo unrelated query parameters.

The wire scanner test adds no production symbols.

## Whack-a-mole risks to freeze before shell authoring

- E and F cannot compile independently: all `sbproxy-ai` `cfg(test)` modules compile before nextest filtering.
- F's unnamed rollup/refusal/watermark type names and E probe `events()` return type are test-inferred, not pinned. Pick the declarations above once and share them with both shell/reviewer.
- Do not add legacy string maps to v2 serialization merely to keep admin compiling; use a v1 DTO/conversion.
- `ChargebackEntry` is legacy input/billing data, while `ChargebackSnapshotEntry` is typed retained state. Conflating them loses missing-vs-literal identity.
- Public field element types need documentation and public visibility for the repository's warning gate.
- No manifest dependency is required: the crate already has SHA-256, chrono, serde, and thiserror.
