# AI Group E RED and design report

Date: 2026-08-24

Status: RED tests authored, static checks complete, controller execution required. No production code, Cargo file, existing non-test code, docs, dashboard, or shared artifact was changed. No Rust, Cargo, rustfmt, staging, commit, fetch, push, or delete command was run.

## Ownership

This slice owns only:

- Test-module additions in `crates/sbproxy-ai/src/agent_orchestration/fsm.rs`.
- Test-module additions in `crates/sbproxy-ai/src/prompt_versioning.rs`.
- This report.

Both Rust files were clean before authoring. The diff adds 468 test-only lines and does not overlap the active Group B or C files.

## Root cause and production boundaries

The FSM constructor checks graph references only after allocating `HashMap::with_capacity(states.len())`. It has no maximum for steps, states, edges, text bytes, or aggregate graph bytes. Custom YAML deserialization calls that constructor, so the constructor is the common validation boundary. Runtime `transition` clones the outcome and commits history before any outcome-byte or projected retained-history check.

The weighted rollout store publishes one version at a time. It validates each weight but not the prospective aggregate before mutating the live vector. Selection sums into `f64` without a finite check and iterates insertion order. Two `f64::MAX` weights therefore publish an infinite-total rollout, while a harmless input reorder changes cohort assignments.

The callers inspected were:

- `sbproxy ai workflow validate/run` in `crates/sbproxy/src/main.rs`, which deserializes YAML through `FsmWorkflow` and passes repeated caller-owned outcomes to `FsmExecution::transition`.
- `sbproxy ai prompt select` in `crates/sbproxy/src/main.rs`, which loops over `add_version` and then interprets `select_for_cohort`'s `None` as both missing and invalid total.
- The crate examples and current library tests, which also construct incrementally.

## Independently derived limits

The tests pin these reviewable maxima:

| Dimension | Maximum | Reasoning |
|---|---:|---|
| states | 256 | Bounded workflow topology and index overhead |
| edges | 4,096 | At most 16 average outgoing edges at the maximum state count |
| steps | 1,024 | Bounded invocation and retained-record count |
| workflow/state/action/outcome text | 256 bytes each | Small operator identifiers and bounded agent output labels, measured as UTF-8 bytes rather than characters |
| aggregate graph string payload | 1 MiB | Counts workflow name, initial state, every state/action, and every outcome/target occurrence |
| retained history string payload | 256 KiB | Keeps history independently tighter than the 1,024-step by two-256-byte theoretical product, leaving bounded allocation overhead outside the raw payload |

The 256 KiB history ceiling is deliberately independently testable. At 512 KiB, the step and per-text maxima already prevent a raw `(state, outcome)` history from exceeding the same value, so a separate history check would be redundant and its max-plus-one test would necessarily violate another limit first.

## Added tests and predicted current result

The predictions below come from the inspected current implementation. They are not accepted RED evidence until the controller runs the exact selector.

| Test | Current prediction | Contract protected |
|---|---|---|
| `workflow_accepts_exact_shape_maxima` | PASS control | Exact 256 states, 4,096 edges, 1,024 steps, 1 MiB graph, and 256-byte ASCII/UTF-8 text remain usable |
| `workflow_rejects_each_shape_max_plus_one` | FAIL | Rejects every max-plus-one independently, including `usize::MAX` steps and a 257-byte multibyte action |
| `workflow_yaml_deserialization_uses_constructor_limits` | FAIL | YAML cannot bypass the exact constructor limits; exact maxima are a passing control inside the same test |
| `oversized_outcome_preserves_execution_state` | FAIL | A 257-byte runtime outcome is refused before clone, history, completion, or state mutation |
| `retained_history_max_plus_one_preserves_execution_state` | FAIL | Exact retained budget is accepted, then the one-byte-over projection is transactionally inert |
| `rollout_finite_positive_snapshot_is_selectable_control` | PASS control | A large but finite positive aggregate remains publishable and selectable |
| `rollout_rejects_nonfinite_aggregate_without_mutating_live_snapshot` | FAIL | Two individually finite maximum weights cannot publish infinity; the prior live cohort mapping is unchanged |
| `rollout_rejects_zero_total_before_publication` | FAIL | An all-zero rollout is not published as a live but unselectable rollout |
| `cohort_mapping_is_invariant_to_input_order` | FAIL | 4,096 fixed cohorts map identically after reversing the same three versions |

Expected exact current signature: 9 selected, 2 passed controls, 7 failed semantic assertions, 0 skipped. A compiler error, zero selected tests, a control failure, runner timeout, or a different failure cause must be rejected rather than counted as RED.

The expected current failure details are:

- Constructor reports all ten accepted dimensions: steps, platform-width steps, states, edges, workflow name bytes, state identifier bytes, action bytes, UTF-8 action bytes, outcome bytes, and aggregate graph bytes.
- YAML reports accepted oversized steps and action bytes.
- Oversized transition returns `Ok(Completed)` after appending one history row and setting completion.
- History max-plus-one returns `Ok(Advanced("s"))` and grows from 1,021 to 1,022 records.
- Aggregate overflow returns `Ok(())`, publishes versions `[1, 2]`, and the current fall-through selects version 2 instead of preserving version 1.
- Zero total publishes `[1, 2]` and selection returns `None`.
- Reversed insertion produces nonempty cohort mismatches.

## Exact controller selector

Run only from the controller-owned serialized build slot with the AI target directory and `CARGO_BUILD_JOBS=2` already exported:

```bash
cargo nextest run -p sbproxy-ai --locked --lib -E 'test(=agent_orchestration::fsm::tests::workflow_accepts_exact_shape_maxima) + test(=agent_orchestration::fsm::tests::workflow_rejects_each_shape_max_plus_one) + test(=agent_orchestration::fsm::tests::workflow_yaml_deserialization_uses_constructor_limits) + test(=agent_orchestration::fsm::tests::oversized_outcome_preserves_execution_state) + test(=agent_orchestration::fsm::tests::retained_history_max_plus_one_preserves_execution_state) + test(=prompt_versioning::tests::rollout_finite_positive_snapshot_is_selectable_control) + test(=prompt_versioning::tests::rollout_rejects_nonfinite_aggregate_without_mutating_live_snapshot) + test(=prompt_versioning::tests::rollout_rejects_zero_total_before_publication) + test(=prompt_versioning::tests::cohort_mapping_is_invariant_to_input_order)' --no-capture --no-fail-fast
```

The same exact selector must pass 9/9 after GREEN and again after every mutation is restored.

## Controller execution

The controller ran the corrected no-fail-fast command on 2026-08-24 with the protected AI target directory and `CARGO_BUILD_JOBS=2`.

```text
9 tests run: 2 passed, 7 failed, 2100 skipped
```

Both named controls passed. All seven predicted semantic tests failed with the exact causes described above: ten accepted max-plus-one graph dimensions, YAML acceptance, committed oversized outcome/history state, published infinite and zero totals, and nonempty reversed-order cohort mismatches. There was no compiler failure, selector miss, runner timeout, skipped selected test, or unrelated panic. Group E RED is accepted.

## Missing production seams that must not be faked in tests

Two required typed contracts cannot be asserted honestly against the current signatures without turning the whole test binary into a compile-only RED:

1. `FsmValidationError` and `FsmExecutionError` have no size-exhaustion variant carrying dimension, configured limit, and observed bytes/count. The behavioral REDs therefore assert exact boundary behavior and transactional state. GREEN should add a typed dimension vocabulary and then strengthen these matches before the focused proof is considered closed.
2. `WeightedPromptStore` has no whole-rollout activation or replacement method, and `select_for_cohort` returns `Option`. There is no call that can atomically publish a complete immutable version set, and missing rollout cannot be distinguished from invalid total. The aggregate tests prove prospective-update atomicity and publication safety, but successful immutable batch replacement needs a production seam such as `replace_versions(name, Vec<WeightedPromptVersion>) -> Result<(), PromptVersionError>` backed by one validated snapshot swap. Selection also needs a typed missing/invalid-total result, including a defensive invalid-total branch for corrupted or legacy state.

No parallel test helper or private test-only activation path was added. The D integration owner must use the real batch seam, not a loop over `add_version`.

## Required mutation proofs after GREEN

- Move state-cap validation after `HashMap::with_capacity`; allocation-order evidence is still required because a semantic result alone cannot observe the preallocation.
- Remove each constructor dimension independently, count Unicode characters instead of bytes, and bypass `FsmWorkflow::new` from deserialization.
- Clone or push an outcome before checking its byte length or projected retained history.
- Restore unchecked aggregate summation or push the overflowing version before validation.
- Restore insertion-order cumulative selection.
- Publish versions one at a time in the D live activation caller instead of swapping one validated snapshot.

## Static verification

- `git diff --check -- crates/sbproxy-ai/src/agent_orchestration/fsm.rs crates/sbproxy-ai/src/prompt_versioning.rs`: PASS.
- Exact test-name search found all 9 intended additions once.
- `git diff --unified=0` confirms every Rust addition is inside an existing `#[cfg(test)] mod tests` block.
- No production code or disallowed file was changed.

## Risks and handoff notes

- The existing `select_by_weight_returns_none_when_all_weights_zero` test pins the unsafe ambiguous behavior and must be replaced or updated during GREEN, not silently retained beside the new typed contract.
- Existing CLI and examples build a rollout incrementally. They must move to the batch activation seam before immutable publication can be claimed.
- The graph payload accounting is deliberately conservative and counts repeated target/initial strings as supplied input bytes. If the controller chooses a different accounting contract, change the test first, recapture genuine RED, and document the memory derivation before production edits.
- These are library-boundary tests only. Group D still owns real child-process workflow execution and a real request-path rollout acceptance test.

AI_GROUP_E_RED_READY

## Append-only correction after independent review

Date: 2026-08-24

The first RED batch above is superseded. Independent review rejected it with 0 Blockers, 4 Majors, and 0 Minors. This correction records the replacement test contract; the earlier predictions must not be used as evidence.

### Review dispositions

1. **Bounded deserialization, fixed in the replacement tests.** The old YAML test proved only that `FsmWorkflow::deserialize` eventually called constructor validation after `RawWorkflow` had already materialized the document. The replacement calls the real `Deserialize` implementation with ordered max-plus-one fixtures for steps, workflow name, initial state, state name, action, outcome, transition target, state count, edge count, and aggregate graph bytes. Every fixture places a valid-YAML malformed-type sentinel after the first excessive value. The required typed limit must win before the sentinel is consumed.
2. **Typed errors and allocation/clone ordering, fixed in the replacement tests.** Every constructor and transition refusal now requires `dimension`, `limit`, and `observed`. Test-only, current-thread callsite probes are required on the actual `FsmWorkflow::new` and `FsmExecution::transition` paths. Exact controls require an allocation/clone/commit event; refused inputs require no such event.
3. **Zero-weight contract, corrected.** The incremental test that required the first zero-weight version to fail was removed. The replacement requires atomic `[0, 1]` activation to succeed and select the positive version. Only the complete `[0, 0]` rollout is invalid.
4. **Immutable rollout and typed selection, fixed in the replacement tests.** Incremental update tests were replaced with the required `replace_versions` batch seam, transactional zero/nonfinite refusal, concurrent old-or-new complete snapshot observation, canonical input-order invariance, and typed missing-versus-invalid selection errors.

### Phase E0: intentionally compile RED

The reviewer and controller explicitly approved a narrow compile RED because asserting the required contracts against generic `Err` or `Option` would preserve the original loopholes. No semantic RED may be claimed until the API shell exists and the test binary compiles.

The exact missing production symbols are:

- `FsmLimitDimension` with `Steps`, `States`, `Edges`, `WorkflowNameBytes`, `InitialStateBytes`, `StateNameBytes`, `ActionBytes`, `OutcomeBytes`, `TransitionTargetBytes`, `GraphBytes`, and `HistoryBytes`.
- `FsmValidationError::LimitExceeded { dimension, limit, observed }`.
- `FsmExecutionError::LimitExceeded { dimension, limit, observed }`.
- Test-build-only `FsmCallsiteProbe::install_for_current_thread()` and `FsmCallsiteEvent::{GraphIndexAllocated, TransitionTargetCloned, OutcomeCloned, HistoryPushed}`.
- `WeightedPromptStore::replace_versions`.
- `WeightedPromptStore::select_for_cohort_typed`.
- `PromptVersionError::InvalidTotalWeight { total }`.
- `PromptSelectionError::{MissingRollout, InvalidTotalWeight}`.

The callsite probe must be `#[cfg(test)]`, current-thread scoped, and observational only. It must not add a runtime option, product configuration, release-build branch, or alternate constructor/transition path. Events belong immediately to the real `HashMap::with_capacity`, target/outcome ownership, and history commit operations. Installing the probe after fixture construction prevents test setup allocations from counting.

Phase E0 command, to be run only by the controller in the serialized AI build slot:

```bash
cargo nextest run -p sbproxy-ai --locked --lib -E 'test(=agent_orchestration::fsm::tests::workflow_accepts_exact_shape_maxima) + test(=prompt_versioning::tests::rollout_batch_accepts_zero_weight_when_total_is_positive_control)' --no-capture
```

Expected E0 result: Rust compilation exits nonzero on the exact missing symbols above. No test result or selected count is accepted in this phase. A syntax error, unrelated type error, warning-denied failure, or missing-symbol error outside this list rejects the checkpoint. Secondary inference diagnostics are acceptable only when their causal source is one of the listed missing APIs; they are not independent RED evidence.

### Phase E1: semantic RED after the shell exists

After adding only the typed API/probe shell needed to compile, run this exact 14-test selection:

```bash
cargo nextest run -p sbproxy-ai --locked --lib -E 'test(=agent_orchestration::fsm::tests::workflow_accepts_exact_shape_maxima) + test(=agent_orchestration::fsm::tests::workflow_rejects_each_shape_max_plus_one) + test(=agent_orchestration::fsm::tests::state_limit_precedes_graph_index_capacity_allocation) + test(=agent_orchestration::fsm::tests::valid_workflow_indexes_only_after_validation_control) + test(=agent_orchestration::fsm::tests::workflow_deserialization_stops_at_each_limit_before_later_sentinel) + test(=agent_orchestration::fsm::tests::workflow_deserialization_accepts_exact_graph_maximum_control) + test(=agent_orchestration::fsm::tests::oversized_outcome_preserves_execution_state) + test(=agent_orchestration::fsm::tests::valid_transition_clones_and_commits_only_after_checks_control) + test(=agent_orchestration::fsm::tests::retained_history_max_plus_one_preserves_execution_state) + test(=prompt_versioning::tests::rollout_batch_accepts_zero_weight_when_total_is_positive_control) + test(=prompt_versioning::tests::rollout_batch_rejects_invalid_totals_transactionally) + test(=prompt_versioning::tests::rollout_batch_publication_exposes_only_complete_snapshots) + test(=prompt_versioning::tests::cohort_mapping_is_invariant_to_batch_input_order) + test(=prompt_versioning::tests::typed_selection_distinguishes_missing_from_corrupt_total)' --no-capture --no-fail-fast
```

The five controls are:

- `workflow_accepts_exact_shape_maxima`.
- `valid_workflow_indexes_only_after_validation_control`.
- `workflow_deserialization_accepts_exact_graph_maximum_control`.
- `valid_transition_clones_and_commits_only_after_checks_control`.
- `rollout_batch_accepts_zero_weight_when_total_is_positive_control`.

All five must pass before enforcement failures count as semantic RED. The controller must record the exact selected/pass/fail/skip signature after the shell is authored rather than infer it from this report.

### Deserializer proof boundary

The sentinel fixtures prove that the actual Serde visitor detects each max-plus-one boundary before requesting a later sequence/map element or field whose type is invalid. This prevents eager materialization of the remainder of a state list, transition map, or graph after the budget is exhausted.

They do not prove that `serde_yaml`'s scanner buffers no later source bytes, and they do not prove zero allocation for the max-plus-one scalar itself. Each offending scalar is bounded to the configured maximum plus one byte, and each offending sequence/map is bounded to the configured maximum plus one element. Scanner buffering is dependency behavior outside `FsmWorkflow::Deserialize`; the production visitor still must avoid `RawWorkflow` and enforce budgets incrementally.

### Immutable rollout proof boundary

- `replace_versions` validates names, versions, duplicates, every individual weight, checked finite positive aggregate, and canonical version order before one live snapshot swap.
- `[0, 1]` is valid; `[0, 0]` and `[f64::MAX, f64::MAX]` return `InvalidTotalWeight` and leave the prior snapshot byte-for-byte observable.
- The concurrent reader accepts only the complete 64-version old or new set across 128 replacements. Empty, mixed, or partial vectors fail.
- `select_for_cohort_typed` reports `MissingRollout` for absence and `InvalidTotalWeight` for invalid state created through the compatibility incremental builder. The existing `Option` method may remain as a compatibility wrapper, but D must use the typed batch API.

### Revised static verification

- `git diff --check` on both owned Rust files: PASS.
- The replacement has 14 uniquely named focused tests: 9 FSM and 5 rollout.
- The Rust diff is 942 test-only inserted lines, all inside the existing two `#[cfg(test)]` modules.
- No production, Cargo, docs, shared artifact, staging, commit, fetch, push, rustfmt, or Rust command was run.

AI_GROUP_E_E0_COMPILE_RED_READY

## Append-only controller mutation-gap correction

Date: 2026-08-25

The 14-test E1 selector above is superseded by the 15-test selector below.

- The publication test now performs 129 replacements, deterministically ending on the new snapshot, and asserts that final state. The concurrent reader still permits only the complete old or complete new set. This kills an implementation that installs absent names but silently no-ops every replacement of an existing rollout.
- `rollout_batch_validates_every_member_transactionally` freezes the whole-batch validation inherited from the public member contract. Against an installed control snapshot it independently refuses an empty batch, empty embedded name, key/name mismatch, duplicate version, zero version, NaN weight, and negative weight with the existing typed variants (plus `InvalidTotalWeight` for the empty aggregate). Every refusal must preserve the full prior fingerprint. The separate aggregate test continues to cover all-zero and overflowing totals transactionally.

Definitive Phase E1 selector:

```bash
cargo nextest run -p sbproxy-ai --locked --lib -E 'test(=agent_orchestration::fsm::tests::workflow_accepts_exact_shape_maxima) + test(=agent_orchestration::fsm::tests::workflow_rejects_each_shape_max_plus_one) + test(=agent_orchestration::fsm::tests::state_limit_precedes_graph_index_capacity_allocation) + test(=agent_orchestration::fsm::tests::valid_workflow_indexes_only_after_validation_control) + test(=agent_orchestration::fsm::tests::workflow_deserialization_stops_at_each_limit_before_later_sentinel) + test(=agent_orchestration::fsm::tests::workflow_deserialization_accepts_exact_graph_maximum_control) + test(=agent_orchestration::fsm::tests::oversized_outcome_preserves_execution_state) + test(=agent_orchestration::fsm::tests::valid_transition_clones_and_commits_only_after_checks_control) + test(=agent_orchestration::fsm::tests::retained_history_max_plus_one_preserves_execution_state) + test(=prompt_versioning::tests::rollout_batch_accepts_zero_weight_when_total_is_positive_control) + test(=prompt_versioning::tests::rollout_batch_rejects_invalid_totals_transactionally) + test(=prompt_versioning::tests::rollout_batch_validates_every_member_transactionally) + test(=prompt_versioning::tests::rollout_batch_publication_exposes_only_complete_snapshots) + test(=prompt_versioning::tests::cohort_mapping_is_invariant_to_batch_input_order) + test(=prompt_versioning::tests::typed_selection_distinguishes_missing_from_corrupt_total)' --no-capture --no-fail-fast
```

This selects 15 unique tests: 9 FSM and 6 rollout. The five passing controls listed above are unchanged. The Rust diff is now 1,151 test-only inserted lines, all inside the existing two `#[cfg(test)]` modules. Static `git diff --check` passes. No Rust, Cargo, or rustfmt command was run.

AI_GROUP_E_E0_COMPILE_RED_READY

## Append-only static-audit refinement

Date: 2026-08-25

The final static audit tightened the corrected package without changing its 14-test selector or production API contract:

- Every direct-constructor max-plus-one case now installs the approved current-thread callsite probe after its owned fixture arguments are built. Each typed refusal also requires that no `GraphIndexAllocated` event occurred. The separate exact-state control still requires the real allocation event, so an unconnected probe cannot make the refusals pass.
- The real-deserializer control now accepts exact maxima for steps and every scalar byte dimension in addition to the existing single document at the exact state, edge, and aggregate graph maxima. The malformed later-element sentinels remain the RED half of the same visitor boundary.
- The immutable-publication writer now signals completion through a drop guard, including during unwinding, so an unexpected writer panic is reported by `join` instead of leaving the reader loop spinning indefinitely.
- Typed defensive selection now checks both corrupt aggregate classes reachable through the retained compatibility builder: all-zero and overflow to non-finite.
- The revised Rust diff is 1,038 test-only inserted lines, all inside the existing two `#[cfg(test)]` modules. `git diff --check` still passes. No Rust, Cargo, or rustfmt command was run.

AI_GROUP_E_E0_COMPILE_RED_READY

## Append-only final status clarification

The controller mutation-gap correction is the definitive latest contract and supersedes the earlier static-refinement count. Use its 15-test E1 selector, including `rollout_batch_validates_every_member_transactionally`. Current final facts are 9 FSM tests, 6 rollout tests, 129 replacements ending on and requiring the new snapshot, and 1,151 Rust test-only inserted lines. The five controls and Phase E0 missing-symbol list remain unchanged.

AI_GROUP_E_E0_COMPILE_RED_READY

## Append-only correction after second independent review

Date: 2026-08-25

The second independent review was not approved with 0 Blockers, 3 Majors, and 0 Minors. All three findings were verified against the tests and corrected without changing the production API contract.

### Second-review dispositions and mutation analysis

1. **Later batch members are now authoritative.** Every malformed-member fixture has a valid first member and the malformed value in a later member: empty embedded name, key/name mismatch, zero version, NaN weight, and negative weight. The duplicate fixture already has a valid first member and a duplicate second version. Totals remain valid for the empty-name, mismatch, zero-version, and negative-weight cases; the NaN case requires `InvalidWeight` rather than an aggregate error. Each exact typed refusal is followed by a comparison of the complete preexisting live fingerprint. A mutation that validates full fields only on `member[0]` either publishes the later malformed member or returns the wrong aggregate error, so it fails before the unchanged-snapshot assertion can be credited.
2. **Selection now has an independent literal oracle.** The canonical `[(1, 1), (2, 3), (3, 6)]` rollout keeps the 4,096-cohort forward-versus-reverse comparison and additionally freezes six independently calculated literal mappings: `customer-4` and `customer-8` to version 1, `customer-0` and `customer-3` to version 2, and `customer-1` and `customer-2` to version 3. The corresponding normalized draws are approximately 0.047994, 0.034616, 0.308955, 0.192180, 0.878392, and 0.506906 against cumulative boundaries 0.1 and 0.4. No production selector, hash helper, or rollout algorithm computes expected values in the test. A selector that always returns the highest positive version fails four literal cases, while the separate reverse-input corpus still kills insertion-order selection.
3. **Publication observes complete payload fingerprints.** Old and new 64-version fixtures have distinct version ranges, literal prompt contents, and positive weights (`1.0` versus `3.0`). Every concurrent read across 129 replacements and the deterministic final-new check compare `(name, version, content, weight.to_bits())` for all 64 members. A mutation publishing new IDs and weights with stale old prompt content matches neither allowed fingerprint and fails; stale weight, mixed members, empty state, partial publication, and no-op replacement fail for the same reason.

The 15 test names and five passing controls are unchanged. Definitive Phase E1 selector after the approved E0 shell exists:

```bash
cargo nextest run -p sbproxy-ai --locked --lib -E 'test(=agent_orchestration::fsm::tests::workflow_accepts_exact_shape_maxima) + test(=agent_orchestration::fsm::tests::workflow_rejects_each_shape_max_plus_one) + test(=agent_orchestration::fsm::tests::state_limit_precedes_graph_index_capacity_allocation) + test(=agent_orchestration::fsm::tests::valid_workflow_indexes_only_after_validation_control) + test(=agent_orchestration::fsm::tests::workflow_deserialization_stops_at_each_limit_before_later_sentinel) + test(=agent_orchestration::fsm::tests::workflow_deserialization_accepts_exact_graph_maximum_control) + test(=agent_orchestration::fsm::tests::oversized_outcome_preserves_execution_state) + test(=agent_orchestration::fsm::tests::valid_transition_clones_and_commits_only_after_checks_control) + test(=agent_orchestration::fsm::tests::retained_history_max_plus_one_preserves_execution_state) + test(=prompt_versioning::tests::rollout_batch_accepts_zero_weight_when_total_is_positive_control) + test(=prompt_versioning::tests::rollout_batch_rejects_invalid_totals_transactionally) + test(=prompt_versioning::tests::rollout_batch_validates_every_member_transactionally) + test(=prompt_versioning::tests::rollout_batch_publication_exposes_only_complete_snapshots) + test(=prompt_versioning::tests::cohort_mapping_is_invariant_to_batch_input_order) + test(=prompt_versioning::tests::typed_selection_distinguishes_missing_from_corrupt_total)' --no-capture --no-fail-fast
```

Current static facts: 15 unique focused tests, comprising 9 FSM and 6 rollout tests; 1,221 Rust test-only inserted lines, comprising 768 in `fsm.rs` and 453 in `prompt_versioning.rs`; all additions remain inside the existing `#[cfg(test)]` modules. `git diff --check` passes. No Rust, Cargo, rustfmt, staging, commit, fetch, push, or deletion command was run.

AI_GROUP_E_E0_COMPILE_RED_READY

## Append-only Group E production-shell handoff

Date: 2026-08-25

Status: the smallest coherent Group E production implementation is present and statically
reviewed. The controller still owns compilation, formatting, the definitive 15-test selector,
and all broader gates; this section does not claim executable GREEN.

### Production implementation completed

- `FsmWorkflow::new` now refuses the frozen step, state, edge, per-text, aggregate-graph,
  and retained-history maxima with typed `LimitExceeded { dimension, limit, observed }`
  errors. Every graph limit is checked before the production graph-index allocation.
- `FsmWorkflow::Deserialize` no longer materializes `RawWorkflow`. Its nested Serde visitors
  consume state and transition containers incrementally, bound count and string dimensions as
  they arrive, and return the typed limit before asking for the approved later sentinels.
- The test-build-only probe is thread-local and scoped. Its events are adjacent to the actual
  graph-index allocation, transition-target clone, outcome clone, and history commit callsites;
  release builds contain no probe state or runtime configuration.
- `FsmExecution::transition` checks outcome and projected retained-history bytes before cloning
  or committing, then updates its retained-byte counter in the same history commit.
- `WeightedPromptStore::replace_versions` validates every caller-owned member and the complete
  finite positive aggregate, canonicalizes by version, detects duplicates, and performs one
  mutex-protected live-snapshot replacement. Invalid batches never lock or mutate the live map.
- `select_for_cohort_typed` distinguishes a missing rollout from a zero/non-finite legacy
  aggregate. The existing `select_for_cohort` remains an `Option` compatibility wrapper, and
  `add_version` remains available (including construction of legacy zero/overflow totals) while
  maintaining canonical version order.
- `FsmLimitDimension` is re-exported from `agent_orchestration`; all existing public constructor,
  transition, incremental rollout, listing, and selection signatures remain available.

### Exact owned files changed

- `crates/sbproxy-ai/src/agent_orchestration/fsm.rs`
  (`sha256 7b0c271356297a468cba9f601ec2f1524d13de2ccc1b2d38587f72ec4d2e3b6d`)
- `crates/sbproxy-ai/src/agent_orchestration/mod.rs`
  (`sha256 5c033a45aeddfa05cd074e9ce1283c8e8006235dceece0874880cbed67b66fb4`)
- `crates/sbproxy-ai/src/prompt_versioning.rs`
  (`sha256 954e0034d952b6bb9d7c200e1742e1455d438c13c26e6cf3b7af184116f35f1e`)
- `.superpowers/sdd/2026-08-23-wor2661-agy-handoff/ai-group-e-red-report.md`
  (this append-only handoff)

### Static verification and unresolved controller checks

- `git diff --check --` on the three owned Rust files: PASS.
- Static name/callsite inspection found the frozen typed APIs, all eleven dimension variants,
  the real visitor path, one production graph allocation, and the three transition events.
- No Cargo, Rust, rustfmt, staging, commit, fetch, push, or deletion command was run.
- Controller must compile the combined E/F test binary first. The only material compile
  uncertainty is ordinary compiler validation of the new generic Serde seed/visitor lifetimes
  and error-type inference; no issue was identified by static inspection.
- Controller must then run the definitive 15-test E1 selector. If it exposes a semantic defect,
  retain the accepted RED tests and return the exact failure to this owner for a scoped fix.
- CLI/example migration to grouped `replace_versions` and the D live-activation callsite remain
  outside this owned production shell and must not be inferred complete here.
- Controller formatting may change the three Rust hashes above; they identify the exact static
  handoff reviewed in this section.

AI_GROUP_E_E0_SHELL_READY_FOR_CONTROLLER

## Append-only E2 systemic-review RED correction

Date: 2026-08-25

Status: strict RED-only correction after the fresh Group E implementation review returned
NOT APPROVED with 0 Blockers, 4 Majors, and 0 Minors. No current release behavior was fixed in
this phase. The additions are focused tests plus `cfg(test)` observations at the current
incorrect callsites so the controller can capture genuine semantic RED before implementation.

### Review dispositions frozen as tests

1. `state_count_limit_precedes_deserializing_the_257th_state_body` supplies exactly 256 valid
   states followed by a 257th state carrying an oversized action and a malformed later
   transition sentinel. It requires `States { limit: 256, observed: 257 }` before the 257th body
   is entered. The current-thread visitor observation must report exactly 256 entered bodies;
   current code enters body 257 and reports the action limit instead.
2. `state_name_limit_precedes_empty_action_without_cloning_oversized_name` exercises both the
   exact 257-byte refusal and a 2-MiB-plus-one state name paired with a whitespace-only action.
   Both must return only typed `StateNameBytes` metadata. A probe on the current `EmptyAction`
   error clone proves the rejected name is neither cloned nor exposed; current code clones it
   into the structural error before checking its byte limit.
3. `exhausted_step_budget_precedes_oversized_outcome_without_cloning` fills a one-step workflow,
   then submits a 257-byte result. It characterizes the retained legacy precedence exactly:
   `StepLimit { max_steps: 1 }`, completed=true, unchanged state/history, and no target/outcome/
   history clone-or-commit event. Current code reports `OutcomeBytes` and leaves completion false.
4. `rollout_selection_releases_global_lock_before_lookup_cohort_hash_and_content_clone` uses
   MiB-scale name/cohort/salt inputs and a 2-MiB selected content body. A thread-local barrier
   pauses at the actual current lookup hash, cohort hash, and selected-content clone callsites;
   the controller thread uses non-blocking `try_lock` at each rendezvous. The event payloads and
   selected result are controls, while current code deterministically reports the global mutex
   unavailable at all three unbounded operations.
5. `rollout_replacement_releases_global_lock_before_retired_snapshot_drop` replaces a live
   512-version snapshot whose members carry 4-KiB bodies. The test-build mirror retains the
   current insert/drop order and pauses immediately before the actual retired-vector drop.
   `try_lock` must succeed at that rendezvous; current code deterministically holds the mutex.

The rollout rendezvous deadlines are harness fail-safes only. Pass/fail is determined by exact
event identity and instantaneous `try_lock`, not elapsed time. Probe storage is thread-local and
all hook calls compile only under `cfg(test)`. The unchanged release branch retains the original
replacement expression.

### Exact E2 selector and expected current signature

Run only in the controller-owned serialized AI build slot:

```bash
cargo nextest run -p sbproxy-ai --locked --lib -E 'test(=agent_orchestration::fsm::tests::state_count_limit_precedes_deserializing_the_257th_state_body) + test(=agent_orchestration::fsm::tests::state_name_limit_precedes_empty_action_without_cloning_oversized_name) + test(=agent_orchestration::fsm::tests::exhausted_step_budget_precedes_oversized_outcome_without_cloning) + test(=prompt_versioning::tests::rollout_selection_releases_global_lock_before_lookup_cohort_hash_and_content_clone) + test(=prompt_versioning::tests::rollout_replacement_releases_global_lock_before_retired_snapshot_drop)' --no-capture --no-fail-fast
```

Expected accepted current signature: 5 selected, 0 passed, 5 failed, 0 skipped. Each failure must
be semantic and match the five causes above. A compile error, selector miss, timeout, panic,
unexpected event sequence, or unrelated failure rejects this RED checkpoint.

### Static handoff

- Five new focused tests: three FSM and two rollout-lock tests.
- `crates/sbproxy-ai/src/agent_orchestration/fsm.rs`
  (`sha256 70979e1b30d52ae2a05ef6abed4da50e9af455d8cf54a32eb3baee922d945ac3`)
- `crates/sbproxy-ai/src/prompt_versioning.rs`
  (`sha256 0e1e30eac259e9fe65429a4e1be3da33215ba225eda14bb692e2e3f8416972ac`)
- `git diff --check --` on both owned Rust files: PASS.
- No Cargo, Rust, rustfmt, staging, commit, fetch, push, or deletion command was run.
- Controller must capture the exact five-test RED before any production ordering or lock-scope
  fix. On acceptance, return the failure transcript for the scoped GREEN implementation.

AI_GROUP_E_E2_SYSTEMIC_REVIEW_RED_READY

## E2 systemic-review GREEN production correction

Date: 2026-08-25

The controller accepted the frozen E2 semantic RED exactly: the selector compiled cleanly,
selected 5 tests, passed 0, failed 5, and skipped 2,154. All five failures matched their
predicted ordering or lock-ownership causes; there was no harness, timeout, compile, or unrelated
failure. The following minimal production corrections are now ready for the controller's coupled
GREEN run.

### Production corrections

1. FSM sequence deserialization consumes at most 256 normal `StateSeed` elements. It probes for a
   257th element with a rejecting seed that returns typed
   `States { limit: 256, observed: 257 }` at the element boundary, before `StateVisitor` enters or
   any state body, oversized action, transitions, or later sentinel is consumed. An exact
   256-state sequence still reaches the sequence terminator and is accepted.
2. Direct workflow construction checks `StateNameBytes` immediately after the empty-name check,
   before inspecting the action or cloning the state name into `EmptyAction`. Oversized names now
   return only bounded typed metadata, including for whitespace-only actions.
3. Execution checks an exhausted step budget immediately after `AlreadyCompleted`, sets
   `completed = true`, and returns the legacy `StepLimit` before outcome/history bounds or any
   target, outcome, or history clone/commit. Outcome and retained-history limits retain their E1
   mutation-free behavior when step budget remains.
4. Weighted prompt storage now publishes immutable
   `Arc<HashMap<String, Arc<[WeightedPromptVersion]>>>` snapshots. Readers clone only the outer
   snapshot pointer while holding the global mutex; rollout lookup/hash, aggregate calculation,
   cohort hashing, selected-content clone, and list materialization all run after guard release.
5. `add_version` and `replace_versions` build canonical replacement maps outside the mutex and
   publish with a pointer-identity retry. The bounded critical section performs only current-
   snapshot comparison and pointer replacement. The displaced snapshot is returned to the caller
   and inspected/dropped only after the helper's mutex guard has been released.

The existing public compatibility wrappers and signatures are unchanged. The original E1 typed
errors, exact-max controls, atomic old-or-new publication, canonical cohort selection, legacy
incremental-add behavior, and terminal execution behavior remain represented by their 15 accepted
tests.

### Exact E2 files and static handoff

- `crates/sbproxy-ai/src/agent_orchestration/fsm.rs`
  (`sha256 0af98a4536ab5764ced9695ec4d7c5ba9ea633ea72f117adc1889018b3296d51`)
- `crates/sbproxy-ai/src/prompt_versioning.rs`
  (`sha256 29373906173d7f8d0a84d8ddde298d1cc1f3d3fcb78fe1b120e20a3960f1e84e`)
- `.superpowers/sdd/2026-08-23-wor2661-agy-handoff/ai-group-e-red-report.md`
  (this append-only E2 GREEN handoff)

- `git diff --check --` on the owned Rust files was clean before this append.
- Static inspection found no API or ownership blocker. The remaining uncertainty is ordinary
  compiler/Clippy validation of the immutable-snapshot deref coercions and the rejecting Serde
  seed; no concrete issue was found.
- No Cargo, Rust, rustfmt, staging, commit, fetch, push, or deletion command was run.
- The controller must rerun the exact five-test E2 selector and the preserved 15-test E1 selector;
  this section makes no executable GREEN claim. Coupled F work and repository-wide gates remain
  controller-owned.

AI_GROUP_E_E2_GREEN_READY_FOR_CONTROLLER

## E3 systemic-review strict RED package

Date: 2026-08-25

Status: RED-only response to the post-E2 review result (0 Blockers, 4 Majors, 1 Minor).
Release behavior is unchanged in this phase. The only executable additions are focused tests,
`cfg(test)` observations at the current incorrect ownership/clone/retry callsites, and a
current-thread raw-draw injection/observation seam. No D `PromptStore`, CLI, example, or request
integration is included in Group E.

### Eleven independent tests and expected current semantic failures

1. `authoritative_edge_quota_accepts_2048_and_refuses_2049`: literal 2,048 passes, literal 2,049
   must return typed `Edges`; current duplicated limit accepts 2,049.
2. `authoritative_action_quota_accepts_512_and_refuses_513`: literal 512 passes and 513 returns
   typed `ActionBytes`; current shared 256-byte limit rejects the exact control.
3. `authoritative_outcome_quota_accepts_4096_and_refuses_4097`: literal 4,096 passes and 4,097
   returns typed `OutcomeBytes`; current shared 256-byte limit rejects the exact control.
4. `authoritative_history_quota_accepts_1mib_and_refuses_plus_one`: a retained snapshot composed
   only of independently valid 256-byte state and 4,096-byte outcome chunks advances at exactly
   1,048,576 bytes, then refuses 1,048,577 without mutation; current 262,144-byte duplicate
   refuses the exact control.
5. `huge_known_scalar_is_refused_before_application_string_ownership`: a 2-MiB-plus-one known
   workflow-name scalar must return the typed 256-byte limit without the application visitor ever
   owning a `String`; the current `next_value::<String>` event proves premature ownership.
6. `huge_unknown_key_is_refused_before_application_string_ownership`: a 2-MiB-plus-one unknown
   structural key must be bounded/rejected without an application-owned key `String`; current
   `next_key::<String>` both owns and ignores it. These two tests use JSON to exercise the custom
   Serde visitor and make no claim about serde_yaml/libyaml scanner-owned buffering.
7. `add_version_contention_bounds_deep_clones_and_falls_back`: three deterministic competing
   publications invalidate the worker snapshot at its actual pre-CAS rendezvous. Immutable target
   reads remain complete, while the public writer must finish after at most one optimistic retry
   and at most two rollout/caller/map/name clone cycles; current code performs four cycles.
8. `replace_versions_contention_bounds_snapshot_clones_and_falls_back`: the same deterministic
   protocol requires bounded map/name cloning and writer completion for batch replacement; current
   code performs three retries/four clone cycles. Ten-second receives are fail-safes only; conflict
   and pass/fail decisions use exact hook events and public competing writes, not elapsed timing.
9. `mathematical_weight_overflow_hidden_by_f64_rounding_is_rejected`: finite members
   `[f64::MAX, 1]` must be transactionally rejected, including defensive selection from legacy
   incremental state; the naïve fold rounds away `+1`, publishes it, and selects successfully.
10. `every_positive_band_survives_a_2pow53_leading_weight`: literal raw-u64 draws
    `18446744073709548544` and `18446744073709550592` are independent exact-integer interior
    oracles for the two one-unit bands in `[2^53, 1, 1]`; current total/cumulative f64 math erases
    at least the second-version band.
11. `maximum_draw_is_strictly_below_one_and_never_selects_zero_tail`: injected `u64::MAX` must
    convert into `[0, 1)` and select the positive member of `[1, 0]`; current conversion produces
    `1.0` and falls through to the zero-weight tail.

The pre-existing test-local quota literals and fixtures were also corrected to the authoritative
values (`Edges=2048`, `ActionBytes=512`, `OutcomeBytes=4096`, `HistoryBytes=1048576`) so later E1
regression runs do not preserve the duplicated wrong constants. Other frozen maxima remain
unchanged.

### Exact controller selector and expected signature

Run only in the controller-owned serialized AI build slot:

```bash
cargo nextest run -p sbproxy-ai --locked --lib -E 'test(=agent_orchestration::fsm::tests::authoritative_edge_quota_accepts_2048_and_refuses_2049) + test(=agent_orchestration::fsm::tests::authoritative_action_quota_accepts_512_and_refuses_513) + test(=agent_orchestration::fsm::tests::authoritative_outcome_quota_accepts_4096_and_refuses_4097) + test(=agent_orchestration::fsm::tests::authoritative_history_quota_accepts_1mib_and_refuses_plus_one) + test(=agent_orchestration::fsm::tests::huge_known_scalar_is_refused_before_application_string_ownership) + test(=agent_orchestration::fsm::tests::huge_unknown_key_is_refused_before_application_string_ownership) + test(=prompt_versioning::tests::add_version_contention_bounds_deep_clones_and_falls_back) + test(=prompt_versioning::tests::replace_versions_contention_bounds_snapshot_clones_and_falls_back) + test(=prompt_versioning::tests::mathematical_weight_overflow_hidden_by_f64_rounding_is_rejected) + test(=prompt_versioning::tests::every_positive_band_survives_a_2pow53_leading_weight) + test(=prompt_versioning::tests::maximum_draw_is_strictly_below_one_and_never_selects_zero_tail)' --no-capture --no-fail-fast
```

Required accepted RED signature: 11 selected, 0 passed, 11 failed. Every failure must be semantic
and match its numbered cause above. The controller should record the coupled suite's skipped count,
which may move with concurrent F tests; it is not part of the Group E oracle. Any compile error,
selector miss, timeout, panic, unrelated failure, or unexpectedly passing test rejects this RED.

### Static handoff

- `crates/sbproxy-ai/src/agent_orchestration/fsm.rs`
  (`sha256 b5d0c5e23693d8057da53f19cf899504fc0e16081038b013be7f2eeeeae415d5`)
- `crates/sbproxy-ai/src/prompt_versioning.rs`
  (`sha256 e98deea47a04164903328d0766fb1dc98c5442fcbcecfd1f32ee9e2b2e1843e8`)
- `.superpowers/sdd/2026-08-23-wor2661-agy-handoff/ai-group-e-red-report.md`
  (this append-only E3 RED handoff)
- `git diff --check --` on both owned Rust files: PASS.
- Static inspection verified all current `next_key::<String>`, `next_value::<String>`, and
  sequence-string ownership sites are observed, publication probes are independent of the E2 lock
  probe, and the draw override is current-thread scoped/restored by its guard.
- No Cargo, Rust, rustfmt, staging, commit, fetch, push, or deletion command was run.
- Controller must capture this exact RED before any E3 production correction.

AI_GROUP_E_E3_SYSTEMIC_RED_READY

## Append-only E4 proof-closure freeze

Date: 2026-08-25

The E4 test-only correction closes the prior 1-Blocker/7-Major review without
changing release behavior. The contention fixtures now force one real CAS
conflict under one absolute deadline and a 128-event ceiling, require the
writer to signal completion before it is joined, and compare the complete
final store (target plus every successful racing rollout). The Serde fixtures
trace the deserializer method actually requested at every root/state/
transition map and sequence string seam, include successful small controls,
and require typed max-plus-one refusal without an application-owned `String`.
The package also executes the 4,096-byte runtime outcome before a transactional
4,097-byte refusal, repeats the 1-MiB-plus-one history refusal while checking
the cached byte counter, and keeps a single `f64::MAX` rollout valid through
both batch and incremental APIs.

The controller selector is the prior eleven-test selector plus these four
independent closure tests:

```bash
cargo nextest run -p sbproxy-ai --locked --lib --no-fail-fast -E 'test(=agent_orchestration::fsm::tests::authoritative_edge_quota_accepts_2048_and_refuses_2049) + test(=agent_orchestration::fsm::tests::authoritative_action_quota_accepts_512_and_refuses_513) + test(=agent_orchestration::fsm::tests::authoritative_outcome_quota_accepts_4096_and_refuses_4097) + test(=agent_orchestration::fsm::tests::runtime_outcome_4096_advances_before_4097_transactional_refusal) + test(=agent_orchestration::fsm::tests::authoritative_history_quota_accepts_1mib_and_refuses_plus_one) + test(=agent_orchestration::fsm::tests::huge_known_scalar_is_refused_before_application_string_ownership) + test(=agent_orchestration::fsm::tests::huge_unknown_key_is_refused_before_application_string_ownership) + test(=agent_orchestration::fsm::tests::map_deserialization_ownership_matrix_is_bounded_and_connected) + test(=agent_orchestration::fsm::tests::sequence_deserialization_ownership_matrix_is_bounded_and_connected) + test(=prompt_versioning::tests::add_version_contention_bounds_deep_clones_and_falls_back) + test(=prompt_versioning::tests::replace_versions_contention_bounds_snapshot_clones_and_falls_back) + test(=prompt_versioning::tests::mathematical_weight_overflow_hidden_by_f64_rounding_is_rejected) + test(=prompt_versioning::tests::single_f64_max_is_valid_for_batch_and_legacy_selection_control) + test(=prompt_versioning::tests::every_positive_band_survives_a_2pow53_leading_weight) + test(=prompt_versioning::tests::maximum_draw_is_strictly_below_one_and_never_selects_zero_tail)' --no-capture
```

Expected current semantic signature: 15 selected, the single-`f64::MAX`
positive control passes, and the other 14 tests fail for their frozen release
defects. A compile error, selector miss, timeout, unrelated failure, or a
different split rejects the RED.

Static verification: all 15 names are repository-unique; `git diff --check`
passes for both Rust files. Frozen hashes are
`540bbdf9594476fe06eb8df6a4565d0566eee6b93166dcc05b2165beaf683c81`
for `agent_orchestration/fsm.rs` and
`a38fff610df7c06b527e0dd9e18bc617a933dbd8661af8123c7326aec617bf43`
for `prompt_versioning.rs`.

AI_GROUP_E_E4_SYSTEMIC_RED_READY

## 2026-08-25 controller E2 RED/GREEN evidence

With the coupled `sbproxy-ai` test target stable, the controller ran the exact
five-test E2 selector. It compiled cleanly and produced the frozen accepted RED:
5 selected, 0 passed, 5 failed, 2,154 skipped. Every failure was semantic and
matched its predicted callsite cause; there was no timeout, harness failure, or
unrelated diagnostic.

After the minimal correction, the same selector selected and passed 5/5. The
controller then reran the definitive E1 selector and passed 15/15 with 2,144
skipped. A fresh post-GREEN review and production mutation batch remain required;
no D runtime, commit, repository gate, push, PR, or merge is credited.

AI_GROUP_E_E2_CONTROLLER_GREEN_5_OF_5_E1_GREEN_15_OF_15

## 2026-08-25 controller compile and semantic GREEN

The protected-target combined E/F shell command compiled without warnings or
unrelated diagnostics and selected/passed all four cross-package controls. The
controller then ran the definitive 15-test Group E selector exactly as frozen
above. It selected 15 tests, passed 15, failed 0, skipped 2,130, and completed
without a harness or timeout failure. This is the first Group E semantic GREEN.

A fresh implementation-level adversarial review remains required, followed by
production mutation kills and restored-tree GREEN. No D runtime, CLI, example,
commit, repository gate, push, PR, or merge is credited by this result.

AI_GROUP_E_E1_SEMANTIC_GREEN_15_OF_15

## Append-only concurrent-order clarification

The E1 GREEN section immediately above was appended concurrently while the later systemic-review
RED package was being authored. It records only the original 15-test E1 selector and predates the
five E2 tests; it does not supersede or execute the E2 checkpoint. Current Group E status remains
E2 RED ready and awaiting the controller's exact five-test run.

AI_GROUP_E_E2_SYSTEMIC_REVIEW_RED_READY

## Append-only E2 GREEN current-status pointer

The E2 production-correction section above supersedes this earlier concurrent-order clarification:
the controller subsequently accepted all five semantic RED failures, and the scoped fixes are now
statically ready for the controller's E2 and E1 GREEN selectors. No executable GREEN is claimed by
this pointer.

AI_GROUP_E_E2_GREEN_READY_FOR_CONTROLLER

## Append-only E3 current-status pointer

The E3 strict-RED section above is the current Group E state and supersedes the earlier E2-ready
tail marker. Eleven E3 tests are statically frozen and await the controller's exact semantic RED
capture; no E3 production fix or executable result is claimed here.

AI_GROUP_E_E3_SYSTEMIC_RED_READY

## Append-only E3 final static hash correction

A final test-fixture refinement made the replacement-contention target name 64 KiB so repeated
map/name cloning is caller-sized, without changing the 11-test selector or expected signature.
The exact final Rust hashes are:

- `crates/sbproxy-ai/src/agent_orchestration/fsm.rs`
  (`sha256 b5d0c5e23693d8057da53f19cf899504fc0e16081038b013be7f2eeeeae415d5`)
- `crates/sbproxy-ai/src/prompt_versioning.rs`
  (`sha256 f499acf5aab9bb3ffa7163786d9acc5c710d65c47d55db5f05d0b411c5c9ad9f`)

`git diff --check --` on both files remains clean. This correction supersedes the earlier prompt
hash in the E3 section.

AI_GROUP_E_E3_SYSTEMIC_RED_READY
