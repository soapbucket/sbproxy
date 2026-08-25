# AI Group F1/F2 revised RED contract

Date: 2026-08-25

Status: **compile-RED authored, controller verification required**

## Scope and ownership

This revision changes only test modules in:

- `crates/sbproxy-ai/src/billing/chargeback.rs`
- `crates/sbproxy-ai/src/billing/unified.rs`

It also replaces this test report. It does not edit production code, manifests,
the lockfile, usage-sink production code, admin code, shared artifacts, staging,
or commits. No Cargo, Rust, rustfmt, Clippy, fetch, push, deletion, or target
command was run. The controller owns compilation and every RED/GREEN claim.

## Why the first package was rejected

The controller previously verified 17 existing-API tests at 3 passing controls
and 14 intended semantic failures. Independent review accepted that as partial
RED evidence but rejected it as closure evidence with 1 Blocker, 4 Majors, and
1 Minor:

- The only bill test passed while an in-period row was missing. There was no
  executable snapshot-aware `PartialPeriod` contract.
- Refusals were inferred from unchanged finance state. There was no typed
  `try_record` result, per-reason delta, or sticky incomplete state through
  both direct recording and live `UsageSink` dispatch.
- Token and cost overflow were covered, but workspace/team request counts and
  the accepted-entry counter could still saturate silently.
- String-map rollups could not distinguish caller values from missing or
  internal overflow identity on the wire. Digest stability, real collapse,
  and provider/model grouping were not fully proved.
- A single eviction count could not prove a half-open billing period complete.
  Timestamp validation, out-of-order minimum/maximum eviction evidence, and a
  poisoned-watermark posture were absent.

The passing retained-slice test is preserved under a non-acceptance name. It
documents only the lower-level caller-asserted-complete `generate_bill` seam.

## Frozen compile-RED API

The revised tests deliberately name a small future API that does not exist yet.
This is the honest first TDD phase.

### Ingestion and arithmetic

- `ChargebackTracker::try_record(workspace: Option<&str>, entry:
  ChargebackEntry) -> Result<(), ChargebackRecordError>` is the one fallible
  transaction used by direct callers and the object-safe `UsageSink::record`
  adapter.
- `ChargebackRecordError` has closed `InvalidCost`, `InvalidTimestamp`, and
  `ArithmeticOverflow { scope, field }` variants.
- `ChargebackOverflowScope` is closed over `Tracker`, `Workspace`, and `Team`.
- `ChargebackOverflowField` is closed over `RecordedEntries`, `RequestCount`,
  `Tokens`, and `Cost`.
- A refusal mutates only bounded refusal evidence and the monotonic
  `complete = false` bit. Raw rows, rollups, accepted-entry count, retention,
  collapse counters, and eviction evidence remain transactionally unchanged.
- Refusal and pressure counters may saturate as telemetry. Completeness must
  not be derived from whether one of those counters happened to increment.

### Snapshot wire compatibility

The current unversioned snapshot/admin shape is treated as implicit schema v1.
It cannot be losslessly interpreted as typed identity because literal
`unattributed` and `__other__` already collide with internal meaning.

The new wire is explicitly schema v2:

- `CHARGEBACK_SNAPSHOT_SCHEMA_VERSION == 2` and every serialized snapshot
  carries `schema_version: 2`.
- `DimensionKey::{Value(String), Missing, Overflow}` uses the adjacent-tagged
  forms `{"kind":"value","value":"..."}`, `{"kind":"missing"}`, and
  `{"kind":"overflow"}`.
- A separate `ChargebackSnapshotEntry` carries typed workspace/team identity.
  The legacy public `ChargebackEntry` remains the input and lower-level billing
  row, so existing literals do not silently change meaning.
- Snapshot rollups are typed `workspace_rollups` / `team_rollups` rows. The
  ambiguous v1 `workspace_totals` / `team_totals` string maps are not emitted
  in v2. This is the test-pinned compatibility boundary for admin clients.
- Caller text `unattributed` and `__other__` stays `Value`; only absent input is
  `Missing`, and only real cardinality collapse is `Overflow`. Raw retained rows
  keep their typed caller identity even when their rollup lands in `Overflow`.

Long values are UTF-8-safe and bounded to 256 bytes. Values that require
shortening use a stable lowercase full SHA-256 hex suffix separated by `~`.
The tests pin the exact digest for one multibyte dimension and one provider.
Workspace, team, provider, and model must remain distinct across tracker
instances and reversed insertion order. Project is at least bounded and absent
in full from the v2 payload.

### Retention and billing completeness

The snapshot adds:

- sticky `complete`;
- bounded `refused_entries` and typed refusal counts;
- `earliest_retained_timestamp` and `latest_retained_timestamp`;
- an eviction watermark with minimum timestamp, maximum timestamp, and a
  poisoned bit.

Accepted direct timestamps are validated before mutation. A malformed legacy
row encountered during eviction poisons the watermark and completeness. For
out-of-order accepted rows, the minimum may decrease and the maximum may
increase; neither can be replaced by the most recently evicted timestamp.

`generate_bill_from_snapshot` returns `BillError::PartialPeriod { reason }`.
The closed `PartialPeriodReason` distinguishes `IncompleteSnapshot`,
`EvictedRange`, and `PoisonedEvictionWatermark`.

For a requested half-open interval `[start, end)`:

- no eviction is complete;
- all evictions with `max < start` are complete;
- an eviction at `start` or inside the interval is partial;
- a sole eviction at or after `end` is complete;
- a retained min/max eviction interval that may intersect the requested period
  is conservatively partial, even when the exact out-of-order evictions were on
  opposite sides;
- refusal/unknown completeness or a poisoned watermark is partial for every
  period.

## Revised tests

The compile-RED package has 39 selected tests: 29 in `chargeback` (28
`group_f_` tests plus the corrected live invalid-cost contract) and 10 in
`unified` (9 `group_f_` tests plus the retained-slice characterization).

### Ingestion and atomic finance

- Negative, NaN, and infinite costs cross the live `UsageSink` and produce one
  typed invalid-cost delta without evicting the valid control row.
- Direct invalid cost and timestamp return their exact closed variants, add one
  refusal delta, and preserve all financial and retention state.
- Workspace/team token and cost overflow return independently scoped errors.
- Workspace/team request-count and tracker accepted-entry overflow are seeded
  one field at a time and return independently scoped errors.
- Exact `u64::MAX` token aggregation remains accepted.
- A representable `0.5` cost commits after a cost-overflow refusal while the
  previous refusal remains sticky.
- A refusal at saturated refusal counters still flips completeness false.
- Real cardinality collapse at saturated collapse counters retains exact spend
  in typed overflow rollups and remains financially complete.

### Identity and wire

- Missing and literal `unattributed` remain distinct for workspace and team in
  raw rows and rollups.
- Literal `__other__` and a separately forced real overflow remain distinct for
  workspace and team. The collapse delta is exactly one.
- The v2 serialization test covers exact Value/Missing/Overflow forms in raw
  rows and rollups, requires `schema_version: 2`, and refuses emission of the
  ambiguous v1 maps.
- Multibyte long identities remain distinct, bounded, and deterministic across
  trackers and reversed order. Eight distinct long identities exert real
  bounded cardinality pressure.
- Provider/model normalization remains distinct and stable, produces two bill
  groups, and does not retain full raw provider/model/project strings.

### Timestamp and period completeness

- Malformed direct timestamps are typed refusals before mutation.
- Evicting `2026-08-10` and then an older `2026-08-05` keeps min `08-05` and
  max `08-10`; the maximum never regresses to the most recent eviction.
- A malformed retained legacy row poisons the eviction watermark.
- The snapshot-aware bill has independent controls for no eviction, all
  evictions before the period, eviction at/inside the period, and a sole
  eviction at/after the exclusive end.
- A min/max interval straddling the requested period is partial.
- Refusal-poisoned and watermark-poisoned snapshots are partial with exact
  typed reasons.
- The original in-period eviction fixture now has a genuine executable
  `PartialPeriod` assertion. Forwarding only retained entries cannot satisfy it.

## Controller staging

### Stage 1: compile RED

Run the two anchored selectors below. The only accepted initial result is a
compile failure attributable to the explicitly frozen symbols/fields above.
A syntax error, warning promoted to error, unrelated type failure, selector
mistake, harness failure, panic, or timeout is not accepted RED evidence.

```bash
export CARGO_TARGET_DIR="$PWD/target-ai-cluster"
export CARGO_BUILD_JOBS=2
export NEXTEST_HIDE_PROGRESS_BAR=1

cargo nextest run -p sbproxy-ai --locked --lib --no-fail-fast -E '
test(/^billing::chargeback::tests::group_f_/) +
test(=billing::chargeback::tests::usage_sink_invalid_cost_refusal_stays_incomplete_after_a_valid_record)'

cargo nextest run -p sbproxy-ai --locked --lib --no-fail-fast -E '
test(/^billing::unified::tests::group_f_/) +
test(=billing::unified::tests::retained_slice_bill_remains_a_caller_asserted_complete_lower_level_boundary)'
```

Expected missing contract families include `DimensionKey`,
`ChargebackSnapshotEntry`, `ChargebackRecordError`, the two closed overflow
enums, v2 snapshot fields, `try_record`, `generate_bill_from_snapshot`,
`PartialPeriodReason`, and `BillError::PartialPeriod`.

### Stage 2: semantic RED

After the production owner lands only the compiling API shell and faithful
current-behavior adapter, rerun the same selectors. Record the exact selected,
passed, failed, and skipped counts and every semantic failure site in this
report before implementing finance behavior. All 39 tests must select. The
retained-slice characterization is expected to pass; no other pass/fail count
is claimed until the controller observes it.

### Stage 3: GREEN and mutation

After minimal implementation, both selectors must pass with 39/39 selected.
Then apply one production-only mutation at a time and restore exact hashes:

| Mutation | Required killer |
|---|---|
| Rewrite invalid money to zero or bypass `try_record` from `UsageSink` | Live invalid-cost tests and sticky completeness |
| Saturate any prospective request/token/cost/accepted-entry aggregate | Independently scoped overflow test and exact-boundary control |
| Append/evict before every prospective rollup validates | Full-row transaction comparisons |
| Derive completeness from refusal/collapse counter movement | Saturated-counter tests |
| Restore prefix-only or process-seeded shortening | Exact digest, cross-tracker, reverse-order, and distinct bill-group tests |
| Serialize string sentinels or label caller `__other__` as internal overflow | Exact v2 wire and real-collapse tests |
| Validate timestamp after append | Invalid-timestamp transaction test |
| Replace min/max watermark with the last evicted timestamp | Out-of-order watermark and straddling-period tests |
| Forward only `snapshot.entries` to the slice biller | In-period `PartialPeriod` test |
| Treat the exclusive end as intersecting | At/after-end full-bill control |

The independent reviewer must accept the revised tests before production is
credited, and must review the GREEN plus restored mutations before Group F is
closed.

## Static verification

- `git diff --check -- crates/sbproxy-ai/src/billing/chargeback.rs crates/sbproxy-ai/src/billing/unified.rs crates/sbproxy-ai/src/billing/mod.rs`: pass.
- All source hunks remain inside the existing `#[cfg(test)]` modules.
- Authored source hashes are `96496e4be5ba1a8ad5669d28c2dc0dba2ba67695404b3ea8dd2587a5a2501e5d`
  for `chargeback.rs` and
  `9912f8384fc9b58d4d8f314e4dec3af23284b4e6a5ad113acdecf7b00b9aa8cc`
  for `unified.rs`.
- This report is test evidence only. Compilation, semantic RED, GREEN, Clippy,
  rustfmt, and repository-gate success are intentionally not claimed.

GROUP_F_R2_COMPILE_RED_READY_FOR_CONTROLLER

## Append-only correction after F R2 independent review

Date: 2026-08-25

Status: **corrected compile-RED package ready for fresh independent review; no
Cargo authorization requested**

The F R2 package above was not approved (1 Blocker, 6 Majors). This section is
the definitive correction and supersedes its test counts, controller staging,
wire-boundary coverage, and completion posture. The earlier R2 compile attempt
is not accepted evidence. Group F is not complete: pagination and a production
response-byte refusal remain the later F3 RED package.

### Ownership extension

The corrected package retains test-module-only changes in:

- `crates/sbproxy-ai/src/billing/chargeback.rs`
- `crates/sbproxy-ai/src/billing/unified.rs`

It adds one isolated integration test:

- `crates/sbproxy/tests/chargeback_admin_wire.rs`

The integration test is itself a test target. No production admin, routing,
usage-sink, billing, manifest, lockfile, shared artifact, staging, or commit was
edited. No Rust, Cargo, rustfmt, Clippy, fetch, push, deletion, or target command
was run. Existing unrelated dirty-worktree files were not touched.

### Review dispositions and static mutation analysis

1. **Real wire boundary and v1 compatibility.**
   `group_f_admin_chargeback_wire_preserves_v1_and_negotiates_typed_v2` starts
   the shipped `sbproxy` child with separate real proxy and admin loopback
   listeners and a bounded local OpenAI fixture. Three real chat requests use
   governed credentials whose teams are Value, Missing, and a later Value that
   crosses the configured team-cardinality limit. The same configured
   chargeback sink therefore produces real Value/Missing raw identities and
   Value/Missing/Overflow rollups. The workspace is a caller Value whose
   one-row rollup is real Overflow.

   The authenticated default `GET /admin/ai-chargeback` is compared as one
   complete legacy v1 JSON fixture after only RFC3339 timestamps and derived
   costs are replaced with typed placeholders. The exact legacy entries,
   `workspace_totals`/`team_totals` maps, limits, request/token totals, and four
   pressure counters remain pinned. After an explicit v2 read, a second default
   read must equal the first normalized fixture, preventing negotiation from
   silently changing default clients. `?schema_version=2` requires both the
   outer envelope and inner snapshot to say 2, typed raw and rollup arrays, all
   three `DimensionKey` wire variants, and no ambiguous v1 maps. Numeric `3`
   and the bounded parsed token `future` each require the exact typed 400:

   ```json
   {
     "code": "unsupported_schema_version",
     "requested_schema_version": 3,
     "supported_schema_versions": [1, 2]
   }
   ```

   An unrelated query value must not be echoed. Mutations that ignore the
   query because routing compares only `path_only`, make v2 the default,
   serialize the v2 snapshot directly as v1, omit either version field,
   restore string-sentinel maps, fabricate a tracker instead of reading the
   live sink, or return 200/404/untyped 400 are killed independently.

   Harness output is bounded before inspection: fixture requests at 64 KiB,
   every HTTP response at 256 KiB, and captured child output at 32 KiB. The
   prompt, admin Basic value/password, provider credential, and all three
   bearer credentials are asserted absent from every retained response and
   captured-log failure surface. Failures report only status, category, or
   bounded byte count, never bodies or logs.

2. **The object-safe adapter now has a valid-cost overflow RED.**
   `group_f_live_usage_sink_refuses_valid_cost_arithmetic_overflow_transactionally`
   first commits `f64::MAX` to one workspace, then sends another finite,
   nonnegative `f64::MAX` event through `UsageSink::record`. The new team is
   empty beforehand, so only the workspace cost can overflow. The snapshot
   must gain exactly the closed Workspace/Cost refusal, mutate no finance or
   retention field, and remain incomplete after a later valid live event.
   Reusing the old invalid-cost sanitizer, bypassing `try_record`, clamping the
   total, or partially installing the new team/raw row fails this test.

3. **Eviction poison and extrema are independent of lossy telemetry.**
   The malformed legacy eviction test now forces a later valid eviction. Its
   min/max evidence advances to that valid timestamp while the poison and
   incomplete bit remain set. A separate test seeds `evicted_entries` to
   `u64::MAX`; three valid out-of-order evictions must still move min down and
   max up while the counter cannot change. A second saturated fixture evicts a
   malformed row and must still set poison. Clearing poison on success, gating
   watermark work on `evicted_entries.checked_add`, or replacing both extrema
   with the last eviction fails.

4. **Generic unknown incompleteness is authoritative.**
   `group_f_unknown_incomplete_snapshot_is_partial_without_counter_evidence`
   starts from an empty, unpoisoned snapshot with zero evictions, refusals, and
   refusal rows, then sets only `complete = false`. Snapshot-aware billing must
   return `PartialPeriod(IncompleteSnapshot)`. Deriving completeness from
   counters/watermarks, or treating an unknown empty snapshot as a complete
   empty bill, fails.

5. **Refusal vocabulary and deltas are closed.**
   `assert_refusal_delta` now compares the entire refusal-row collection. The
   selected reason is the only row allowed to be inserted or incremented;
   every unselected reason must remain present with the exact prior count and
   duplicate rows fail. Exhaustive, wildcard-free matches cover all variants
   of `ChargebackRecordError`, `ChargebackOverflowScope`, and
   `ChargebackOverflowField`, making vocabulary expansion compile-visible.
   Ordinary refusals require exact +1 overall and selected-reason deltas. The
   saturated-counter test separately requires exact zero telemetry deltas at
   `u64::MAX` while the independent completeness bit flips false. Adding a
   generic reason, incrementing two rows, losing a row, wrapping a counter, or
   inferring completeness from a counter delta fails.

6. **Model identity has an independent literal oracle.**
   For `"x" * 270 + "-model-alpha"`, the expected normalized model is pinned
   literally as 191 `x` bytes, `~`, and SHA-256
   `9df9822fb045e57a5b8a1c9ca6614ff9174f8e4d1ddeb8b89e094f18497c0339`.
   The corresponding provider retains its separately pinned
   `c0104a...bb4d` digest. The alpha row and bill line must carry that exact
   provider/model pair. This preserves the cross-tracker and reverse-order
   comparisons while killing a mutation that derives the model value from the
   provider source or reuses its digest.

7. **Retained extrema are independently maintained.**
   `group_f_retained_extrema_are_independent_without_eviction` records four
   valid rows in order 08-20, 08-05, 08-30, 08-10 with retention for all four.
   With no eviction evidence, earliest must be 08-05 and latest 08-30. A
   last-written-to-both implementation ends at 08-10/08-10 and fails; deriving
   retained extrema from the eviction watermark also fails.

### Frozen admin compatibility boundary

- Auth and GET-only behavior stay at the existing admin gate.
- Omitted `schema_version` means legacy schema 1 indefinitely.
- `schema_version=2` means an envelope `{schema_version: 2, origins: ...}` in
  which every returned snapshot independently carries `schema_version: 2`.
- v1 keeps legacy `ChargebackEntry` rows plus string-keyed
  `workspace_totals`/`team_totals`; it does not silently acquire typed v2
  fields.
- v2 carries `ChargebackSnapshotEntry` rows with typed workspace/team identity
  and typed `workspace_rollups`/`team_rollups`; it emits neither ambiguous v1
  map.
- Unsupported numeric or bounded nonnumeric parsed version tokens return the
  typed 400 above. The handler may echo only the parsed bounded version token,
  never the raw URI or unrelated query parameters.

The child test deliberately does not claim pagination or a production response
byte ceiling. Its 256 KiB reader cap protects the test harness only. Pagination
and server-side response-byte refusal remain open F3 work, so this corrected
package must not be used to mark Group F complete.

### Definitive selected tests

The corrected library package selects **44 unique tests**:

- chargeback: 32 `group_f_` tests plus
  `usage_sink_invalid_cost_refusal_stays_incomplete_after_a_valid_record` = 33;
- unified: 10 `group_f_` tests plus
  `retained_slice_bill_remains_a_caller_asserted_complete_lower_level_boundary`
  = 11.

The isolated wire selector adds exactly 1 integration test, for 45 total Group
F contract/characterization tests across the two packages. Static exact-name
search found no duplicates. These are selection counts only; no compile,
semantic RED, or GREEN result is inferred.

### Corrected controller staging with E/F compile coupling

`sbproxy-ai` compiles every `#[cfg(test)]` module before nextest applies its
runtime selector. Group E and Group F therefore cannot establish independent
compile-RED checkpoints in the same crate. The prior contaminated E-only
attempt is not accepted RED.

#### Combined Stage 1: one E + F compile-RED gate

Only after fresh independent review approves both packages, the controller
runs one command from the serialized AI build slot:

```bash
export CARGO_TARGET_DIR="$PWD/target-ai-cluster"
export CARGO_BUILD_JOBS=2
export NEXTEST_HIDE_PROGRESS_BAR=1

cargo nextest run -p sbproxy-ai --locked --lib --no-fail-fast -E '
test(=agent_orchestration::fsm::tests::workflow_accepts_exact_shape_maxima) +
test(=prompt_versioning::tests::rollout_batch_accepts_zero_weight_when_total_is_positive_control) +
test(=billing::chargeback::tests::group_f_refusal_and_overflow_vocabularies_are_closed_and_exhaustive) +
test(=billing::unified::tests::group_f_unknown_incomplete_snapshot_is_partial_without_counter_evidence)' --no-capture
```

Accepted Stage-1 evidence is compilation exiting nonzero only on the union of:

- Group E's approved `FsmLimitDimension`, typed FSM errors/probes,
  `replace_versions`, typed selection, and prompt error contracts recorded in
  `ai-group-e-red-report.md`; and
- Group F's approved closed record/overflow enums, `try_record`, typed v2
  snapshot/identity/rollup/refusal/watermark fields, and snapshot-aware bill
  error contracts recorded here.

Because the integration test uses only the shipped HTTP surface and dynamic
JSON, its version-negotiation failure is semantic and is not an expected Rust
missing-symbol diagnostic. Syntax failures, unrelated type errors,
warning-denied failures, selector mistakes, timeouts, or missing-symbol errors
outside the approved union reject Stage 1. No selected/pass count is accepted
while compilation fails.

After this combined checkpoint is accepted, E and F production owners may add
only their compiling API shells in parallel, because their files are disjoint:
E owns FSM/prompt-versioning seams; F owns billing and the narrow admin route
negotiation seam. The controller then compiles their union once before any
semantic result is credited.

#### Later semantic selectors

The definitive Group E semantic selector remains the 15-test selector in the
latest append-only correction of `ai-group-e-red-report.md` (9 FSM, 6 rollout,
5 named passing controls).

The definitive Group F library semantic selector is:

```bash
cargo nextest run -p sbproxy-ai --locked --lib --no-fail-fast -E '
test(/^billing::chargeback::tests::group_f_/) +
test(=billing::chargeback::tests::usage_sink_invalid_cost_refusal_stays_incomplete_after_a_valid_record) +
test(/^billing::unified::tests::group_f_/) +
test(=billing::unified::tests::retained_slice_bill_remains_a_caller_asserted_complete_lower_level_boundary)' --no-capture
```

It must select exactly 44 tests. The controller records selected, passed,
failed, skipped, every control result, and every semantic failure; this report
does not predict them before the shell exists.

The real wire semantic selector is separate and unique:

```bash
cargo nextest run -p sbproxy --locked --test chargeback_admin_wire --no-fail-fast \
  -E 'test(=group_f_admin_chargeback_wire_preserves_v1_and_negotiates_typed_v2)' \
  --no-capture
```

It must select exactly 1 test. The current handler's `path_only` dispatch and
hard-coded schema 1 are the expected semantic boundary, but the controller must
observe and record the actual failure rather than credit this static
prediction. Cargo commands remain serialized by the one build gate even when
the disjoint shell authors work in parallel.

### Corrected static verification

- Tracked-source `git diff --check` passes for both billing files. The new
  integration target is checked independently with `git diff --no-index
  --check /dev/null crates/sbproxy/tests/chargeback_admin_wire.rs`; the report
  is checked the same way while it remains untracked in this shared worktree.
- Every billing-source hunk remains below the pre-existing `#[cfg(test)] mod
  tests` boundary. The new Rust file is an integration test target in
  `crates/sbproxy/tests`; no production module imports it.
- Current authored source hashes are:
  - `9ca6aa5f8059e426a735cb855590b4bcdffb4fb9634225daadf57e16cdfc9856`
    — `crates/sbproxy-ai/src/billing/chargeback.rs`
  - `f254182c2424b74879894df17e5973a7ddce96350296ee82e57163a424304eb4`
    — `crates/sbproxy-ai/src/billing/unified.rs`
  - `ded1b17c2b30c876d1b356545fe7775587b2f836163622465297a1b8f31c09f5`
    — `crates/sbproxy/tests/chargeback_admin_wire.rs`
- Exact static counts are 32 chargeback `group_f_` names, 10 unified
  `group_f_` names, the two explicitly selected characterization/control
  names, and one integration name. Each occurs once.
- Compilation, semantic RED, GREEN, mutation restoration, formatting, Clippy,
  and repository-gate success are intentionally not claimed.

GROUP_F_R3_CORRECTED_RED_READY_FOR_REREVIEW

## Append-only correction after F R3 scoped re-review

Date: 2026-08-25

Status: **both scoped review findings corrected; test/report-only package ready
for fresh scoped re-review; no Cargo authorization requested**

This section is the definitive R4 correction. It supersedes the R3 selected
test counts, wire selector, child-output description, and source hashes. It
does not broaden the package into F3: pagination and the production response
byte ceiling remain explicitly open.

### Finding 1: executable whole-map refusal preservation

`group_f_second_refusal_preserves_the_first_reason_row` supplies the state the
R3 helper lacked. It starts from an empty snapshot, records an ordinary
`InvalidCost` refusal, and proves that exact reason has one row with count one.
It then records a distinct ordinary `InvalidTimestamp` refusal against the
same tracker. After the second refusal:

- `assert_refusal_delta` executes with a pre-existing unselected reason row;
- the InvalidCost row remains present with its exact count of one;
- only the newly selected InvalidTimestamp reason has count one;
- there are exactly two closed reason rows;
- `refused_entries - initial.refused_entries` is exactly two; and
- retained rows, both rollup sets, accepted/evicted/collapse counters, retained
  extrema, and eviction evidence remain unchanged.

Static mutation result: clear-the-map-then-insert-latest now fails because the
second snapshot would have one row rather than two and the pre-existing
InvalidCost lookup inside `assert_refusal_delta` would be absent. Incrementing
both rows, duplicating either reason, losing the aggregate increment, wrapping
a counter, or mutating finance state also fails independently. Both refusal
counters are deliberately unsaturated; the separate saturation RED remains
responsible for lossy telemetry behavior.

### Finding 2: bounded complete-stream child-output scanner

The wire harness no longer creates or reads a child log file. The shipped
child's stdout and stderr are both `Stdio::piped()` and are taken immediately
after spawn. A dedicated drain thread continuously reads each pipe in fixed
4096-byte chunks, preventing either pipe from filling while the child is
running. Each stream retains its own bounded overlap tail, whose length is the
longest private/address marker minus one, so matches spanning read boundaries
cannot escape detection and bytes from separate streams are never
artificially concatenated.

Both drains update a shared bounded state that:

- retains at most 32 KiB total across stdout and stderr;
- scans every byte through EOF even after retention is full;
- tracks a saturating total byte count and an exact retained-overflow bit;
- records only booleans for private-marker and case-insensitive
  address-in-use detection; and
- never returns retained output text in an error or summary.

`finish` joins both drain threads before producing a summary and marks an I/O
error, panic, or poisoned state as an incomplete scan. Early exit reaps the
child and finishes both drains; timeout kills and reaps before finishing;
normal completion uses explicit `ProxyChild::shutdown`; and every unwind or
early-return path through `Drop` stops/reaps the child and finishes any
remaining scanner. Address-in-use retry decisions use only the full-stream
boolean. Other startup diagnostics contain exit status, retained byte count,
total byte count, and truncation state only. No temporary stdout/stderr file
can grow, and no captured bytes, auth value, password, prompt, provider key,
or bearer key are included in a failure.

`group_f_bounded_child_output_scans_beyond_retention_and_across_chunks`
executes the same two-drain implementation used by `ProxyChild`. Stdout is
exactly 32 KiB of filler followed by `sec` and `ret` in separate reads;
stderr supplies `ADDRESS ` and `IN USE` in separate reads. The literal expected
total is 32 KiB + 20 bytes, retained bytes must remain exactly 32 KiB,
overflow must be set, both complete-stream flags must be true, both drains
must succeed, and the rejection message must itself contain none of the
private markers.

Static mutation result: stopping scanning when retention fills misses the
secret; dropping the per-stream overlap misses both split markers; omitting a
drain loses bytes/flags and the literal total; retaining all bytes exceeds the
ceiling; prefix-only accounting loses the total/overflow assertions; and
snapshotting without joining races the completed summary. Removing finish
from early-exit, timeout, explicit shutdown, or `Drop` leaves a lifecycle path
with live join handles and is visible directly in the isolated harness.

### Definitive R4 selectors and counts

The library selector is unchanged in shape but must now select **45 unique
tests**:

- chargeback: 33 `group_f_` tests plus
  `usage_sink_invalid_cost_refusal_stays_incomplete_after_a_valid_record` = 34;
- unified: 10 `group_f_` tests plus
  `retained_slice_bill_remains_a_caller_asserted_complete_lower_level_boundary`
  = 11.

```bash
cargo nextest run -p sbproxy-ai --locked --lib --no-fail-fast -E '
test(/^billing::chargeback::tests::group_f_/) +
test(=billing::chargeback::tests::usage_sink_invalid_cost_refusal_stays_incomplete_after_a_valid_record) +
test(/^billing::unified::tests::group_f_/) +
test(=billing::unified::tests::retained_slice_bill_remains_a_caller_asserted_complete_lower_level_boundary)' --no-capture
```

The isolated wire target now contains exactly **2 unique Group F tests** and
uses an explicit two-name selector:

```bash
cargo nextest run -p sbproxy --locked --test chargeback_admin_wire --no-fail-fast \
  -E '
test(=group_f_bounded_child_output_scans_beyond_retention_and_across_chunks) +
test(=group_f_admin_chargeback_wire_preserves_v1_and_negotiates_typed_v2)' \
  --no-capture
```

The corrected focused total is therefore 47 tests. Exact-name static search
found no duplicate among the 45 library and 2 wire selectors. These remain
selection counts, not compile, RED, or GREEN claims.

### Controller staging

The definitive combined E + F Stage-1 compile-RED gate from R3 remains
unchanged. `sbproxy-ai` still compiles all `#[cfg(test)]` modules before
nextest selection, so the controller must run one combined Stage 1 against the
union of independently approved E/F missing APIs, then allow disjoint shell
owners, compile their union once, and only then run the semantic selectors.
The earlier contaminated E-only attempt remains rejected evidence. The new
wire scanner test uses existing Rust APIs and does not add an authorized
missing production contract; the admin compatibility test remains a later
semantic RED at the real process boundary.

### R4 static verification and ownership audit

- `git diff --check -- crates/sbproxy-ai/src/billing/chargeback.rs
  crates/sbproxy-ai/src/billing/unified.rs` exits zero.
- `git diff --no-index --check /dev/null
  crates/sbproxy/tests/chargeback_admin_wire.rs` exits one only because the
  test is untracked and emits zero whitespace diagnostics. The report receives
  the same no-index check after this append.
- Static absence search finds no `File::create`, `.log`, `log_path`,
  `read_bounded_private_log`, `Stdio::from`, or `MAX_CAPTURED_LOG` in the wire
  harness. Both child streams are piped and all early-exit, timeout, shutdown,
  and drop paths visibly consume `finish`.
- The pre-existing test-module boundaries are line 412 in `chargeback.rs` and
  line 192 in `unified.rs`; every tracked billing hunk starts below those
  boundaries. `chargeback_admin_wire.rs` is wholly an integration test target.
- Current authored source hashes are:
  - `c405f54e36e6c355c5021ddd64b76a1039fc0b4dc40ff708a062a1a53e0116a7`
    — `crates/sbproxy-ai/src/billing/chargeback.rs`
  - `f254182c2424b74879894df17e5973a7ddce96350296ee82e57163a424304eb4`
    — `crates/sbproxy-ai/src/billing/unified.rs`
  - `c1c349cb3665e9c13c5e47aa8b3f42ff297f1b964b9facc3f3c6151f6145e29c`
    — `crates/sbproxy/tests/chargeback_admin_wire.rs`
- No production source, manifest, lockfile, shared artifact, staging area, or
  commit was changed. No Cargo, Rust, rustfmt, Clippy, fetch, push, deletion,
  or target command was run.

Compilation, semantic RED, GREEN, mutation restoration, formatting, Clippy,
and repository-gate success remain intentionally unclaimed pending fresh
scoped review and controller authorization.

GROUP_F_R4_SCOPED_FIX_READY_FOR_REREVIEW

## Append-only preemptive readiness-harness correction

Date: 2026-08-25

Status: **readiness false-negative corrected statically before any Group F
controller run; approved semantic contracts unchanged**

No Group F controller command has run yet, so this is not an observed F test
failure and no runtime result is claimed. Cross-package inspection of the
classifier child harness exposed the same readiness invariant before the F
gate was attempted.

### Root cause and evidence

`ProxyChild::start` supplies `SBPROXY_E2E_HARNESS_TOKEN`, and
`proxy_readiness_probe` accepts a response only when it has both HTTP 200 and
the exact `x-sbproxy-e2e-harness-token` value. The prior F fixture routed
`ready.localhost` to `type: static`. The shipped generated-response dispatch
returns the configured Static response without stamping the harness token, so
a healthy F child would repeatedly fail the identity check and reach the
30-second startup timeout before any chargeback assertion ran.

The working classifier child harness documents and uses the correct pattern:
a schema-valid fieldless Echo action. The shipped Echo dispatch returns 200
and, when the child environment contains the harness token, explicitly stamps
that exact response header. This preserves the two properties the readiness
probe is designed to establish: server readiness and correct-child identity.

The isolated F fixture now contains exactly:

```yaml
"ready.localhost":
  action:
    type: echo
```

The former Static-only `status_code`, `content_type`, and `body` fields were
removed rather than left as invalid Echo fields. A repository scan of the
`crates/sbproxy/tests` child harnesses that set `SBPROXY_E2E_HARNESS_TOKEN`
found only the F and classifier readiness origins: both now use Echo, and no
remaining Static/token readiness assumption exists there.

### Scope and mutation analysis

This is a one-variable test-harness configuration fix. The two test names,
bounded readiness probe, correct-child token comparison, output scanner,
real proxy/admin requests, v1/v2 fixtures, typed 400s, and all approved Group
F semantic expectations are unchanged. No production action behavior or
configuration schema was altered.

Restoring `type: static` (or removing the Echo token stamp in production)
causes `proxy_readiness_probe` to reject every otherwise healthy 200 response;
the real wire test then times out before its first admin assertion. Accepting
status alone would weaken the existing correct-child race guard and is not
part of this correction.

### Selectors, counts, hashes, and static checks

The definitive R4 selectors remain unchanged:

- library: 33 chargeback `group_f_` + one chargeback characterization + 10
  unified `group_f_` + one unified control = **45 unique tests**;
- `chargeback_admin_wire`: the same two exact `group_f_` names = **2 unique
  tests**;
- focused Group F total = **47 tests**.

Only the wire-harness hash changes. Current authored source hashes are:

- `c405f54e36e6c355c5021ddd64b76a1039fc0b4dc40ff708a062a1a53e0116a7`
  — `crates/sbproxy-ai/src/billing/chargeback.rs`
- `f254182c2424b74879894df17e5973a7ddce96350296ee82e57163a424304eb4`
  — `crates/sbproxy-ai/src/billing/unified.rs`
- `4f40e05e24c6540e49a4e9b49cf08ac7c3b0f108a22d8a4cc61d369212c70b28`
  — `crates/sbproxy/tests/chargeback_admin_wire.rs`

Tracked billing `git diff --check` remains clean. The untracked wire target
and this report receive independent no-index whitespace checks after this
append. Exact static counts remain 33/10/2 with no duplicate selected name.
The owned staging set remains empty.

No Cargo, Rust, rustfmt, Clippy, controller, fetch, push, deletion, staging, or
commit command was run. Compile, semantic RED, GREEN, and repository-gate
results remain intentionally unclaimed.

GROUP_F_R5_READINESS_HARNESS_CORRECTED_STATIC_ONLY

## Append-only correction after the first Group F wire controller run

Date: 2026-08-25

Status: **fixture-only tenant declaration added; controller rerun still
required; no Group F production semantic result inferred**

This section supersedes R5's statement that no Group F controller command had
run. The controller selected exactly both wire tests:

- `group_f_bounded_child_output_scans_beyond_retention_and_across_chunks`
  passed;
- `group_f_admin_chargeback_wire_preserves_v1_and_negotiates_typed_v2`
  exited before readiness and reported a bounded 114-byte child diagnostic.

The passing control is runtime evidence for the bounded output scanner only.
The live test did not reach an admin request or any approved chargeback
production behavior, so this run supplies neither semantic RED nor GREEN
evidence for the v1/v2 contract.

### Exact root cause and minimal correction

The controller reproduced the generated F YAML directly against the shipped
binary and recovered this privacy-safe startup diagnostic:

```text
Fatal: origin wire.ai.localhost references tenant_id wire-workspace which is not declared under proxy.tenants
```

This matches the shipped configuration compiler: every origin `tenant_id`
other than the synthetic `__default__` must name an existing
`proxy.tenants[].id`. The F fixture assigned `wire-workspace` to the AI origin
so the live chargeback rows could exercise workspace identity, but had not
declared that tenant.

The only correction is the schema-valid declaration under `proxy`:

```yaml
tenants:
  - id: wire-workspace
```

The `ready.localhost` Echo action remains unchanged and continues to use the
synthetic default tenant. All process/HTTP/output byte ceilings, correct-child
token checks, retry bounds, auth behavior, real chargeback requests, legacy v1
fixture, typed v2 fixture, typed unsupported-version responses, and private
marker assertions are unchanged. Removing the declaration reproduces the
compiler's exact fatal branch before listener readiness; changing the
chargeback origin to the synthetic tenant would avoid the error by weakening
the workspace-identity fixture and is intentionally not done.

### Counts, current hashes, and verification boundary

Selectors and counts remain unchanged: 45 unique library tests, 2 unique wire
tests, and 47 focused Group F tests total. No test was added, renamed, removed,
or semantically relaxed.

Current whole-file hashes in the shared worktree are:

- `7f0dc6002976596d9d41664fc9bd6e4f80611a7a95351d183b9af7755bcbb990`
  — `crates/sbproxy-ai/src/billing/chargeback.rs`
- `21753196faacba0c72c6ea73f991400485ceeeb1968baf53307dfa935cfb3b9e`
  — `crates/sbproxy-ai/src/billing/unified.rs`
- `465e0569074fed17692103363570fcafe19f611f7e0e399fe4b5aabee7f5c308`
  — `crates/sbproxy/tests/chargeback_admin_wire.rs`

The billing hashes changed after R5 as other controller-owned work advanced in
the shared worktree; this fixture correction did not edit either billing file.
Only the untracked integration target and this append-only report were edited
for R6. Tracked billing `git diff --check` and independent no-index checks for
the wire target and report are rerun after this append. The exact static test
counts remain 33/10/2 with no duplicate selected name, and the owned staging
set remains empty.

The reported controller failure and bounded-output control pass are retained
as historical evidence. This author ran no Cargo, Rust, rustfmt, Clippy,
controller, stage, commit, fetch, push, deletion, or target command for the
correction. The post-correction live wire result remains unclaimed until the
controller reruns its existing two-test selector.

GROUP_F_R6_TENANT_FIXTURE_CORRECTED_STATIC_ONLY

## 2026-08-25 controller F0 GREEN evidence

The combined E/F shell compiled cleanly and its four controls passed. The
definitive Group F library selector then selected and passed 45/45 tests with
2,100 skipped and no warning, harness failure, or timeout.

The first wire attempt selected two tests. The bounded-output mutation control
passed; the live admin case exited before readiness. A bounded controller
reproduction exposed only the undeclared `wire-workspace` test tenant recorded
above, before any chargeback production behavior ran. After the fixture-only
tenant declaration, the controller reran the exact two-test selector. It passed
2/2, including the shipped-child default-v1, explicit typed-v2, unsupported
typed-400, authentication, and live sink path.

These 47 GREEN tests are not final Group F approval. A fresh implementation
review is active and has already identified accepted-long-timestamp corruption
and O(retained rows) timestamp reparse/clone work under the record mutex. Those
findings require a new test-first fix cycle. F3 pagination and response-byte
admission also remain explicitly open.

GROUP_F_F0_CONTROLLER_GREEN_47_OF_47_REVIEW_OPEN

## Append-only F0 production/API shell handoff

Date: 2026-08-25

Status: **production/API shell authored; controller compilation and semantic
verification required**

The isolated Group F production owner implemented the approved contract in the
four assigned production files and made no test changes:

- `crates/sbproxy-ai/src/billing/chargeback.rs`
- `crates/sbproxy-ai/src/billing/unified.rs`
- `crates/sbproxy-ai/src/billing/mod.rs`
- `crates/sbproxy-core/src/admin.rs`

The chargeback tracker now has one fallible transaction used by direct callers
and the object-safe usage-sink adapter. It validates cost and timestamp before
locking finance state, computes checked tracker/workspace/team aggregates
before any finance mutation, records a closed typed refusal with sticky
incompleteness on failure, and commits retained data plus both rollups under the
existing single lock on success. Caller Value/Missing identity is retained in
typed v2 rows, cardinality collapse alone uses `DimensionKey::Overflow`, and
long caller values use the test-pinned UTF-8-safe SHA-256-suffix normalization.
Eviction min/max evidence advances independently from its saturating telemetry
counter, while malformed legacy eviction poisons the watermark and
completeness.

`generate_bill_from_snapshot` validates the requested half-open period, refuses
poisoned or otherwise incomplete snapshots, rejects an eviction interval that
may intersect the requested period, and delegates only a proven-complete
retained window to the existing lower-level biller. The new public types and
entry points are re-exported from `billing::mod`.

The admin route keeps a single mutable v2 source of truth. Omitted or explicit
`schema_version=1` is converted to an owned legacy DTO with exactly the former
fields; `schema_version=2` serializes the typed snapshots; other numeric or
bounded nonnumeric tokens return the approved typed 400 without echoing other
query parameters. Dispatch passes the full request target to negotiation. CSV
uses the same legacy rollup conversion. There is no second mutable financial
map.

Static source audit found no remaining production consumer of the removed v2
`workspace_totals` / `team_totals` snapshot fields outside the intentional
private tracker state and legacy DTO. `git diff --check` exits zero for all four
owned production files. No Cargo, rustc, nextest, rustfmt, Clippy, staging,
commit, fetch, or push command was run by this owner.

Current whole-file hashes, before controller formatting or fixes, are:

- `7f0dc6002976596d9d41664fc9bd6e4f80611a7a95351d183b9af7755bcbb990`
  — `chargeback.rs`
- `21753196faacba0c72c6ea73f991400485ceeeb1968baf53307dfa935cfb3b9e`
  — `unified.rs`
- `0c2e23186856b9bb7adc6d0e9658305a8ee94c224532d83be17e1921ba7da9ae`
  — `billing/mod.rs`
- `5e3bf23d0423068ea975a90a576246b3282d26ac3b24a0947595bef80d40abe9`
  — `admin.rs`

Open verification risks are intentionally explicit: the controller must compile
the coupled E/F union, run the exact 45-test library selector and two-test wire
selector, record every semantic result, format the Rust, and request fresh
review. The current owner used static type/borrow inspection only, so compiler
diagnostics may still require a narrow follow-up. Group F3 pagination and a
production response-byte refusal remain out of scope and are not claimed.

GROUP_F_F0_SHELL_READY_FOR_CONTROLLER

## Append-only F1 systemic-review RED package

Date: 2026-08-25

Status: **strict RED-only correction authored; controller compile/RED evidence
required before any production fix**

The fresh F0 implementation review was not approved at 3 Blockers, 3 Majors,
and 1 Minor. This correction changes tests only in the three assigned source
files. It does not change the current F0 production behavior, the integration
harness, manifests, lockfile, staging, or commits. No Cargo, rustc, nextest,
rustfmt, Clippy, fetch, push, or deletion command was run.

### New executable contracts

The package adds exactly eleven unique `group_f_` tests.

Chargeback adds five:

1. `group_f_long_parseable_timestamp_is_refused_or_retained_bounded_and_parseable`
   independently proves the 300-fractional-digit fixture is valid RFC 3339.
   The tracker may either return the typed `InvalidTimestamp` refusal before
   finance mutation, or accept only a bounded timestamp that remains RFC 3339,
   supplies both retained extrema, and passes snapshot-aware billing. Accepting
   and then hashing/truncating the timestamp into invalid text fails.
2. `group_f_hash_shaped_literal_does_not_alias_its_long_source_identity`
   uses the literal current projection of the long provider-alpha source as a
   second caller identity. Typed workspace/team raw rows and rollups and
   provider/model bill groups must remain distinct, bounded, and free of the
   full long source. This kills the long-source-versus-hash-shape collision,
   not merely two-long-source prefix collapse.
3. `group_f_present_empty_dimensions_remain_distinct_from_missing` sends real
   `LlmUsageEvent` values with `None` and `Some("")`. Raw workspace/team keys
   and rollups must be `Missing` and `Value("")` respectively.
4. `group_f_full_retention_hot_path_does_not_revisit_or_clone_retained_rows`
   fills a 512-row configured retention window through the real accepted-event
   path, installs a current-thread production-callsite probe, then accepts one
   evicting event. The frozen counter result is one accepted timestamp parse,
   zero retained-row revisits, zero retained-row clones, one commit, and no
   refusal signal. Independent extrema assertions require 08-10/08-30 after
   the 08-20 row is evicted. Timing is deliberately not used.
5. `group_f_live_usage_sink_refusal_signal_is_closed_and_non_flooding` drives
   64 invalid-cost and 64 checked workspace-cost-overflow refusals through the
   object-safe live `UsageSink`. The production-callsite probe must observe
   exactly the first occurrence of each typed closed reason, in order, with no
   repeated flood and no workspace, team, or money value in the signal.

The test-pinned test-only seam is current-thread scoped:

```rust
ChargebackCallsiteProbe::install_for_current_thread()
ChargebackCallsiteProbe::counters()
```

Its counter view has `accepted_timestamp_parses`,
`retained_rows_revisited`, `retained_rows_cloned`, `accepted_commits`, and
`refusal_signals: Vec<ChargebackRecordError>`. It must observe the actual
accepted-record, retained-index, and release logging/metric signal callsites;
it is not authorization for a release fault branch or parallel recorder.

Unified billing adds four:

1. `group_f_snapshot_bill_rejects_unsupported_snapshot_schema` requires the
   exact new `PartialPeriodReason::UnsupportedSnapshotSchema` for schema 99.
2. `group_f_snapshot_bill_rejects_inverted_missing_and_impossible_eviction_evidence`
   independently covers missing min, missing max, inverted min/max, and a
   watermark with zero evictions. Missing/inverted evidence is
   `PoisonedEvictionWatermark`; the impossible zero-counter contradiction is
   `InconsistentSnapshot`.
3. `group_f_snapshot_bill_rejects_contradictory_refusal_evidence` requires
   `InconsistentSnapshot` for complete-plus-refusal, count without aggregate,
   aggregate without count, aggregate/count mismatch, a zero-count row, and
   duplicate reason rows. Existing unknown incompleteness remains the passing
   `IncompleteSnapshot` control.
4. `group_f_snapshot_billing_borrows_v2_rows_without_materializing_legacy_entries`
   requires the real snapshot biller to aggregate three borrowed typed rows,
   create zero legacy rows, clone zero snapshot entries, retain the borrowed
   source for the caller, and produce the exact two-line, three-request bill.

The billing test-only seam is:

```rust
SnapshotBillingCallsiteProbe::install_for_current_thread()
SnapshotBillingCallsiteProbe::counters()
```

Its view exposes `borrowed_entries_aggregated`,
`materialized_legacy_entries`, and `snapshot_entry_clones` at the real
aggregation/conversion callsites.

Admin compatibility adds two:

1. `group_f_v1_and_csv_preserve_historical_long_identity_projection` records
   two distinct long multibyte identities whose historical first-UTF-8-safe-
   256-byte projection is the same literal 85-character/255-byte value. V2
   rows and rollups must remain distinct, while the derived v1 entry fields and
   workspace/team maps aggregate under that exact legacy projection. A pure
   `render_ai_chargeback_csv(&origins)` seam must render the same two aggregate
   rows. This is compatibility metadata/view behavior, not a second mutable
   financial ledger.
2. `group_f_default_v1_conversion_consumes_and_moves_entry_graph_at_million_row_bound`
   configures a one-million-entry ceiling, captures the actual short-entry
   string buffers, passes the snapshot by value to
   `legacy_chargeback_snapshot`, and requires all five buffers to be moved into
   the v1 row. A borrowed streaming implementation may replace this owned DTO
   design later, but the current DTO may not coexist with a cloned million-row
   v2 graph.

### Expected current RED and controls

The current source is expected to be compile-RED on the two missing probe
types/counter views, the two new `PartialPeriodReason` variants, the extracted
CSV renderer, and the now-owned legacy conversion call. These names are the
authorized F1 API-shell union. Unrelated syntax, type, warning, or cross-group
failures reject the checkpoint.

After only those shells compile, the current behavior is expected to remain
semantic RED because it hashes a long accepted timestamp into invalid text;
aliases a hash-shaped literal and `Some("")`; rescans retained timestamps;
emits no de-duplicated live-refusal signal; accepts unsupported,
inverted/impossible, and contradictory snapshots; materializes a second
legacy billing vector; emits the v2 digest projection as v1; lacks the pure CSV
renderer; and clones the owned v1 entry strings. These are static predictions,
not controller runtime evidence.

The prior standard timestamp/extrema/billing tests, complete no-eviction and
outside-period controls, unknown-incomplete and explicitly poisoned controls,
long-versus-long digest tests, exact arithmetic/refusal tests, v2 typed-wire
tests, real v1/v2 process wire test, and bounded child-output test remain in
place. In the new tests specifically, the long RFC parser check, v2 alpha/beta
distinctness, full-window retained length, and exact post-eviction extrema are
independent positive controls.

### Definitive counts and controller selectors

Static exact-name counts after this correction are:

- `chargeback`: 38 `group_f_` tests plus the named live invalid-cost control;
- `unified`: 14 `group_f_` tests plus the retained-slice control;
- `sbproxy-core::admin`: 2 new `group_f_` tests;
- `chargeback_admin_wire`: the existing 2 exact `group_f_` tests.

The focused Group F total is therefore **58 unique tests**: 54 AI-library, 2
core-admin, and 2 real-wire tests. The definitive AI selector remains the two
module regexes plus the two named controls and must select exactly 54 after the
F1 shell compiles. The core-admin selector is:

```bash
cargo nextest run -p sbproxy-core --locked --lib --no-fail-fast -E '
test(=admin::tests::group_f_v1_and_csv_preserve_historical_long_identity_projection) +
test(=admin::tests::group_f_default_v1_conversion_consumes_and_moves_entry_graph_at_million_row_bound)' --no-capture
```

The existing two-name `chargeback_admin_wire` selector is unchanged. Cargo
remains serialized by the controller, and the E/F `sbproxy-ai` compile coupling
still applies.

### Static verification and hashes

`git diff --check` exits zero for all assigned Rust files. Every new hunk is
inside an existing `#[cfg(test)]` module; `billing/mod.rs` is unchanged by this
RED pass. Current whole-file hashes are:

- `dbf7badbbc939c44de4e3f4ea040065eb817b665df4ba07bcbd3e81097ff23ee`
  — `crates/sbproxy-ai/src/billing/chargeback.rs`
- `214a76056d19fb8d9bf4642df0d56f32bd4eafb2ac2ba65fc8f4f6b109352c35`
  — `crates/sbproxy-ai/src/billing/unified.rs`
- `0c2e23186856b9bb7adc6d0e9658305a8ee94c224532d83be17e1921ba7da9ae`
  — `crates/sbproxy-ai/src/billing/mod.rs`
- `1753715b8fee217359c91f3f3516599ebcab2f7d2f154b2f54e436359b8e7996`
  — `crates/sbproxy-core/src/admin.rs`

F3 pagination and a production response-byte refusal remain visibly open and
are not claimed by F1.

GROUP_F_F1_SYSTEMIC_REVIEW_RED_READY

### Append-only F1 compile-contamination correction

The controller's attempted frozen E2 selector was rejected before evidence
because the whole `sbproxy-ai` test target encountered the then-undefined
Group F probe names. That rejected run is not E or F compile/RED evidence.

The RED package is now statically compile-plausible rather than intentionally
compile-RED:

- `ChargebackCallsiteProbe` and its counter view are defined under
  `cfg(test)`, scoped to the current thread, and wired to the existing timestamp
  validation, accepted commit, retained-row scan/clone, and every-refusal
  callsites. The current wrong full-window path is predicted to expose one
  accepted timestamp parse, 512 row revisits, three extrema-string clones, and
  one accepted commit. The current wrong refusal path is predicted to expose
  all 128 repeated signals rather than only two first-occurrence signals.
- `SnapshotBillingCallsiteProbe` is likewise defined and wired to the current
  v2-to-legacy materialization. The three-row fixture is predicted to expose
  zero borrowed-v2 aggregations, three materialized legacy entries, and three
  cloned snapshot entries.
- `LegacyChargebackConversionProbe` makes the borrowed current v1 converter's
  duplicate entry graph observable without requiring a nonexistent owned
  converter signature. Its fixture is predicted to expose one borrowed source
  row and one materialized clone, with different string-buffer addresses.
- `render_ai_chargeback_csv(&origins)` now contains the existing CSV rendering
  body, and the live handler delegates to it. This extraction is intended to
  preserve current release behavior; it only makes the long-identity
  compatibility contract directly testable.

The admin graph test's definitive name is now
`group_f_default_v1_conversion_does_not_duplicate_entry_graph_at_million_row_bound`.
The corrected core-admin selector is:

```bash
cargo nextest run -p sbproxy-core --locked --lib --no-fail-fast -E '
test(=admin::tests::group_f_v1_and_csv_preserve_historical_long_identity_projection) +
test(=admin::tests::group_f_default_v1_conversion_does_not_duplicate_entry_graph_at_million_row_bound)' --no-capture
```

All eleven new contracts are now expected to compile with existing closed
production types and fail or pass for semantic reasons. No new
`PartialPeriodReason` variant is referenced. Counts remain 38/14/2/2 plus the
two named controls, or 58 focused tests total. This is static inspection only:
the controller still owns compilation, execution, formatting, staging, and
commit evidence.

`git diff --check` exits zero for all assigned files. Current whole-file
hashes are:

- `7f6f80605f3b0c6a4de9d435a06e50a5bcf91fb1eb3e52cf475e7d46a8be1971`
  — `crates/sbproxy-ai/src/billing/chargeback.rs`
- `a278d5a8c1a322726558408936b4ac14e1c96f47c1b7bb2fe3c1b378296871ce`
  — `crates/sbproxy-ai/src/billing/unified.rs`
- `0c2e23186856b9bb7adc6d0e9658305a8ee94c224532d83be17e1921ba7da9ae`
  — `crates/sbproxy-ai/src/billing/mod.rs`
- `fc81a6a0888cfa76bb39095a61e0757e2eeed16dd5bd048e69f59ed49825ac69`
  — `crates/sbproxy-core/src/admin.rs`

F3 pagination and production response-byte closure remain explicitly open.

GROUP_F_F1_SYSTEMIC_REVIEW_SEMANTIC_RED_READY

GROUP_F_F1_SYSTEMIC_REVIEW_RED_READY

## Append-only F1 library GREEN handoff

Date: 2026-08-25

Status: **chargeback and snapshot-billing production corrections are statically
ready for the controller gate; admin compatibility remains frozen**

The controller accepted the F1 AI-library semantic RED at 54 selected tests,
45 passed, exactly 9 expected failures, and 2,105 skipped. This pass changes
only `billing/chargeback.rs` and `billing/unified.rs`; `billing/mod.rs` already
exports the F0 public shell and was not changed again. No admin production
change is claimed here.

The nine accepted failures now have these minimal production corrections:

- overlong timestamps are refused with typed `InvalidTimestamp` before parsing
  or finance mutation; accepted timestamps are parsed once and retained in
  their bounded, parseable input representation;
- collision-safe dimension normalization keeps the historical long-source
  digest projection while moving caller literals that occupy a generated
  253--256-byte projection or the dedicated `~v~<sha256>` namespace through a
  domain-separated escape. The mapping is deterministic in either insertion
  order, and a present empty workspace/team remains `Value("")` rather than
  `Missing`;
- retained timestamp extrema use bounded FIFO timestamp metadata plus an
  ordered timestamp index. A normal accepted record parses once, never scans
  or clones the retained row graph, and handles all five frozen extrema shapes;
- refusal bookkeeping returns an atomic first-occurrence bit. Only that first
  occurrence emits a WARN after releasing the finance mutex, with the closed
  typed reason and no raw dimensions or money;
- snapshot billing validates the requested period first, then rejects an
  unsupported schema, any completeness/refusal evidence, explicit poison, and
  missing, malformed, inverted, or zero-eviction watermark evidence with the
  frozen existing `PartialPeriodReason` vocabulary;
- the snapshot biller feeds borrowed v2 rows directly into the shared checked
  aggregator. It creates no full legacy entry vector and no second retained-row
  graph while preserving the original row-validation, arithmetic, grouping,
  sorting, and half-open-period behavior.

Independent read-only static audits report 0 semantic Blockers and 0 semantic
Majors for both the chargeback and unified changes. Their only mechanical
finding, `clone_on_copy` on chrono/error values, was removed. A final scoped
`git diff --check` exits zero. No Cargo, rustc, nextest, rustfmt, Clippy,
staging, commit, fetch, or push command was run by this owner, so compilation,
formatting, runtime GREEN, and the prior 45/45 regression result remain for the
controller to prove.

Current whole-file hashes before the controller gate are:

- `7004adcd43013e383ebb5657d69de913cc628556ad0a19d7a1b1b992cb415693`
  — `crates/sbproxy-ai/src/billing/chargeback.rs`
- `2d4183ba7053569a0fc9af3273fafbb97329ba1bfae85c18a300ada60b8dce72`
  — `crates/sbproxy-ai/src/billing/unified.rs`
- `0c2e23186856b9bb7adc6d0e9658305a8ee94c224532d83be17e1921ba7da9ae`
  — `crates/sbproxy-ai/src/billing/mod.rs`
- `5cf7f0a9c36768974be1cf5902593654cc22304fde3aa6749b1b5d61662306e6`
  — `crates/sbproxy-core/src/admin.rs` (unchanged in this GREEN pass)

The two core-admin tests remain unclaimed while Group B's deliberate compile
seams contaminate that crate. Their later GREEN needs an explicit historical
v1/CSV projection view without a second mutable financial ledger; the bounded
v2 digest key alone does not retain every discarded byte needed to reconstruct
that legacy prefix. F3 pagination and production response-byte closure also
remain explicitly open.

GROUP_F_F1_LIBRARY_GREEN_READY_FOR_CONTROLLER

## Append-only F2 definitive systemic RED package

Date: 2026-08-25

Status: **nine new semantic RED contracts are frozen; no production or guide/example fix was made**

The fresh F1 post-GREEN review reported 2 Blockers and 2 Majors. This F2 pass
adds deterministic contracts for all four findings and removes the two
tautological zero-writer probe designs. It changes only test-gated
instrumentation/tests in `billing/chargeback.rs` and `billing/unified.rs`, plus
this append-only report. It does not change release behavior, Cargo metadata,
the frozen admin implementation/tests, or the guide and runnable example whose
current unsafe primary path is deliberately observed as RED.

### New RED contracts and predicted current failures

The exact nine new test names are:

1. `billing::chargeback::tests::group_f_positive_workspace_cost_absorption_is_transactionally_refused`
2. `billing::chargeback::tests::group_f_positive_team_cost_absorption_is_transactionally_refused`
3. `billing::unified::tests::group_f_bill_refuses_positive_cost_absorption_inside_each_line_item`
4. `billing::unified::tests::group_f_bill_refuses_positive_cost_absorption_in_final_total`
5. `billing::unified::tests::group_f_snapshot_bill_rejects_retention_accounting_contradictions`
6. `billing::unified::tests::group_f_snapshot_bill_rejects_request_rollup_and_cardinality_contradictions`
7. `billing::unified::tests::group_f_snapshot_bill_rejects_retained_timestamp_extrema_contradictions`
8. `billing::unified::tests::group_f_invalid_snapshot_is_refused_before_billing_rows_are_touched_or_cloned`
9. `billing::unified::tests::group_f_primary_guide_and_example_use_snapshot_aware_billing`

Current production is predicted to fail all nine semantically:

- `f64::MAX + 0.5` remains finite and equal to `f64::MAX`, so both tracker
  dimensions currently increment request/token accounting and commit a row
  while losing the positive `$0.50` cost;
- the shared bill aggregator likewise accepts the lost `$0.50` inside a
  provider/model line in either input order and across two exact line items in
  the final total;
- snapshot-aware billing currently accepts every new retention partition,
  rollup/request/cardinality, collapse-count, and retained-extrema
  contradiction, including the binding empty-retention fixture with
  `recorded_entries = 1`, `evicted_entries = 0`, and `complete = true`;
- the representative invalid snapshot reaches both retained billing rows
  instead of being refused before aggregation; and
- `docs/ai-chargeback.md` and the runnable
  `crates/sbproxy-ai/examples/ai_chargeback_billing.rs` still recommend
  `entries_snapshot()` followed by lower-level `generate_bill`.

The monetary fixtures assert independently that the floating-point operation
really is finite absorption. Each tracker refusal also requires the existing
closed `ArithmeticOverflow { scope, field: Cost }` reason, exact financial
inertia, one bounded refusal delta, and sticky incompleteness. The bill tests
require the existing exact `ArithmeticOverflow` field names, so no new public
error shell is requested.

### Snapshot invariant matrix

The required validator is a borrowed, allocation-free pass over the public
snapshot and must run after the already-frozen period/schema/refusal/watermark
precedence but before any bill row, key, line item, or legacy graph is
materialized. Contradictions use the existing typed
`PartialPeriodReason::IncompleteSnapshot`; malformed eviction evidence keeps
the prior `PoisonedEvictionWatermark` precedence.

| Invariant | Production-used seam | Independent control | Mutation killed |
|---|---|---|---|
| `recorded_entries == evicted_entries + retained_len` with checked conversions/addition | `generate_bill_from_snapshot` before `aggregate_bill` | unmodified two-row snapshot bills 2 requests / `$3` | empty complete snapshot claiming one row; recorded lower/higher than retained; valid outside-period watermark with a broken partition |
| `max_entries >= 1` and `retained_len <= max_entries` | same validator | tracker-created limit 4 with two rows | public zero limit; two rows under declared limit 1 |
| checked workspace request sum and checked team request sum each equal `recorded_entries` | borrowed rollup slices | tracker-created workspace/team sums both equal 2 | missing rollups, totals of 1, and `u64::MAX + 2` overflow |
| rollup lengths fit nonzero dimension limits and dimensions are unique | borrowed rollup slices; no set/map allocation required because tracker snapshots are canonically ordered | one canonical workspace row and one canonical team row | zero declared limits; duplicate workspace/team dimensions whose request sums still equal 2 |
| each collapse counter is at most `recorded_entries` | snapshot scalar validation | both tracker-created counters are zero | workspace/team collapse count 3 against 2 accepted rows |
| empty retention has no extrema; nonempty retention has parseable extrema equal to the actual borrowed-row minimum/maximum | one borrowed entry pass before aggregation | out-of-order rows prove exact August 10 / August 20 bounds | missing, inverted, inexact, and extrema-without-row fixtures |
| invalid public accounting is rejected before billing touches source rows | real `generate_bill_from_snapshot` plus positive borrowed-row observation | valid snapshot billing observes exactly one borrowed aggregation per row | changing `recorded_entries` from 2 to 3 must observe zero aggregations and zero row clones |

The prior schema, refusal-count, eviction-watermark, half-open-period,
unsupported-schema, complete/no-eviction, outside-period eviction, and
borrowed-v2 controls remain selected. The new accounting validator must not
reclassify their established typed reasons.

### Mutation-sensitive observation correction

The previous `retained_rows_revisited`, `retained_rows_cloned`, and
`materialized_legacy_entries` fields had no production writers; asserting they
were zero could not fail if an old scan/conversion returned. They are removed.

- Retained-row reparsing remains observed positively at the actual
  `parse_chargeback_timestamp` function. The five-shape full-window test
  requires exactly one total parser call for the incoming row.
- `ChargebackSnapshotEntry` has a test-only manual `Clone` implementation that
  records the language-level clone operation into whichever scoped chargeback
  or snapshot-billing probe is active. Any restored `entry.clone()` or
  `.iter().cloned()` now changes the oracle without relying on a production
  author to update a side counter.
- Snapshot billing requires a positive count equal to the number of borrowed
  source rows at the actual `BillableEntry` iterator and zero real snapshot-row
  clones. A legacy-vector conversion that bypasses the borrowed iterator or
  clones v2 rows therefore fails.

This instrumentation is `cfg(test)` only and preserves release derives and
behavior.

### Executable API/documentation contract

The F2 doc test compiles the actual guide and runnable example into the test
binary with `include_str!`. Both must contain the primary sequence
`tracker.snapshot()` then `generate_bill_from_snapshot(&snapshot, ...)`. The
guide must explicitly label `entries_snapshot()` plus `generate_bill` as
`caller-asserted-complete`, and the runnable primary example may not contain
`tracker.entries_snapshot()`. This is deliberately RED without modifying the
currently unassigned guide/example paths.

### Re-audit of prior F0/F1 findings

| Prior invariant | Current production seam/control | F2 disposition |
|---|---|---|
| invalid/overflow finance rows are atomic and observable | fallible tracker transaction, closed refusal counts, first-reason WARN | retained; F2 adds finite-positive absorption at both rollup scopes |
| accepted timestamps remain bounded and parseable | pre-mutation timestamp admission and extrema index | retained |
| long/hash-shaped and present-empty identities do not alias | domain-separated bounded projection and typed `DimensionKey` | retained |
| full retention updates are independent of retained row count | parser-call oracle, ordered timestamp index, real row-Clone oracle | strengthened; tautological fields removed |
| public schema/refusal/eviction evidence cannot certify a partial bill | snapshot-aware boundary and frozen typed reasons | retained and extended with accounting/cardinality/extrema validation |
| snapshot billing borrows v2 rows | shared borrowed `BillableEntry` iterator | strengthened with positive iterator count and real Clone instrumentation |
| v1/CSV historical long projection and one-graph conversion | two frozen core-admin tests | still deferred until Group B restores core test compilation; not claimed here |
| real v1/v2 admin wire and bounded child stream | two frozen integration tests | retained; not rerun by this RED-only owner |
| pagination and response-byte admission | F3 | still visibly open and not claimed by F2 |

### Definitive selector, counts, and static evidence

The exact controller-owned AI-library selector is:

```bash
cargo nextest run -p sbproxy-ai --locked --lib --no-fail-fast -E '
test(/^billing::chargeback::tests::group_f_/) +
test(=billing::chargeback::tests::usage_sink_invalid_cost_refusal_stays_incomplete_after_a_valid_record) +
test(/^billing::unified::tests::group_f_/) +
test(=billing::unified::tests::retained_slice_bill_remains_a_caller_asserted_complete_lower_level_boundary)' --no-capture
```

Static exact-name counts are 40 chargeback `group_f_` tests plus its named
control, and 21 unified `group_f_` tests plus its named control: **63 unique
AI-library tests**. The predicted current split is the prior 54 GREEN controls
plus exactly nine new semantic failures. The two frozen core-admin and two
real-wire tests remain outside this selector, making **67 focused Group F
tests** across all three targets.

No Cargo, rustc, nextest, rustfmt, Clippy, staging, commit, fetch, push, or file
deletion command was run. `git diff --check` exits zero for all assigned files,
and both `include_str!` targets resolve on disk. Whole-file hashes at freeze are:

- `45960c3d22ddcce8ec9d5771a09747cda68fdc8f1e92b942d69e12ca0d8a38c4`
  — `crates/sbproxy-ai/src/billing/chargeback.rs`
- `977c21fce8f578f80d57cbcb0ee5b62bb539b05069236ffd4603e1395c20b40a`
  — `crates/sbproxy-ai/src/billing/unified.rs`
- `0c2e23186856b9bb7adc6d0e9658305a8ee94c224532d83be17e1921ba7da9ae`
  — `crates/sbproxy-ai/src/billing/mod.rs` (unchanged)
- `5cf7f0a9c36768974be1cf5902593654cc22304fde3aa6749b1b5d61662306e6`
  — `crates/sbproxy-core/src/admin.rs` (unchanged)
- `ba6b5467902ef6e273597a4a774262d036ea4745c9531fc65d82fd99051d4b00`
  — `docs/ai-chargeback.md` (observed, unchanged)
- `ddcb86d5193f381d7fd99dc9198badabcd3e384f804f8b17046aabc5cf77f5c5`
  — `crates/sbproxy-ai/examples/ai_chargeback_billing.rs` (observed, unchanged)

Controller compilation/execution is required to accept the predicted 54/9
semantic RED split. Production, guide, and example fixes are not authorized
by this RED-only handoff.

GROUP_F_F2_SYSTEMIC_RED_READY

### Append-only F2 legacy-materialization oracle correction

The F2 text above says the old unwritten `materialized_legacy_entries` field
was removed. The definitive implementation replaces it with the renamed,
wired `legacy_entries_materialized` counter at the real `legacy_entry`
conversion seam. The named retained-slice control now positively observes
exactly two materializations from `entries_snapshot()`, proving the writer is
live; snapshot-aware billing and pre-aggregation invalid-snapshot refusal both
require zero. Together with the positive borrowed-row count and manual public
row `Clone` instrumentation, this kills restored legacy-vector conversion,
source-row clone, and observation-bypass mutations. Counts and predicted 54/9
split are unchanged.

`git diff --check` remains clean. The superseding Rust hashes are:

- `45d6408852a7d0cd69d5804c99dac8a77368ebd543045e532b686c517e983e75`
  — `crates/sbproxy-ai/src/billing/chargeback.rs`
- `7d773b858f6a9648d069003e66c9b62d508261d2fe2c1df7ec84b5f1683dd431`
  — `crates/sbproxy-ai/src/billing/unified.rs`

GROUP_F_F2_SYSTEMIC_RED_READY

## 2026-08-25 controller F1 library GREEN

The controller reran the exact 54-test AI-library selector after the nine
authorized production fixes. It compiled cleanly, selected 54, passed 54,
failed 0, and skipped 2,105. This restores all 45 prior/control contracts and
turns the nine accepted systemic review REDs green.

A fresh post-GREEN library review remains active. The two core-admin contracts
are still unexecuted because Group B's intentional missing `sbproxy-core` test
seams contaminated that target before selection. Default-v1/CSV production
work, F3 pagination/response-byte admission, mutation proof, commit, gate,
push, PR, and merge remain uncredited.

GROUP_F_F1_LIBRARY_CONTROLLER_GREEN_54_OF_54

### Append-only F1 mutation-oracle closure and final static approval

This final appendix supersedes every older compile-RED, owned-converter, probe,
selector, and hash statement above. The bounded 3-Blocker/3-Major/1-Minor F1
RED batch is frozen as statically compile-plausible semantic RED. A fresh
no-edit static re-review approved it at **0 Blockers / 0 Majors / 0 Minors**.

The final mutation-sensitive refinements are:

- The one hot-path test now exercises five full 512-row retention shapes:
  evicting a non-extreme row, the sole minimum, and the sole maximum, plus an
  incoming row that becomes the new minimum and one that becomes the new
  maximum. Every case requires exact extrema, one total timestamp parser call,
  zero retained-row revisits/clones, and one accepted commit. The parse counter
  is inside `parse_chargeback_timestamp`, not manually adjacent to one caller,
  so eviction or scan reparses are visible. Current behavior is predicted to
  expose 514 parser calls, 512 revisits, and three extrema-string clones in the
  first case.
- The live-refusal contract now installs a real tracing subscriber rather than
  observing refusal bookkeeping. It requires exactly two WARN events from the
  chargeback module with a closed typed `reason`, proves the finance-state lock
  is available during event delivery, and scans every rendered field for the
  sensitive workspace, team, and money fixtures. Current behavior emits zero
  such operational signals and is semantic RED.
- The million-row-bound test calls the actual default-v1 JSON renderer. Its
  scoped production-callsite counters distinguish total and currently-live v2
  source rows, materialized legacy rows/string clones, materialized
  `serde_json::Value` entry rows, and peak simultaneously-live entry rows. The
  route must either consume/move or borrow/stream without exceeding one source
  graph, clone no entry strings, and serialize directly with zero intermediate
  `Value` rows. Current behavior is predicted to expose one source row, one
  legacy clone, one `Value` row, and a peak of three logical entry rows.
- The extracted CSV renderer consumes its origins map, preserving the prior
  progressive-drop lifetime while retaining direct long-identity coverage.

No test was added or removed by those refinements. Definitive static counts
remain 38 chargeback `group_f_` tests plus the named live-invalid-cost control,
14 unified `group_f_` tests plus the named retained-slice control, two admin
tests, and two real-wire tests: **58 focused tests total**. The definitive
admin test names are:

1. `group_f_v1_and_csv_preserve_historical_long_identity_projection`
2. `group_f_default_v1_conversion_does_not_duplicate_entry_graph_at_million_row_bound`

All other expected semantic REDs from the prior appendix remain: accepted
long timestamp corruption, hash-shaped and empty/missing identity collisions,
unsupported or contradictory snapshot evidence, legacy-vector snapshot
billing, and historical v1/CSV long-identity projection. The positive parser,
extrema, exact-finance, complete-window, v2-distinctness, route-schema, and
rendered-payload checks remain independent controls.

Final scoped `git diff --check` exits zero. No Cargo, rustc, nextest, rustfmt,
Clippy, staging, commit, fetch, or push command was run by this owner. Current
whole-file hashes before controller formatting or fixes are:

- `1d7f897c0a819ee7ace365b6f8abb44e86826d0fd9e4f4f5e8bbda11cb9a875d`
  — `crates/sbproxy-ai/src/billing/chargeback.rs`
- `a278d5a8c1a322726558408936b4ac14e1c96f47c1b7bb2fe3c1b378296871ce`
  — `crates/sbproxy-ai/src/billing/unified.rs`
- `0c2e23186856b9bb7adc6d0e9658305a8ee94c224532d83be17e1921ba7da9ae`
  — `crates/sbproxy-ai/src/billing/mod.rs`
- `5cf7f0a9c36768974be1cf5902593654cc22304fde3aa6749b1b5d61662306e6`
  — `crates/sbproxy-core/src/admin.rs`

Controller compilation/execution is still required before any production
GREEN change. F3 pagination and production response-byte closure remain open.

GROUP_F_F1_SYSTEMIC_REVIEW_SEMANTIC_RED_READY

GROUP_F_F1_SYSTEMIC_REVIEW_RED_READY

### Append-only F1 pre-review contract correction

The prior F1 text over-expanded the already frozen closed
`PartialPeriodReason` vocabulary. This correction is definitive: no new reason
variant is authorized. Unsupported snapshot schemas and internally
contradictory refusal evidence require the existing
`PartialPeriodReason::IncompleteSnapshot`; missing, inverted, malformed, or
counter-impossible eviction evidence requires the existing
`PartialPeriodReason::PoisonedEvictionWatermark`. The current compile-RED API
union is therefore only `ChargebackCallsiteProbe`,
`SnapshotBillingCallsiteProbe`, the extracted `render_ai_chargeback_csv`, and
the owned legacy-conversion signature. M1 remains semantic RED after those
shells compile.

The hash-shape collision test also now records the long source and its exact
hash-shaped literal in both insertion orders. It identifies each original by
an independent cost literal and requires its typed workspace, team, provider,
and model representation to remain stable across trackers. A map-dependent
"escape whichever arrived second" fix therefore fails even if it happens to
produce two rows in one ordering.

Counts and selectors remain 38/14/2/2 plus the two named controls, or 58 total.
The corrected whole-file hashes are:

- `f59fd3941e760d42e1008bb73795b846774b848c2e629ee5d052f774f01d5f65`
  — `crates/sbproxy-ai/src/billing/chargeback.rs`
- `63fad78a4747f3ffdc22162b5e78eed27cd45b51636e6842349da1e527eae91a`
  — `crates/sbproxy-ai/src/billing/unified.rs`
- `0c2e23186856b9bb7adc6d0e9658305a8ee94c224532d83be17e1921ba7da9ae`
  — `crates/sbproxy-ai/src/billing/mod.rs`
- `1753715b8fee217359c91f3f3516599ebcab2f7d2f154b2f54e436359b8e7996`
  — `crates/sbproxy-core/src/admin.rs`

Static whitespace checks remain clean. Runtime and compiler results remain
unclaimed.

GROUP_F_F1_SYSTEMIC_REVIEW_RED_READY

### Append-only F1 final chronology correction

The immediately preceding pre-review correction was authored before the
compile-contamination correction but appears after it in this append-only
file. The compile-contamination correction is the definitive current state:
the two AI probes and the admin conversion probe are now defined and wired,
the CSV renderer exists, and the admin conversion remains borrowed with a
semantic clone/graph oracle. There is no missing owned-converter signature and
no intentionally missing test symbol. The renamed core-admin selector and the
four current Rust hashes in that correction are authoritative. Compiler and
runtime results remain unclaimed pending the controller gate.

GROUP_F_F1_SYSTEMIC_REVIEW_SEMANTIC_RED_READY

GROUP_F_F1_SYSTEMIC_REVIEW_RED_READY

### Append-only F1 final precedence correction

The `F1 mutation-oracle closure and final static approval` appendix above was
authored after the chronology text that immediately precedes this correction,
despite its position in this append-only file. It is the definitive F1 state:
static review is approved at 0/0/0; the five-shape hot-path, tracing-subscriber,
actual default-v1 route/JSON-intermediate, and consuming-CSV contracts are
current; its two admin test names and four Rust hashes are authoritative.
Compilation and runtime evidence remain unclaimed pending the controller gate.

GROUP_F_F1_SYSTEMIC_REVIEW_SEMANTIC_RED_READY

GROUP_F_F1_SYSTEMIC_REVIEW_RED_READY

## Append-only F1 library GREEN final precedence

The `F1 library GREEN handoff` section above is later than every RED chronology
section despite its physical position in this append-only file. Its nine
library corrections, four Rust hashes, controller-gate disclaimer, deferred
admin compatibility risk, and open F3 scope are the definitive current Group F
state. A final follow-up static audit of the last timestamp, identity, Copy,
and refusal-map deltas approved them at 0 Blockers / 0 Majors / 0 Minors.

GROUP_F_F1_LIBRARY_GREEN_READY_FOR_CONTROLLER

### Append-only F2 physical-order precedence

The `F2 definitive systemic RED package` above was authored after every F1
section but was inserted beside the earlier repeated F1 GREEN marker. Its nine
new tests, 63-test AI selector, 67-test whole-Group count, invariant matrix,
hashes, and static-only disclaimer are the definitive current Group F state.
This physical-order note does not alter or duplicate any contract.

GROUP_F_F2_SYSTEMIC_RED_READY

### Append-only F2 final oracle precedence

The later `F2 legacy-materialization oracle correction` beside the main F2
package supersedes that package's two Rust hashes and its statement that the
materialization counter was removed. The wired positive/zero oracle and hashes
in that correction are definitive; all other F2 contracts, counts, selector,
and disclaimers remain unchanged.

GROUP_F_F2_SYSTEMIC_RED_READY

## Append-only F2R independent-review closure

Date: 2026-08-25

Status: **the complete 1-Blocker/5-Major verdict is represented by one frozen,
static-only RED package**

This appendix strengthens four of the existing nine F2 semantic RED tests and
adds one passing positive-control test. It makes no production, guide, example,
lockfile, admin, or wire-test correction. The prior 54 controls remain selected.

### Checked arithmetic for forged public counts

`group_f_snapshot_bill_rejects_retention_accounting_contradictions` now carries
two forged snapshots whose workspace and team request rollups match the forged
`recorded_entries`, so no unrelated rollup mismatch can mask the partition bug:

- `evicted_entries = u64::MAX`, retained length 2, and
  `recorded_entries = 1` kills `wrapping_add`, because `MAX + 2` wraps to 1;
- `evicted_entries = recorded_entries = u64::MAX` with retained length 2 kills
  `saturating_add`, because `MAX + 2` saturates to `MAX`.

Both carry a well-formed, strictly pre-period eviction watermark. Each call is
wrapped by the production-used snapshot billing probe and requires zero
borrowed aggregations, zero legacy materializations, zero public row clones,
and typed `PartialPeriod(IncompleteSnapshot)`. Only a checked retained-length
conversion and checked `evicted + retained` addition can satisfy both.

### Real allocation observation

A repository search found no pre-existing global allocator or allocation
counter in `sbproxy-ai`; its crate root also forbids unsafe code. The controller
therefore authorized and added exactly one test-only dev dependency,
`allocation-counter = "0.8.1"`, whose global observer and `measure` API use
thread-local scoped counters without weakening `forbid(unsafe_code)` or
polluting unrelated parallel test threads. This RED owner did not edit Cargo or
the lockfile.

`group_f_invalid_snapshot_is_refused_before_billing_rows_are_touched_or_cloned`
first measures a real heap-owning `String` as a positive control and requires
nonzero object and byte counts. It then measures a closure containing only the
production `generate_bill_from_snapshot` call and assignment of its result to a
stack-owned `Option`. All assertions and formatting occur after measurement.
The invalid snapshot must produce zero total/peak allocation objects and bytes,
zero billing-row observations, and the typed refusal. Current production
accepts it and allocates the bill map, line items, and output strings, so this
remains semantic RED.

### Row limits, uniqueness, and canonical order

`group_f_snapshot_bill_rejects_request_rollup_and_cardinality_contradictions`
now adds all missing independent mutations for both workspace and team slices:

- literal positive limit 1 with two unique, matching-request rows;
- non-adjacent `A, B, A` duplicates with three positive request rows and a
  separately valid `recorded = evicted + retained` partition;
- unique `Z, A` rows whose request sum and declared limit are valid but whose
  order is not the canonical `DimensionKey` order emitted by the tracker.

These supplement, rather than replace, zero limits, count overflows, adjacent
duplicates, request-sum mismatches, impossible collapse counters, and missing
rollups. A borrowed allocation-free validator can enforce both uniqueness and
canonical order in one adjacent comparison only because canonical ordering is
itself mandatory; an adjacent-equality-only validator cannot accept `A,B,A`.

### Positive completeness controls

The new passing
`group_f_legitimate_empty_and_collapsed_overflow_snapshots_are_complete` test
freezes both valid boundary shapes:

- a real empty tracker has zero counts, empty entry/rollup slices, no retained
  extrema, and produces a complete empty bill;
- a real tracker with two-row workspace/team limits records two distinct
  dimensions, folds the second into each typed `Overflow` row, reports one
  collapse per dimension, retains exact request totals, and produces a complete
  two-request `$3` bill.

This prevents the validator from "fixing" RED cases by rejecting all empty,
collapsed, or `Overflow` snapshots.

### Chronological extrema and error precedence

`group_f_snapshot_bill_rejects_retained_timestamp_extrema_contradictions` now
uses two valid RFC3339 offsets whose lexical and chronological order diverge:

- `2026-08-10T00:00:00+14:00` is the chronological minimum despite being
  lexically later;
- `2026-08-09T23:00:00-12:00` is the chronological maximum despite being
  lexically earlier.

The real tracker-produced extrema are a positive complete control; swapping
them into lexical order must be refused. A malformed retained minimum must also
be `IncompleteSnapshot`. Invalid period admission still precedes snapshot
semantics, while explicit poisoned eviction evidence retains its established
`PoisonedEvictionWatermark` precedence over malformed retained extrema.

### Structural, ordered guide/example contract

The documentation test no longer searches the whole files for appendable
tokens. It locates the exact `## Unified billing statements` guide section,
requires its primary block to acquire `tracker.snapshot()` before calling
`generate_bill_from_snapshot`, and prohibits both lower-level calls there. It
requires the only retained-slice sequence, in order, inside the exact
`### Caller-asserted-complete retained slices` secondary section and rejects
either lower-level call before or after the bounded billing section.

For the runnable example it bounds the primary billing block between the
existing `Unified bill for the period` print and the forecasting comment,
requires the safe calls in order inside that block, and prohibits
`entries_snapshot()` plus `generate_bill(` throughout the example. Appending
safe prose or a disconnected safe snippet therefore cannot make the current
unsafe primary path pass.

### F0-F2R invariant-to-mutation re-audit

| Invariant | Production seam and positive control | Mutation/refusal coverage |
|---|---|---|
| finance transaction exactness | checked tracker workspace/team transaction; valid `f64::MAX` alone | integer overflow, non-finite overflow, and finite-positive absorption at both dimensions |
| bill exactness | shared `aggregate_bill`; ordinary multi-line totals | positive absorption within a line in both orders and in final total |
| retained partition | snapshot-aware pre-bill validation; empty and ordinary snapshots | low/high/missing counts, positive/zero limits, checked-add overflow, wrapping and saturation forgeries |
| rollup accounting | canonical tracker rollups; valid typed `Overflow` collapse | missing/mismatched/overflowing request sums, zero/positive-small limits, adjacent/non-adjacent duplicates, noncanonical order, impossible collapse counts |
| retained extrema | real Z and offset timestamp indexes | missing/inverted/inexact/malformed extrema, lexical-order substitution, extrema without rows, fixed period/poison precedence |
| zero-allocation invalid validation | thread-local real allocator positive control | any bill map, key, row, string, set, clone, or other heap object before refusal |
| bounded identities/timestamps | typed/digested identity and accepted timestamp controls | long/hash-shaped collisions, present-empty vs missing, overlong timestamp corruption |
| hot-path row independence | actual parser, materializer, borrowed iterator, and manual Clone observation | retained reparse/clone and v2-to-v1 materialization restoration |
| refusal observability | real tracing subscriber and closed reason counts | silence, flooding, sensitive fields, under-lock emission, contradictory refusal snapshots |
| primary billing guidance | structurally bounded guide/example sections | unsafe primary slice billing and appended-safe-text bypass |
| v1/CSV compatibility | two frozen core-admin tests | still deferred behind Group B compile ownership; not claimed |
| response pagination/bytes | F3 | still open and not claimed |

### Definitive counts, selector, and hashes

The exact AI-library selector remains:

```bash
cargo nextest run -p sbproxy-ai --locked --lib --no-fail-fast -E '
test(/^billing::chargeback::tests::group_f_/) +
test(=billing::chargeback::tests::usage_sink_invalid_cost_refusal_stays_incomplete_after_a_valid_record) +
test(/^billing::unified::tests::group_f_/) +
test(=billing::unified::tests::retained_slice_bill_remains_a_caller_asserted_complete_lower_level_boundary)' --no-capture
```

Static counts are now 40 chargeback `group_f_` tests plus its named control and
22 unified `group_f_` tests plus its named control: **64 unique AI-library
tests**. The honest predicted current split is **55 pass / exactly 9 semantic
failures**: the prior 54 controls, the new empty/collapsed positive control, and
the same nine strengthened F2 RED names. The two frozen core-admin and two
real-wire tests make **68 focused Group F tests** across all targets.

No Cargo, rustc, nextest, rustfmt, Clippy, staging, commit, fetch, push, or file
deletion command was run by this owner. `git diff --check` exits zero for the
assigned files. Whole-file hashes at F2R freeze are:

- `45d6408852a7d0cd69d5804c99dac8a77368ebd543045e532b686c517e983e75`
  — `crates/sbproxy-ai/src/billing/chargeback.rs` (unchanged in F2R)
- `4ac89798cc952495c3eb621d4bfcc21aee7ad51bfa499bc50a3d36e97838423e`
  — `crates/sbproxy-ai/src/billing/unified.rs`
- `0c2e23186856b9bb7adc6d0e9658305a8ee94c224532d83be17e1921ba7da9ae`
  — `crates/sbproxy-ai/src/billing/mod.rs` (unchanged)
- `aaa5d400d5ba96627a3dfe8242942399e2adc7849c268fa79cbff3f251367d8b`
  — `crates/sbproxy-ai/Cargo.toml` (controller-owned allocator dependency)
- `ba6b5467902ef6e273597a4a774262d036ea4745c9531fc65d82fd99051d4b00`
  — `docs/ai-chargeback.md` (observed, unchanged)
- `ddcb86d5193f381d7fd99dc9198badabcd3e384f804f8b17046aabc5cf77f5c5`
  — `crates/sbproxy-ai/examples/ai_chargeback_billing.rs` (observed, unchanged)

Controller compilation/execution must confirm the predicted 55/9 semantic RED
split. Production, guide/example, admin, and F3 fixes remain unclaimed.

GROUP_F_F2R_SYSTEMIC_RED_READY

### Append-only F2R must-use cleanup

The allocator positive control now explicitly discards `black_box`'s borrowed
return value, avoiding a possible must-use warning without changing the
measured allocation. The definitive `billing/unified.rs` hash is
`1549777364ce2d6215e15de2a37a0c478a8badbb87148069770f98006944c705`.
All counts, predictions, and contracts above remain unchanged.

GROUP_F_F2R_SYSTEMIC_RED_READY
