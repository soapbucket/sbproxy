# AI Group B round-4 RED closure report

## Scope and method

This batch adds test-only RED coverage for the two remaining Group B Blockers and the seven Major/one Minor findings from `ai-group-b-r3-independent-review.md`. It changes no production code, Cargo metadata, generated/proto/docs/dashboard files, staging area, or commits. No Cargo, Rust binary, rustfmt, fetch, or push command was run; verification here is static only.

Owned files in this round:

- `crates/sbproxy-classifier/src/admission.rs` (test module only)
- `crates/sbproxy-classifier/src/health.rs` (test module only)
- `crates/sbproxy-classifier/src/grpc.rs` (test module only)
- `crates/sbproxy-classifier/src/tcp.rs` (test module only)
- `crates/sbproxy-core/src/classifier_hooks.rs` (test module only; one prior narrow test renamed)
- this report

The batch adds 15 test functions. Together with the renamed, pre-existing N-M3 control and the existing omitted-tenant wire control, the intended focused selection contains 17 tests. One of the 15 is an isolated child fixture that is a no-op unless its private environment marker is set by its parent privacy test.

## Provisional resource contract

The gRPC literals are one provisional 16 MiB non-model ingress envelope, not three unrelated guesses:

- at most 64 live connections, reserving the other 12 MiB (about 192 KiB per connection) for H2 state, task/stack, flow-control, and parser overhead;
- at most four concurrently retained decoded request bodies;
- at most 1 MiB of request text per unary call, hence a 4 MiB decoded-body pool.

These values must be measured against the chosen H2 implementation before they become operator documentation. The outer owner must enforce both connection memory and body/stream memory; a count-only handler queue is not equivalent. TCP retains its already-selected independent 16 MiB frame pool (four 4 MiB frames).

The registry contract exercised here is 64 resident tenants, 64 enabled classifier patterns in aggregate per tenant, 64 supplied normalization rules in aggregate per tenant, and 256 KiB total classifier-regex plus all supplied normalization-pattern/replacement source bytes per tenant. Disabled rules remain persistent configured input for count/source/config ceilings, but only enabled rules consume compiled-program reservation. The exact-byte control uses cheap bounded regexes; the plus-one cases carry a deliberately invalid final regex so a warning proves compilation happened when it should have been refused before compilation. The process still needs a weighted compiled-regex reservation in addition to these source-shape ceilings.

## Current-tree intended signature

This is a design-time RED signature, not claimed execution evidence.

Expected PASS on the current tree (5):

- `admission::tests::timed_out_blocking_worker_retains_running_lease_until_worker_exit`
- `admission::tests::worker_error_and_panic_child` (standalone, without its private marker)
- `tcp::tests::public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover`
- `tcp::tests::omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp`
- `classifier_hooks::tests::quality_hook_shares_pre_rpc_prompt_storage_across_candidates`

Expected FAIL on the current tree (12):

- `admission::tests::worker_failures_use_fixed_wire_status_and_never_log_panic_payloads`
- `health::tests::http_terminal_outcome_matrix_records_exact_attempt_and_error_deltas`
- `grpc::tests::real_tonic_terminal_outcome_matrix_records_exact_deltas`
- `grpc::tests::cancelling_real_queued_quality_rpc_restores_queue_gauge_and_capacity`
- `grpc::tests::real_tonic_unary_bodies_obey_four_mib_retained_budget_before_queueing`
- `grpc::tests::real_tonic_listener_caps_sixty_four_idle_connections_and_recovers`
- `grpc::tests::real_tonic_stream_uses_only_first_message_rules_and_ignores_later_rules`
- `grpc::tests::real_version_and_model_info_share_complete_mixed_model_inventory`
- `tcp::tests::authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery`
- `tcp::tests::admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation`
- `tcp::tests::public_and_admin_tcp_terminal_matrix_records_exact_deltas`
- `classifier_hooks::tests::quality_hook_bounds_real_downstream_protobuf_prompt_high_water`

The three exact-delta metric matrices should be run as exact nextest selections (one test process apiece), which isolates the process-global Prometheus registry while still tolerating prepopulated children through before/after equality. Do not run the privacy child with its marker by hand; its parent owns the marker and captured output.

## What each boundary proves

### Registry Blocker

`authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery` starts real authenticated admin and unauthenticated public MessagePack listeners with one registry. It registers the exact 64-tenant limit, attempts tenant 65 twice under different ids, snapshots the count after each refusal, checks bounded list output, deletes one tenant, registers the refused tenant, and classifies through the real public listener. This makes tenant-count refusal atomic and proves capacity recovery rather than merely checking an error string.

`admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation` uses the real authenticated admin wire boundary. It accepts exactly 64 aggregate simple classifier patterns. Its 65th pattern is invalid, so the plus-one must be rejected with no compiler warning and no insert. It separately accepts exactly 64 enabled normalization rules totaling 256 KiB of pattern/replacement bytes, then adds one replacement byte while keeping 64 rules; that request also contains an invalid regex and must be refused before compilation, without a warning or partial insert. It does not compile thousands of large expressions.

The existing tree has no public heuristic CPU executor/permit and no pagination request/cursor contract. The bounded list assertion can force a safe response cap, but full pagination and public classify deadline/recovery require the staged seams below.

### gRPC resource Blocker: accepted and insufficient boundaries

The gRPC tests use a real loopback Tonic listener and the current generated services/production handlers. They are useful RED sub-invariants:

- decoded unary retention is held behind real `Quality` calls on eight independently established channels and must stop at four 1 MiB request bodies before CPU queueing; therefore a four-stream limit scoped to one connection cannot satisfy the process-wide assertion. The fixture waits up to a bounded deadline for four actual early terminal refusals rather than sampling task state after a fixed sleep;
- 64 connections are split between stalled prefaces and established idle H2 sessions; connection 65 is refused, both idle classes expire, and expiry—not client drop—restores admission. The close probe drains a bounded number of H2 control/data frames through GOAWAY until EOF/reset or a single deadline, so GOAWAY itself cannot be mistaken for a still-live socket;
- real unary and streaming calls exercise generated codecs and method dispatch.

They do **not** close the Blocker. `main.rs` inlines `Server::builder()` and exposes neither its incoming-stream owner nor its startup assembly to tests. The test listener in `grpc.rs` therefore cannot detect a mutation in main, and the decoded-body test can be satisfied by a handler-only semaphore after protobuf already owns the body. Credit it only as a bounded post-decode/queued-retention requirement.

Required staged production seam: `grpc::serve_on(listener, state, GrpcServerLimits)`, constructed by startup and used by main and tests. Its incoming IO wrapper must own the whole-process connection permit, reset bounded handshake/idle timers only on actual read/write progress, and delegate Tonic `Connected` metadata. A shared outer Tower limiter with load shedding must run before generated protobuf decoding; generated services also need a finite decoding-message ceiling (including protobuf envelope overhead above the 1 MiB text field), finite H2 streams/flow-control, request timeout, and maximum connection age. A future exact real-startup test must observe that owner while holding 32 stalled handshakes plus 32 established idle connections, refuse 65 before H2 service dispatch, exercise both drop and idle-expiry recovery, then retain four maximum requests from multiple real connections while refusing request five before handler admission/decode. Removing the incoming permit, either deadline, the global limiter/stream ceiling, or moving ownership inside a handler must fail independently.

### Systemic OBS-1

The HTTP, TCP, and gRPC matrices use real listeners and exact before/after deltas collected before any assertions can mask later cases.

- HTTP: `/healthz` success, 404, unauthenticated `/tenants`, and a truncated header.
- public/admin TCP: successful version, partial length prefix, admin oversized frame, and admin invalid registration, including zero delta on the wrong public sibling.
- gRPC: classify size, missing classifier, unimplemented compress, successful version, and quality size.

The desired result is one attempt and one typed non-success terminal outcome. Current early returns, missing writers, and `tcp` hardcoding make these RED. Closed reasons needed by the implementation include `not_found`, `model_not_found`, and `unimplemented`; mapping those to `unknown` does not satisfy the exact children.

### Lifecycle, privacy, model, and wire findings

- Queue cancellation: a real queued `Quality` RPC is aborted, the exact gauge must return to its baseline, the running holder is released, and a real recovery call succeeds. The test repairs the deliberately leaked global test gauge only after observing it so later tests are not poisoned.
- Post-timeout worker: real `Admission::run_blocking` work stays behind a condvar after the caller deadline; replacement work is refused and never starts until the original worker exits, then capacity recovers. The production ONNX handlers have no injectable blocking executor, so the future handler-level version should use the executor seam described below.
- Worker privacy: an isolated child captures the actual test-binary default panic-hook stderr plus wire-status marker output. Synthetic error and panic sentinels must be absent everywhere, both public statuses must be the fixed `classifier inference failed`, and capacity must recover. `catch_unwind`/JoinError handling alone cannot suppress the default panic hook.
- Model truth: real Tonic `ModelInfo("")` pins the default classifier, an embedder-only catalog must not silently use its default embedder for that empty classifier query, and `Version` must return the sorted complete classifier-plus-embedder inventory. Duplicate ids, cross-kind collisions, and invalid defaults remain startup-seam tests.
- Wire contract: a real bidi stream proves rules from later `SafetyToken` messages are ignored and the first-message rules remain active. The current `INVALID_ARGUMENT` behavior is contract-inverted and RED.
- N-M3: the renamed pointer test remains a passing proof that the already-accepted pre-RPC candidate clones were eliminated. The new real local Tonic service holds the actual decoded `ClassifyRequest.text` strings from two independently constructed stock hooks. Their combined high-water must be at most four 256 KiB prompt copies while all 16 candidates are eventually evaluated and each caller's input order is restored. This catches a four-call semaphore allocated per hook/origin; the byte/concurrency owner must be process-wide and acquired before `ClassifierClient::classify` creates its protobuf `String`.

## Required staged seams

These assertions cannot be made mutation-sensitive and compile-valid against the current production API without inventing parallel production behavior:

1. `grpc::serve_on` plus validated `GrpcServerLimits`, described above, for main-callsite connection, handshake/idle, connection age, stream/flow-control, decode ceiling, and pre-decode request ownership.
2. Opaque `FrameBudget` created exactly once by public/admin listener assembly and passed as a non-constructible clone to both TCP listeners. The current cross-listener test passes because its fixture explicitly clones one raw semaphore; it cannot catch `main.rs` giving admin a fresh owner.
3. Validated `TenantSpec`, `TenantRegistryLimits`, and `TenantRegistryBudget` with conservative per-program compiled-state reservations, a bounded blocking compile executor, a public classification executor/deadline, and deterministic typed list pagination (`page_size` plus cursor and response-byte cap). A replaced/deleted tenant's reservation must live until its final reader `Arc` drops. The current wire has no cursor field.
4. Injectable production `BlockingWorkExecutor` used by all four ONNX callers (`classify`, `embed`, embedding `model_info`, `quality`) so the condvar timeout and error/panic cases can enter an actual handler without synthetic models.
5. Validated, bounded `ModelCatalog` manifest owned before model loading and before listener bind, plus shipped-binary or `run_with_cli` startup assembly callable from tests. It must reject duplicate same-kind ids, cross-kind collisions, empty/oversized/excessive ids, and missing/wrong-kind defaults before readiness; resolution, `ModelInfo`, and sorted `Version` inventory must all consume that catalog.
6. A wire-contract source-of-truth check spanning generated proto comments, Rust protocol docs, and behavior. This RED batch can prove behavior only; it was forbidden to edit proto/docs.

## Representative mutation kills

- Move the blocking lease outside `spawn_blocking`: the post-timeout replacement starts/refuses incorrectly.
- Remove the queued-gauge RAII `Drop`, or decrement only after a successful semaphore wait: the canceled real RPC leaves `quality` above baseline.
- Restore raw `format!("...{e}")` for worker errors, raw JoinError formatting, or leave the default arbitrary-payload panic hook active: the isolated privacy capture finds a sentinel.
- Remove tenant reservation, validate tenant count after insertion, count 64 patterns per label instead of per tenant, count disabled normalization rules, omit replacement bytes, or compile before shape validation: exact/plus-one/count/warning checks fail.
- Hardcode public TCP for admin decode/register errors, omit an attempt, double-finalize, or map a typed cause to its sibling: exact OBS tuples fail.
- Restore `join_all` or bypass a four-call/weighted fanout permit: the real server observes more than four decoded prompt copies/bytes.
- Return only `models.keys()` from `Version`: the mixed inventory test fails.
- Reject or apply later stream rules: the ignored-later-rule compatibility sequence fails.
- Future seams: fresh admin frame budget, missing gRPC incoming permit, missing handshake/idle expiry, handler-only body accounting, duplicate/colliding model overwrite, or invalid default acceptance must each have a dedicated exact startup test.

## Privacy and logging safety

All payloads are synthetic fixed sentinels; no prompt, tenant credential, filesystem secret, or model content is logged. The admin token is a fixed test literal on loopback. Assertions capture and inspect child stdout/stderr without echoing it on success. Failure messages report counts, labels, and bounded synthetic identifiers only. The panic test intentionally demonstrates the current release-path leak; the fix must install a bounded sidecar panic-reporting policy before any untrusted worker payload can reach the default hook.

## Static verification

- `git diff --check` passed for the five owned Rust files before this report was added.
- Test selectors and ownership were enumerated with `rg`.
- No compile/test result is claimed; the controller must run the single Cargo/nextest gate after GREEN implementation.

## Round-4 independent-review corrections (authoritative append)

The independent Round-4 review rejected the first package with nine Major and
one Minor test-quality findings.  This append supersedes the earlier test
count, current-tree signature, registry accounting description, OBS sample
matrix, model fixture, and staged-boundary claims wherever they conflict.  The
earlier text remains as audit history; it must not be used as the acceptance
claim for the corrected package.

### Frozen ownership and exact selection

The corrected package still owns exactly six paths and only test-module bytes
inside the five Rust sources:

- `crates/sbproxy-classifier/src/admission.rs`
- `crates/sbproxy-classifier/src/health.rs`
- `crates/sbproxy-classifier/src/grpc.rs`
- `crates/sbproxy-classifier/src/tcp.rs`
- `crates/sbproxy-core/src/classifier_hooks.rs`
- `.superpowers/sdd/2026-08-23-wor2661-agy-handoff/ai-group-b-r4-red-report.md`

The focused corrected selection is 19 tests (18 active parent/control tests
plus one isolated child fixture):

1. `admission::tests::timed_out_blocking_worker_retains_running_lease_until_worker_exit`
2. `admission::tests::worker_error_and_panic_child`
3. `admission::tests::worker_failures_use_fixed_wire_status_and_never_log_panic_payloads`
4. `health::tests::http_terminal_outcome_matrix_is_exhaustive_and_exactly_once`
5. `grpc::tests::real_tonic_terminal_outcome_matrix_is_exhaustive_and_exactly_once`
6. `grpc::tests::cancelling_real_queued_quality_rpc_restores_queue_gauge_and_capacity`
7. `grpc::tests::real_tonic_admission_deadlines_finalize_every_leased_method_once`
8. `grpc::tests::real_tonic_unary_bodies_obey_four_mib_retained_budget_before_queueing`
9. `grpc::tests::production_tonic_listener_owns_exact_connection_permits_and_deadline_recovery`
10. `grpc::tests::real_tonic_stream_uses_only_first_message_rules_and_ignores_later_rules`
11. `grpc::tests::validated_model_catalog_owns_inventory_defaults_and_prebind_rejection`
12. `tcp::tests::public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover`
13. `tcp::tests::authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery`
14. `tcp::tests::admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation`
15. `tcp::tests::public_classification_timeout_retains_bounded_worker_lease_and_recovers`
16. `tcp::tests::public_and_admin_tcp_terminal_matrix_is_exhaustive_and_exactly_once`
17. `tcp::tests::omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp`
18. `classifier_hooks::tests::quality_hook_shares_pre_rpc_prompt_storage_across_candidates`
19. `classifier_hooks::tests::quality_hook_bounds_real_downstream_protobuf_prompt_high_water`

Exact future selector (run only after a fresh reviewer accepts the compile-RED
package and GREEN supplies the production seams):

```text
cargo nextest run -p sbproxy-classifier -p sbproxy-core -E 'test(/(timed_out_blocking_worker_retains_running_lease_until_worker_exit|worker_error_and_panic_child|worker_failures_use_fixed_wire_status_and_never_log_panic_payloads|http_terminal_outcome_matrix_is_exhaustive_and_exactly_once|real_tonic_terminal_outcome_matrix_is_exhaustive_and_exactly_once|cancelling_real_queued_quality_rpc_restores_queue_gauge_and_capacity|real_tonic_admission_deadlines_finalize_every_leased_method_once|real_tonic_unary_bodies_obey_four_mib_retained_budget_before_queueing|production_tonic_listener_owns_exact_connection_permits_and_deadline_recovery|real_tonic_stream_uses_only_first_message_rules_and_ignores_later_rules|validated_model_catalog_owns_inventory_defaults_and_prebind_rejection|public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover|authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery|admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation|public_classification_timeout_retains_bounded_worker_lease_and_recovers|public_and_admin_tcp_terminal_matrix_is_exhaustive_and_exactly_once|omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp|quality_hook_shares_pre_rpc_prompt_storage_across_candidates|quality_hook_bounds_real_downstream_protobuf_prompt_high_water)/)'
```

### Exact current-tree RED signature

The corrected package intentionally fails at compile time on absent production
owners.  Therefore the honest current-tree result is **compile-RED; zero tests
execute**.  It is not a claim that 15 independent runtime failures can be
observed before those types exist.  The first unresolved production contracts
are the typed outcome vocabulary/probe, `grpc::serve_on` and
`GrpcServerLimits`, startup/runtime panic assembly, bounded blocking executor,
validated `ModelCatalog`, opaque paired `TcpListenerAssembly`, bounded tenant
registry types/compiler probe, and process-wide `QualityFanoutProbe` at the
real protobuf ownership point.

After only compile-shape shells are supplied (with no behavior change), the
intended semantic signature is:

- PASS controls (4): post-timeout direct admission lease, no-op privacy child
  without its marker, omitted/empty TCP tenant warning control, and the narrow
  pre-RPC shared-prompt control.
- FAIL active closure tests (15): privacy parent, exhaustive HTTP, exhaustive
  gRPC, cancellation/queue replacement, all-method admission deadlines,
  pre-decode body pressure, production connection owner, later-rule/tenant
  compatibility, catalog truth/prebind rejection, opaque frame owner, tenant
  atomicity, registry aggregate budgets, public CPU worker lifecycle,
  exhaustive TCP, and weighted downstream prompt ownership.

The child fixture is selected for name/compile coverage but is intentionally a
no-op unless the privacy parent supplies its private marker.  No Cargo, Rust
binary, or rustfmt command was run to manufacture a result before review.

### OBS-1: exhaustive executable coverage and structural owner

All three matrices now use a serialized `OutcomeProbe` snapshot of the whole
closed family.  A success requires exactly one attempt, exactly one completion,
and zero delta for every sibling error.  A non-success requires exactly one
attempt, zero completion, exactly one typed terminal, and zero for every
sibling.  Batch pressure asserts the exact terminal multiset.  Prepopulated
global children and `>= 1` cannot satisfy any assertion.

- HTTP covers slot saturation, empty request, malformed request line, header
  cap, truncated post-route headers, read I/O, whole-connection deadline,
  `/healthz`, both `/readyz` states, `/metrics`, authenticated and
  unauthenticated `/tenants`, 404, handler failure, encode 500, write failure,
  and flush failure.  A valid `/healthz` start line immediately updates the
  guard, so all later header cap/truncation/deadline outcomes are attributed to
  `cmd=healthz`, not `cmd=decode`.
- public and admin TCP each cover clean zero-byte EOF (no frame attempt),
  partial length, header and payload deadlines, length/payload I/O, oversize,
  malformed MessagePack, connection saturation, and actual transport labels.
  Real frames cover every public command and every admin command, success,
  missing fields, unknown tenant/delete, invalid config, unknown command,
  public/admin authorization, missing/invalid/scoped credentials, handler
  failure, serialization failure, write failure, and flush failure.  The
  cross-listener frame-pressure test adds exact byte-admission terminals on
  both modes.
- real generated Tonic clients cover Classify, Embed, Compress, ModelInfo,
  Version, Quality, and StreamSafety.  The matrix includes successes, all
  request/item/aggregate/rule limits, missing models, worker failures,
  unimplemented, inbound stream error, clean stream end, client cancellation,
  unary/stream body write failures, and terminal delivery.  Separate real
  tests add every leased method's admission deadline, queue full, queued-call
  cancellation, outer request refusal, and connection refusal.  Worker and I/O
  fault controls are `cfg(test)`, one-shot/current-call scoped, are consumed at
  the actual production branch, and must report exactly-once consumption; they
  are not alternate handlers or release runtime options.

The required GREEN owner is a `#[must_use]` typed outcome guard installed in
the production listener/layer before the first identifiable attempt.  Handler
code sets a typed cause; only the boundary guard finalizes after successful
flush/body trailers or on cancellation/drop.  Removing, doubling, moving, or
mislabeling any finalizer changes a whole-family snapshot and fails.

### Registry accounting correction and atomicity

The earlier text incorrectly described disabled normalization rules as outside
all budgets.  The corrected contract is:

- all supplied classifier patterns and normalization rules, enabled or
  disabled, count toward configured-count, aggregate source-byte, and complete
  config-byte ceilings because their source remains persistent input;
- every classifier pattern reserves bounded compiled-program work;
- only **enabled** normalization rules reserve/compile a normalization program;
- a disabled invalid normalization regex must neither compile nor warn, but it
  cannot bypass count/source/config limits.

The real admin test distributes 64 classifier patterns across eight labels and
refuses an invalid 65th before compilation.  It accepts 64 normalization rules
with half enabled valid programs and half disabled invalid programs, proves
only the enabled half reached the bounded compiler, and refuses a disabled
65th before compilation.  A mixed classifier/normalizer fixture reaches
exactly 256 KiB of aggregate pattern/replacement source with cheap compiled
patterns and persistent filler in a disabled replacement; the extra byte is
refused before compile.  A separate exact/plus-one complete-config-byte case
uses disabled rule metadata, so source and config accounting cannot be
conflated.  Thread-safe `TenantCompileProbe` sentinels sit on the production
bounded `spawn_blocking` compiler branch and fail the test if validation tries
compile/insert/rollback.  That same probe counts warning events inside the
production compiler task, rather than relying on a thread-local tracing
subscriber that cannot observe `spawn_blocking`; the exact disabled-invalid
control and every preflight refusal require a zero warning delta.

At the 64-tenant limit the test snapshots the complete sorted original key set
and an `Arc` identity for every tenant.  Both refused ids remain absent, the
complete set is unchanged, no original identity is replaced, and compiler
start count is unchanged.  After deliberate deletion, the deleted tenant's
deliberately held reader `Arc` keeps its persistent reservation live, so one
more recovery attempt is refused before compilation.  Only after that final
reader drops may recovery compile/insert; every unaffected identity stays
stable and the recovered tenant classifies through the public listener.  The public CPU test separately
holds the actual heuristic worker beyond caller timeout, proves replacement
work does not start, and recovers only after worker exit.

### Production connection/body owner

`spawn_real_tonic` no longer builds a test-local `Server`.  It binds a socket
then invokes the deliberately absent production `grpc::serve_on`, the same
function main must call.  `GrpcServerLimits::from_process_memory_budget(16
MiB)` pins the provisional 64-connection, four-global-request, and 4 MiB
decoded-retention values to one budget and also requires a decode ceiling above
the 1 MiB text maximum for protobuf envelope overhead.

The fast connection proof uses a configurable limit of four.  Two stalled H2
handshakes and two established idle H2 sessions each cross an observable
production permit barrier before plus-one.  Kernel `connect` completion is
never used as acceptance evidence.  A production refusal counter and exact
typed terminal prove plus-one; bounded frame draining tolerates GOAWAY before
EOF/reset.  Independent handshake and idle-expiry counters reach two each,
active permits reach zero, then a new H2 session recovers.  A `cfg(test)`
paused clock advances only after the exact-limit barrier, so slow CI cannot
expire an early connection during setup and no fixed sleep is used.

Eight maximum unary calls use eight independent channels.  The ingress probe
requires four outer leases before decode, zero decodes without a lease, four
handler entries, and four refusals that never enter the handler.  It also
asserts the useful post-decode/queued-retention sub-invariant of at most 4 MiB.
The decoded-byte assertion alone remains insufficient for the Blocker; the
lease-before-decode event ordering is what kills moving the owner into the
handler.

### Queue and non-cancellable worker lifecycle

The queue-cancellation test now holds the running slot with a real Classify
handler worker.  A real queued Quality call owns the sole queue permit and
gauge lease, is cancelled, and both the exact gauge and actual available permit
return.  A replacement then obtains that permit while the running slot remains
held and is observably still queued.  A third call receives the exact queue-full
terminal.  Only after releasing the running worker do the holder and
replacement complete.  There is no compensating metric write in the test.

The all-method deadline test holds a real worker beyond the caller deadline and
drives Classify, Embed, embedding ModelInfo, Quality, and StreamSafety through
the shared admission boundary.  Each has one exact deadline terminal while the
worker retains capacity.  The direct `Admission::run_blocking` condvar control
remains, with an unwind-safe RAII release guard, to kill moving the lease
outside `spawn_blocking` without leaving a parked OS thread.

### Weighted quality fanout

The accepted N-M3 proof remains narrow: candidate preparation borrows one
pre-RPC prompt allocation.  The newly discovered downstream high-water is a
separate requirement and does not invalidate that proof.

The real local downstream now receives unequal 768 KiB and 384 KiB prompts
from independently built hooks.  A one-MiB process byte owner plus a four-call
secondary ceiling must keep both leased and protobuf-owned high-water within
one MiB, report one owner id across hooks, evaluate all candidates, and restore
each request's input order.  An input one byte over the one-MiB request maximum
must produce zero protobuf owners and zero dials.  `QualityFanoutProbe` attaches
to the production leased-request constructor at the real
`ClassifyRequest.text` allocation and proves lease-before-allocation-before-dial
and exactly-once release.  Global count-only four, per-hook owners,
allocate-all-before-gate, permit-after-allocation, and `join_all` mutations all
fail independently.

### Model catalog and privacy corrections

The invalid tiny-classifier-as-embedder fixture is removed.  Model truth first
uses a validated descriptor/metadata catalog before load or bind: classifier
and embedder kinds, classifier labels, embedder dimensions, default
classifier/default embedder, and one sorted inventory are checked without
running a fake inference shape.  Real Tonic `Version` and `ModelInfo` then
consume genuine mixed and embedder-only fixtures loaded through that same
catalog owner.  Duplicate same-kind
ids, cross-kind collision, absent classifier default, and wrong-kind default
enter the production startup preparation seam; a startup probe requires zero
model loads and zero listener binds for every invalid manifest.  Empty
`ModelInfo` selects only the default classifier; embedder-only does not silently
become the classifier default.

The privacy child now invokes the production panic-policy installer, validated
catalog runtime assembly, shared blocking executor, production `grpc::serve_on`,
and generated Quality client.  One-shot error and panic sentinels are injected
at the actual blocking-executor branch and their consumption is asserted.
Both public statuses stay fixed, the real permit recovers, and marker/stdout/
stderr omit both sentinels.  The parent continuously drains stdout/stderr pipes
while retaining at most 16 KiB from each, polls a ten-second deadline, and
kills/reaps on timeout.  It also fails on capture overflow.  `catch_unwind` alone is not
credited because the process panic hook runs before join observation.

### Wire compatibility and bounded waits

The real bidi compatibility test requires first-message rules to govern the
whole stream, later rule fields to be ignored, the later-only match to remain
safe, and the first-rule match to block.  A production observation also proves
the first tenant is captured and later tenant/rule fields are not applied.  The
existing real public TCP control keeps omitted/empty tenant refusal pinned.

Every external Tonic connect, RPC, stream message/EOF, raw H2 read/write, task
join, and server cleanup in this batch has a finite deadline.  The connection
test drains bounded control frames through EOF/reset.  The privacy process has
bounded capture, kill, and reap.  No pressure assertion depends on a fixed
sleep; exact permit/probe barriers establish readiness.

### Static mutation audit

The corrected assertions kill these representative mutations:

- sampled/leaf OBS writers, omitted or doubled finalization, success with a
  sibling error, wrong stage/reason, hard-coded public TCP, completion before
  flush, cancellation treated as success, or guard creation after route/model
  checks;
- insert/compile/rollback before tenant preflight, count replacement as a new
  identity, omit either refused id, count patterns per label, ignore disabled
  rules in configured/source/config bytes, compile disabled rules, omit
  replacement/name bytes, or reserve normalization programs for disabled
  rules;
- test-local Tonic builder, missing/fresh connection owner, kernel-connect
  acceptance, missing handshake/idle expiry, handler-only request limiter,
  decode before outer lease, per-connection-only stream cap, or a count-only
  post-decode queue;
- queue gauge decrement after await only, cancelled queue permit leak,
  replacement bypassing the queue, or worker lease outside `spawn_blocking`;
- global fanout count-only four, per-hook byte owner, `join_all`, oversized
  dial, allocation before lease, lease after allocation, or release before RPC
  completion;
- classifier-only Version inventory, embedder selected by empty ModelInfo,
  duplicate/collision overwrite, missing/wrong-kind default accepted, or load/
  bind before validation;
- raw worker/JoinError formatting, default arbitrary-payload panic hook, direct
  Admission-only privacy fixture, or a fault control that bypasses the real
  executor branch;
- rejecting/applying later stream rules, ignoring the first tenant, or
  attributing malformed post-route `/healthz` headers to decode.

### Corrected non-claims and review gate

- A decoded-body semaphore by itself does not close pre-decode retention.
- A test-created raw semaphore does not prove cross-listener frame ownership.
- Input regex bytes do not estimate compiled heap; conservative per-program
  reservations remain mandatory.
- Descriptor metadata proves catalog identity/capability truth, not inference
  tensor correctness.
- A downstream server count without allocation/lease events does not prove
  pre-allocation ownership.
- Test fault controls provide no release configuration surface and cannot
  substitute an alternate handler.

This is a compile/semantic RED submission for fresh static review.  The
controller should not run Cargo until that reviewer accepts the package.  File
hashes and the report hash are supplied from the final frozen tree so the
self-referential report hash is not embedded here.

### Final static-tightening addendum

The final audit made five further robustness assertions without changing the
19-test selection or the six-path ownership boundary:

- the registry's zero-warning proof now reads a counter on the thread-safe
  production `TenantCompileProbe`, including a whole-test baseline/final
  equality.  It does not rely on a thread-local tracing subscriber to observe
  the bounded `spawn_blocking` compiler.  Exact source/config fixture padding
  also uses checked subtraction so an unrelated limit change fails explicitly;
- the HTTP matrix covers both absent and invalid bearer credentials.  Its
  deadline uses a production `HttpTestClock` paused until the parsed
  `healthz` route barrier is held, then advances exactly past the configured
  deadline.  The later slot-pressure case therefore cannot lose its holder to
  wall-clock scheduling;
- every raw TCP matrix case waits for the actual mode's connection permit to
  return before inspecting the exact metric delta or starting its sibling.
  Public and admin modes both consume real handler, serialization, write, and
  flush fault controls, and the matrix also rejects an inference command on
  the admin listener.  Thus a public-only fault writer or an admin transport
  hard-code cannot satisfy the shared-boundary claim;
- the weighted fanout control first holds exactly two 384 KiB decoded requests
  under the one-MiB owner, then starts a 768 KiB origin and proves it remains
  before protobuf allocation and dial while only 256 KiB is free.  This both
  demonstrates useful weighted concurrency and rejects count-one,
  global-count-only-four, per-hook, and allocate-before-gate substitutes;
- the privacy child no longer constructs `Admission` or the executor assembly
  itself.  A task-scoped `RuntimeTestControl` observes the same production
  `ClassifierRuntime::prepare` path used before binary bind, injects only the
  executor-branch fault control, and asserts that assembly was wired exactly
  once.  Stream cancellation likewise keeps the inbound request body open
  until the cancellation terminal is observed, preventing a clean-EOF race.

The cross-package bounded-I/O gate is also explicit.  Privacy stdout/stderr
are continuously drained through pipes, retain at most 16 KiB each, record the
total drained byte count, and fail if output exceeded that ceiling; there is no
unrestricted capture file or pipe-backpressure deadlock.  HTTP and raw/framed
TCP response vectors reject a declared or observed byte count above their
fixed test ceilings before extending/allocating.  The StreamSafety terminal
reader has one absolute deadline and an eight-message ceiling, while raw H2
draining has one absolute deadline and a 128-frame ceiling, so continuous
traffic cannot perpetually reset a per-read timeout.  Connection expiry also
asserts one exact `grpc/unknown/read/deadline` terminal for each of the two
stalled handshakes and two established-idle sessions.  Catalog rejection now
checks missing and wrong-kind embedder defaults as well as the classifier
default cases.

Every test-owned blocking worker barrier (direct admission, real gRPC holder,
all-method deadline holder, and public TCP heuristic holder) now has an
unwind-safe release guard.  An assertion failure therefore cannot strand a
`spawn_blocking` thread and hang the test process before the controller can
report the RED result.

The last static pass checks whitespace, unique selected function names,
`cfg(test)` placement, forbidden markers, exact selector membership, and
bounded capture/wait sites.  No Cargo, Rust binary, rustfmt, staging, commit,
fetch, or push command is part of this RED authoring pass.

## Full-review correction package (authoritative final append)

The fresh full review rejected the preceding six-path package with zero
Blockers, ten Majors, and one Minor.  This append supersedes every earlier
test count, selector, ownership list, resource calculation, pagination
non-claim, outcome-coverage claim, fanout schedule, cleanup claim, and
current-tree signature that conflicts with it.  Earlier sections remain only
as audit history.

### Frozen ownership and exact selector

The corrected RED package owns exactly eight paths.  Existing production bytes
remain untouched; changes in the six source files are inside their existing
`#[cfg(test)]` modules, and the seventh Rust path is a test target:

- `crates/sbproxy-classifier/src/admission.rs`
- `crates/sbproxy-classifier/src/health.rs`
- `crates/sbproxy-classifier/src/grpc.rs`
- `crates/sbproxy-classifier/src/tcp.rs`
- `crates/sbproxy-classifier/src/main.rs`
- `crates/sbproxy-core/src/classifier_hooks.rs`
- `crates/sbproxy-classifier/tests/group_b_startup.rs`
- this report

The exact 23-test gate, after fresh static approval, is:

```sh
cargo nextest run -p sbproxy-classifier -p sbproxy-core -E 'test(/(timed_out_blocking_worker_retains_running_lease_until_worker_exit|worker_error_and_panic_child|worker_failures_use_fixed_wire_status_and_never_log_panic_payloads|http_terminal_outcome_matrix_is_exhaustive_and_exactly_once|real_tonic_terminal_outcome_matrix_is_exhaustive_and_exactly_once|cancelling_real_queued_quality_rpc_restores_queue_gauge_and_capacity|real_tonic_admission_deadlines_finalize_every_leased_method_once|real_tonic_unary_bodies_obey_four_mib_retained_budget_before_queueing|production_tonic_listener_owns_exact_connection_permits_and_deadline_recovery|production_tonic_decode_h2_timeout_and_age_limits_are_finite_and_live|real_tonic_stream_uses_only_first_message_rules_and_ignores_later_rules|validated_model_catalog_owns_inventory_defaults_and_prebind_rejection|public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover|authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery|admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation|compiled_program_budget_weights_old_and_new_tenant_generations_until_final_drop|public_classification_timeout_retains_bounded_worker_lease_and_recovers|public_and_admin_tcp_terminal_matrix_is_exhaustive_and_exactly_once|omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp|quality_hook_shares_pre_rpc_prompt_storage_across_candidates|quality_hook_bounds_real_downstream_protobuf_prompt_high_water|production_entrypoint_orders_preparation_and_listener_owners_before_readiness|shipped_binary_uses_production_http_tcp_and_grpc_startup_owners)/)'
```

The current tree intentionally remains **compile-RED; zero selected tests
execute**.  The failures begin at deliberately absent production-owned seams:
typed outcome guards/probes, bounded Tonic/startup owners, runtime panic and
executor preparation, catalog, opaque paired TCP owner, bounded registry and
pagination types, and the downstream ownership probe.  No unrelated typo is
used as RED.

After compile-shape shells only, four controls are intended to pass:

1. `timed_out_blocking_worker_retains_running_lease_until_worker_exit`
2. standalone `worker_error_and_panic_child` without its private marker
3. `omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp`
4. `quality_hook_shares_pre_rpc_prompt_storage_across_candidates`

The other 19 selected tests are intended semantic RED.  In particular, the
current shipped binary's unbounded inline Tonic builder admits the 65th live
H2 session, so the new integration test remains meaningfully RED even if all
missing type shells are made to compile.

### Shipped startup ownership and panic-policy reachability

`production_entrypoint_orders_preparation_and_listener_owners_before_readiness`
requires one observed production startup state machine.  Its exact event order
is panic-policy installation, catalog validation, blocking-executor
preparation, creation of one typed prepared-runtime token, binding, construction
of the gRPC owner, construction of the paired TCP owner, construction of the
HTTP owner, and readiness publication.  Every listener event carries the same
opaque prepared-runtime identity; raw listener starts must remain zero.  The
test owns shutdown and a bounded join through an unwind-safe abort guard.

`shipped_binary_uses_production_http_tcp_and_grpc_startup_owners` launches the
actual `CARGO_BIN_EXE_sbproxy-classifier`, not `run_with_cli` or a test server.
It observes `/healthz` and `/readyz`, authenticated admin and public
MessagePack, and generated gRPC Version.  Sixty-four independent raw H2
sessions must each receive server SETTINGS before connection 65 reaches exact
EOF/reset without response bytes.  Four header-only 4 MiB frames split evenly
between the public and admin ports make both plus-one sockets fail exactly;
an admin frame then reuses capacity released by a public socket.  This kills a
main function that retains the old inline Tonic builder or raw per-listener
assembly even when production-sounding helpers exist unused beside it.

There is deliberately no release environment/config fault knob.  A release
child therefore cannot be forced to panic through an untrusted handler.  The
privacy proof remains at the actual `cfg(test)` executor branch, while the
typed startup-order proof and shipped-child owner proof jointly establish its
reachability from the real entrypoint.  This is the honest boundary: the
package does not claim that the shipped release child itself executes a test
panic payload.

### One finite gRPC ingress calculation and live behavior

The provisional non-model ingress envelope is one 16 MiB budget:

- 64 connection windows of 80 KiB reserve 5 MiB;
- four concurrent encoded bodies at a 1 MiB + 64 KiB protobuf ceiling reserve
  4.25 MiB;
- four simultaneously retained decoded application bodies reserve 4 MiB;
- four active 64 KiB stream windows reserve 256 KiB;
- the remaining 2.5 MiB is reserved for connection/task/parser/control
  overhead and must be measured before operator documentation is finalized.

The contract also pins four concurrent streams per connection, a two-second
outer request timeout, a five-second handshake timeout, a 30-second idle
timeout, and a five-minute maximum connection age.  The decoded and encoded
lines are intentionally both present because a decoder may transiently own
both representations.

The finite-contract test reads live server SETTINGS and the connection-level
WINDOW_UPDATE to prove the stream and both window values are applied, rather
than trusting getters.  It sends exact-ceiling and plus-one protobuf messages
through both generated services.  Exact bodies decode and reach the smaller
application cap; plus-one bodies receive `OUT_OF_RANGE` before handler decode,
with exactly one typed decode terminal.  Decode counters advance only for the
two exact messages.  A handler barrier plus paused production clock proves the
outer request timeout live; a separate established H2 session survives the
long idle setting but closes at its live maximum-age timer.

The eight-connection pressure test additionally asserts a nonzero and bounded
predecode-byte high-water, zero predecode bytes without the process request
lease, a global ceiling of four times the finite decode maximum, four handler
entries, and four outer refusals.  Its 4 MiB decoded-body assertion remains a
postdecode sub-invariant; it is not credited alone for predecode closure.

### Registry reservations, independent accounting, and complete pagination

The count/shape contract is now executable at every missing dimension:

- an orthogonal literal oracle separately totals classifier patterns,
  enabled-normalizer pattern/replacement, disabled-normalizer
  pattern/replacement, label/default/rule names, and persistent strings;
- the 256 KiB mixed source fixture uses only the test oracle; the full-config
  fixture uses independent named-MessagePack serialization.  Neither calls a
  production `TenantSpec` size helper;
- all supplied rules remain subject to configured-count, source-byte, and
  complete-config-byte limits.  Disabled invalid rules neither compile nor
  warn and reserve no compiled normalizer program, but cannot bypass those
  persistent-input ceilings;
- program reservations are independently weighted at 48 KiB for each
  classifier regex and 64 KiB for each enabled normalizer regex.  A one-program
  old generation (48 KiB) remains reader-owned while a three-classifier/two-
  normalizer replacement (272 KiB) reaches the exact 320 KiB process budget.
  A further one-program tenant is refused under a compile sentinel.  Only the
  final old `Arc` drop returns 48 KiB, after which that tenant compiles and the
  process returns to exactly 320 KiB.  Fixed one-unit-per-tenant, early old-
  generation release, and reserve-after-compile mutations all fail.

The 64-tenant authenticated test first proves an empty exact-limit page and
refuses page-size 33 even though the empty response itself would fit.  It then derives
an independent deterministic seven-entry MessagePack page at the exact
response-byte cap.  Replacing one visible label with a one-byte-longer label
makes the same page exactly plus one and must return a bounded refusal; the
original config is restored before identity snapshots.  Typed advancing
cursors traverse the exact complete 64-key set over persistent admin TCP with
no duplicates or omissions.  An actual authenticated HTTP `/tenants` listener
then traverses the same set in three-entry JSON pages under the same body cap.
Cursor values are bounded URL-safe last-key tokens, responses are byte-capped
before capture, and both loops have explicit page ceilings.  Empty/permanently
truncated output, unbounded clone-all HTTP, repeated cursors, and late
serialization admission all fail.

The previous identity proof remains: both tenant-65 ids stay absent, all
original `Arc` identities remain exact until deliberate replacement/delete,
compile sentinels reject insert/compile/rollback, and deletion does not make a
reservation reusable until the deliberately held reader drops.

### Exhaustive outcomes and deterministic fanout

The systemic typed outcome matrix now adds the four omitted branches:

- `MAX_STREAM_CHUNKS + 1` real bidi input, with one 20-second absolute
  terminal deadline and a 4097-message ceiling;
- a valid gRPC envelope containing a deliberately truncated unary protobuf,
  sent through the generated Version path and attributed exactly to
  `grpc/version/decode/malformed_frame`;
- public and admin response-write deadline faults at the actual timed writer,
  each attributed to its real transport and `write/deadline` terminal;
- Version success, Quality success, and unknown-tenant failure as three
  sequential frames on one still-live public connection, each with a fresh
  exact whole-family snapshot.  Moving a frame guard outside the persistent
  loop fails on frame two.

All previously listed method/transport/auth/resource/handler/write/stream
cases remain.  A valid `/healthz` start line continues to change route
ownership immediately, so malformed later headers are `cmd=healthz`.

The fanout fixture now uses separate small- and large-request release barriers.
Exactly two 384 KiB bodies are held first while a 768 KiB origin remains
pre-allocation.  Only the six small candidates are released; after that origin
fully completes, exactly one 768 KiB body must be live and the next large
candidate must be observed blocked before allocation.  A count-two gate would
hold 1.5 MiB at this deterministic barrier and cannot pass.  Only then are the
large candidates released.  Final decoded, leased, and protobuf-owned peaks
are reread after all 12 candidates, every origin must own exactly six requests,
order is restored, and every lease releases once.

The all-method deadline holder is also ordered: its caller terminal is awaited
and exactly asserted while the noncancellable worker remains live, then a
fresh baseline is taken before the five method snapshots.

### Bounded external I/O and cleanup

Every new external sink has both time and byte bounds.  The shipped child uses
continuous stdout/stderr drains retaining at most 16 KiB each, tracks total
bytes and fails overflow, and has bounded readiness, kill, `try_wait` reap,
drain completion, and thread joins.  The privacy child likewise retains and
joins both bounded drain threads after either normal exit or kill/reap.  The
startup unit probe keeps its production future stack-owned, so an assertion
cannot detach a listener task.  No output file, unbounded `read_to_end`,
or unbounded `wait` is used.  HTTP capture is at most one MiB, framed TCP is at
most four MiB, raw H2 refusal/settings capture is fixed, and every looping read
uses one absolute deadline plus a frame/byte ceiling.  The token fixture is
fixed synthetic mode-0600 data.

All test listener aborts require their join before a three-second deadline;
startup oneshots/barriers and every selected TCP connect/read/write are
bounded directly or by one enclosing absolute deadline.  Unwind-safe release
guards prevent a failed assertion from parking a blocking worker or held
handler indefinitely.

### Static mutation audit and non-claims

Representative mutations rejected by the final package include:

- leave `main` inline, add unused/test-only owners, publish readiness before
  preparation, construct a listener without the prepared token, or bypass the
  panic installer/executor/catalog;
- set decode maximum to `usize::MAX`, omit either generated-service cap,
  remove global predecode lease, apply only a per-connection request cap,
  omit/expand H2 streams/windows, ignore request timeout or maximum age;
- reserve one compiled unit per tenant, omit normalization weight, release an
  old generation at map replacement, compile before reserve, or let disabled
  rules bypass persistent input/config budgets;
- return empty/first-only tenant pages, repeat a cursor, clone all tenants for
  HTTP, serialize before response-byte admission, or omit one original key;
- remove stream chunk count, create gRPC guard after protobuf decode, map TCP
  write timeout as I/O, or reuse one frame guard across a connection;
- retain stale pre-release fanout peaks, use a global count-two/per-hook gate,
  allocate before lease, dial oversize input, omit a candidate, or release a
  lease twice;
- restore `ModelInfoResponse.dimensions` instead of stable `embedding_dim`,
  race the holder terminal into a sibling snapshot, discard plus-one socket
  bytes, detach failed listener cleanup, or use unbounded child/socket reads.

The package still makes no tensor-shape claim from catalog metadata, no claim
that decoded-body accounting alone closes predecode retention, and no claim
that a test fault knob exists in release builds.  N-M3 remains correctly split:
the existing control proves one borrowed pre-RPC prompt; the weighted test is
the newly discovered bounded downstream protobuf-copy high-water.

No Cargo, Rust binary, rustfmt, staging, commit, fetch, push, production edit,
Cargo/lock edit, generated/proto/doc/dashboard edit, or Group C/E/F edit was
performed for this correction.  Source hashes below are computed after the
final static freeze; the report hash is reported externally to avoid a
self-referential digest.

### Frozen source hashes

```text
86c6eb374a7c1ca968c62136561b01f3c96587adbda6002d58b4ec257622d976  crates/sbproxy-classifier/src/admission.rs
907f5612ca008e2c7cf5c0344341badca7227f7071ec9d49cac9d28d684a82cd  crates/sbproxy-classifier/src/health.rs
ca616b4b6d205898f4d4d89ee38ed1e01cbb1749731536b21d0e2a78f005f106  crates/sbproxy-classifier/src/grpc.rs
846d6b2e6aa7c357a960ebf984f9be9eb24d48842eb30cdb7e618f06498f7cfc  crates/sbproxy-classifier/src/tcp.rs
7f97afb7a7959a41bf4df1ecda5fd1f15806440d680473c3c4cccd88c0dadba2  crates/sbproxy-classifier/src/main.rs
6c5cc234e516e4cf7dd3fe0ee255791be20bb4d971ce024611d928eede9037f7  crates/sbproxy-core/src/classifier_hooks.rs
a1c8537f30182a8f50b0718b2060fce7dc75991227c3f116aa629679c803176a  crates/sbproxy-classifier/tests/group_b_startup.rs
```

## R6 review corrections (authoritative final append)

The R5 review rejected the preceding freeze with zero Blockers, six Majors,
and one Minor.  This R6 append supersedes earlier selector, signature,
startup-ownership, mixed-service, pagination/materialization, fanout-
cancellation, cleanup, and source-hash statements where they conflict.  The
owned path set remains the same eight paths and production bytes remain out of
scope.

### Exact locked selector and signature

The exact 24-test gate for the next controller compile is:

```sh
cargo nextest run --locked -p sbproxy-classifier -p sbproxy-core -E 'test(/(timed_out_blocking_worker_retains_running_lease_until_worker_exit|worker_error_and_panic_child|worker_failures_use_fixed_wire_status_and_never_log_panic_payloads|http_terminal_outcome_matrix_is_exhaustive_and_exactly_once|real_tonic_terminal_outcome_matrix_is_exhaustive_and_exactly_once|cancelling_real_queued_quality_rpc_restores_queue_gauge_and_capacity|real_tonic_admission_deadlines_finalize_every_leased_method_once|real_tonic_unary_bodies_obey_four_mib_retained_budget_before_queueing|production_tonic_listener_owns_exact_connection_permits_and_deadline_recovery|production_tonic_decode_h2_timeout_and_age_limits_are_finite_and_live|real_tonic_stream_uses_only_first_message_rules_and_ignores_later_rules|validated_model_catalog_owns_inventory_defaults_and_prebind_rejection|public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover|authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery|admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation|compiled_program_budget_weights_old_and_new_tenant_generations_until_final_drop|public_classification_timeout_retains_bounded_worker_lease_and_recovers|public_and_admin_tcp_terminal_matrix_is_exhaustive_and_exactly_once|omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp|quality_hook_shares_pre_rpc_prompt_storage_across_candidates|quality_hook_bounds_real_downstream_protobuf_prompt_high_water|quality_hook_timeout_returns_weighted_leases_and_full_capacity_recovers|production_entrypoint_orders_preparation_and_listener_owners_before_readiness|shipped_binary_uses_production_http_tcp_and_grpc_startup_owners)/)'
```

The current tree remains intentionally compile-RED at absent production
seams, so zero selected tests execute.  After compile-shape shells only, the
same four controls are intended PASS and the remaining 20 tests are semantic
RED.  No Cargo/Rust/rustfmt command was run for this authoring round.

### Type-enforced prepared startup ownership

The startup RED now requires a real Rust factory shape, not only matching
event ids.  `ClassifierListenerOwners::from_prepared` must borrow the opaque
`PreparedRuntimeCapability` and the complete `BoundClassifierListeners` set;
that capability is issued exactly once only after panic policy, catalog, and
blocking executor preparation.  Stable compile-time ambiguity assertions also
require that the capability implement neither `Clone` nor `Default`, excluding
the two ordinary ways a parallel equivalent could be forged.  The production startup probe independently
requires one issuance, one consumption, one owner set, zero owner starts
without the capability, zero duplicate-equivalent owner-path starts, and no
raw listener starts.  All three listeners retain the same prepared owner and
their children are joined before the production startup future returns.

This combines a compile-time constructor signature, the actual
`run_with_cli` state machine, and the shipped-binary test.  Merely adding a
test-only factory, duplicating the listener assembly beside main, forging a
second equivalent owner, or retaining an inline `Server::builder` path fails
one of those independent layers.

### One mixed-service gRPC owner and both outer timeouts

The four-MiB pressure case is no longer ClassifierService-only.  It first
holds two independent maximum `Quality` bodies and two independent maximum
`Classify` bodies, waits until all four shared process permits and both real
handler barriers are held, and only then starts two plus-one calls from each
generated service.  Exactly two successes and two predecode refusals per
method are required.  The ingress probe reports one global request-owner id,
one retained-body-owner id, a four-permit/high-water ceiling across both
services, and zero decode or retained bytes outside that owner.  A 4+4
per-service split, handler-only lease, or owner duplication fails.

The finite live-server case now drives the outer request timeout through
both `ClassifierService::Quality` and a valid loaded-model
`InferenceService::Classify`, with separate handler barriers and exact typed
deadline terminals.  This supplements the existing finite decode, SETTINGS,
windows, handshake/idle, and maximum-age behavior.

### Scoped pagination and pre-page materialization

The 64-tenant registry now carries a second credential granted exactly the
32 alternating even-numbered tenants.  Persistent authenticated admin TCP and
real authenticated HTTP traverse that sparse grant with independent page
sizes.  Both must return the exact complete visible set without duplicates or
skips; every returned cursor names a visible tenant, and raw MessagePack/JSON
page bytes are scanned to prove that neither entries nor cursors disclose any
of the 32 hidden ids.  Filtering after a raw registry slice, advancing on a
hidden row, or authorizing entries but not cursors fails.

`TenantListProbe` is attached to the production registry callsites and records
logical entry count and string bytes at the instant they are cloned or
materialized, before either serializer.  A typed boundary distinguishes admin
TCP from HTTP.  The wildcard traversals require exact total materialization of
64 entries while peak count equals only seven for TCP and three for HTTP; the
sparse traversals require exactly 32 total and peaks of five/four.  Both
boundaries require zero materializations before the entry/byte page lease and
remain beneath the explicit materialized-byte cap.  Therefore clone-all then
slice, clone-all then authorize, and probe-after-slice mutations are semantic
RED rather than allocation estimates.

### Weighted fanout timeout, cancellation, and recovery

`quality_hook_timeout_returns_weighted_leases_and_full_capacity_recovers`
drives the stock hook through a real local Tonic server.  Two 384 KiB protobuf
requests remain held until the single five-second hook deadline cancels the
whole fanout.  The downstream handler count, owned bytes, leased bytes, and
call leases must all return to zero; all four call permits and the full one-MiB
process byte budget must be available, and each acquired owner/weighted lease
must release exactly once.

A second independently built hook then holds four 256 KiB real requests at
exactly four calls and one MiB, releases them, and completes all six candidates
in original order.  Per-hook budgets, timeout paths that leak a blocked or
in-flight lease, response cancellation that leaves the server handler alive,
and partial capacity recovery fail independently.

### Joined listener and child cleanup

Every selected server fixture now asserts that its listener is still live
immediately before explicit cleanup, that the bounded join returns the exact
expected cancellation rather than an ignored inner `JoinHandle`, and that
connection-child spawned/finished counts match at zero active children.  This
is enforced centrally for every production gRPC fixture and paired TCP
fixture, directly for the HTTP outcome and registry-HTTP listeners, and for
the privacy handler.  Both core real-Tonic fanout fixtures require zero live
downstream bodies and exact listener cancellation.  Production startup joins
all typed-owner children.  The shipped child records whether a kill was
actually issued and rejects a clean/early process exit after serving its
responses.  Parent-only abort, detached per-connection tasks, handler panic
after response, ignored `JoinError`, or early listener/process exit now fail
under bounded waits.

### R6 mutation and bounded-I/O audit

Representative R6 mutations are: replace the capability factory with an
event-only raw builder; issue/consume two equivalent capabilities; split
request or byte owners by generated service; omit the InferenceService outer
timeout; page before sparse authorization; derive a cursor from a hidden key;
clone all tenants before either materialization probe; reset only count but
not weighted bytes on hook timeout; release a lease twice; abort only the
accept loop while detaching children; swallow a listener panic as expected
cleanup; or let the shipped child exit before kill.  Each has a direct
behavior/type assertion.

All added socket, child, stream, barrier, and cleanup waits retain an item/byte
ceiling and one enclosing absolute deadline.  No output sink, response body,
cursor loop, or pipe capture is unbounded.  The existing privacy and N-M3
non-claims remain unchanged.

### R6 frozen source hashes

```text
432664bac0acacd112e1ed3e14b835e3b4af59670a4ca23d89ab133ee69ab418  crates/sbproxy-classifier/src/admission.rs
9e7a9914d3a00b42fec92e0b0166cb80f61da053de902c4c7306ead85e571015  crates/sbproxy-classifier/src/health.rs
0a1f762e5a08a8313abdbd1b75b6d3da2f06f0f19ddc130427819a046b203877  crates/sbproxy-classifier/src/grpc.rs
84b46ca9cb30429efbce40ce5fe5f6d3a5e1598ba7ceec5b97ee6dc36925deb2  crates/sbproxy-classifier/src/tcp.rs
df771949481b992d1066fea3d8cbdf52d845180dc8397eb7474d2a472151b970  crates/sbproxy-classifier/src/main.rs
161a573b5c2374eb618bed1e24ebd5e70873722e88e4cd14e0fb7ab96caaf465  crates/sbproxy-core/src/classifier_hooks.rs
43f19f4d4a9e94aea22a7cc81757163e5bce6311eee23fd45fa6ead052fbdd4a  crates/sbproxy-classifier/tests/group_b_startup.rs
```

AI_GROUP_B_R6_RED_READY_FOR_REREVIEW

## R7 review corrections (authoritative final append)

The R6 review rejected the preceding freeze with zero Blockers, six Majors,
and one Minor.  This R7 append supersedes every earlier statement about the
startup capability's borrow semantics, mixed-service split, TCP allocation
boundary, HTTP response cap, listener cleanup, selector count, and source
hashes.  It preserves all other approved R6 contracts and non-claims.

### Exact locked selector and current-tree signature

The exact 25-test gate for a controller run, only after a fresh static review
accepts this package, is:

```sh
cargo nextest run --locked -p sbproxy-classifier -p sbproxy-core -E 'test(/(timed_out_blocking_worker_retains_running_lease_until_worker_exit|worker_error_and_panic_child|worker_failures_use_fixed_wire_status_and_never_log_panic_payloads|http_terminal_outcome_matrix_is_exhaustive_and_exactly_once|real_tonic_terminal_outcome_matrix_is_exhaustive_and_exactly_once|cancelling_real_queued_quality_rpc_restores_queue_gauge_and_capacity|real_tonic_admission_deadlines_finalize_every_leased_method_once|real_tonic_unary_bodies_obey_four_mib_retained_budget_before_queueing|production_tonic_listener_owns_exact_connection_permits_and_deadline_recovery|production_tonic_decode_h2_timeout_and_age_limits_are_finite_and_live|real_tonic_stream_uses_only_first_message_rules_and_ignores_later_rules|validated_model_catalog_owns_inventory_defaults_and_prebind_rejection|public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover|paired_tcp_listener_surfaces_connection_child_panic_after_response|authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery|admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation|compiled_program_budget_weights_old_and_new_tenant_generations_until_final_drop|public_classification_timeout_retains_bounded_worker_lease_and_recovers|public_and_admin_tcp_terminal_matrix_is_exhaustive_and_exactly_once|omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp|quality_hook_shares_pre_rpc_prompt_storage_across_candidates|quality_hook_bounds_real_downstream_protobuf_prompt_high_water|quality_hook_timeout_returns_weighted_leases_and_full_capacity_recovers|production_entrypoint_orders_preparation_and_listener_owners_before_readiness|shipped_binary_uses_production_http_tcp_and_grpc_startup_owners)/)'
```

The exact current-tree signature remains **compile-RED; zero selected tests
execute**.  R7 deliberately adds absent production contracts for by-value
startup ownership, acquisition-site gRPC owner fingerprints, pre-allocation
TCP frame leases, transport-specific registry response caps, and joined
listener-child results.  These are the expected first errors, not accidental
syntax failures.  After compile-shape shells only, the four established
controls remain intended PASS:

1. `timed_out_blocking_worker_retains_running_lease_until_worker_exit`
2. standalone `worker_error_and_panic_child` without its private marker
3. `omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp`
4. `quality_hook_shares_pre_rpc_prompt_storage_across_candidates`

The remaining 21 tests are intended semantic RED, including the new
response-then-child-panic case.  No Cargo, Rust binary, rustfmt, stage, commit,
fetch, or push command was run while authoring R7.

### By-value capability and sole release startup reachability

`ClassifierListenerOwners::from_prepared` now has an exact function-pointer
contract that consumes `PreparedRuntimeCapability` **by value** and returns a
non-borrowing owner set.  A second function-pointer contract requires the
owner set to retain and expose a reference to that same capability.  Negative
trait-ambiguity checks require the capability to implement neither `Clone`
nor `Default`; `Copy` is excluded transitively by Rust's `Copy: Clone`
requirement.  A borrowed/reusable token, owner set that drops the token, or a
factory callable twice from one preparation no longer compiles.

The unit probe invokes the non-test `startup::run_release_main` assembly, not
a test constructor, and requires exactly one release entrypoint invocation,
zero test-mirror invocations, one issuance/consumption/retention, zero raw
listener starts, zero raw listener-builder exports from the owning module,
and zero duplicate-equivalent owner starts.  The existing integration test
independently launches `CARGO_BIN_EXE_sbproxy-classifier` and proves that the
shipped process exposes HTTP, paired TCP, and gRPC behavior.  The required
GREEN shape is therefore a thin release `main` calling this same non-test
assembly, with raw listener constructors private to its owner module; adding
a parallel cfg(test) assembly or leaving the old inline builders reachable
fails the unit/integration pair.

### Asymmetric mixed-service owner pressure and one collection deadline

The four-MiB Tonic case now runs two independent eight-call waves on the same
production server:

- wave A holds three `Quality` plus one `Classify`, then refuses one
  `Quality` plus three `Classify`;
- wave B holds one `Quality` plus three `Classify`, then refuses three
  `Quality` plus one `Classify`.

Each wave proves all four exact-limit handler barriers before its plus-one
batch.  Thus a partitioned two-plus-two service budget fails in both
directions, even if it lies about an owner id.  The supplemental owner proof
uses allocation fingerprints captured at the actual request-permit and
weighted-body-lease acquisitions (the probe records the backing allocation,
not a listener-supplied/configured id).  All four successful acquisitions for
each method must collapse to the same single request owner and the same single
retained-byte owner.  Totals are exactly four successes and four typed
resource refusals per method.

Every barrier, refusal observation, and all eight `JoinSet` results in one
wave share one `tokio::time::Instant` and `timeout_at`; no per-result timeout
can reset the batch deadline.  Dropping the bounded `JoinSet` aborts residual
callers on an assertion failure.

### TCP allocation lease before the real Vec boundary

The frame pressure test now requires two production function shapes:

1. `FrameAllocationLease::try_acquire(Arc<Semaphore>, bytes)` performs byte
   admission and returns a non-`Clone`, non-`Default` owned lease;
2. `BudgetedFrame::allocate_from_lease(lease, probe)` consumes that lease by
   value at the only payload `Vec` allocation boundary and retains its permit.

The allocation probe is required at that real boundary.  With four maximum
frames held, two cross-listener plus-one declarations leave both the admitted
allocation count and allocator-call count at four.  After two deliberate
cross-listener releases they reach exactly six, peak bytes remain sixteen
MiB, and both allocator calls and bytes without a live lease remain zero.
Allocating a fifth four-MiB `Vec` and discarding it before a failed semaphore
acquire is now directly observable and fails.

### Independent HTTP JSON exact/plus-one admission

Registry limits now have separate admin-MessagePack and HTTP-JSON response
ceilings.  The HTTP ceiling comes from a literal, hand-checked three-tenant
JSON byte string, not `AdminResponse`, the MessagePack serializer, or a
production sizing helper.  A real authenticated `/tenants?page_size=3`
response must be status 200, exactly fill that JSON ceiling, and equal the
literal page semantically.

The test then changes only `tenant-00`'s emitted label by one byte, arms the
production HTTP-boundary serialization sentinel, and requires exact status
507 with a bounded refusal body before any JSON page serialization.  It
restores the tenant before the full and sparse traversal controls.  A shared
MessagePack-derived cap, serialize-then-measure implementation, JSON-size
off-by-one, or small-capture shortcut fails independently.

### Joined listener children and surfaced post-response panic

Production gRPC, paired TCP, registry HTTP, outcome-matrix HTTP, privacy gRPC,
and release-startup fixtures now request graceful shutdown and inspect the
inner task result rather than aborting the accept loop and accepting a
`JoinError`.  Their cleanup probes require active children zero, spawned equal
finished, child results collected equal spawned, and zero swallowed child
panics.  The two core real-Tonic fixtures likewise use
`serve_with_incoming_shutdown` and require the inner server result to be
`Ok(())` under a bounded join.

`paired_tcp_listener_surfaces_connection_child_panic_after_response` arms the
actual public `Version` write branch, reads and validates the complete real
response, then triggers a child panic.  The paired owner must stop, join every
sibling, return a typed `TcpListenerAssemblyError` identifying the public
child panic, record exactly one panic, and collect every child result.  An
outer `Ok(())`, detached child, ignored nested `JoinHandle`, or panic occurring
before the response all fail.

### R7 mutation, bounds, privacy, and ownership audit

Representative mutations killed directly are: change the startup factory
back to `&PreparedRuntimeCapability`; drop the capability from the owner set;
add `Clone`, `Default`, a cfg(test) mirror, or a raw release-main listener
path; split gRPC owners 2+2 by service; record a configured owner string
instead of the actual acquisition allocation; reset one timeout per result;
allocate a payload before the frame lease; use the MessagePack cap for JSON;
serialize the oversized JSON page before refusing it; abort only an accept
loop; ignore a child result; or treat a response-then-panic child as success.

All new sockets, bodies, joins, barriers, and child output remain item/byte
bounded and use an enclosing absolute deadline.  `wire_exchange` was tightened
to one deadline covering both writes and both bounded reads.  No unrestricted
stdout/stderr file, `read_to_end`, `read_line`, response-body sink, or
newline-reset loop was introduced.  Acquisition fingerprints and panic fault
payloads never cross a release wire or log surface; test failure messages do
not print raw owner addresses.  The panic fault is cfg(test), one-shot, and
armed at the real response-write branch.

The exact owned path set remains:

1. `crates/sbproxy-classifier/src/admission.rs`
2. `crates/sbproxy-classifier/src/health.rs`
3. `crates/sbproxy-classifier/src/grpc.rs`
4. `crates/sbproxy-classifier/src/tcp.rs`
5. `crates/sbproxy-classifier/src/main.rs`
6. `crates/sbproxy-core/src/classifier_hooks.rs`
7. `crates/sbproxy-classifier/tests/group_b_startup.rs`
8. `.superpowers/sdd/2026-08-23-wor2661-agy-handoff/ai-group-b-r4-red-report.md`

No production implementation, Cargo/lock, generated/proto, dashboard, doc,
Group C/E/F, staging, or commit bytes are owned by this RED author.  The
decoded-body accounting remains only a postdecode/queued-retention
sub-invariant; it does not by itself close the outer predecode Blocker.  N-M3
also remains split: the borrowed pre-RPC prompt control is accepted, while the
weighted downstream protobuf-copy ceiling is the new bounded-high-water
contract.

### R7 frozen source hashes

```text
fac9761b406ebf8f7a6a0ad0caa7e56664a826307472d20f8ba1f42a55a5ce02  crates/sbproxy-classifier/src/admission.rs
ad642fe0e9e68964e37e190dbf8e9d557f3d7b15405f9055a12c3d96133816bf  crates/sbproxy-classifier/src/health.rs
cd12000e0a9e06aaf3b8a60cb53cd69d70f23830873ce57de69e8b4e67d18852  crates/sbproxy-classifier/src/grpc.rs
25d7c5d30d5f158cdb76d18da9b41f99df1351e7ba9ecdaf2937b5cfdc666632  crates/sbproxy-classifier/src/tcp.rs
7b37c48d9f830f3009a24ceb6ef8ba295707a61123dce74ba9a5575255da0ee4  crates/sbproxy-classifier/src/main.rs
89d45acb36e458871b88dfdd664ad4de10d83fd1860267e6e13935fa409a9709  crates/sbproxy-core/src/classifier_hooks.rs
43f19f4d4a9e94aea22a7cc81757163e5bce6311eee23fd45fa6ead052fbdd4a  crates/sbproxy-classifier/tests/group_b_startup.rs
```

AI_GROUP_B_R7_RED_READY_FOR_REREVIEW

## R8 RED corrections and definitive R3-R7 audit (authoritative final append)

The unanimous R7 review rejected the preceding freeze with zero Blockers, six
Majors, and zero Minors.  This R8 append supersedes every earlier selector,
test count, current-tree signature, startup-reachability claim, allocation-
boundary claim, response-admission claim, owner-return cleanup claim, model-
manifest bound claim, shipped-child cleanup claim, and source hash where they
conflict.  Earlier appendices remain audit history only.

R8 changes tests and test observation only.  It does not implement any
production behavior or production API shell.  The crate-root allocator is
`cfg(test)` and exists solely to observe the real payload `Vec` allocation
from the binary test crate.  `classifier_hooks.rs` is unchanged from the R7
freeze but remains part of the cumulative owned and selected package.

### Exact locked Unix selector and honest RED signature

The exact focused gate on Unix, after a fresh static reviewer accepts this
compile-RED package, is 26 unique tests:

```sh
cargo nextest run --locked -p sbproxy-classifier -p sbproxy-core -E 'test(/(timed_out_blocking_worker_retains_running_lease_until_worker_exit|worker_error_and_panic_child|worker_failures_use_fixed_wire_status_and_never_log_panic_payloads|http_terminal_outcome_matrix_is_exhaustive_and_exactly_once|real_tonic_terminal_outcome_matrix_is_exhaustive_and_exactly_once|cancelling_real_queued_quality_rpc_restores_queue_gauge_and_capacity|real_tonic_admission_deadlines_finalize_every_leased_method_once|real_tonic_unary_bodies_obey_four_mib_retained_budget_before_queueing|production_tonic_listener_owns_exact_connection_permits_and_deadline_recovery|production_tonic_decode_h2_timeout_and_age_limits_are_finite_and_live|real_tonic_stream_uses_only_first_message_rules_and_ignores_later_rules|validated_model_catalog_owns_inventory_defaults_and_prebind_rejection|public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover|paired_tcp_listener_surfaces_connection_child_panic_after_response|authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery|admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation|compiled_program_budget_weights_old_and_new_tenant_generations_until_final_drop|public_classification_timeout_retains_bounded_worker_lease_and_recovers|public_and_admin_tcp_terminal_matrix_is_exhaustive_and_exactly_once|omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp|quality_hook_shares_pre_rpc_prompt_storage_across_candidates|quality_hook_bounds_real_downstream_protobuf_prompt_high_water|quality_hook_timeout_returns_weighted_leases_and_full_capacity_recovers|production_entrypoint_orders_preparation_and_listener_owners_before_readiness|shipped_binary_uses_production_http_tcp_and_grpc_startup_owners|shipped_child_cleanup_surfaces_failures_and_never_detaches_owned_handles)/)'
```

`group_b_startup.rs` begins with `#![cfg(unix)]`.  That keeps its Unix
permission and process semantics portable without weakening the Linux/macOS
CI gate.  The 26-test count is the Unix count; the integration target is
intentionally empty on non-Unix platforms.

The exact current-tree signature is still **compile-RED; zero selected tests
execute**.  No compiler run was used to discover or manufacture that result.
Static source inspection shows the deliberate missing production-contract
union below:

- startup ownership: `PreparedRuntimeCapability`,
  `BoundClassifierListeners`, `ClassifierListenerOwners`, `StartupEvent`,
  `StartupTestControl`, `ClassifierRuntime`, `RuntimeLimits`,
  `ReleaseMainBinding`, `shipped_release_main_binding`, and the typed
  `run_release_main` exit report;
- gRPC ownership: `GrpcServerLimits`, `GrpcListenerCleanupProbe`,
  `GrpcListenerExitReport`, `GrpcListenerError`, the ingress/acquisition
  probes and handler/fault controls, and production `grpc::serve_on`;
- model ownership: `ModelCatalog`, `ModelCatalogLimits`, `ModelManifest`,
  `ModelDescriptor`, `ModelKind`, and validated fixture/catalog startup
  assembly;
- TCP ownership: `FrameAllocationLease`, the lease-consuming
  `BudgetedFrame::allocate_from_lease`, `FrameTrackingAllocator`, the global
  `FrameAllocationProbe` acquisition/actual-allocation observations,
  `TcpListenerAssembly`, `TcpListenerCleanupProbe`,
  `TcpListenerExitReport`, and `TcpListenerAssemblyError`;
- registry ownership: `TenantRegistryLimits`, `TenantRegistryBudget`,
  `TenantCompiler`, `TenantCompileProbe`, `TenantListProbe`,
  `TenantPageBoundary`, scoped cursor/page fields, materialization sentinels,
  and transport-specific response admission;
- terminal, executor, and fanout ownership: typed outcome guards/probes,
  blocking executor fault controls, production HTTP/gRPC/TCP cleanup reports,
  and the process-wide weighted quality fanout probe/lease contracts;
- shipped-child ownership: `ChildGuard::cleanup_before`,
  `ShippedChildCleanupReport`, `ShippedChildCleanupError`,
  `ShippedChildCleanupFault`, and
  `ShippedChildCleanupMutationFixture`.

Those are intentional missing shells.  No unrelated field typo, syntax
error, conflict marker, or platform import is expected to be part of RED.

After compile-shape shells only, exactly four selected controls remain
intended PASS:

1. `timed_out_blocking_worker_retains_running_lease_until_worker_exit`
2. standalone `worker_error_and_panic_child` without its private marker
3. `omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp`
4. `quality_hook_shares_pre_rpc_prompt_storage_across_candidates`

The other 22 tests remain intended semantic RED.  Their expected first
behavioral gaps are classified explicitly here:

| Selected semantic RED | Expected semantic failure after shells only |
|---|---|
| `worker_failures_use_fixed_wire_status_and_never_log_panic_payloads` | The current release assembly does not provide the required panic-policy/executor privacy path and joined cleanup. |
| `http_terminal_outcome_matrix_is_exhaustive_and_exactly_once` | The current HTTP boundary lacks the complete typed exactly-once outcome owner and atomic child-exit report. |
| `real_tonic_terminal_outcome_matrix_is_exhaustive_and_exactly_once` | The current Tonic path lacks the complete predecode-to-terminal typed owner. |
| `cancelling_real_queued_quality_rpc_restores_queue_gauge_and_capacity` | Queued cancellation does not yet satisfy the production permit/gauge replacement contract. |
| `real_tonic_admission_deadlines_finalize_every_leased_method_once` | All leased methods do not yet share the required admission/deadline finalization behavior. |
| `real_tonic_unary_bodies_obey_four_mib_retained_budget_before_queueing` | The shipped Tonic owner does not yet enforce one mixed-service predecode process budget. |
| `production_tonic_listener_owns_exact_connection_permits_and_deadline_recovery` | The production listener does not yet expose/enforce the finite connection owner and live recovery contract. |
| `production_tonic_decode_h2_timeout_and_age_limits_are_finite_and_live` | Decode, H2 window/stream, request-timeout, and max-age settings are not yet one live bounded assembly. |
| `real_tonic_stream_uses_only_first_message_rules_and_ignores_later_rules` | Current stream behavior remains incompatible with the pinned first-message rule contract. |
| `validated_model_catalog_owns_inventory_defaults_and_prebind_rejection` | No validated catalog owner yet enforces truth, defaults, literal ID/count limits, and pre-load/pre-bind rejection. |
| `public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover` | No production paired owner/global allocator contract yet proves lease-before-real-`Vec` across both listeners. |
| `paired_tcp_listener_surfaces_connection_child_panic_after_response` | The paired listener does not yet return a typed, atomically quiescent post-response child-panic report. |
| `authenticated_registry_budget_is_atomic_at_exact_plus_one_and_recovery` | Registry pagination, transport-specific response admission, and actual pre-admission clone/materialization ownership are absent. |
| `admin_registry_refuses_aggregate_pattern_rule_and_byte_plus_one_before_compilation` | The bounded preflight/compiler owner is not implemented. |
| `compiled_program_budget_weights_old_and_new_tenant_generations_until_final_drop` | Weighted compiled-program ownership across replacement readers is not implemented. |
| `public_classification_timeout_retains_bounded_worker_lease_and_recovers` | The public heuristic handler does not yet use the required noncancellable worker owner. |
| `public_and_admin_tcp_terminal_matrix_is_exhaustive_and_exactly_once` | The complete persistent-frame typed terminal owner is absent. |
| `quality_hook_bounds_real_downstream_protobuf_prompt_high_water` | The process-wide pre-allocation weighted protobuf-copy owner is absent. |
| `quality_hook_timeout_returns_weighted_leases_and_full_capacity_recovers` | Timeout/cancellation does not yet prove release of every weighted downstream owner and full capacity. |
| `production_entrypoint_orders_preparation_and_listener_owners_before_readiness` | The real crate main is still inline and lacks the macro-bound sole capability mint/consume assembly and atomic exit report. |
| `shipped_binary_uses_production_http_tcp_and_grpc_startup_owners` | The non-`cfg(test)` child cannot yet emit the sole release-entrypoint capability attestation or use the bounded owners. |
| `shipped_child_cleanup_surfaces_failures_and_never_detaches_owned_handles` | Normal, `Drop`, and unwind cleanup still swallow failures and discard ownership instead of reporting and retaining handles. |

### R8 correction 1: the real non-test crate main is the capability owner

The startup unit test now requires a `ReleaseMainBinding` emitted together
with the real crate-level `main`.  Its function-pointer accessor is
`startup::shipped_release_main_binding`; the binding must accept the actual
`main` item through `assert_bound_to_crate_main` and report that it enters the
sole capability mint/consume assembly.  This is in addition to the existing
by-value, non-`Clone`, non-`Default` `PreparedRuntimeCapability` constructor
and retained-capability accessor.

The shipped integration child independently scrapes `/metrics` and requires
exactly one
`sbproxy_classifier_startup_owner_info{entrypoint="release_main",owner="prepared_capability"}`
sample with value one, while forbidding `entrypoint="test_only"`.  A selected
wire-only helper, a parallel `cfg(test)` startup, an unused macro, or an old
inline non-test `main` cannot satisfy both proofs.  The startup owner also
returns a typed exit report under the same shutdown deadline used by its
probe, so the test mirror cannot hide detached release children.

### R8 correction 2: admission is observed at the actual payload allocation

The binary test crate installs `FrameTrackingAllocator<System>` as its
`cfg(test)` global allocator.  `FrameAllocationProbe::acquire_unique()` scopes
the observation to the pressure test, allowing the allocator itself to count
the actual four-MiB payload `Vec` allocations, bytes, and live-lease state.
Four exact frames across public/admin must produce exactly four real
allocations and 16 MiB.  Both refused plus-one frames produce zero additional
payload allocations.  Cross-listener recovery produces exactly allocations
five and six while the peak remains 16 MiB.

The type contract additionally requires `FrameAllocationLease` to have the
exact size and alignment of `OwnedSemaphorePermit`, to implement neither
`Clone` nor `Default`, and to be consumed by
`BudgetedFrame::allocate_from_lease`.  That rules out hiding a preallocated
`Vec`, `Box`, or other payload owner inside the lease while leaving the
selected boundary call apparently ordered.  Allocator calls/bytes and actual
payload allocations without a live lease must all remain zero.  Moving a
fifth allocation before admission, allocating and discarding on refusal, or
preallocating inside the lease now changes the allocator observation directly.

### R8 correction 3: response admission precedes projection and cloning

Admin MessagePack uses the independent literal ceiling 326, hand-derived as
`1 + 4 + 9 + 9 + (7 * 39) + 30`; it no longer derives the cap from
`rmp_serde` or a production response helper.  The exact page must contain the
literal tenant ids `tenant-00.example` through `tenant-06.example` and the
literal cursor `tenant-06.example`.  HTTP keeps its separate literal JSON
byte string and semantic `serde_json::Value` oracle for three rows.

`TenantListProbe` now carries monotonic lifetime response-admission,
materialized-entry, and `String`-clone counters for both `AdminTcp` and
`Http`.  At the exact boundary, one response admission precedes exactly seven
admin projections/fourteen string clones or three HTTP projections/six
string clones.  At the one-byte-over boundary, simultaneously armed
serialization and materialization sentinels require zero new projection,
clone, or serialization work and exactly one response-admission refusal.
Window resets used by later full/sparse pagination cannot reset the lifetime
violation counters, which are rechecked at the end for both transports.

Thus estimating after projection, clone-all then slice, materialize then
reserve, use one serializer's cap for both transports, serialize then measure,
or reset evidence before the final assertion all fail independently.

### R8 correction 4: owner return is the quiescence boundary

Every selected gRPC, paired TCP, registry HTTP, outcome HTTP, privacy gRPC,
and production-startup owner now receives one absolute shutdown deadline and
returns a typed exit report.  At the instant the owner future returns the
report must attest all of the following:

- zero active connection/listener children;
- children finished equal children spawned;
- child results collected equal children spawned;
- zero swallowed child panics on successful cleanup;
- zero child events after owner return; and
- the collection deadline identity equals the shutdown probe's deadline
  identity.

No sleep or delayed-reaper catch-up is allowed after owner return.  The TCP
response-then-panic case binds the failure-collection deadline before arming
the real write-branch fault, and its connect, complete response exchange,
owner failure, sibling join, and report collection all consume that same
deadline.  The typed error must retain the exit report and identify exactly
one public child panic.  Aborting only the accept loop, returning before a
reaper catches up, ignoring an inner result, or starting a fresh timeout for
each cleanup step now fails at the owner-return boundary.

### R8 correction 5: model-manifest dimensions have literal bounds

The catalog test owns literal oracles `MAX_MODEL_ID_BYTES = 256` and
`MAX_MANIFEST_MODELS = 64`, and requires production defaults to match them.
A 256-byte non-ASCII id (`"é"` repeated 128 times) and exactly 64 model
descriptors are positive controls.  Three independent negative manifests add
an empty id, a 257-byte UTF-8 id, and 65 descriptors.  They join the prior
duplicate, cross-kind collision, and absent/wrong-kind default cases.

Every negative manifest enters the real `ClassifierRuntime::prepare` catalog
seam.  Each must fail with zero model loads, zero listener binds, and zero
catalog-owned id bytes.  A getter-only limit, character-count limit,
validate-after-load implementation, or unbounded manifest vector cannot pass
the literal exact/plus-one controls.

### R8 correction 6: shipped-child cleanup never silently abandons ownership

`ChildGuard::cleanup_before` has an exact typed driver signature and one
absolute `Instant`.  The mutation fixture independently injects failure at
kill, reap, stdout drain, stderr drain, stdout thread join, and stderr thread
join.  Explicit normal cleanup must surface the exact stage and deadline id,
detach zero handles, retain every unfinished handle, and allow a bounded retry
inside the original deadline.

The same six faults run through ordinary `Drop` and caller unwind.  A cleanup
observation must surface the typed error even though `Drop` cannot return it;
the caller's original unwind remains primary; and a retention probe proves
zero detached handles plus bounded recovery.  The successful ordinary-Drop
control reports one deadline and zero detachments.  Every fixture is capped at
250 ms.  Ignoring `kill`, `try_wait`, drain-receiver, or join errors; taking a
new deadline for each stage; dropping a process/thread handle on failure; or
panicking over the caller unwind fails a dedicated row.

### Definitive invariant-to-mutation matrix

The tables below re-audit every independent finding from R3 through R7.  A
"RED constrained" disposition means the current tests now pin the seam and
mutation; it does not claim that missing production GREEN exists.

#### R3 re-review: 0 Blockers, 5 Majors, 0 Minors

| Finding and invariant | Production seam | Positive control | Independent negative mutation | R8 disposition |
|---|---|---|---|---|
| R3-M1 routine omitted/empty tenants produce no release warning | `Registry::get` as reached by real public MessagePack classify | Both omitted and empty tenant frames return bounded `tenant_not_registered` responses with zero WARN events | Change only the absent/empty branch back to `warn!` | Accepted production behavior remains pinned by `omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp` |
| R3-M2 admission/parser/deadline/oversize refusals are scrapeable exactly once | HTTP listener terminal mapping and TCP oversized-frame branch, extended by typed outcome guards | Exact per-child deltas for HTTP slot/cap/truncation/deadline and TCP oversize, plus full HTTP/TCP matrices | Remove one record, relabel it, double-finalize it, or write only a debug log | RED constrained by the selected HTTP/TCP whole-family matrices; accepted narrow R3 counters remain compatible |
| R3-M3 auth path never follows a final symlink and never reopens after descriptor validation | Unix `OpenOptions` and same opened file descriptor for metadata/read | Existing `final_component_symlink_is_refused_without_following` and `post_open_path_replacement_cannot_change_auth_descriptor_identity` controls | Drop only `O_NOFOLLOW`, or reopen only the pathname after metadata | Accepted pre-existing controls remain sound; auth is outside the R8 edit/selector boundary |
| R3-M4 direct HTTP `serve_on` rejects every invalid limit before accept | `health::serve_on` first-call `HttpLimits::validate` | Existing bounded zero/max-plus-one connection and deadline cases | Remove only the defensive `validate()?` call | Accepted pre-existing direct-server control remains sound; selected startup also refuses invalid limits before readiness |
| R3-M5 frame observation follows the real payload allocation | Sole `BudgetedFrame` payload constructor and allocator | Four exact 4 MiB frames, two refused plus-ones, two recoveries, 16 MiB allocator peak | Allocate the fifth `Vec` before the lease, discard it on refusal, or hide payload allocation inside the lease | Strengthened in R8 with the global allocator plus size/alignment lease contract |

#### R4 full review: 0 Blockers, 10 Majors, 1 Minor

| Finding and invariant | Production seam | Positive control | Independent negative mutation | R8 disposition |
|---|---|---|---|---|
| R4-M1 outcome coverage is exhaustive, structural, and exactly once | Boundary-installed typed guard before identifiable attempt/decode, finalized after write/flush/trailers/drop | Full-family HTTP, gRPC, public TCP, and admin TCP snapshots include all success/error siblings | Omit/double a finalizer, install after parsing/model lookup, map to sibling, or finalize before flush | RED constrained by the three selected exhaustive matrices |
| R4-M2 tenant refusal cannot replace an existing identity | Registry preflight and atomic map update | Sorted 64-key set and every original `Arc` identity remain unchanged after two refused ids | Insert then roll back, replace an existing entry, or omit one refused id from the snapshot | RED constrained by the authenticated registry exact/plus-one test |
| R4-M3 all configured/source/config dimensions and cross-thread compiler warnings are independent | `TenantSpec` preflight plus bounded compiler probe before insert | Multi-label, enabled/disabled, source-byte, config-byte, zero-warning, and zero-compile sentinels | Count per label, ignore disabled persistent input, omit replacement/name bytes, or compile before validation | RED constrained by the aggregate registry test and literal accounting oracles |
| R4-M4 connection pressure uses accepted-owner barriers, not scheduling sleeps | Production incoming Tonic connection permit and paused test clock | Two stalled plus two idle accepted permits at exact four, typed plus-one refusal, expiry and recovery | Treat kernel connect as acceptance, create a fresh owner, or depend on a fixed sleep | RED constrained by the production Tonic listener test |
| R4-M5 fanout proves weighted pre-allocation ownership rather than count-only gating | Process-wide lease acquired before `ClassifyRequest.text` allocation/dial | Unequal small/large deterministic barriers, exact owner and byte peaks, all candidates ordered | Use per-hook/count-two/count-four owner, allocate before gate, or dial oversized input | RED constrained by both selected fanout tests |
| R4-M6 catalog truth uses genuine classifier/embedder fixtures and kind-correct defaults | One validated descriptor catalog feeding load, `ModelInfo`, and `Version` | Mixed and embedder-only real fixtures, sorted inventory, kind-specific empty default | Reuse classifier fixture as embedder, report classifiers only, or choose embedder for empty classifier lookup | RED constrained by the catalog test; stable `embedding_dim` field is used |
| R4-M7 canceled queued work restores its actual queue permit while the running worker stays held | Admission queue RAII owner in real handlers | Replacement obtains the sole returned queue permit while still queued; third call is queue-full | Decrement gauge without releasing permit, release only on success, or bypass queue ordering | RED constrained by the selected cancellation test |
| R4-M8 external and cleanup waits are bounded and cannot detach on timeout | Child/listener/task/drain owners and absolute-deadline joins | Every socket/body/barrier has a byte/item cap and deadline; owner exit reports are atomic | Unbounded `wait`/barrier/read, discard timeout, or detach failed cleanup | Strengthened in R8 by typed exit reports and shipped-child six-stage cleanup |
| R4-M9 privacy reaches the same startup panic/executor assembly as release | Panic-policy installer, validated runtime, blocking executor, real gRPC handler, shipped main | Private child proves fixed status/no sentinel; startup binding and child metric prove release reachability | Use direct `Admission`, a test-only panic handler, raw release main, or format panic/error payload | Strengthened in R8 by the crate-main binding and release-only metric attestation |
| R4-M10 malformed post-route HTTP headers retain the parsed command owner | HTTP guard route transition after valid start line | Cap, truncation, and deadline after `/healthz` start line are attributed to `cmd=healthz` | Leave guard at `decode` until all headers complete | RED constrained by the exhaustive HTTP matrix |
| R4-m1 frame refusal accepts only EOF/reset and no response bytes | Real plus-one public/admin sockets | Bounded read accepts EOF or normalized reset/abort only | Return one corrupt byte before closing or discard the inner read result | RED constrained by `assert_socket_refused_without_response` in the frame-pressure test |

#### R5 review: 0 Blockers, 6 Majors, 1 Minor

| Finding and invariant | Production seam | Positive control | Independent negative mutation | R8 disposition |
|---|---|---|---|---|
| R5-M1 startup ownership is a Rust type capability, not an event-id convention | Prepared runtime issuance and listener-owner factory | Non-`Clone`/non-`Default` capability plus exact factory/accessor signatures | Replace capability with an event string/raw builder or forge an equivalent | Strengthened through R6/R7 and finally bound to real main in R8 |
| R5-M2 one process gRPC owner spans both generated services | Request and retained-byte acquisition site before decode | Mixed held `Quality` and `Classify` calls share exact permits/bytes | Allocate a separate four-request owner per generated service | Strengthened by asymmetric waves and acquisition fingerprints in R7 |
| R5-M3 both generated services use the finite outer request timeout | Shared outer Tonic layer before service dispatch | Held valid `Quality` and loaded-model `Classify` each produce exact deadline terminal | Apply the timeout only to `ClassifierService` | RED constrained by the finite live-server and all-method tests |
| R5-M4 authorization is applied before pagination and cursor creation | Scoped registry page/cursor iterator | Wildcard and alternating 32-tenant grants traverse exact visible sets; cursor is always visible | Slice before auth, advance on hidden id, or disclose hidden cursor/page bytes | RED constrained by authenticated TCP and HTTP sparse traversals |
| R5-M5 clone/materialization is bounded at its real pre-serializer callsite | `TenantListProbe` attached to production registry projection | Exact per-page peaks/totals and zero work without page budget | Clone all then slice, clone all then authorize, or probe only after slicing | Strengthened in R8 with response-admission-first lifetime clone counters |
| R5-M6 fanout timeout/cancellation restores full weighted capacity | Process-wide call and byte lease owner around downstream RPC body | Held timeout returns all calls/bytes/handlers to zero, then exact four-call/1 MiB recovery completes in order | Leak blocked/in-flight lease, cancel only caller, or restore only count not bytes | RED constrained by `quality_hook_timeout_returns_weighted_leases_and_full_capacity_recovers` |
| R5-m1 cleanup must join owners rather than accept outer cancellation alone | gRPC/TCP/HTTP/startup listener owner result | Listener live before cleanup, bounded inner result, spawned equals collected | Abort accept loop, ignore nested `JoinHandle`, or accept early child/process exit | Strengthened in R8 to quiescence at the exact return instant |

#### R6 review: 0 Blockers, 6 Majors, 1 Minor

| Finding and invariant | Production seam | Positive control | Independent negative mutation | R8 disposition |
|---|---|---|---|---|
| R6-M1 prepared capability is consumed and retained, not reusable by borrow | `ClassifierListenerOwners::from_prepared` by-value constructor | Exact by-value function pointer, retained accessor, no `Clone`/`Default` | Change factory back to `&PreparedRuntimeCapability`, drop it from owners, or reuse it | RED constrained since R7; R8 binds this constructor to the real main |
| R6-M2 symmetric mixed pressure cannot hide a two-plus-two service split | Actual request/body owner acquisitions for both generated services | Wave A is 3 Quality + 1 Classify; wave B is 1 Quality + 3 Classify, each with four opposite plus-ones | Give each service two permits | RED constrained by asymmetric mixed-service waves |
| R6-M3 owner identity comes from acquisition storage, not configured metadata | Request-permit and weighted-body lease allocation fingerprints | Every successful acquisition collapses to one actual request owner and one actual body owner | Report the same configured owner string while allocating separate owners | RED constrained by allocation fingerprints |
| R6-M4 every batch result shares one absolute collection deadline | One wave deadline created before barriers/refusals and used by all `JoinSet` results | All barriers, plus-ones, and eight joins finish under the same `timeout_at` | Start a new duration timeout per result and let total cleanup exceed the contract | RED constrained; R8 applies the same deadline-identity rule to owner cleanup |
| R6-M5 TCP proof observes the actual `Vec`, not a nearby constructor counter | Lease-consuming frame constructor and real allocator boundary | Exact/refusal/recovery allocator counts and bytes | Move the real allocation before the adjacent probe | Strengthened again in R8 for hidden-in-lease allocation and global observation |
| R6-M6 HTTP response admission uses its own JSON wire oracle and precedes serialization | Transport-specific registry response owner | Literal exact JSON body and one-byte-larger 507 with zero serialization | Reuse MessagePack cap, serialize then measure, or use production sizer as oracle | Strengthened in R8 to forbid projection and string cloning as well |
| R6-m1 response-then-panic and socket exchange remain under one owner deadline | Paired TCP child collection and `wire_exchange_before` | Full Version response precedes exactly one typed public-child panic and atomic sibling collection | Panic before response, swallow after response, or reset the timeout for each write/read/join | Strengthened in R8 with deadline identity and zero post-return events |

#### R7 review: 0 Blockers, 6 Majors, 0 Minors

| Finding and invariant | Production seam | Positive control | Independent negative mutation | R8 disposition |
|---|---|---|---|---|
| R7-M1 the actual non-`cfg(test)` crate main uses the sole capability mint/consume assembly | Macro-emitted `main` plus `ReleaseMainBinding`; shipped `/metrics` startup-owner attestation | Binding accepts the real `main`; child exposes all three protocols and exactly one release capability sample | Leave old inline main, test only a selected helper, or add a cfg(test) mirror | New R8 RED constraint |
| R7-M2 allocation-before-lease is impossible and observable at the true `Vec` boundary, including hidden lease payload and refusals | Crate global allocator plus size/alignment-constrained lease and consuming constructor | Four exact real allocations, zero from two plus-ones, exact two recoveries, 16 MiB peak | Preallocate/discard fifth payload or store payload owner inside lease | New R8 RED constraint |
| R7-M3 admin MessagePack and HTTP JSON projection/cloning cannot precede exact/plus-one response admission, and resets cannot erase evidence | Transport-specific response admission before registry `TenantInfo`/`String` projection | Literal 326-byte MessagePack and literal JSON exact pages; exact clone counts; plus-one zero work; final lifetime zero violations | Materialize/clone/serialize before lease, share caps, or reset the violation counter | New R8 RED constraint |
| R7-M4 every TCP/gRPC/startup owner is quiescent at return under one deadline, including response-then-panic | Typed exit report returned by owner future/error with deadline identity | Zero active, finished=spawned, collected=spawned, zero late events at return | Return before delayed reaper, ignore child result, detach sibling, or renew timeout | New R8 RED constraint |
| R7-M5 model manifest has literal empty/id-byte/count bounds at real startup/catalog seam | `ModelCatalogLimits` and `ClassifierRuntime::prepare` before load/bind | 256-byte UTF-8 id and 64 descriptors accepted; empty, 257-byte, and 65 refused with zero ownership | Count chars, enforce getter only, or validate after load/bind | New R8 RED constraint |
| R7-M6 shipped-child normal/Drop/unwind cleanup surfaces every stage failure, retains handles, and shares one deadline | `ChildGuard::cleanup_before`, Drop observation, retention probe | Success plus six failure stages in explicit cleanup, Drop, and unwind, all within 250 ms | Swallow kill/reap/drain/join error, discard handle, create new deadline, or double-panic | New R8 RED constraint |

### Cross-round last-callsite and mutation audit

The complete matrix leaves no finding dependent only on a getter, test-local
owner, adjacent counter, configured identity, post-return sleep, or production
sizing helper.  The final R8 package requires these last-callsite facts in
combination:

1. the bound crate `main` itself enters the by-value capability assembly;
2. the incoming gRPC boundary owns connection and predecode resources for
   both generated services;
3. the frame lease exists before the allocator-observed payload `Vec`;
4. registry authorization and response admission exist before cursor,
   projection, string cloning, and serialization;
5. listener/startup owners collect every child result before returning;
6. the startup catalog rejects bounded manifests before any model or socket
   ownership; and
7. process/drain/thread handles remain owned and observable through every
   cleanup failure, including unwind.

Representative combined mutations are still killed independently: keep the
old inline `main`; emit only a test binding; split gRPC owners by service;
report a configured owner id; make decode/H2 limits getters only; allocate a
frame before its permit; conceal a vector inside the lease; authorize or page
after raw slicing; materialize or serialize before response admission; reset
a lifetime violation; reserve compiled regex state after compile; release an
old generation before its last reader; retain stale fanout peaks; leak a
weighted lease on timeout; move an outcome guard outside a persistent frame
loop; return an owner before its child reaper; swallow a response-then-panic;
validate 65 models after loading one; ignore a drain-thread join error; or
discard the failed handle.

All selected sockets, H2 frames, stream messages, response bodies, child
captures, barriers, process waits, joins, cleanup retries, and page loops have
both finite item/byte bounds and one enclosing absolute deadline.  No
unbounded `read_to_end`, `read_line`, capture file, pipe sink, wait, or retry
loop was introduced.  Synthetic fault payloads remain test-only and do not
cross a release wire or successful assertion message.  The prior privacy,
tensor-shape, postdecode-only, and N-M3 non-claims remain unchanged.

### R8 frozen ownership and source hashes

The exact owned path set remains:

1. `crates/sbproxy-classifier/src/admission.rs`
2. `crates/sbproxy-classifier/src/health.rs`
3. `crates/sbproxy-classifier/src/grpc.rs`
4. `crates/sbproxy-classifier/src/tcp.rs`
5. `crates/sbproxy-classifier/src/main.rs`
6. `crates/sbproxy-core/src/classifier_hooks.rs`
7. `crates/sbproxy-classifier/tests/group_b_startup.rs`
8. `.superpowers/sdd/2026-08-23-wor2661-agy-handoff/ai-group-b-r4-red-report.md`

No non-test production behavior/API implementation, Cargo/lock,
generated/proto, dashboard, operator doc, Group C/E/F, stage, commit, fetch,
push, or deletion is part of this RED authoring pass.  No Cargo, rustc,
nextest, rustfmt, or Clippy command was run.

```text
f5ce616e84baef7c1bac4546898e7ec1ba8ee2a10f99c2d3f5032efb14e1f249  crates/sbproxy-classifier/src/admission.rs
67c65cb73f85ae93b6a11bd52f3a6b052edb27dafa3a15dff5509f467589538e  crates/sbproxy-classifier/src/health.rs
804f1c77c95ad49bdef343acf10d85ec75131ae34f2535744ac54fb8eb6fd31f  crates/sbproxy-classifier/src/grpc.rs
229a20df07556e982144c7d10520d07a01b22e93970d5bf690f9741c1e8dfe0b  crates/sbproxy-classifier/src/tcp.rs
5d337ce268675c64b08ae151d803b7c4674acf339302c10cf35bcddb0d7f0526  crates/sbproxy-classifier/src/main.rs
89d45acb36e458871b88dfdd664ad4de10d83fd1860267e6e13935fa409a9709  crates/sbproxy-core/src/classifier_hooks.rs
1daf1b609d4f251ba5d24f2c7eb0823d454d1d2a6c931d4e47df80f732f25515  crates/sbproxy-classifier/tests/group_b_startup.rs
```

The report hash is intentionally reported externally after append to avoid a
self-referential digest.

AI_GROUP_B_R8_RED_READY_FOR_REREVIEW
