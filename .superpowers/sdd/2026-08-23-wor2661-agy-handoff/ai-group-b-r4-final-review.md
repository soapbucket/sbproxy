# AI Group B Round-4 final independent review

- Date: 2026-08-25
- Status: **NOT APPROVED**
- Findings: **0 Blockers, 10 Majors, 1 Minor**
- Mode: fresh independent static adversarial review; no Cargo, Rust binary,
  rustfmt, edits outside this report, staging, or commits

## Scope and verdict

This review inspected the frozen six-path AI Group B Round-4 RED package,
the controlling handoff and Round-3 review, the Round-4 production design,
the cross-boundary invariant audit, the repository review rubric, and the
current production call sites needed to evaluate whether the tests constrain
the shipped boundaries they claim to constrain.

The package is **not approved**. The corrected package materially improves
tenant identity, compiler-warning, deterministic connection, queue-permit,
model-fixture, and health-route coverage. It nevertheless still permits the
shipped startup path, the full gRPC retained-memory boundary, weighted prompt
high-water, compiled-regex process accounting, list pagination, and several
terminal/cleanup lifecycles to remain wrong while the focused tests pass.

## Findings

### Major 1: the shipped startup path is not mutation-sensitive

- Evidence:
  `crates/sbproxy-classifier/src/admission.rs:278-312`,
  `crates/sbproxy-classifier/src/grpc.rs:483-497`, and
  `crates/sbproxy-classifier/src/tcp.rs:909-928` directly invoke the proposed
  startup/server/listener seams from unit-test code. No selected test enters
  the binary's actual startup path. The current live call sites remain the raw
  frame budget at `crates/sbproxy-classifier/src/main.rs:302-356` and the
  inlined `tonic::transport::Server::builder()` at `main.rs:313-321`.
- Failure scenario: an implementation adds `ClassifierRuntime`,
  `grpc::serve_on`, and `TcpListenerAssembly` only for tests, or adds them as
  unused production helpers, while `main` continues to build an unbounded
  Tonic server, construct/pass raw frame semaphores, and omit the classifier
  panic-policy installer. The selected package can go green while the shipped
  binary retains the original resource and disclosure defects.
- Required correction: make the binary delegate through one production
  runtime/assembly entry point and prove that call site with a shipped-child or
  `run_with_cli` boundary. Merely giving a helper a production-sounding name is
  not a last-callsite proof.

### Major 2: the gRPC process-memory Blocker remains under-specified

- Evidence:
  `crates/sbproxy-classifier/src/grpc.rs:2051-2056` only asserts that
  `max_decoding_message_bytes()` is greater than the one-MiB application text
  limit. `usize::MAX` satisfies that assertion. The real-body pressure test at
  `grpc.rs:1856-1981` sends exactly one-MiB texts and proves the four-request
  outer owner, but never sends a message at the decoding ceiling or verifies
  that the ceiling is applied to either generated service. The selected tests
  also contain no behavioral assertion for finite concurrent H2 streams,
  flow-control windows, outer request timeout, or maximum connection age.
- Failure scenario: `GrpcServerLimits` reports plausible getters while
  `serve_on` omits `max_decoding_message_size` and the finite H2 settings. Four
  arbitrarily large messages can then be decoded/retained concurrently, so the
  documented four-MiB process budget remains false while every selected test
  passes.
- Required correction: pin an upper decode ceiling derived from the process
  budget, send exact/plus-one encoded messages through both services, and add
  mutation-sensitive live assertions for the remaining finite H2 settings.

### Major 3: compiled-regex reservation weight is not tested

- Evidence:
  `crates/sbproxy-classifier/src/tcp.rs:1302-1412` proves reservation lifetime
  using 64 tenants carrying the one-pattern sample config. The aggregate
  registry test at `tcp.rs:1477-1556` proves counts and compile starts within a
  tenant, but never drives a process compiled-state budget to exact/plus-one or
  compares reservations for one versus 64 compiled programs.
- Failure scenario: `TenantRegistryBudget` reserves one fixed unit per tenant,
  regardless of compiled-program count. It passes tenant count, held-`Arc`
  lifetime, pattern-count, compiler-start, and recovery assertions while
  under-accounting a 64-pattern tenant by up to 64 times. The underlying
  persistent compiled-memory Blocker remains reachable.
- Required correction: add independent weighted process-budget fixtures,
  including exact/plus-one compiled-program reservations and replacement while
  the old weighted tenant `Arc` remains live.

### Major 4: pagination and response-byte admission are not staged

- Evidence:
  `crates/sbproxy-classifier/src/tcp.rs:1370-1374` records only one list
  response and `tcp.rs:1429` asserts only `listed <= MAX_LIST_PAGE`. No selected
  code refers to a cursor, traverses every registered tenant across pages,
  rejects a response-byte plus-one, or drives HTTP `/tenants` against the
  bounded page API. This conflicts with the required seam recorded in
  `ai-group-b-r4-red-report.md:106`.
- Failure scenario: the TCP implementation returns an empty list or permanently
  truncates to the first 32 tenants, while HTTP continues to clone/serialize
  the complete registry. The selected test passes even though records are
  unreachable and one production response path remains unbounded.
- Required correction: require a typed cursor/page contract, traverse the exact
  64-tenant set without omission/duplication, enforce a response-byte ceiling
  before serialization, and exercise both authenticated TCP and HTTP callers.

### Major 5: the terminal-outcome matrices are still not exhaustive

- Evidence:
  - `crates/sbproxy-classifier/src/grpc.rs:1383-1423` tests stream bytes and
    rules but never drives `MAX_STREAM_CHUNKS + 1`; removing the chunk-count
    bound remains green.
  - The gRPC matrix at `grpc.rs:970-1544` has no malformed unary protobuf decode
    case, even though the guard is required to start before decoding.
  - The TCP matrix tests header and payload deadlines at
    `crates/sbproxy-classifier/src/tcp.rs:1937-1974`, but the response cases at
    `tcp.rs:2367-2445` inject I/O errors only. A write deadline has no exact
    typed terminal proof.
  - The `assert_wire_case!` helper at `tcp.rs:1861-1884` creates and closes one
    connection per frame. No exact-outcome case writes two valid frames over
    the protocol's persistent connection.
- Failure scenario: a `TcpFrameOutcomeGuard` is moved outside the connection's
  frame loop and counts only the first frame, while the stream chunk-count
  terminal and write-deadline mapping are removed. All selected exact-delta
  cases can still pass.
- Required correction: cover these omitted real branches, including two frames
  on one connection, and require whole-family deltas for each.

### Major 6: the byte-weighted fanout proof reads stale high-water values

- Evidence:
  `crates/sbproxy-core/src/classifier_hooks.rs:752-753` snapshots
  `peak_active` and `peak_prompt_bytes` before the initial blocked requests are
  released at `classifier_hooks.rs:777`. The remaining ten candidates execute
  afterward, but the stale local values are asserted at
  `classifier_hooks.rs:816-823`. The ownership-probe peaks are likewise checked
  before the release at `classifier_hooks.rs:769-775` and not re-read after both
  score tasks join.
- Failure scenario: a global count-two gate admits the two 384-KiB controls and
  initially blocks the 768-KiB request, satisfying every pre-release
  assertion. After release it runs two 768-KiB requests concurrently, reaching
  roughly 1.5 MiB, but the final assertions still compare the earlier 768-KiB
  snapshot and pass.
- Required correction: observe and assert the final peaks after every candidate
  completes, stage a deterministic post-release large/large or large/small
  overlap, and explicitly kill the global-count-two mutation.

### Major 7: the all-method deadline test races its own exact snapshots

- Evidence:
  the held Classify worker uses the same 100-ms admission deadline at
  `crates/sbproxy-classifier/src/grpc.rs:1722-1747`. Its client task is not
  awaited until `grpc.rs:1836-1841`, while the first whole-family snapshot is
  taken at `grpc.rs:1751-1767` and the five queued cases then run sequentially.
- Failure scenario: on a fast run, the held call's worker-deadline terminal
  lands after the first snapshot and contaminates that case with a second
  terminal. On a slower run it lands before the snapshot. The same correct
  implementation therefore passes or fails depending on scheduling, and the
  fixture does not independently assert the holder's terminal.
- Required correction: await and exactly assert the holder's caller deadline
  while its blocking worker remains behind the barrier, then establish a clean
  snapshot baseline before driving the queued-method matrix.

### Major 8: registry byte tests use the production implementation as their oracle

- Evidence:
  `crates/sbproxy-classifier/src/tcp.rs:1615-1631` calls
  `TenantSpec::source_bytes` both to size the filler and to assert the expected
  boundary. `tcp.rs:1669-1685` does the same with
  `TenantSpec::config_bytes`. The admission implementation will consume those
  same helpers.
- Failure scenario: both the helper and validator omit classifier pattern
  bytes, label names, or another persistent field. The fixture simply adds
  more filler to the counted disabled replacement/name, still reaches the
  helper's claimed exact value, and the extra byte is still refused. The
  omitted field remains unbounded while the test passes.
- Required correction: calculate the contract with a test-owned literal oracle
  and add orthogonal fixtures proving each classifier, enabled-normalizer,
  disabled-normalizer, name, pattern, and replacement contribution before the
  mixed aggregate case.

### Major 9: the catalog test has an unrelated compile error

- Evidence:
  `crates/sbproxy-classifier/src/grpc.rs:2351` reads
  `explicit_embedder.dimensions`. The stable protobuf field is
  `ModelInfoResponse.embedding_dim` at
  `crates/sbproxy-classifier-proto/proto/classifier.proto:104`, and the current
  handler constructs `embedding_dim` at `grpc.rs:238-258`.
- Failure scenario: after the intended missing production shells are supplied,
  the focused package still stops on an unapproved field error rather than
  reaching the promised semantic RED. Making it compile by renaming the stable
  source API would create an unnecessary client compatibility break.
- Required correction: assert `explicit_embedder.embedding_dim`.

### Major 10: bounded cleanup remains incomplete

- Evidence:
  - On timeout, the privacy parent calls unbounded `child.wait()` at
    `crates/sbproxy-classifier/src/admission.rs:447-449`.
  - `TestGrpcServer::stop` at
    `crates/sbproxy-classifier/src/grpc.rs:553-557` and
    `TestTcpListenerPair::stop` at
    `crates/sbproxy-classifier/src/tcp.rs:936-940` discard timeout results,
    silently detaching a task that failed to terminate.
  - The direct blocking-worker control awaits `started_rx` with no deadline at
    `admission.rs:218`.
- Failure scenario: a cleanup regression or a worker that never reaches its
  barrier hangs indefinitely during kill/reap, or a server that fails to stop
  is detached and contaminates later process-global metric assertions while
  the test reports success.
- Required correction: use bounded kill/reap and bounded barrier waits, assert
  every cleanup join result, and ensure timeout paths do not leave detached
  tasks or drain threads.

### Minor 1: the frame-refusal socket result is discarded

- Evidence:
  `crates/sbproxy-classifier/src/tcp.rs:1216-1219` waits for the plus-one read
  but discards its inner result. EOF/reset and an unexpected successfully read
  response byte all satisfy the assertion.
- Failure scenario: the owner correctly rejects allocation and increments its
  metric, but emits a protocol-corrupt byte before close. The resource
  assertions remain green and the claimed wire refusal is overstated.
- Required correction: require EOF or an accepted reset/abort error and reject
  any positive byte count.

## Prior Round-4 finding disposition

1. **Sampled OBS matrices / missing exact attempts and siblings:**
   **NOT ADDRESSED.** The whole-family `OutcomeProbe` design is materially
   stronger, but the omitted gRPC/TCP lifecycle cases above leave the
   exhaustive claim false.
2. **Tenant-count test allowed identity replacement:** **ADDRESSED.** The test
   now snapshots the complete sorted key set, verifies both refused ids remain
   absent, and checks `Arc::ptr_eq` for every unaffected tenant.
3. **Registry lacked multi-label, disabled, mixed-byte, and cross-thread
   warning evidence:** **PARTLY ADDRESSED.** Multi-label counts, enabled versus
   disabled compile behavior, and the thread-safe compile-warning probe are
   sound. Source/config byte accounting remains circular and weighted compiled
   reservations remain unproved.
4. **Connection test used scheduling sleeps rather than accepted-permit
   barriers:** **ADDRESSED LOCALLY.** Active-permit probes and the paused test
   clock remove the pressure sleep. The shipped startup callsite can still
   bypass the tested owner, so the overall ownership claim is not closed.
5. **Equal-prompt/count-only fanout and no preallocation/no-dial proof:**
   **NOT ADDRESSED.** Unequal prompts and pre-dial checks were added, but stale
   post-release high-water values allow a global count-two mutation.
6. **Classifier ONNX fixture used as an embedder:** **ADDRESSED.** The package
   requires genuinely shaped classifier/embedder fixtures and tests defaults
   and collisions. The independent `dimensions` compile error remains.
7. **Queue cancellation did not prove permit reuse while the running worker
   stayed held:** **ADDRESSED.** The replacement reuses the sole queue permit,
   remains queued behind the held Classify worker, and the third call receives
   the exact queue-full terminal.
8. **Unbounded child/Tonic waits:** **NOT ADDRESSED.** Ordinary reads and RPCs
   are substantially better bounded, but kill/reap, barrier, and ignored
   cleanup-timeout paths remain.
9. **Privacy child bypassed startup panic policy and real handler assembly:**
   **NOT ADDRESSED AT THE SHIPPED CALLSITE.** The child now invokes the proposed
   production-style APIs and generated client, but no proof requires `main` to
   use those APIs.
10. **Minor malformed-header command attribution:** **ADDRESSED.** Truncated,
    capped, and deadline cases wait for the parsed `/healthz` route barrier and
    require `cmd=healthz`.

## Selected tests, controls, and ownership

Static enumeration confirms exactly 19 unique selected function names across
the five Rust files. The report's intended four standalone PASS controls are:

1. `timed_out_blocking_worker_retains_running_lease_until_worker_exit`
2. `worker_error_and_panic_child` without its private environment marker
3. `omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp`
4. `quality_hook_shares_pre_rpc_prompt_storage_across_candidates`

The remaining 15 names are intended active closure tests. The names are unique
repository-wide. The four-control semantic prediction is not accepted yet:
the catalog field typo blocks the intended post-shell compilation, and the
all-method deadline fixture is scheduling-dependent.

All 19 selected functions and their Round-4 test helpers are beneath the five
files' `#[cfg(test)]` modules (`admission.rs:135`, `health.rs:298`,
`grpc.rs:468`, `tcp.rs:711`, and `classifier_hooks.rs:316`). No Round-4
production implementation is present in those owned paths. That clean
test-only ownership does not remedy Major 1: the proposed GREEN can still add
parallel/test-only seams without rewiring the binary.

## Checked and sound

- Exact tenant key/identity and final-reader reservation lifetime assertions
  are strong for the one-pattern reservation they exercise.
- Multi-label aggregate counts, enabled/disabled normalization compile
  behavior, and thread-safe warning observation are sound apart from the
  independent byte/reservation gaps above.
- Queue cancellation proves both gauge restoration and actual queue-permit
  reuse while the running worker remains held.
- Connection-pressure setup uses production-observed permit barriers and a
  paused test clock rather than a fixed sleep.
- Genuine mixed and embedder-only fixtures replace the invalid
  classifier-as-embedder shortcut; duplicate and default-kind cases enter the
  proposed startup preparation seam before load/bind.
- `/healthz` route attribution is pinned after the start line for truncation,
  cap, and deadline outcomes.
- Retained HTTP/raw-TCP/privacy buffers are capped, stream-terminal reads use
  one absolute deadline and a message ceiling, and raw H2 draining uses one
  absolute deadline and a frame ceiling. The remaining cleanup gaps are
  reported above rather than obscuring these sound improvements.

## Frozen hashes and static verification

```text
dae0c2d5dfbc0b2caf97fbb3a37a1bcadc0b94ccb91e9932c724e43e2d5072a9  crates/sbproxy-classifier/src/admission.rs
dc934006972ab96ff187f8c73f18c3daca56b7c6ebd1e939196e901631e236f9  crates/sbproxy-classifier/src/health.rs
f94c67ffc914f6c6c47780e89e0fcfe6c5bc4b571e6e6f56706f881b6a21a98c  crates/sbproxy-classifier/src/grpc.rs
559be67d1ecdaf4fd79acab9f614af21ddca83d27757487fc2d71381a70efe49  crates/sbproxy-classifier/src/tcp.rs
6055a08ff27608226fb5a619caf2ea6b20814b895e66572269ba2bc46d230b01  crates/sbproxy-core/src/classifier_hooks.rs
7d1bee26da66939afce4d539af606639dd231b97839199f05546b31174d7a81d  .superpowers/sdd/2026-08-23-wor2661-agy-handoff/ai-group-b-r4-red-report.md
```

Static checks performed against those frozen bytes:

- `git diff --check` passed for the five tracked owned Rust paths.
- A direct trailing-whitespace scan passed for all six owned paths, including
  the untracked report.
- Conflict-marker, TODO/FIXME, `todo!`, `unimplemented!`, and mutation-marker
  scans found no prohibited scaffolding in the owned paths.
- All 19 selected names occur exactly once repository-wide.
- Hashes were read twice and remained stable during the review.

No Cargo, Rust binary, rustfmt, staging, commit, fetch, push, or production/test
edit was performed by this reviewer.
