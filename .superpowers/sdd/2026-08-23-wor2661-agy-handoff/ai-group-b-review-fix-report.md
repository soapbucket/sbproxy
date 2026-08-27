# AI Group B independent-review fix report

## Checkpoint

`AI_REVIEW_GREEN_READY`

This report preserves the accepted RED evidence and records the minimal GREEN
implementation for the frozen Group B independent-review round. No Cargo,
rustc, rustfmt, staging, or commit command was run by the implementation lane.
Groups C through F and the mixed Group A files remain out of scope. Root
`llms.txt` and `crates/sbproxy-classifier/src/quality.rs` were not altered.

The sections describing the original failures are retained as the RED
contract. The implementation and exact proposed GREEN command follow them.

## RED tests

### Blocker: aggregate TCP frame memory

- `tcp::tests::public_listener_caps_simultaneous_header_only_max_frames_at_16_mib`
  starts the real public listener at the accepted 128-connection ceiling,
  sends five simultaneous 4 MiB length headers without bodies, proves all five
  headers reached framing, and requires the allocation-boundary peak to remain
  exactly 16 MiB. The current code reaches 20 MiB because every connection
  allocates before any shared byte lease exists.
- `tcp::tests::config_rejects_out_of_bounds_tcp_limits` now treats 128 as the
  accepted ceiling and 129 as ceiling-plus-one. The current `1..=100000`
  validation accepts 129.

The production mutation each test must kill is either removing the aggregate
lease or acquiring it after `vec![0; msg_len]`. The later GREEN must introduce
a process-wide 16 MiB lease acquired before the payload allocation and lower
the configuration ceiling to 128.

### Blocker: gRPC backpressure cannot erase the first unsafe verdict

- `grpc::tests::saturated_response_channel_cannot_turn_first_unsafe_token_into_clean_eof`
  uses the actual tonic handler. Sixteen safe verdicts fill the response
  channel, the seventeenth input is the first forbidden match, and response
  consumption resumes only after the outer admission deadline has released
  its lease. After the sixteen accepted safe verdicts, the test requires
  either the unsafe transition or an explicit deadline/resource status. Clean
  EOF is forbidden. The current `try_send(Full)` branch drops the unsafe
  verdict, returns `Ok(())`, and produces clean EOF.

The production mutation this test must kill is collapsing a full verdict
channel or a crowded-out terminal status into clean completion.

### Major: deterministic HTTP header refusal

- `health::tests::header_byte_cap_returns_an_exact_parser_error` requires an
  `InvalidData` error with exactly `HTTP request headers exceed 8192-byte
  limit` and no HTTP 200 response.
- `health::tests::truncated_headers_return_an_exact_parser_error` requires an
  `UnexpectedEof` error with exactly `HTTP request headers ended before blank
  line` and no HTTP 200 response.

The client remains connected and reads the server result, so neither test can
pass because of a client-side write/reset failure. Current cap exhaustion and
ordinary EOF are both cleared into an empty string and mistaken for the blank
header terminator.

### Major: admin-token files must be regular and nonblocking to inspect

- `auth::tests::mode_0600_fifo_without_a_writer_is_rejected_promptly` creates
  a real mode-0600 FIFO with no writer and delegates `AdminAuth::from_file` to
  an isolated child test process. The parent polls for two seconds, kills and
  reaps a blocked child, and then fails its prompt-return assertion. A passing
  child must observe an explicit `must be a regular file` descriptor refusal
  and write a marker, preventing a false pass if the exact child filter does
  not run.
- `auth::tests::auth_file_read_is_capped_when_a_regular_file_grows_after_metadata`
  replaces the obsolete FIFO growth fixture. It grows the same regular file
  after descriptor metadata and proves the existing 256 KiB-plus-one actual
  read cap still holds. This is expected to remain GREEN during the RED run.

The production fix must open Unix paths nonblocking and without following a
replacement symlink, then validate regular-file type, mode, size, and content
from that same descriptor. Merely checking path metadata or capping a blocking
FIFO read will not satisfy the child contract.

### Major: TCP validation must own the readiness and server seams

- `main::tests::invalid_tcp_limits_cannot_publish_readiness` sends both zero
  and 129 connections through the exact private pre-bind helper before making
  one literal assertion over both observations. Current code binds all
  listeners and publishes readiness for both.
- `tcp::tests::serve_on_defensively_rejects_limits_above_the_connection_ceiling`
  starts `serve_on` with 129 connections behind a task-start handshake. The
  current helper reaches `accept()` instead of finishing with the full
  `TcpLimits::validate` error. The test aborts the pending task before failing
  its behavioral assertion, so it does not rely on a test-runner timeout.

The production fix must validate TCP and HTTP limits in the pre-bind helper
and call the complete `TcpLimits::validate` defensively at the start of
`tcp::serve_on`.

## Test-only seams

Three narrow seams exist only under `cfg(test)` and do not change a production
binary:

1. `bind_required_listeners` accepts an ignored test-build-only `TcpLimits`
   argument. This lets RED reach the exact listener/readiness seam without a
   wished-for API compile failure. GREEN should make the argument
   unconditional and validate it before any bind.
2. `tcp::serve_on` and `handle_connection` accept a per-listener
   `FrameAllocationProbe` only in unit-test builds. It counts declared headers
   and tracks current/peak bytes at the exact allocation boundary. It is owned
   by one test and uses no process-global state. GREEN must acquire the real
   byte lease before this observation point.
3. `AdminAuth::from_file` invokes a same-thread post-metadata hook only in
   tests. It deterministically grows the already-open regular file and
   preserves the previous actual-read-cap coverage after FIFOs become invalid.

## Exact controller RED command

### Invalid first attempt and test-only correction

The controller's first RED attempt is invalid and uncredited. Compilation
failed with E0521 at `health.rs:305`: the parser assertion helper accepted
`&(dyn std::error::Error + Send + Sync)` and then called
`downcast_ref::<std::io::Error>()`, which requires a `'static` trait object.
No selected behavior test ran.

The test helper now accepts
`&(dyn std::error::Error + Send + Sync + 'static)`. This matches the
`Box<dyn std::error::Error + Send + Sync>` returned by `handle_health` and
changes only test inspection. No production or operator-documentation
behavior changed. The corrected RED retry below is the same selection and
command as the invalid attempt.

The controller's corrected-lifetime retry compiled and selected exactly nine
tests. It reported one pass and eight failures. Seven failures reached their
intended behavioral assertions, and the growing-regular-file characterization
passed. The header-cap failure is still invalid and uncredited: after the
server closed a connection with unread request bytes, the client received
`ConnectionReset` at `health.rs:290`; its `read_to_string(...).unwrap()`
panicked, and `client.await.unwrap()` masked the server parser result.

The client half of `health_parse_result` now ignores write/shutdown errors,
retains every response byte it receives, and treats reset-like read errors as
normal connection termination. It cannot panic on reset or write behavior.
The server result remains the test contract: current production must reach
`result.expect_err(...)` as `Ok(())` rather than the required exact
`InvalidData` error. The retry command and nine-test selection remain
unchanged.

Run from `/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster`:

```bash
export CARGO_TARGET_DIR="$PWD/target-ai-cluster"
export CARGO_BUILD_JOBS=2
export NEXTEST_HIDE_PROGRESS_BAR=1
cargo nextest run -p sbproxy-classifier --no-fail-fast \
  -E 'test(public_listener_caps_simultaneous_header_only_max_frames_at_16_mib) | test(config_rejects_out_of_bounds_tcp_limits) | test(saturated_response_channel_cannot_turn_first_unsafe_token_into_clean_eof) | test(header_byte_cap_returns_an_exact_parser_error) | test(truncated_headers_return_an_exact_parser_error) | test(auth_file_read_is_capped_when_a_regular_file_grows_after_metadata) | test(mode_0600_fifo_without_a_writer_is_rejected_promptly) | test(invalid_tcp_limits_cannot_publish_readiness) | test(serve_on_defensively_rejects_limits_above_the_connection_ceiling)' \
  --no-capture
```

Expected selection: exactly 9 tests.

Expected result: 1 pass and 8 intended behavioral failures, with no compile
error and no test-runner timeout.

- PASS: `auth_file_read_is_capped_when_a_regular_file_grows_after_metadata`.
- FAIL: public TCP frame peak is 20 MiB, not 16 MiB.
- FAIL: TCP config validation accepts 129 connections.
- FAIL: saturated gRPC output ends in clean EOF after sixteen safe verdicts.
- FAIL: capped HTTP headers return `Ok(())` and HTTP 200 instead of the exact
  `InvalidData` parser error.
- FAIL: truncated HTTP headers return `Ok(())` and HTTP 200 instead of the
  exact `UnexpectedEof` parser error.
- FAIL: the isolated FIFO child is still blocked after two seconds and is
  killed/reaped before the parent assertion.
- FAIL: zero and 129 TCP limits both bind and mark readiness.
- FAIL: `tcp::serve_on` remains pending in `accept()` for 129 connections and
  is aborted before the test assertion.

Any compiler error, a different selection count, a pass in one of those eight
cases, failure of the growing-regular-file characterization, or a nextest
timeout is invalid RED evidence and must be reconciled before production
changes.

### Accepted RED evidence

The controller ran the corrected exact command above and accepted the result:
exactly nine tests selected, the growing-regular-file characterization passed,
and the other eight failed for the intended semantic causes. In particular,
the corrected HTTP harness reached `capped header block must return a parser
error: ()` and the exact truncated-header `Ok(())` failure. The FIFO child was
bounded at approximately two seconds, and there was no runner timeout.

The two preceding attempts remain explicitly uncredited: the first failed to
compile because of the test-helper lifetime, and the second masked the capped
header result with a client connection-reset panic.

## Implementation after accepted RED

- TCP now validates a 128-connection ceiling both before listener binding and
  at the start of `serve_on`. Public and admin listeners share one 16 MiB
  semaphore, and each declared frame acquires its byte lease before the body
  vector is allocated. Exhaustion records a bounded `resource_limit` refusal
  and closes that connection.
- Streaming safety now awaits each verdict send within the existing admission
  deadline. Semantic/input errors return to the outer task, and a separate
  one-item-by-construction terminal-status channel is chained after the
  bounded verdict channel. A full verdict channel can therefore produce the
  unsafe transition when consumption resumes or an explicit deadline status,
  never clean EOF.
- HTTP parsing now requires a newline-terminated request line and every header
  line plus an explicit blank terminator. Cap exhaustion returns exact
  `InvalidData`; ordinary premature EOF returns exact `UnexpectedEof`.
  `health::serve_on` also performs its full defensive limit validation.
- Admin-token loading uses an `OpenOptions` descriptor with Unix
  `O_NONBLOCK | O_NOFOLLOW`, refuses non-regular descriptors, and validates
  mode, metadata size, and capped contents through that same descriptor. The
  regular-file growth characterization remains intact.
- `bind_required_listeners` owns full TCP and HTTP validation before the first
  bind and before readiness can be published.
- `docs/classifier-sidecar.md` is dated 2026-08-24 and documents every rich
  sidecar configurable default/maximum, fixed gRPC/HTTP/auth bounds, the 128
  TCP ceiling, shared 16 MiB frame budget, and regular/nonblocking/no-follow
  admin-token contract.
- The inherited `auth.rs` blank/long assertion and `health.rs` grouped-import
  formatting findings were corrected manually. `rustfmt` was not run because
  this handoff expressly limits the implementation lane to static inspection.

The test-only allocation probe and auth growth hook remain `cfg(test)` only.
The readiness seam became the production seam it observes; none of the test
observability hooks changes production behavior.

## Exact proposed controller GREEN command

Run from `/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster`:

```bash
export CARGO_TARGET_DIR="$PWD/target-ai-cluster"
export CARGO_BUILD_JOBS=2
export NEXTEST_HIDE_PROGRESS_BAR=1
cargo nextest run -p sbproxy-classifier --no-fail-fast \
  -E 'test(public_listener_caps_simultaneous_header_only_max_frames_at_16_mib) | test(config_rejects_out_of_bounds_tcp_limits) | test(saturated_response_channel_cannot_turn_first_unsafe_token_into_clean_eof) | test(header_byte_cap_returns_an_exact_parser_error) | test(truncated_headers_return_an_exact_parser_error) | test(auth_file_read_is_capped_when_a_regular_file_grows_after_metadata) | test(mode_0600_fifo_without_a_writer_is_rejected_promptly) | test(invalid_tcp_limits_cannot_publish_readiness) | test(serve_on_defensively_rejects_limits_above_the_connection_ceiling)' \
  --no-capture
```

Expected GREEN: exactly 9 tests selected and 9 passed, with no warning,
compile error, test failure, or timeout. In particular, the gRPC terminal item
must be an unsafe verdict or explicit deadline/resource status; both HTTP
tests must reach their exact parser-error assertions; the FIFO child must
return promptly with the explicit regular-file refusal; the aggregate frame
peak must be exactly 16 MiB; and zero/129 TCP limits must be refused before
readiness and at the defensive server seam.

## Static evidence

- `git diff --check`: exit 0.
- Exact test names are present in `auth.rs`, `grpc.rs`, `health.rs`, `main.rs`,
  and `tcp.rs`.
- No `patch_*.sh` files are present.
- The scoped production and operator-documentation implementation is present.
  No `llms.txt` or `quality.rs` edit was made in this checkpoint.
- `quality.rs` hashes to its exact HEAD blob,
  `89a8e2ec1feb953d5e3029f92a94b95e4ea0e1d5`; restored root `llms.txt`
  remains `7252c3b9ce747fa302c8f099cb1bf788f4fb23ff`.

## Accepted GREEN and combined production mutation

The controller ran the exact nine-test command above against the completed
implementation. Accepted result: 9 selected, 9 passed, 75 skipped, with no
timeout. Before applying the mutation, the five production files changed by
this batch had these accepted-GREEN hashes:

| Production file | Accepted-GREEN hash |
|---|---|
| `crates/sbproxy-classifier/src/auth.rs` | `81c74578da92ed9dadd0b8d167ec2a3b6e163fcd` |
| `crates/sbproxy-classifier/src/grpc.rs` | `0468ab1d7e3923facdac277f0a56f416404194e7` |
| `crates/sbproxy-classifier/src/health.rs` | `6750b0bc434d4d57d6b9b39ba69636a9b3557068` |
| `crates/sbproxy-classifier/src/main.rs` | `4b18d1c783114b1bc3abf0bb5ed5f256ef1700c7` |
| `crates/sbproxy-classifier/src/tcp.rs` | `9bc3345f14d2979caad0d83cc875954376cc83fd` |

One production-only mutation batch is now active. Its nine mechanical sites
are searchable with:

```bash
rg -n 'MUTATION\(ai-group-b-review\)' \
  crates/sbproxy-classifier/src/{auth,grpc,health,main,tcp}.rs
```

The active mutations are:

- `tcp.rs`: restore the old 100,000 connection ceiling, bypass defensive
  `serve_on` validation, and replace the pre-allocation frame-byte lease with
  an unconstrained `None` guard. Five header-only maximum frames can therefore
  reach a 20 MiB observed allocation peak.
- `grpc.rs`: send terminal status through the already-full bounded verdict
  channel and use `try_send` for verdicts. `Full` and `Closed` both become
  clean completion.
- `health.rs`: bypass defensive HTTP `serve_on` validation and once again
  treat zero-byte/cap-exhausted reads as the blank request/header boundary.
- `auth.rs`: use blocking, symlink-following `File::open` and omit the regular
  descriptor check. A mode-0600 FIFO without a writer blocks before metadata.
- `main.rs`: consume but do not validate the TCP/HTTP limits before binding
  listeners and publishing readiness.

No test, operator-documentation, Cargo manifest/lockfile, `llms.txt`, or
`quality.rs` content changed for the mutation. No Cargo, Rust, rustfmt,
staging, or commit command was run by the implementation lane.

### Exact mutation command and expected kill signature

Run from `/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster`:

```bash
export CARGO_TARGET_DIR="$PWD/target-ai-cluster"
export CARGO_BUILD_JOBS=2
export NEXTEST_HIDE_PROGRESS_BAR=1
cargo nextest run -p sbproxy-classifier --no-fail-fast \
  -E 'test(public_listener_caps_simultaneous_header_only_max_frames_at_16_mib) | test(config_rejects_out_of_bounds_tcp_limits) | test(saturated_response_channel_cannot_turn_first_unsafe_token_into_clean_eof) | test(header_byte_cap_returns_an_exact_parser_error) | test(truncated_headers_return_an_exact_parser_error) | test(auth_file_read_is_capped_when_a_regular_file_grows_after_metadata) | test(mode_0600_fifo_without_a_writer_is_rejected_promptly) | test(invalid_tcp_limits_cannot_publish_readiness) | test(serve_on_defensively_rejects_limits_above_the_connection_ceiling)' \
  --no-capture
```

Expected mutation kill: exactly 9 selected, 1 passed, and 8 failed, with no
compile error and no runner timeout. The only pass must be
`auth_file_read_is_capped_when_a_regular_file_grows_after_metadata`. Expected
failures are the 20 MiB TCP allocation peak, acceptance of 129 TCP
connections, clean gRPC EOF after sixteen safe verdicts, `Ok(())`/HTTP 200 for
both malformed HTTP cases, the bounded two-second FIFO refusal failure,
readiness publication for zero and 129 TCP limits, and `tcp::serve_on`
remaining in `accept()` for 129 until its test aborts it.

### Mechanical restoration after the controller run

Restore every marked site with one `apply_patch` operation:

1. In `tcp.rs`, reinstate `1..=DEFAULT_MAX_CONNECTIONS` and the exact
   `1..=128` error, reinstate `limits.validate()?` at the start of `serve_on`,
   and replace the `None` frame guard with the accepted-GREEN
   `u32::try_from(msg_len)` plus `try_acquire_many_owned` block before the
   allocation observation and `vec!`.
2. In `grpc.rs`, reinstate the separate unbounded terminal-status channel,
   chain it after `ReceiverStream::new(rx)`, send the outer error through that
   channel, and reinstate `tx.send(Ok(verdict)).await`.
3. In `health.rs`, reinstate `limits.validate()?`, require a nonzero,
   newline-terminated request line, and require every header line plus an
   explicit `\r\n` or `\n` terminator. Restore the exact `InvalidData` cap
   and `UnexpectedEof` truncated-header messages.
4. In `auth.rs`, reinstate read-only `OpenOptions` with Unix
   `O_NONBLOCK | O_NOFOLLOW`, then reject a non-regular descriptor before
   checking mode, size, and contents from the same file.
5. In `main.rs`, replace the ignored limit tuple with `tcp_limits.validate()?`
   followed by `http_limits.validate()?` before the first bind.

Remove all nine mutation markers, run `git diff --check`, and confirm all five
files reproduce the accepted-GREEN hashes above before asking the controller
to rerun the exact command for 9/9 GREEN restoration.

## Accepted mutation kill and exact GREEN restoration

The controller ran the exact nine-test command against the combined mutation.
Accepted result: exactly 9 selected, only
`auth_file_read_is_capped_when_a_regular_file_grows_after_metadata` passed,
the other 8 failed for their intended semantic causes, 75 were skipped, and
there was no compile error or runner timeout.

All nine production mutation sites were then restored with one `apply_patch`
operation. No marker remains, and every changed source file now reproduces
its recorded accepted-GREEN hash exactly:

| Restored production file | Restored hash |
|---|---|
| `crates/sbproxy-classifier/src/auth.rs` | `81c74578da92ed9dadd0b8d167ec2a3b6e163fcd` |
| `crates/sbproxy-classifier/src/grpc.rs` | `0468ab1d7e3923facdac277f0a56f416404194e7` |
| `crates/sbproxy-classifier/src/health.rs` | `6750b0bc434d4d57d6b9b39ba69636a9b3557068` |
| `crates/sbproxy-classifier/src/main.rs` | `4b18d1c783114b1bc3abf0bb5ed5f256ef1700c7` |
| `crates/sbproxy-classifier/src/tcp.rs` | `9bc3345f14d2979caad0d83cc875954376cc83fd` |

Those whole-file hashes also prove the embedded unit tests returned exactly
to their accepted-GREEN bytes. The mutation-excluded operator document
`docs/classifier-sidecar.md` remains
`f3dab82eaf4dad30445ccc88d7a686a82cb85c84`. Protected
`crates/sbproxy-classifier/src/quality.rs` remains its exact HEAD blob,
`89a8e2ec1feb953d5e3029f92a94b95e4ea0e1d5`, and restored root `llms.txt`
remains `7252c3b9ce747fa302c8f099cb1bf788f4fb23ff`.

Static restoration evidence:

- `rg -n 'MUTATION\(ai-group-b-review\)'` over the five production files
  returns no matches.
- `git diff --check` exits 0.
- No test, operator-documentation, Cargo manifest/lockfile, `llms.txt`, or
  `quality.rs` content changed during mutation restoration.
- No Cargo, Rust, rustfmt, staging, or commit command was run by the
  implementation lane.

### Exact final GREEN command

Run from `/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster`:

```bash
export CARGO_TARGET_DIR="$PWD/target-ai-cluster"
export CARGO_BUILD_JOBS=2
export NEXTEST_HIDE_PROGRESS_BAR=1
cargo nextest run -p sbproxy-classifier --no-fail-fast \
  -E 'test(public_listener_caps_simultaneous_header_only_max_frames_at_16_mib) | test(config_rejects_out_of_bounds_tcp_limits) | test(saturated_response_channel_cannot_turn_first_unsafe_token_into_clean_eof) | test(header_byte_cap_returns_an_exact_parser_error) | test(truncated_headers_return_an_exact_parser_error) | test(auth_file_read_is_capped_when_a_regular_file_grows_after_metadata) | test(mode_0600_fifo_without_a_writer_is_rejected_promptly) | test(invalid_tcp_limits_cannot_publish_readiness) | test(serve_on_defensively_rejects_limits_above_the_connection_ceiling)' \
  --no-capture
```

Expected final GREEN: exactly 9 selected and 9 passed, with 75 skipped and no
compile error, failure, or timeout.

## Round 3 invariant-level RED checkpoint

The independent adversarial re-review reported five Majors: routine
omitted/empty-tenant warnings, missing refusal metrics, auth descriptor
identity proof gaps, an unisolated HTTP `serve_on` validation invariant, and
synthetic rather than allocator-coupled TCP frame observation. This checkpoint
adds only tests and narrow test observation seams. Accepted runtime behavior
and operator documentation are unchanged; Groups C through F remain unopened.

### Invariant tests and independent mutations

- `tcp::tests::omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp`
  sends both wire shapes through real public length-prefixed MessagePack
  sockets. Each refusal is decoded and the release-level subscriber must see
  exactly zero WARN events. Current `Registry::get` emits two WARNs. Replacing
  only that routine `warn!` with non-release logging makes this test pass.
- `health::tests::http_connection_slot_refusal_records_closed_error_labels`
  occupies the sole real HTTP listener slot with a partial request, drives a
  second full request to an observed socket close, then completes the first
  request cleanly. It requires exactly one increment at
  `http/unknown/resource_limit`.
- `health::tests::http_parser_refusals_record_closed_error_labels` sends a
  capped header and an ordinarily truncated header through the actual
  `serve_on` loop. It requires one increment at
  `http/decode/resource_limit` for the cap and one at
  `http/decode/malformed_frame` for truncation.
- `health::tests::slowloris_deadline_releases_http_admission_slot` retains its
  real slot-release/next-request proof and now additionally requires one
  `http/unknown/deadline` increment.
- `tcp::tests::oversized_tcp_frame_refusal_records_closed_error_labels` sends
  a 4 MiB-plus-one length prefix through the real public server and requires
  one `tcp/decode/resource_limit` increment before the connection closes.
  These four metric cases read exact label children from the production
  `sbproxy_classifier_errors_total`; no fake recorder or test-only writer is
  involved. Removing any corresponding production `record_error` call, or
  choosing a different normalized label, independently fails its assertion.
- `auth::tests::final_component_symlink_is_refused_without_following` supplies
  a valid mode-0600 target through a final-component symlink. Current
  `O_NOFOLLOW` refuses it; removing only that flag makes the test accept the
  target and fail.
- `auth::tests::post_open_path_replacement_cannot_change_auth_descriptor_identity`
  atomically replaces the pathname after descriptor metadata with a distinct
  valid auth file. It requires authorization from the original open inode and
  rejects the replacement token. Reopening only the pathname for content
  independently fails this test.
- `health::tests::serve_on_defensively_rejects_each_http_limit_boundary`
  directly and task-boundedly calls the actual server with zero and 100001
  connections, then zero and 60001 ms deadlines. It pins both exact validation
  messages. Removing only the defensive `limits.validate()?` leaves the first
  server in `accept()` and the test aborts it before failing, rather than
  relying on a runner timeout.
- `tcp::tests::public_listener_caps_simultaneous_header_only_max_frames_at_16_mib`
  now observes the function that performs `vec![0u8; bytes]` itself. The
  observation guard is returned with the real payload, and the test requires
  five declared headers but exactly four allocator calls and a 16 MiB peak.
  Moving the actual allocation call above the lease produces five allocator
  calls and a 20 MiB peak, so that mutation can no longer hide behind the
  old post-lease synthetic counter.

### Test-only seams

- `metrics::error_count` is `cfg(test)` and only reads an exact child of the
  production counter family. It neither records nor substitutes a metric.
- The TCP test build routes payload construction through
  `ObservedFramePayload`; its observation is created only after the real
  vector allocation and lives with that allocation. The non-test build still
  performs the same single `vec![0u8; bytes]` allocation.
- The existing thread-local post-metadata auth hook coordinates pathname
  replacement after the real descriptor is open. It remains `cfg(test)` and
  does not alter a production binary.

### Exact Round 3 controller RED command

Run from `/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster`:

```bash
export CARGO_TARGET_DIR="$PWD/target-ai-cluster"
export CARGO_BUILD_JOBS=2
export NEXTEST_HIDE_PROGRESS_BAR=1
cargo nextest run -p sbproxy-classifier --no-fail-fast \
  -E 'test(omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp) | test(http_connection_slot_refusal_records_closed_error_labels) | test(http_parser_refusals_record_closed_error_labels) | test(slowloris_deadline_releases_http_admission_slot) | test(oversized_tcp_frame_refusal_records_closed_error_labels) | test(final_component_symlink_is_refused_without_following) | test(post_open_path_replacement_cannot_change_auth_descriptor_identity) | test(serve_on_defensively_rejects_each_http_limit_boundary) | test(public_listener_caps_simultaneous_header_only_max_frames_at_16_mib)' \
  --no-capture
```

Expected RED: exactly 9 selected, 4 passed, and 5 failed, with 82 skipped and
no compile error or runner timeout.

Expected passes:

- final-component symlink refusal;
- post-open descriptor identity under pathname replacement;
- all four direct HTTP server validation boundaries;
- allocator-coupled TCP accounting at four allocations and 16 MiB.

Expected failures:

- omitted/empty tenants produce two WARN events instead of zero;
- HTTP slot saturation leaves `http/unknown/resource_limit` unchanged;
- HTTP cap/truncation leave their exact `http/decode/*` children unchanged;
- HTTP whole-connection expiry leaves `http/unknown/deadline` unchanged;
- the oversized TCP frame leaves `tcp/decode/resource_limit` unchanged.

Any compile error, timeout, different selection count, characterization-test
failure, or additional pass is invalid RED evidence and must be reconciled
before production or operator-documentation changes.

Round 3 static evidence:

- `git diff --check` exits 0, and the report has no trailing whitespace.
- The classifier test binary contains 91 unit tests after the seven new tests;
  the exact nine-test selection therefore leaves 82 skipped.
- `docs/classifier-sidecar.md` remains
  `f3dab82eaf4dad30445ccc88d7a686a82cb85c84`.
- Protected `quality.rs` remains
  `89a8e2ec1feb953d5e3029f92a94b95e4ea0e1d5`, and restored root `llms.txt`
  remains `7252c3b9ce747fa302c8f099cb1bf788f4fb23ff`.
- No production mutation marker, conflict marker, or `patch_*.sh` helper is
  present. No Cargo, Rust, rustfmt, staging, or commit command was run by the
  implementation lane.

## Round 3 accepted RED and GREEN implementation

The controller ran the exact Round 3 selection. Accepted RED: 9 selected, 4
passed, 5 failed for the intended semantic causes, 82 skipped, with no
compile, harness, or timeout issue. The two auth invariants, direct HTTP
validation, and allocator-coupled frame characterization passed. The routine
tenant warning plus four refusal-observability tests failed exactly as
specified.

Minimal GREEN implementation after that accepted RED:

- `Registry::get` emits `debug!`, not `warn!`, for absent or empty tenant ids.
  The existing public handler remains responsible for its bounded response
  and `tenant_not_registered` metric.
- `health::serve_on` owns one terminal-outcome vocabulary and one mapping to
  `sbproxy_classifier_errors_total`. Slot exhaustion records
  `http/unknown/resource_limit`; exact cap exhaustion records
  `http/decode/resource_limit`; truncated or otherwise malformed parser input
  records `http/decode/malformed_frame`; and the whole-connection timeout
  records `http/unknown/deadline`. The mapping runs once at the listener
  boundary. Authenticated `/tenants` refusal remains its separate request
  decision and is not double-counted as a terminal parser/admission outcome.
- The oversized-frame branch records `tcp/decode/resource_limit` immediately
  after decoding a length above 4 MiB and before closing the public socket.
- Auth opening remains `O_NONBLOCK | O_NOFOLLOW`, and type, mode, size, and
  contents still come from the same descriptor. `health::serve_on` still
  performs full validation before constructing admission or awaiting accept.
- `BudgetedFrame` is now the production owner of both the semaphore permit and
  payload. Its sole constructor converts the declared length, acquires the
  full byte lease, performs the real vector allocation, installs the test-only
  allocator observation, and returns a type that keeps the permit alive with
  the bytes. Callers cannot construct or receive an unleased payload buffer.

### Round 3 last-callsite mutation ledger

| Finding | Last production callsite/invariant | Independent mutation killed by |
|---|---|---|
| Routine absent/empty tenant WARN | `Registry::get`'s absent/empty branch is `debug!` | Change only this call back to `warn!`; the real public MessagePack warning test observes two WARNs. |
| HTTP refusal metrics | `record_http_terminal_outcome` is the sole listener-boundary label mapping; `serve_on` invokes it once for slot full, classified parser failure, or deadline | Remove any one invocation, map any variant to another label, or invoke it twice; the corresponding exact production-counter delta is respectively 0, on the wrong child, or 2 instead of 1. |
| TCP oversized-frame metric | `msg_len > MAX_FRAME_BYTES` records `tcp/decode/resource_limit` before return | Remove that call or change one label; the real public oversized-frame counter delta remains zero at the expected child. |
| Auth and HTTP defensive invariants | `OpenOptions` retains `O_NOFOLLOW`; all auth reads use `file`; `health::serve_on` begins with `limits.validate()?` | Drop only `O_NOFOLLOW`, reopen only the pathname after metadata, or remove only direct validation; the symlink, replacement-identity, or bounded four-case server test fails independently. |
| Aggregate frame allocation | `BudgetedFrame::try_new` acquires the owned permit before its only `vec!` and owns both until drop | Move the allocation/observation block above acquisition: five real allocations and a 20 MiB peak replace four and 16 MiB. Bypass the constructor with a raw vector: allocator-call count falls outside the required four and the test fails. |

### Exact Round 3 proposed GREEN command

Run from `/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster`:

```bash
export CARGO_TARGET_DIR="$PWD/target-ai-cluster"
export CARGO_BUILD_JOBS=2
export NEXTEST_HIDE_PROGRESS_BAR=1
cargo nextest run -p sbproxy-classifier --no-fail-fast \
  -E 'test(omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp) | test(http_connection_slot_refusal_records_closed_error_labels) | test(http_parser_refusals_record_closed_error_labels) | test(slowloris_deadline_releases_http_admission_slot) | test(oversized_tcp_frame_refusal_records_closed_error_labels) | test(final_component_symlink_is_refused_without_following) | test(post_open_path_replacement_cannot_change_auth_descriptor_identity) | test(serve_on_defensively_rejects_each_http_limit_boundary) | test(public_listener_caps_simultaneous_header_only_max_frames_at_16_mib)' \
  --no-capture
```

Expected GREEN: exactly 9 selected and 9 passed, with 82 skipped and no
compile error, warning, failure, or timeout.

Proposed Round 3 GREEN source hashes for controller acceptance/restoration:

| Source file | Proposed GREEN hash |
|---|---|
| `crates/sbproxy-classifier/src/auth.rs` | `2931a47d96b1bac02c38370a4b83d83da1273953` |
| `crates/sbproxy-classifier/src/health.rs` | `f567e7ca13db5b456740875880aef7b24472df6f` |
| `crates/sbproxy-classifier/src/metrics.rs` | `6216d37a5abd0de5f4b882613446e415e299d91c` |
| `crates/sbproxy-classifier/src/registry.rs` | `1f2d56ccb1b9e5977fa538e0be17e85c958e0756` |
| `crates/sbproxy-classifier/src/tcp.rs` | `a625a250f39080117e70a4bc0f9e1e567223f8f6` |

## Round 3 accepted GREEN, independent mutation, and restoration

The controller ran the proposed nine-test Round 3 selection on the production
implementation. Accepted result: 9 selected, 9 passed, and 82 skipped, with no
warning, failure, or timeout.

Before mutation, the controller found that the cap and truncated-header metric
assertions shared one test, so the first assertion could mask the second. The
test was split into two real-listener tests without changing production:

- `health::tests::http_header_cap_refusal_records_closed_error_labels`
- `health::tests::http_truncated_header_refusal_records_closed_error_labels`

The resulting ten-test selection passed 10/10 with 82 skipped. This split is
part of the accepted proof because each terminal variant can now fail
independently.

A production-only mutation batch then changed ten last-callsite contracts:

1. restored the absent/empty-tenant `warn!`;
2. moved every HTTP terminal variant to a sibling closed-label child;
3. ignored direct `health::serve_on` validation;
4. removed final-component `O_NOFOLLOW`;
5. reopened the auth pathname after descriptor validation;
6. moved the real frame allocation and observation before its byte lease; and
7. moved the oversized TCP refusal to the wrong command label.

The first mutation invocation reached the correct 0-pass/10-fail behavior but
emitted an unused-import compiler warning after replacing the registry's last
`debug!` call. It is retained as diagnostic evidence but is not credited. The
mutation-only import was corrected, with no accepted production behavior or
test change, and the controller reran the exact ten-test selection. Credited
mutation result: exactly 10 selected, 0 passed, 10 failed for their individual
semantic assertions, and 82 skipped, with no compiler warning, compiler error,
harness error, or runner timeout.

The controller restored every marked site with one `apply_patch` operation.
No `MUTATION(ai-group-b-r3)` marker remains, `git diff --check` exits zero, and
the restored raw-content SHA-1 identities are:

| Restored source file | Raw SHA-1 |
|---|---|
| `crates/sbproxy-classifier/src/auth.rs` | `4ecf2b42932da72c8b42c91d75ae83ffd9c1fc69` |
| `crates/sbproxy-classifier/src/health.rs` | `5dd08232ef214df3013ee797f41eb4d57a1ba404` |
| `crates/sbproxy-classifier/src/metrics.rs` | `956149a0fe4d1d5f54c10166aa2b151f426d8a85` |
| `crates/sbproxy-classifier/src/registry.rs` | `8f92ef54a3f984988299ea1dc1788e4e5e5efc36` |
| `crates/sbproxy-classifier/src/tcp.rs` | `4c16a4dd8f96621601ea954cfcece7c0d2ea72a3` |

The exact restored ten-test selection then passed 10/10 with 82 skipped and no
warning, failure, or timeout. Group B is frozen at these bytes for fresh
independent review against the full cross-boundary invariant matrix. Groups
C-F remain outside this focused proof and are not claimed complete.

The controller also ran the complete package selection after restoration:
`cargo nextest run -p sbproxy-classifier --no-fail-fast --no-capture` selected
and passed all 92 tests with no skipped test, warning, failure, or timeout.
The separate N-M3 production-seam selection
`classifier_hooks::tests::quality_hook_shares_large_prompt_storage_across_candidates`
also passed 1/1 in `sbproxy-core`, with 2,652 tests skipped by the exact filter.
