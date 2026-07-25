# Lane B task 2 report: WOR-1982 classifier safety repair round 1

## Outcome

The classifier-backed `toxicity`, `jailbreak`, and `content_safety`
guardrails now fail closed at construction time, on per-request backend
errors, and throughout enforcing output streams. Keyword mode remains the
default. No dependency, schema, GPU, or remote-classifier work was added.

## Review findings

### 1. Incomplete or malformed taxonomy construction

- `build_class_centroids` now requires a usable centroid for every configured
  class instead of silently dropping an unusable class.
- Centroids with inconsistent vector dimensions are rejected with a
  class-specific construction error.
- Lazy artifact publication remains structural, but artifact load failure is
  retained as a handler-generation error and produces a fail-closed request
  result.
- Regressions:
  `classifier_construction_requires_a_centroid_for_every_configured_class`,
  `classifier_construction_rejects_mismatched_class_dimensions`, and
  `publication_is_structural_and_lazy_artifact_failure_stays_fail_closed`.

### 2. Backend errors cached as clean verdicts

- `TextClassifier::classify` now returns `Result<Option<ClassifierVerdict>>`,
  separating a valid abstention from a backend failure.
- Enforcing classifier backend failures become
  `SecurityBackendFailure`; routing-only failures remain non-enforcing.
- Backend failures are not entered into the mesh verdict cache.
- Enforcing failures bypass the normal quorum threshold and block even when
  the mesh block threshold is greater than one.
- Metrics use the fixed, bounded `class="error"` label rather than a
  user-controlled error string.
- Regressions:
  `backend_error_fails_closed_and_is_not_recorded_as_allow`,
  `ordinary_threshold_abstention_remains_an_allow`,
  `mesh_does_not_cache_an_enforcing_classifier_backend_error_as_allow`, and
  `enforcing_classifier_backend_error_blocks_regardless_of_mesh_quorum`.

### 3. Streaming bytes emitted before the classifier verdict

- Enforcing close-time output classifiers advertise a relay holdback
  requirement.
- Every outbound relay frame, translated tail frame, and reversible-restorer
  tail passes through `RelayBodyHoldback`.
- Held bytes are bounded and are released only after decoder close and the
  final guardrail verdict both succeed.
- Overflow, undecodable SSE, and malformed SSE after an earlier valid event
  fail closed without releasing a prefix.
- Regressions:
  `relay_emits_no_body_bytes_before_classifier_close_verdict`,
  `relay_holdback_overflow_fails_closed_without_releasing_a_prefix`,
  `undecodable_enforcing_stream_fails_closed_instead_of_classifying_raw_sse`,
  `short_undecodable_enforcing_body_fails_closed_at_stream_end`, and
  `malformed_frame_after_a_decoded_event_still_fails_closed`.

### 4. Buffered and streaming subject mismatch

- Buffered classification extracts the complete assistant response from the
  supported OpenAI Chat, OpenAI Responses, and Anthropic response envelopes.
- Streaming classification continues to assemble canonical assistant deltas
  and evaluates the same complete assistant text at close.
- The raw provider envelope and SSE framing are not included in the subject.
- Regression:
  `buffered_envelopes_and_streamed_deltas_classify_the_same_assistant_text`.

## Strict TDD evidence

The recovered worktree already contained the regressions for the four review
findings and their minimal implementation changes. The following additional
gaps were found during repair-round self-review and were handled one at a time:

1. Mesh quorum backend failure:
   - RED:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(enforcing_classifier_backend_error_blocks_regardless_of_mesh_quorum)'`
     failed because an enforcing backend error did not block at threshold 2.
   - GREEN:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(enforcing_classifier_backend_error_blocks_regardless_of_mesh_quorum) or test(mesh_does_not_cache_an_enforcing_classifier_backend_error_as_allow)'`
     passed 2/2.
2. Inconsistent centroid dimensions:
   - RED:
     `cargo nextest run -p sbproxy-core --features inprocess-classify --locked -E 'test(classifier_construction_rejects_mismatched_class_dimensions)'`
     failed because dimensions 2 and 3 were accepted.
   - GREEN:
     `cargo nextest run -p sbproxy-core --features inprocess-classify --locked -E 'test(classifier_construction_rejects_mismatched_class_dimensions) or test(classifier_construction_requires_a_centroid_for_every_configured_class)'`
     passed 2/2.
3. Malformed SSE following a valid decoded event:
   - RED:
     `cargo nextest run -p sbproxy-core --locked -E 'test(malformed_frame_after_a_decoded_event_still_fails_closed)'`
     failed because the close check returned no block after a prior valid event.
   - GREEN:
     `cargo nextest run -p sbproxy-core --locked -E 'test(malformed_frame_after_a_decoded_event_still_fails_closed) or test(short_undecodable_enforcing_body_fails_closed_at_stream_end) or test(relay_emits_no_body_bytes_before_classifier_close_verdict)'`
     passed 3/3.

Recovered regressions were re-run in focused groups:

- `cargo nextest run -p sbproxy-ai --locked -E 'test(classifier) or test(mesh_does_not_cache) or test(relay_) or test(undecodable) or test(short_undecodable)'`
  passed 45/45.
- `cargo nextest run -p sbproxy-ai --locked -E 'test(publication_is_structural_and_lazy_artifact_failure_stays_fail_closed)'`
  passed 1/1.
- `cargo nextest run -p sbproxy-core --features inprocess-classify --locked -E 'test(classifier) or test(stream_classifier_holdback_tests)'`
  passed 29/29.
- `cargo nextest run -p sbproxy-ai -p sbproxy-core --features sbproxy-core/inprocess-classify --locked`
  passed 2249 with 11 skipped.

## Verification

- `cargo build --workspace`: passed.
- `cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci`:
  passed 7527 with 56 skipped. One unrelated
  `model_host_reload::empty_startup_reload_is_atomic_and_collects_every_origin`
  attempt failed and passed on the configured retry, so nextest reported one
  flaky test.
- `cargo test --workspace --exclude sbproxy-e2e --locked --doc`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items`:
  passed.
- `cargo fmt --all -- --check`: passed.
- `cargo nextest run -p sbproxy-config --locked`: passed 384/384, including
  all example validation.
- `scripts/regen-llms-full.sh --check`: passed after regenerating the corpus.
- `scripts/docs-ci.sh`: passed offline links and 252 checked code blocks.
- `git diff --check`: passed.

## Self-review

- Audited all relay `write_response_body(Some(...))` sites in the streaming
  loop. Protected outbound chunks, translated tail chunks, and restorer tail
  bytes all enter the holdback; release occurs only after clean close.
- Confirmed classifier errors are not cached and enforcing errors cannot be
  defeated by mesh quorum.
- Confirmed keyword configuration and keyword matching implementation were not
  changed.
- Confirmed metric labels remain a closed taxonomy and errors use the bounded
  `error` class.
- Confirmed no dependency, schema, GPU, or remote-backend files changed.
- Confirmed rejected commit `ddddb761` is not an ancestor of this branch.
- Confirmed documentation describes keyword defaults, full-response subject
  parity, fail-closed errors, and output holdback behavior.

## Remaining concerns

No scoped correctness concern remains. The full workspace suite observed the
unrelated flaky model-host reload test noted above; it passed on retry. Live GPU
or remote-classifier validation was intentionally out of scope.
