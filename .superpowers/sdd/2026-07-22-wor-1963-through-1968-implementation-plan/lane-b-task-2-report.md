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

## Round 2

### Outcome

All three re-review findings are closed. The repair preserves the keyword
default, fixed metric labels, and the existing classifier seam. It adds no
dependencies, schemas, GPU work, or remote classifiers.

### Finding 1: malformed embeddings failed open

- Configured examples now reject empty, non-finite, and within-class
  dimension-mismatched embeddings before a centroid is published.
- Query embeddings must be non-empty, finite, and match every centroid's
  dimension. Structural defects return classifier errors; finite threshold and
  margin abstentions remain `Ok(None)`.
- Code: `crates/sbproxy-core/src/server/ai_classifier.rs`.
- Tests: `classifier_construction_rejects_an_empty_example_embedding`,
  `classifier_construction_rejects_a_non_finite_example_embedding`,
  `classifier_construction_rejects_a_wrong_dimension_example_within_its_class`,
  `malformed_request_embeddings_are_classifier_errors`, and
  `legitimate_threshold_and_margin_abstentions_remain_ok_none`.

### Finding 2: holdback released incomplete, error, or fragmented SSE

- `SseFramer` now buffers bytes until a complete UTF-8 SSE event, preserving
  multi-byte characters across arbitrary network splits and recording framing
  failures instead of lossy replacement.
- The enforcing holdback incrementally validates canonical OpenAI Chat,
  Anthropic Messages, and OpenAI Responses event streams. It requires `[DONE]`,
  `message_stop`, or `response.completed` respectively, rejects provider error
  and unsupported events, and never releases a partial or invalid sequence.
- The close validator now runs for translated/native relay paths as well as the
  OpenAI decode-only path.
- Code: `crates/sbproxy-ai/src/format/native_streams.rs` and
  `crates/sbproxy-core/src/server/ai_dispatch.rs`.
- Tests: `sse_framer_preserves_utf8_across_every_network_split`,
  `sse_framer_rejects_invalid_utf8_instead_of_replacing_it`,
  `canonical_openai_stream_requires_done_before_release`,
  `canonical_anthropic_and_responses_streams_require_their_terminal_event`,
  `canonical_stream_rejects_valid_error_and_unsupported_events`,
  `canonical_stream_rejects_invalid_utf8_even_when_fragmented`, and
  `canonical_terminal_allows_fragmented_sse_grammar_without_changing_bytes`.

### Finding 3: buffered and streaming output subjects diverged

- Buffered Chat choices and close-policy streamed deltas now both concatenate
  assistant text in ascending choice index, independent of arrival order.
- Classifier output enforcement rejects malformed, unsupported, or non-UTF-8
  buffered envelopes instead of classifying raw body bytes or silently skipping
  enforcement. Non-classifier output guards retain their existing behavior.
- Code: `crates/sbproxy-ai/src/guardrails/mod.rs`,
  `crates/sbproxy-ai/src/guardrails/stream.rs`, and
  `crates/sbproxy-core/src/server/ai_dispatch.rs`.
- Tests: `buffered_multi_choice_classifier_subject_uses_choice_index_order`,
  `streamed_multi_choice_classifier_subject_uses_choice_index_order`, and
  `classifier_output_rejects_malformed_and_unsupported_buffered_envelopes`.

### Strict TDD evidence

The four-file in-progress diff was preserved and audited before editing.
Recovered source regressions cover malformed configured/query embeddings,
byte-safe SSE framing, terminal-event holdback, and canonical-output parity.
The following new RED/GREEN cycles were observed during round 2:

1. Buffered multi-choice order:
   - RED: `cargo nextest run -p sbproxy-ai --locked -E 'test(buffered_multi_choice_classifier_subject_uses_choice_index_order)'` failed because array/arrival order produced `onezero`, not `zeroone`.
   - GREEN: the same command passed 1/1 after sorting buffered choices by index.
2. Streamed multi-choice order:
   - RED: `cargo nextest run -p sbproxy-ai --locked -E 'test(streamed_multi_choice_classifier_subject_uses_choice_index_order)'` failed to compile because `StreamGuardSession::on_content_delta_at` did not exist.
   - GREEN: `cargo nextest run -p sbproxy-ai --locked -E 'test(buffered_multi_choice_classifier_subject_uses_choice_index_order) or test(streamed_multi_choice_classifier_subject_uses_choice_index_order) or test(buffered_envelopes_and_streamed_deltas_classify_the_same_assistant_text)'` passed 3/3 after indexed close-buffer assembly and dispatch wiring.
3. Malformed buffered envelopes:
   - RED: `cargo nextest run -p sbproxy-ai --locked -E 'test(classifier_output_rejects_malformed_and_unsupported_buffered_envelopes)'` failed because raw malformed/provider envelopes became an allow.
   - GREEN: the same command passed 1/1 after canonical-envelope failure blocks. A deliberate temporary mutation of the non-UTF-8 branch made the same test fail with `non-UTF-8 must not skip classifier output enforcement`; restoring the fail-closed branch returned it to green.
4. Missing terminal event:
   - RED: `cargo nextest run -p sbproxy-core --locked -E 'test(canonical_openai_stream_requires_done_before_release)'` failed because EOF after a valid delta had no `[DONE]` requirement.
   - GREEN: `cargo nextest run -p sbproxy-core --locked -E 'test(canonical_openai_stream_requires_done_before_release) or test(canonical_stream_rejects_valid_error_and_unsupported_events) or test(canonical_stream_rejects_invalid_utf8_even_when_fragmented) or test(canonical_anthropic_and_responses_streams_require_their_terminal_event) or test(canonical_terminal_allows_fragmented_sse_grammar_without_changing_bytes) or test(short_undecodable_enforcing_body_fails_closed_at_stream_end) or test(malformed_frame_after_a_decoded_event_still_fails_closed)'` passed 7/7.

### Verification

- `cargo nextest run -p sbproxy-core --features inprocess-classify --locked -E 'test(malformed_request_embeddings_are_classifier_errors) or test(legitimate_threshold_and_margin_abstentions_remain_ok_none) or test(classifier_construction_rejects_an_empty_example_embedding) or test(classifier_construction_rejects_a_non_finite_example_embedding) or test(classifier_construction_rejects_a_wrong_dimension_example_within_its_class)'`: passed 5/5.
- `cargo nextest run -p sbproxy-core --locked -E 'test(stream_classifier_holdback_tests)'`: passed 11/11.
- `cargo nextest run -p sbproxy-ai --locked -E 'test(sse_framer_)'`: passed 7/7.
- `cargo nextest run -p sbproxy-ai -p sbproxy-core --features sbproxy-core/inprocess-classify --locked`: passed 2265 with 11 skipped after the final clippy-only loop refactor.
- `cargo build --workspace`: passed.
- `cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci`: passed 7543/7543, zero failures and zero disabled tests (from `target/nextest/ci/junit.xml`).
- `cargo test --workspace --exclude sbproxy-e2e --locked --doc`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed after converting the SSE frame-drain loop to `while let`.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items`: passed.
- `cargo fmt --all -- --check` and `git diff --check`: passed.

### Self-review

- Audited every held response-byte path: ordinary outbound chunks, translated
  tail frames, and reversible-restorer tails all enter the same validator and
  are released only after the final classifier verdict and canonical terminal.
- Confirmed no non-finite or wrong-dimension embedding can turn into an
  abstention/cacheable allow; legitimate finite abstentions retain their
  original behavior.
- Confirmed buffered and streamed classifier subjects use choice-index order;
  non-classifier guards, keyword defaults, and bounded metric taxonomy remain
  unchanged.
- Confirmed the final diff contains no dependency, schema, GPU, or remote
  classifier changes.

### Remaining concerns

No scoped correctness concern remains. The canonical terminal validator covers
the three gateway response protocols that can reach an enforcing held body:
OpenAI Chat, Anthropic Messages, and OpenAI Responses. Live model artifacts and
remote classifiers remain intentionally out of scope.

## Final Review Fix Wave

### Outcome

All seven final-review findings are closed. Enforcing classifier output now
fails closed rather than classifying a truncated prefix, mesh latency budgets
cannot suppress an enforcing safety classifier, zero query embeddings are
backend errors, final multimodal user text is scoped before bounding, canonical
stream validation covers every staged tail byte, and malformed classifier
verdicts fail closed without entering the cache. Keyword mode remains the
zero-dependency default. No dependency, schema, GPU, remote-classifier, or
unrelated change was added.

### Finding-to-code and regression mapping

1. **Full-output enforcement (`CRITICAL`)**
   - `SafetyClassifierGuardrail::check_output` compares the character-bounded
     subject with the complete canonical assistant text and fails closed with
     the bounded `class="error"` metric when any suffix would be omitted.
     Buffered and close-policy streaming entry points use this output-specific
     method; request-side bounded-prefix behavior is unchanged.
   - Code: `crates/sbproxy-ai/src/guardrails/safety_classifier.rs`,
     `crates/sbproxy-ai/src/guardrails/mod.rs`, and
     `crates/sbproxy-ai/src/guardrails/stream.rs`.
   - Tests:
     `buffered_harmful_suffix_beyond_classifier_max_chars_fails_closed` and
     `streamed_harmful_suffix_beyond_classifier_max_chars_fails_closed`.
2. **Latency-budget/cache bypass (`IMPORTANT`)**
   - The mesh still skips optional work after the configured budget, but always
     evaluates `SafetyClassifierGuardrail`. Backend failures retain the
     existing fail-closed, quorum-bypassing, non-cacheable treatment.
   - Code and test: `crates/sbproxy-ai/src/guardrails/mesh.rs`,
     `exhausted_budget_still_runs_enforcing_classifier_without_caching_partial_allow`.
3. **Zero query embedding (`IMPORTANT`)**
   - Query embeddings must have a finite L2 norm greater than
     `f32::EPSILON`, in addition to the existing nonempty, finite-value, and
     expected-dimension invariants. Invalid vectors return `Err`; legitimate
     finite threshold and margin abstentions remain `Ok(None)`.
   - Code and test: `crates/sbproxy-core/src/server/ai_classifier.rs`,
     extended `malformed_request_embeddings_are_classifier_errors`.
4. **Final multimodal user scope (`IMPORTANT`)**
   - String and array message content now share one text extractor. The final
     user message is selected and its text parts extracted before `max_chars`
     is applied, so oversized prior history cannot displace the operative
     multimodal prompt.
   - Code: `crates/sbproxy-ai/src/guardrails/mod.rs` and
     `crates/sbproxy-ai/src/guardrails/safety_classifier.rs`.
   - Test:
     `last_user_scope_extracts_final_multimodal_text_before_bounding`.
5. **Canonical tail ordering (`IMPORTANT`)**
   - Every ordinary outbound frame, translated decoder tail, and reversible
     restorer tail is staged before the single final canonical validation.
     Staging invalidates prior validation, and `release` refuses protected
     bytes without a validation of the latest held state.
   - Code and test: `crates/sbproxy-core/src/server/ai_dispatch.rs`,
     `canonical_validation_is_invalidated_by_a_late_tail_before_release`.
6. **Malformed classifier verdict (`IMPORTANT`)**
   - Safety classifiers accept only their closed configured taxonomy and a
     finite score in `[0, 1]`. Unexpected labels and invalid scores become
     `SafetyClassifierOutcome::BackendFailure`, record only
     `class="error"`, bypass mesh quorum, and are not cached.
   - Code: `crates/sbproxy-ai/src/guardrails/safety_classifier.rs`.
   - Tests:
     `serial_pipeline_fails_closed_on_an_unexpected_classifier_label`,
     `non_finite_and_out_of_contract_scores_are_backend_failures`, and
     `mesh_fails_closed_and_does_not_cache_an_unexpected_classifier_label`.
7. **Stale construction comment (`MINOR`)**
   - `crates/sbproxy-core/src/server/ai_classifier.rs` now states that any
     malformed configured example rejects construction; it no longer claims
     malformed examples are skipped.

### Strict TDD evidence

Each production change followed an observed regression failure for the
intended reason:

1. Full-output enforcement:
   - RED:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(buffered_harmful_suffix_beyond_classifier_max_chars_fails_closed) or test(streamed_harmful_suffix_beyond_classifier_max_chars_fails_closed)'`
     failed 0/2 because both paths classified the safe bounded prefix and
     returned no block.
   - GREEN:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(buffered_harmful_suffix_beyond_classifier_max_chars_fails_closed) or test(streamed_harmful_suffix_beyond_classifier_max_chars_fails_closed) or test(buffered_envelopes_and_streamed_deltas_classify_the_same_assistant_text)'`
     passed 3/3.
2. Exhausted mesh budget:
   - RED:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(exhausted_budget_still_runs_enforcing_classifier_without_caching_partial_allow)'`
     failed 0/1 at `the first backend failure must fail closed`; the backend
     was skipped and the empty allow was cached.
   - GREEN:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(exhausted_budget_still_runs_enforcing_classifier_without_caching_partial_allow) or test(mesh_does_not_cache_an_enforcing_classifier_backend_error_as_allow) or test(enforcing_classifier_backend_error_blocks_regardless_of_mesh_quorum)'`
     passed 3/3.
3. Zero query embedding:
   - RED:
     `cargo nextest run -p sbproxy-core --features inprocess-classify --locked -E 'test(malformed_request_embeddings_are_classifier_errors)'`
     failed 0/1 because `[0.0, 0.0]` became an abstention.
   - GREEN:
     `cargo nextest run -p sbproxy-core --features inprocess-classify --locked -E 'test(malformed_request_embeddings_are_classifier_errors) or test(legitimate_threshold_and_margin_abstentions_remain_ok_none)'`
     passed 2/2.
4. Multimodal last-user scope:
   - RED:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(last_user_scope_extracts_final_multimodal_text_before_bounding)'`
     failed 0/1 because the selected array fell back to the oversized flattened
     history.
   - GREEN:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(last_user_scope_extracts_final_multimodal_text_before_bounding) or test(input_scope_uses_only_the_last_user_message) or test(extract_text_multimodal_content)'`
     passed 3/3.
5. Tail validation ordering:
   - RED:
     `cargo nextest run -p sbproxy-core --locked -E 'test(canonical_validation_is_invalidated_by_a_late_tail_before_release)'`
     failed 0/1 because bytes staged after a previously valid terminal remained
     releasable.
   - GREEN:
     `cargo nextest run -p sbproxy-core --locked -E 'test(canonical_validation_is_invalidated_by_a_late_tail_before_release) or test(relay_emits_no_body_bytes_before_classifier_close_verdict) or test(canonical_terminal_allows_fragmented_sse_grammar_without_changing_bytes)'`
     passed 3/3.
6. Malformed verdicts:
   - RED:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(serial_pipeline_fails_closed_on_an_unexpected_classifier_label) or test(non_finite_and_out_of_contract_scores_are_backend_failures) or test(mesh_fails_closed_and_does_not_cache_an_unexpected_classifier_label)'`
     failed 0/3: serial and mesh paths allowed the unexpected label, and the
     score cases did not become backend failures.
   - GREEN:
     `cargo nextest run -p sbproxy-ai --locked -E 'test(serial_pipeline_fails_closed_on_an_unexpected_classifier_label) or test(non_finite_and_out_of_contract_scores_are_backend_failures) or test(mesh_fails_closed_and_does_not_cache_an_unexpected_classifier_label) or test(backend_error_fails_closed_and_is_not_recorded_as_allow) or test(ordinary_threshold_abstention_remains_an_allow)'`
     passed 5/5.

### Verification

- Acceptance set:
  `cargo nextest run -p sbproxy-ai -p sbproxy-core --features sbproxy-core/inprocess-classify --locked -E 'test(buffered_harmful_suffix_beyond_classifier_max_chars_fails_closed) or test(streamed_harmful_suffix_beyond_classifier_max_chars_fails_closed) or test(exhausted_budget_still_runs_enforcing_classifier_without_caching_partial_allow) or test(malformed_request_embeddings_are_classifier_errors) or test(last_user_scope_extracts_final_multimodal_text_before_bounding) or test(canonical_validation_is_invalidated_by_a_late_tail_before_release) or test(serial_pipeline_fails_closed_on_an_unexpected_classifier_label) or test(non_finite_and_out_of_contract_scores_are_backend_failures) or test(mesh_fails_closed_and_does_not_cache_an_unexpected_classifier_label)'`:
  passed 9/9.
- Affected suites:
  `cargo nextest run -p sbproxy-ai -p sbproxy-core --features sbproxy-core/inprocess-classify --locked`:
  passed 2273/2273 with 11 skipped.
- Lint:
  `cargo clippy -p sbproxy-ai -p sbproxy-core --features sbproxy-core/inprocess-classify --all-targets -- -D warnings`:
  passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.

The controller will run final exact-tree verification, so the full workspace
lane was not duplicated in this fix wave.

### Self-review

- Hot-path bounds: output-size detection scans at most `max_chars + 1`
  Unicode scalar values and refuses a larger output before inference. The
  stream close buffer and relay body remain bounded by their existing byte
  caps. Mesh budget exhaustion walks the bounded configured guard list only to
  find enforcing safety classifiers.
- Byte fidelity: `RelayBodyHoldback` continues storing the original `Bytes`
  chunks and releases them in original order. Canonical framing observes but
  never reserializes held bytes. Fragmented SSE byte-fidelity coverage remains
  green.
- Fail-closed/cache behavior: backend errors and malformed verdicts both use
  `SecurityBackendFailure`; they bypass quorum and cannot enter the verdict
  cache. Optional mesh budget work remains optional, but enforcing safety
  classifiers cannot be skipped.
- Scope and compatibility: keyword code/config defaults were untouched.
  Request subjects still use the configured bounded prefix. Only complete
  enforcing output subjects fail closed above the backend maximum.
- Scope audit: no dependency, schema, GPU, remote classifier, external ledger,
  integration, or unrelated files changed.

### Remaining concerns

No scoped correctness concern remains. Failing closed on enforcing assistant
output longer than `max_chars` is intentionally conservative; operators that
need longer classifier-backed output must raise the existing bound within the
relay/stream caps.
