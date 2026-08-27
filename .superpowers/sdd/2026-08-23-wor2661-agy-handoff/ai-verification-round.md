# Verification round: `feat/wor2661-ai-cluster`

Independent static verification of the two prior review rounds' fixes. Read-only:
no cargo, rustc, rustfmt, clippy, nextest, `check-config-readers.sh`, or
`tapes-check` was run. Grep-only guards that touch no build artifacts were run
and are reported where they bear on a verdict (`check-doc-drift.sh`,
`scan-unwrap-usage.py`, `scan-log-url-usage.py`, `scan-pub-item-usage.py`,
`scan-metric-visibility.py`, `scripts/tests/test_doc_generators.py`).

## Part 1: Group B majors

- **M1 `crates/sbproxy-classifier/src/registry.rs:81` (now `:1143`) - ADDRESSED.** The
  `None`/empty arm of `Registry::get` is `debug!` (`registry.rs:1143`) and the
  matching refusal in `handle_classify` is `debug!` (`tcp.rs:527`); no `warn!`
  remains anywhere in `registry.rs` or `tcp.rs`. The named regression
  `omitted_and_empty_tenants_do_not_emit_release_warnings_over_public_tcp`
  (`tcp.rs:3317-3337`) drives both `None` and `Some(String::new())` through a real
  TCP socket and `rmp_serde` round trip (`round_trip` -> `wire_exchange`,
  `tcp.rs:3185-3218`) under a WARN-only subscriber and asserts zero warnings.
  Mutation kill: reverting `registry.rs:1143` to `warn!` puts both iterations on
  the `_` arm; the test runs `flavor = "current_thread"` so the spawned handler
  executes on the thread `set_default` installed the counter on, the count reaches
  2, and `assert_eq!(.., 0)` fails.
- **M2 `crates/sbproxy-classifier/src/health.rs:83` - ADDRESSED.** All four refusals now
  move `sbproxy_classifier_errors_total`. Admission: `finish_http_failure(Unknown,
  Admission, ResourceLimit)` at `health.rs:1002-1008`, proven through the real
  `serve_on` listener by `http_connection_slot_refusal_records_closed_error_labels`
  (`health.rs:1932-1976`, exact delta 1 on `http/unknown/resource_limit`). Parser:
  `health.rs:1438-1453`, proven by `http_header_cap_refusal_records_closed_error_labels`
  (`health.rs:2008`) and `http_truncated_header_refusal_records_closed_error_labels`
  (`health.rs:2024`). Whole-connection deadline: `health.rs:1200-1216`, proven by
  `slowloris_deadline_releases_http_admission_slot` (`health.rs:2108-2163`). Oversized
  TCP frame: the release path records it at `tcp.rs:2025-2032`
  (`Decode`/`Limit`/`ResourceLimit`, transport-correct for both modes) and
  `public_and_admin_tcp_terminal_matrix_is_exhaustive_and_exactly_once`
  (`tcp.rs:5236-5248`) asserts the exact terminal delta on the production listener
  pair for public and admin. Mutation kill: deleting any one record leaves its
  delta at 0 and the corresponding `assert_eq!` fails. Caveat worth recording:
  `oversized_tcp_frame_refusal_records_closed_error_labels` (`tcp.rs:5872`) and the
  `record_error` it observes (`tcp.rs:353`) sit on `serve_on`/`handle_connection`,
  which are `#[cfg(test)]` (`tcp.rs:266`, `tcp.rs:327`); the release-path proof is
  the matrix test, not that one.
- **M3 `crates/sbproxy-classifier/src/auth.rs:60` - ADDRESSED.** Production open is
  unchanged and correct (`auth.rs:55-89`: one `O_NONBLOCK | O_NOFOLLOW` open,
  metadata and mode from that descriptor, read from the same descriptor). Both
  named regressions exist: `final_component_symlink_is_refused_without_following`
  (`auth.rs:413-427`) and
  `post_open_path_replacement_cannot_change_auth_descriptor_identity`
  (`auth.rs:433-461`). Mutation kills, independent of the FIFO case: dropping only
  `libc::O_NOFOLLOW` at `auth.rs:59` makes the open follow the link to a valid
  0600 regular file, `from_file` returns `Ok`, and `expect_err` panics. Reopening
  the pathname after `file.metadata()` reads the file the post-metadata hook
  (`auth.rs:81` -> `auth.rs:451-456`) renamed over the path, so
  `authorize(Some("original"), ..)` is false and the assertion fails.
- **M4 `crates/sbproxy-classifier/src/health.rs:79` - ADDRESSED.** `serve_on_with_options`
  validates before creating the slot semaphore and before the accept loop
  (`health.rs:915-918`), and `serve_on` (`health.rs:882-890`) is a thin wrapper over
  it, so the test drives the release listener. The named regression
  `serve_on_defensively_rejects_each_http_limit_boundary` (`health.rs:2040-2103`)
  calls `health::serve_on` directly for `max_connections` 0 and 100_001 and
  `io_timeout` 0 and 60_001 ms, requires `server.is_finished()` before any accept,
  and asserts the exact error string. Mutation kill: removing only
  `limits.validate()?` leaves the task in the accept loop, `is_finished()` is false,
  and the test's explicit `panic!("health::serve_on accepted invalid limits")`
  fires - no parser or slowloris test is involved.
- **M5 `crates/sbproxy-classifier/src/tcp.rs:302` - ADDRESSED.** Ordering is now
  type-enforced rather than observed: `FrameAllocationLease` (`tcp.rs:735-776`) is
  the only carrier of an acquired byte permit, is neither `Clone` nor `Default`
  (asserted at `tcp.rs:3410-3416`), and is the same size/alignment as the bare
  permit so it cannot hide a payload (`tcp.rs:3411-3419`);
  `BudgetedFrame::allocate_from_lease` (`tcp.rs:778-800`) consumes it **by value**
  and holds the only `vec![0u8; bytes]` on the release path (`tcp.rs:2036-2056`).
  The described mutation - moving the allocation above acquisition - no longer
  type-checks. Observation also moved onto the allocator itself:
  `frame_probe_note_allocator_boundary` (`tcp.rs:2490-2527`) plus the
  `#[global_allocator] FrameTrackingAllocator` installed at
  `crates/sbproxy-classifier/src/main.rs:57-60` (impl `tcp.rs:2568-2597`) counts
  real `alloc` calls of at least the lease size while a live lease context is set.
  `public_and_admin_listeners_share_one_sixteen_mib_frame_owner_and_recover`
  (`tcp.rs:3391-3604`) runs the production listener pair and asserts
  `allocator_boundary_calls == actual_payload_allocations == FRAME_SLOTS`,
  `actual_payload_allocation_bytes == 16 MiB`, `peak_actual_payload_bytes == 16 MiB`,
  and zero allocator calls/bytes/allocations without a live lease
  (`tcp.rs:3568-3603`). Mutation kill: a fifth 4 MiB allocation before admission
  raises `peak_actual_payload_bytes` to 20 MiB and leaves the boundary counters
  short of `FRAME_SLOTS`; both assertions fail.

## Part 2: toolkit-seam remedies

- **Bullet 1, rollout layer stops refusing plain string prompts - ADDRESSED.**
  `resolve_string_prompt_with_rollout` now gates rollout entry on
  `string_reference_names_rollout` (`ai_dispatch.rs:18404-18414`, helper at
  `18523-18544`), which returns `false` for any reference `ToolkitScope::new` or
  `has_prompt_rollout` rejects, so >128-byte, whitespace-only, and NUL-containing
  text falls through to the config store instead of returning `Some(Err(..))`.
  `has_prompt_rollout` (`toolkit/rollout.rs:11-27`) records no operation, so the
  spurious `Invalid` metric that accompanied the refusal is gone too. The Responses
  object path is untouched (`ai_dispatch.rs:18435-18456`), matching the claim.
  Regression: `plain_text_string_prompt_falls_through_the_rollout_layer`
  (`ai_dispatch.rs:18707-18733`) over all three shapes. Not a test-only fix.
- **Bullet 2, chargeback exports dispatch with the resolved principal - ADDRESSED.**
  `dispatch_ai_chargeback` (`admin.rs:2319-2355`) owns both paths, returns 405 for
  non-GET, 401 for `None` principal, 403 for `principal.tenant.is_some()`, and
  `None` for every other path; it is wired on the connection task at
  `admin.rs:6899-6909`, after principal/CSRF resolution and alongside the meter and
  toolkit dispatchers, and still behind the IP allowlist and rate limiter in
  `serve_admin_conn`. The routes are removed from `handle_admin_request`
  (`admin.rs:5756-5761` is now a comment only), which has exactly one production
  caller (`admin.rs:7150`), so nothing else can still serve them. 401 still carries
  `WWW-Authenticate` because that header is keyed on status
  (`admin.rs:7273-7275`). Regressions updated to prove the 404 on the sync seam, the
  401/405/403 matrix, that the 403 body leaks no rows, and the unscoped 200s
  (`admin.rs:13339-13405`). Docs updated (`docs/admin-api-reference.md:2490-2495`,
  `docs/ai-chargeback.md:42-46`).
- **Bullet 3, concurrency-admission refusals report `busy` - ADDRESSED.** New
  `AiToolkitOutcome::Busy` and label (`ai_metrics.rs:367-388`), new
  `AiToolkitEventOutcome::Busy` and wire label (`events.rs:223-241`), admin event
  mapping (`admin_toolkit.rs:375`), metric-family description
  (`ai_metrics.rs:399`) and registry description (`metric_registry.rs:1052`) both
  carry `busy`, and `docs/metrics-stability.md:133` matches the registry string
  byte for byte. Both admission sites now emit it instead of `Internal`
  (`toolkit/workflow.rs:227-228`, `toolkit/evaluation.rs:53-58`). The duplicate
  table in `admin_toolkit.rs::metric_outcome` is deleted and delegates to the single
  `sbproxy_ai::toolkit::error_metric_outcome` (`toolkit/runtime.rs:35-64`, re-exported
  at `toolkit/mod.rs:11`), which `runtime::metric_outcome` also routes through.
  `admin_toolkit.rs:598` already mapped `ToolkitError::Busy` to 429, so the HTTP
  status and the metric now agree. Regression:
  `busy_maps_to_its_own_closed_outcome_not_internal` (`toolkit/tests.rs:1208-1221`).
- **Bullet 4, sidecar nonlocal plain-http warning - ADDRESSED.** `endpoint_is_local`
  (`sidecar.rs:123-145`) reproduces the bracket/port/canonicalization rules and the
  warning fires at construction (`sidecar.rs:285-299`) without refusing, exactly as
  claimed. The follow-up commit `71402326` routes the field through
  `sbproxy_security::url_redact::redacted_url` (`sidecar.rs:295`), and
  `scan-log-url-usage.py --count raw-url` still reports 41 against a baseline of 41,
  so the raw-URL ratchet is satisfied only because that follow-up landed. Docs
  spell out the `egress.classifier_hooks` boundary
  (`docs/prompt-injection-v2.md:285-293`). Regressions:
  `endpoint_locality_matches_the_stock_hook_classification` (`sidecar.rs:469-491`)
  and `nonlocal_plain_http_endpoint_still_parses_for_released_compat`
  (`sidecar.rs:495-505`).
- **Bullet 5, quality-fanout poison recovery and double-release saturation -
  ADDRESSED.** Both request-path acquisitions recover the lock
  (`classifier_hooks.rs:172-180`, `226-233`) and the two `checked_sub(..).expect(..)`
  panics are replaced with `saturating_sub` plus a once-only `tracing::error!`
  (`classifier_hooks.rs:238-251`). Every remaining `.lock().expect("quality fanout
  state poisoned")` in that file (`267`, `295`, `305`, `320`) is inside a
  `#[cfg(test)]` function, so no production site can still poison the lock -
  this is not a half-fix. `scan-unwrap-usage.py --count unwrap-expect` reports 798
  against a baseline of 798 and `--count panic` reports 0, so the panic ratchet is
  in balance across this diff.
- **Bullet 6, reads out of the operations ring plus a loud retention drop -
  ADDRESSED.** Successful snapshots (`toolkit/snapshot.rs:16-25`) and successful
  discovery reads (`toolkit/runtime.rs:302-306`) no longer call `record_operation`;
  failures still do, and both still record the metric unconditionally.
  `record_operation` now inspects `retain_scoped_row`'s return and reports once via
  `std::sync::Once` (`toolkit/runtime.rs:469-485`). The warning text matches the
  code: `retain_scoped_row` returns `false` only when the process-wide ring is full
  **and** the scope owns no row to evict (`toolkit/runtime.rs:563-588`), so it
  cannot fire on ordinary per-scope eviction. No existing test asserted a
  `toolkit_snapshot` or `agent_discovery` row produced by the wrapper (the three
  call sites at `toolkit/tests.rs:834`, `836`, `914` call `record_operation`
  directly), so nothing is broken by the removal.
- **Bullet 7, `sbproxy ai evaluate` length-range metric - ADDRESSED.** `--min-bytes`
  and `--max-bytes` are now `Option<usize>` with no `default_value_t`
  (`crates/sbproxy/src/main.rs:944-952`); the metric is injected only when a bound
  was asked for and the min<=max check moved inside the same gate
  (`main.rs:10827-10856`). The refusal claim checks out: `compile_metrics` rejects
  `max > limits.max_response_bytes` (`toolkit/evaluation.rs:277-282`), which the old
  always-on 1 MiB default tripped. The resulting empty-metrics case yields a 1.0
  pass rate (`toolkit/evaluation.rs:320-322`) and the docs state that explicitly
  (`docs/ai-evaluation-harness.md:132-137`), so it is a documented outcome rather
  than a silent one.
- **Bullet 8, metric family registration fails instead of recording nothing -
  ADDRESSED.** `AI_TOOLKIT_OPERATIONS` is now a plain `CounterVec` behind
  `.expect(..)` (`ai_metrics.rs:395-409`), `record_ai_toolkit_operation` lost its
  `if let Some(..)` (`ai_metrics.rs:412-416`), and the in-crate test was updated to
  the non-`Option` shape (`ai_metrics.rs:3133-3140`). This matches the two sibling
  families at `ai_metrics.rs:278` and `:304`, and the name has exactly one
  registration site workspace-wide. See the Minor below on the "at startup" wording.
- **Bullet 9, the combined minors - ADDRESSED.** Quality-routing degradation logs
  are `debug!` behind their `record_quality_routing_decision` counters
  (`ai_dispatch.rs:10941`, `10962`). The intent heuristic scans a bounded 8 KiB
  window (`intent_detection.rs:108-109`) via `sbproxy_util::truncate_utf8`, which is
  char-boundary safe (`sbproxy-util/src/lib.rs:150-159`); the truncation is
  observability-only, since `ctx.classifier_intent` reaches nothing but the access
  log. `A2AAuthConfig` is gone from the struct, the re-export, the example, and its
  test (`agent_orchestration/auth.rs`, `mod.rs:47`,
  `examples/agent_orchestration_workflow.rs`), with no reference left anywhere in
  the tree; `verify_agent_token` carries the agent-server rationale
  (`auth.rs:22-27`) and the e2e now pins generator/verifier agreement against the
  hand-computed wire token (`e2e/tests/ai_toolkit.rs:1366-1373`). Evaluation docs
  state generation-pinned retention (`docs/ai-evaluation-harness.md:80-85`).
  `scan-pub-item-usage.py` reports 1462/314 against baselines 1462/314, so the
  removal plus the new `pub fn error_metric_outcome` nets out.

## New findings in the fix diff

- Minor - `scripts/check-doc-drift.sh:99` - pruning every `CORPUS_LAG` entry left an
  empty bash array that is still expanded unguarded at `scripts/check-doc-drift.sh:182`
  under `set -u`. Failure scenario: on a macOS box whose first `bash` on `PATH` is
  the system `/bin/bash` (3.2.57), `bash scripts/check-doc-drift.sh` from
  `scripts/check.sh:356` aborts with `CORPUS_LAG[@]: unbound variable` and exit 1
  before the audit runs - reproduced in this tree (`/bin/bash scripts/check-doc-drift.sh`
  -> exit 1, that message; `bash` 5.3 -> `doc-drift: ok`). It fails loudly rather
  than silently, but it is a false RED on the maintainer's default shell. Guard the
  two loops with `${CORPUS_LAG[@]+"${CORPUS_LAG[@]}"}` or a length test.
- Minor - `crates/sbproxy-core/src/classifier_hooks.rs:234` - the remedy that removed
  the panicking `checked_sub(..).expect(..)` from `Drop` reintroduces a panic on the
  same path through `debug_assert!`, which is live in every non-release profile.
  Failure scenario: a future double release in a `cargo run`/`cargo test` build
  panics inside `QualityFanoutLease::drop`; if that drop is already running during
  unwinding from another panic, the panic-in-drop aborts the process instead of
  reaching the `saturating_sub` and the once-only `tracing::error!` two lines below
  that were written to handle exactly this case. Either drop the `debug_assert!` or
  keep it outside the `Drop` path.
- Minor - `crates/sbproxy-core/src/classifier_hooks.rs:243` - the new operator-facing
  `tracing::error!` message carries a 26-space run inside the string literal
  (`...released twice;                          admission accounting...`), a
  line-continuation that lost its trailing backslash. Failure scenario: the one
  chance this process ever gets to report a lease-accounting bug reaches the
  operator's log and any SIEM with a mangled message body; rustfmt does not reflow
  string literals and clippy has no lint for it, so no gate catches it. The sibling
  warning at `crates/sbproxy-ai/src/toolkit/runtime.rs:478-483` shows the correct
  `\`-continued form.
- Minor - `crates/sbproxy-ai/src/ai_metrics.rs:408` - the commit message claims the
  family "fails at startup on a double registration", but `AI_TOOLKIT_OPERATIONS` is
  a `LazyLock` with no startup forcing point, so it is initialized on the first
  `record_ai_toolkit_operation` call. Failure scenario: a future duplicate
  registration of `sbproxy_ai_toolkit_operations_total` would not refuse the boot;
  it would panic the first AI request or admin toolkit task that touches the
  counter, after the process has already reported itself ready. The behavior matches
  the two siblings at `ai_metrics.rs:278` and `:304` so it is consistent, but the
  claim in the commit message overstates when the failure lands.
- Minor - `crates/sbproxy-core/src/intent_detection.rs:108` - the 8 KiB scan bound
  ships with no regression test. Failure scenario: deleting the
  `sbproxy_util::truncate_utf8(..)` call restores the unbounded
  `prompt.to_lowercase()` and every test in `intent_detection.rs` (including
  `heuristic_alias_matches_detect_intent` at `:394`) stays green, so the remedy can
  be reverted invisibly by a later refactor. A test asserting that a keyword placed
  past 8 KiB no longer changes the category would kill it.
- Minor - `crates/sbproxy-core/src/classifier_hooks.rs:238-250` and
  `crates/sbproxy-ai/src/toolkit/snapshot.rs:19` - the saturation/poison-recovery
  and ring-exclusion remedies also ship with no regression test. Failure scenario:
  restoring `.checked_sub(..).expect(..)` in `release_weighted_lease`, or restoring
  the unconditional `record_operation` in `snapshot`/`discover_agents`
  (`toolkit/runtime.rs:304`), leaves the whole suite green; the bugs these fix
  (a poisoned admission lock and a polling dashboard evicting a scope's decision
  history) would only be noticed again in production.

## Checked and sound

- Security, admin routing: `dispatch_ai_chargeback` (`admin.rs:2319`) sits after
  `resolve_principal` (`admin.rs:6663`) and inside `serve_admin_conn`'s IP-allowlist
  and rate-limit gate, so no gate the sync dispatcher applied was bypassed; both
  paths return 401 for an unauthenticated caller, and `resolve_principal` has no
  "auth disabled" branch (`admin.rs:847-893`), so the route cannot become open.
- Security, tenant scoping: the 403 is issued before any tracker is read, and the
  403 body is a fixed string, so no cross-tenant row can reach a restricted
  operator; `crates/sbproxy/tests/chargeback_admin_wire.rs` authenticates with the
  top-level Basic credential (`tenant: None`) and asserts only the status on its
  unauthenticated case, so it is unaffected by the moved route.
- Security, log redaction: `scan-log-url-usage.py --count raw-url` = 41 = baseline,
  `--count raw-request-error` = 0 = baseline; the new sidecar warning is the only
  URL-shaped field added and it is redacted.
- Security, auth-file handling in Part 1: single-open, same-descriptor,
  `O_NONBLOCK | O_NOFOLLOW`, regular-file and 0o077 mode checks all read from the
  opened descriptor (`auth.rs:55-89`).
- Concurrency: `unwrap_or_else(PoisonError::into_inner)` is applied to both
  request-path acquisitions and nowhere leaves a production `.expect` on that lock;
  `FrameAllocationLease`'s `into_permit` moves the permit out exactly once under
  `ManuallyDrop` (`tcp.rs:755-770`); `OutcomeGuard::drop` still records a
  cancellation for any unfinished guard (`metrics.rs:599-617`).
- Logging: both demoted quality-routing sites keep their counters
  (`ai_dispatch.rs:10939`, `10957`); the retention-drop and lease-underflow reports
  are `Once`-guarded so neither is a new log-flood primitive.
- Metrics: the `busy` addition is a new label *value* on an existing
  `capability,outcome` family, not a new label key; `ai_metrics.rs:399`,
  `metric_registry.rs:1052`, and `docs/metrics-stability.md:133` agree exactly
  (verified by string comparison); `scan-metric-visibility.py` = 246 = baseline;
  `AiToolkitOutcome` has exactly one exhaustive match in the workspace
  (`admin_toolkit.rs:366-377`) and it gained the `Busy` arm, and no test pins a
  closed set of outcome labels.
- Correctness: `endpoint_is_local` handles bracketed IPv6, port stripping, userinfo,
  and IPv4-mapped loopback via `to_canonical()`; `truncate_utf8` walks back to a
  char boundary; `retain_scoped_row`'s `false` return means exactly what the new
  warning says; `handle_ai_evaluate`'s `--max-bytes` default of 1 MiB now applies
  only when `--min-bytes` alone is given, matching its help text.
- Tests and guards: `python3 -m unittest scripts.tests.test_doc_generators.DocDriftCatalogTests`
  passes 5/5 with the reworked seeded-script fixture; the four pruned `CORPUS_LAG`
  needles are absent from the regenerated `docs/llms-full.txt` (0 hits each) and
  `bash scripts/check-doc-drift.sh` exits 0; `scan-unwrap-usage.py` 798/0,
  `scan-pub-item-usage.py` 1462/314, `scan-log-url-usage.py` 41/0,
  `scan-metric-visibility.py` 246 all match their committed baselines, so no ratchet
  needs a move for this diff.
- Scope: nothing outside the Group B boundary and the `93c34e0d..HEAD` fix diff was
  re-adjudicated. `docs/llms-full.txt` was excluded as instructed.
