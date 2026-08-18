# Merge resolution: feat/span-metadata x origin/main (dlp body scanning)

Branch feature (bounded detection-span metadata on `DlpScanResult::Hit`) and
main's feature (shared `scan_text_into` helper, body scanning via
`scan_body`/`scan_request`, PiiGuardrail dead-knob refusals) both survive in
full. Three files resolved and staged; merge left uncommitted for the
controller. No cargo/rustc was run; correctness traced by hand.

## crates/sbproxy-modules/src/policy/dlp.rs (6 blocks)

Impl-side blocks (URI loop, header loop, scan_body, scan_request) were
resolved by adopting main's helper structure and threading spans through it:

- `scan_text_into` final signature:
  `fn scan_text_into(&self, text: &str, hits: &mut Vec<String>, spans: &mut Vec<DetectionSpan>)`.
  It now uses `find_iter` (main used `is_match`) so it pushes one
  `DetectionSpan::new(name, m.start(), m.len())` per match, offsets relative
  to the `text` segment passed in. It appends uncapped; capping is the
  caller's job.
- `scan(uri, headers)`: calls the helper for the URI and each non-auth header
  value, then builds the result exactly as the branch did: on any hit,
  `let (spans, spans_dropped) = cap_spans(found_spans)` and the three-field
  `Hit`. `Clean` unchanged.
- `scan_body(body)`: keeps main's gating (`self.scan_body` flag, empty-body
  short-circuit, lossy decode, `sbproxy_util::truncate_utf8` cap), collects
  spans through the same helper (offsets relative to the capped decoded body),
  and applies `cap_spans` once at its own result build.
- `scan_request(uri, headers, body)`: keeps main's union-of-detectors shape,
  destructures the three-field `Hit` from both sub-scans, extends the span
  list (URI/header spans first, body spans second), sums the sub-scans'
  `spans_dropped`, then runs `cap_spans` once over the merged list.

How `spans_dropped` totals across segments: each sub-scan reports
`kept_i` (max 32) plus `dropped_i`. `scan_request` returns
`dropped_1 + dropped_2 + merge_dropped` where `merge_dropped` is what the
final `cap_spans` over the merged kept lists discards. Algebraically that is
`total_matches - kept_final`, i.e. the exact total dropped across every
scanned segment, with URI/header spans winning the cap by encounter order.

Test-module blocks (2): the tail of `mod tests` was interleaved by the merge.
Rebuilt as a union from the stage versions: the branch's span section
(`hit_carries_a_span_with_type_offset_and_len`,
`spans_past_the_cap_are_dropped_with_a_count`,
`spans_never_carry_the_matched_value`,
`header_match_span_offset_is_relative_to_the_header_value`) followed by
main's body-scanning section (all 7 tests, `body_scanning_is_on_by_default`
through `body_scan_handles_non_utf8_bytes_without_panicking`). Names and
assertions preserved exactly from both sides; the only edit to main's tests
is widening five match patterns from `DlpScanResult::Hit { detectors }` to
`DlpScanResult::Hit { detectors, .. }` so they compile against the
three-field variant. `Clean` equality asserts needed no change.

Imports: the merged `use` set is the superset; the branch's
`use sbproxy_security::span::{cap_spans, DetectionSpan};` survived, and
main's `sbproxy_util::truncate_utf8` stays fully qualified (sbproxy-util is
already in the crate's Cargo.toml).

## crates/sbproxy-core/src/builtin_enforcers/dlp.rs (1 block)

Took main's call, `policy.scan_request(&path_and_query, req.headers(),
req.body())`, with the branch's three-field destructure of the `Hit`, so body
scanning is live and the Block path still folds the span summary into the 403
via `dlp_block_message(&detector_csv, spans.len(), spans_dropped)`. Both
sides' surrounding code (module docs, message builder, tests) had already
auto-merged.

## crates/sbproxy-ai/src/guardrails/pii.rs (2 blocks)

Both blocks were both-sides-appended test code sharing closing lines. Rebuilt
from the stage versions as branch block then main block: the five
`detect_spans` tests, then main's dead-knob refusal tests and the
CaptureLayer-based log-action tests. No content edits on either side. The
non-test head (dead-knob `Deserialize` impl plus the branch's `detect_spans`
method) had auto-merged cleanly.

## Judgment calls

1. `scan_text_into` switched from `is_match` to `find_iter`. Required to
   collect spans; detector-name results are identical since any match still
   marks the detector hit.
2. `scan_request` caps via its sub-scans' results rather than re-collecting
   raw spans. Each public entry point (`scan`, `scan_body`, `scan_request`)
   stays independently capped, and the arithmetic above keeps the total
   exact, so no extra raw-scan plumbing was added.
3. Span priority under the cap in `scan_request` is URI/headers before body,
   matching scan order; documented in the method's rustdoc.
4. One rustdoc link in the new `scan_body` docs uses
   `[`DlpPolicy::scan_body`]`, the exact form already proven green on main's
   docs lane (the name is both a field and a method).
5. Multi-line struct-pattern formatting mirrors shapes already committed on
   the branch and main, so `cargo fmt --check` sees only precedent forms.

## Verification done here

- No `<<<<<<<`/`=======`/`>>>>>>>` markers remain in any of the three files.
- Brace balance is zero in all three; every `scan_text_into` call site passes
  three arguments; every `Hit` pattern either destructures all three fields
  or carries `..`.
- Repo-wide grep found no other consumers of `DlpScanResult`, `scan_request`,
  `scan_body`, or `detect_spans` beyond re-exports and the already-merged
  `ai_dispatch.rs` caller.
- `git status --short` shows no UU entries; the three files are staged and
  the merge is uncommitted, as directed.
