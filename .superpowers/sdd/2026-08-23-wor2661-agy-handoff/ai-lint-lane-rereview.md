# Scoped re-review: 08457c13 "fix: clear the workspace clippy lane"

Scope: behavior changes introduced by the lint fixes, non-test code first, plus
the specific categories named in the review request. Read-only; no cargo run
(a gate is live in this tree). Verified by diffing every hunk against its
pre-image and reading the surrounding code in the worktree.

19 files, 361 insertions, 399 deletions. Every hunk was classified; the
production (non-`#[cfg(test)]`) surface is 11 changes, listed below.

## Findings

None.

## Checked and sound

- **let-else rewritten to `?`** - one instance:
  `/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster/crates/sbproxy-ai/src/billing/unified.rs:343-344`
  (`consistent_rollup_token_total`). Both `let ... else { return None; }` arms
  became `checked_add(..)?`. The enclosing item returns `Option<u64>`, the `?`
  sits directly in a `for` loop in the function body (not a closure), and the
  early-return value is `None` in both shapes. Error type and early-return
  value unchanged.
- **Merged "identical if blocks"** - one instance:
  `/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster/crates/sbproxy-ai/src/billing/chargeback.rs:1084`
  (`rollup_key`). The pre-image's two arms both returned
  `(requested_key.clone(), false)`; they are now `contains_key(..) || len() <
  ceiling`. Neither operand has side effects and `||` preserves the original
  short-circuit (on `contains_key == true` the length was not read before and
  is not read now). The overflow bucket is still reached on exactly the same
  inputs.
- **Derived impl replacing a manual one** - one instance:
  `/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster/crates/sbproxy-ai/src/toolkit/types.rs:231`
  (`AiToolkitConfigInput`, `#[derive(Clone, Default)]`). Field-by-field against
  the deleted hand-written impl: `limits` was `AiToolkitLimits::default()` and
  the derive calls the same; the five `Vec::new()` fields equal
  `Vec::default()`; `agent_egress: None` equals `Option::default()`. No default
  value moves. Public API keeps the same `Default` impl.
- **Needless-reference changes** - three instances, all in
  `chargeback.rs` tests (`&a.reason == &b.reason` to `a.reason == b.reason`)
  and one `Option::as_deref` removal at
  `builtin_enforcers/prompt_injection_v2.rs:270`. `&T == &T` forwards to
  `T::eq`, so the comparisons are identical; the `as_deref` removal only
  compiles because `deny_policy_type` is already `Option<&'static str>`, so it
  was a no-op. The `impl<T: ?Sized + Clone>` to `impl<T: Clone>` narrowings in
  `classifier/src/main.rs:381,388` and `classifier/src/tcp.rs:2711,2718` change
  no impl coverage: `Clone` and `Default` both carry a `Sized` supertrait, so
  the `?Sized` half was already unreachable, and the ambiguity assertion still
  fires for exactly the same set of types.
- **thread_local const initializers** - three instances
  (`chargeback.rs:571`, `unified.rs:131`, `core/src/admin.rs:1698`), all inside
  `#[cfg(test)]` blocks. `const { RefCell::new(None) }` produces the same
  initial value; only the lazy-init check is dropped. No first-touch side
  effect existed to lose.
- **`drop()` removals** - all 11 are `CompileSentinel` or `ListSentinel`
  (`classifier/src/registry.rs:429,709`). Neither type has a `Drop` impl
  anywhere in the workspace and every field is `usize`, a fieldless enum, or a
  shared reference, so drop glue is empty and the calls were inert. The
  sentinels assert through an explicit `assert_not_triggered()` that still runs
  at the same point; nothing moved to end-of-scope that used to run early.
- **`traced_map_workflow` fixture refactor**
  (`/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster/crates/sbproxy-ai/src/agent_orchestration/fsm.rs:1412-1456`)
  - all 11 call sites re-checked position by position against the pre-image
  argument list `(workflow_name, initial_state, state_name, action, outcome,
  target, root_unknown_key, state_unknown_key)`. No field is swapped: slot 1
  `"n"/"w".repeat(..)` to `workflow_name` (asserts `root.name` /
  `WorkflowNameBytes`), slot 2 to `initial_state` (`root.initial_state`), slot
  3 to `state_name` (`state.name`), slot 4 to `action` (`state.action`), slot 5
  to `outcome` (`transition.outcome`), slot 6 to `target`
  (`transition.target`), slot 7 to `root_unknown_key` (`root.key.unknown`),
  slot 8 to `state_unknown_key` (`state.key.unknown`). The one two-field case
  (`root-extra`/`state-extra`) keeps both. The `Default` base is `"w"`, `"s"`,
  `"s"`, `"a"`, `"go"`, `"s"`, `None`, `None`, byte-identical to the base every
  pre-image call passed, and the body binds the same names by destructuring, so
  no interior use moved.
- **`FailureObservation` refactor**
  (`/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster/crates/sbproxy-core/src/prompt_injection_runtime.rs:141-168,347-355`)
  - the transposition risk this change targets (`origin_id: &str` next to
  `scan_path: &'static str`) is closed correctly. The production call site in
  `record_unavailable` uses field shorthand for all seven fields, so each field
  takes the identically named local, and those locals were passed in that same
  order positionally in the pre-image. `stage` is still the per-iteration value
  from `stages.into_iter().flatten()` and is still readable afterwards for the
  `tracing::warn!`.
- **`ListenerResources` refactor**
  (`/Users/rick/projects/soapbucket/sbproxy/.worktrees/ai-cluster/crates/sbproxy-classifier/src/tcp.rs:1976-2000`)
  - exactly two call sites exist (`tcp.rs:1714`, `tcp.rs:1791`) and both were
  checked against the pre-image order `(stream, registry, mode, auth, limits,
  frame_budget, public_executor, shutdown)`. Public keeps `auth.as_deref()` /
  `public_executor`; Admin keeps `Some(auth.as_ref())` / `public_executor:
  None`. The `mode` argument moving ahead of the bundle is positional only and
  is spelled `TransportMode::Public` / `TransportMode::Admin` at both sites, so
  no transport was crossed with an executor. Struct field types match the old
  parameter types one for one; unifying `registry` and `auth` under a single
  `'a` is a compile-time tightening with no runtime effect.
- **`assert!(false, ..)` conversions** - all 18 (11 single-line, 7 multi-line;
  `fsm.rs` and `prompt_versioning.rs`) were read individually. Every message
  string is preserved verbatim, including its captured bindings (`{error}`,
  `{transition:?}`, `{limit}`, `{observed}`, `{other:?}`). `assert!` is never
  compiled out, so each replaced arm always panicked; the `return;` and the
  fallback values (`0`, `String::new()`) that followed were unreachable, and
  dropping them cannot change which branch is reached. The one `.expect(..)`
  conversion (`fsm.rs`, `checked_sub` for `outcome_bytes`) panics on the same
  `None` with the same message and yields the same `Some` value otherwise. No
  `assert!(false` remains anywhere under `crates/`.
- **`#[allow(..)]` reasons** - 10 allows added, every one carries a comment
  directly above it, and each cross-reference checks out: the `result_large_err`
  ones point at the pre-existing rationale on
  `classifier/src/grpc.rs:365-370` (`check_text_bytes`) and at the pre-existing
  budget-helper allows in `classifier-sidecar/src/main.rs:750,774,796,845`,
  both of which exist and predate this commit. The two
  `too_many_arguments` claims were verified against the signatures:
  `health.rs` `serve_connection` has 6 shipped plus 2 `#[cfg(test)]`
  parameters, `write_response` has 7 shipped plus 1. All are `allow`, not
  `expect`, so the `#[cfg(not(test))]` twins carry no unfulfilled-expectation
  risk. Attributes only; no behavior.
- **Remaining production changes** (outside the requested categories, checked
  anyway): 23 `io::Error::new(ErrorKind::Other, e)` to `io::Error::other(e)` -
  every removed line named `ErrorKind::Other`, and `Error::other` fixes that
  same kind, so no error kind changed. `Result::map` to `Result::inspect` at
  `core/src/server/ai_dispatch.rs:18508` - `inspect` runs the closure on `Ok`
  only and returns the same `Ok` value, and the closure's body (prepend
  instructions, remove `prompt`) is unchanged. `Cmd::Ai(Box<AiCmd>)` and
  `AiSub::Evaluate(Box<EvaluateArgs>)` - clap's `Args`/`Subcommand` impls for
  `Box<T>` are already relied on by `AiSub::Prompt(Box<PromptCmd>)`, and both
  dispatch sites (`main.rs:1946` `handle_ai_subcommand(&cmd)`, `main.rs:10686`
  `handle_ai_evaluate(args)`) reach `&AiCmd` / `&EvaluateArgs` by deref
  coercion, so parsing and dispatch are unchanged. `num_permits() as usize`
  cast removals (`tcp.rs:747,752`) are safe: tokio 1.52.1 declares
  `OwnedSemaphorePermit::num_permits(&self) -> usize`.
  `map_or(true, ..)` to `is_none_or(..)` (`startup.rs:1201`) is the same truth
  table. The `match` and `return` tail-expression rewrites
  (`tcp.rs:1219-1225`, `startup.rs:1255-1267`) return the same value on the
  same inputs; the latter is `#[cfg(test)]`-gated with `None` shipped either
  way.

## Not verified here

`cargo clippy`/`nextest` were not run: a gate is live in this tree and the
review brief forbids cargo. The commit's claim that the lane exits 0 rests on
the author's run. Everything above is source-level reasoning against the
pre-image, not a compiler result.
