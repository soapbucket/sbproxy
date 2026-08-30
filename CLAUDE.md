# sbproxy (Rust workspace)
*Last modified: 2026-08-28*

The active implementation of sbproxy. Cargo workspace with ~20
crates under `crates/`, an e2e suite under `e2e/`, examples under
`examples/`, and an internal observability/cache/AI/security stack.

## Pre-commit checks

Before committing any change, run all checks. Each one corresponds to a
required CI gate; if any fails locally, CI will fail too. The table is
ordered the way `scripts/check.sh` runs them, cheapest first, so a
failure that takes seconds to find is not discovered behind a
ten-minute build.

| Check | Command |
|---|---|
| Tracker placeholders | `grep -rn 'WOR-XXX' crates/ --include='*.rs' --include='*.toml'` (any hit fails) |
| pub-item ratchet | `bash scripts/check-pub-item-ratchet.sh` |
| unwrap/expect/panic ratchet | `bash scripts/check-unwrap-ratchet.sh` |
| Operator URLs at log lines | `bash scripts/check-log-url-ratchet.sh` |
| AI dispatch stack budget | `bash scripts/check-stack-budget-ratchet.sh` |
| Attribute placement | `python3 scripts/check-attribute-placement.py --check` |
| Attribute theft (diff-scoped) | `python3 scripts/check-attribute-theft.py --check` |
| Spec citations | `bash scripts/check-spec-citations.sh` |
| Env mutation | `bash scripts/check-env-mutation.sh` |
| Durable file modes | `bash scripts/check-durable-file-modes.sh` |
| Secret-bearing Debug registry | `bash scripts/check-secret-debug-registry.sh` |
| NOTICE (Apache-2.0-only) | `bash scripts/check-notice.sh` |
| Doc drift | `bash scripts/check-doc-drift.sh` |
| Tapes + GIF wiring | `make tapes-check` |
| Doc configs | `python3 scripts/sync-doc-configs.py --check` |
| Documented output | `python3 scripts/check-doc-captures.py --check --stackless-only` |
| Review-evidence parser | `python3 scripts/check-review-evidence.py --self-test` |
| Changelog fragments | `python3 scripts/changelog-fragments.py --check` |
| Installer | `sh scripts/tests/install_verify.sh` |
| Format | `cargo fmt --all -- --check` |
| Nested lockfiles | `bash scripts/check-nested-lockfiles.sh` |
| Supply chain (crates) | `cargo deny --all-features check` |
| Supply chain (npm) | `cd ui && npm audit --package-lock-only --audit-level=high` |
| UI | `cd ui && npm ci && npm run typecheck && npm run test -- --run` |
| Build | `cargo build --workspace --exclude sbproxy-e2e --locked` |
| Test | `cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci` |
| Doctest | `cargo test --workspace --exclude sbproxy-e2e --locked --doc` |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` |
| Docs | `RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc --workspace --no-deps --locked` |
| Payment features (on by default) | `bash scripts/check.sh`; `SBPROXY_CHECK_PAYMENTS=0` skips it |

Two rows in that table are easy to get subtly wrong.

`-D missing_docs` appears in exactly one other place in this repository,
`.github/workflows/ci.yml`, and it is the flag that bites. Do not pair
it with `--document-private-items`: that combination demands rustdoc on
private items too, which is stricter than CI and produces failures CI
will never report. If you want the private-items pass anyway, run
`scripts/check.sh` with `SBPROXY_CHECK_PRIVATE_DOCS=1`, which runs it
as its own phase under plain `-D warnings`.

`--locked` on the build is equally load bearing. Without it, `cargo
build` silently rewrites the root `Cargo.lock` in place, and the
`--locked` test step that follows then passes against the file the build
just regenerated. Lockfile drift gets quietly repaired instead of
reported.

The last row is the only opt-in entry, and opt-in is not the same as
optional: CI requires the `payments` lane like every other one here. No
payment feature is in any default set, so every other row in this table
resolves a union that compiles none of the settlement path, and until
WOR-2222 nothing anywhere did. The phase is behind a variable because
the settlement union has a different fingerprint from the rest of the
gate and recompiles the graph rather than reusing it, which is not a
price worth paying on a change that cannot reach payments. Run it before
pushing anything that touches `crates/sbproxy-billing`,
`crates/sbproxy-core`'s settle or billing modules, `sbproxy-modules`'
crawl pricing, or the shared HTTP kit those reach the network through. A
run without it prints the skip in the `SKIPPED PHASES` block.

Fix the issue before pushing. Do not paper over with `#[allow(...)]`
unless you also write a one-line comment explaining the deliberate
exception.

### Changelog entries are fragments, not CHANGELOG.md edits

`CHANGELOG.md` has one `## [Unreleased]` heading, so every branch that
appended to it edited the same few lines and every branch open at the
same time conflicted there. Five pull requests needed a hand-resolution
on that one file on 2026-08-20. Write a fragment instead:

```bash
python3 scripts/changelog-fragments.py --new fixed 'what changed, in one Markdown bullet'
```

That writes one JSON file under `docs/.changes/`; two branches produce
two files rather than one conflict. `--preview` renders the pending
section and `--release <version>` assembles it into `CHANGELOG.md` and
deletes the fragments it consumed. `docs/.changes/README.md` carries the
schema, the type list, and when a fragment is required.

`--check` is the gate, in `ci.yml`'s `guards` lane and in
`scripts/check.sh`. It refuses a malformed fragment, hand-written
content under `## [Unreleased]`, and a commit that edits `CHANGELOG.md`
without touching `docs/.changes/` in the same diff. A release cut needs
no flag: assembling deletes fragments, so it touches both.

### An insertion can steal the item below it

An attribute block is everything attached to an item ahead of the item
itself: its rustdoc, its `#[test]`, its `#[derive]`. Rust binds that
block to whatever item comes next, so an item inserted between the block
and its owner takes the whole block with it. The owner keeps its body
and loses its meaning.

It reads as a clean diff, which is why it kept happening. The stolen
lines are unchanged context, and the review sees a new item with a doc
comment above it, which is what a new item is supposed to look like.
Twenty-one of these are in the last 260 merges and sixteen were still
live when the guard was written; a seventeenth arrived from main while
the guard was in review, and the guard caught it the moment main moved. One had moved the rustdoc explaining why
a stack-budget test runs on a worker-sized thread onto a `size_of` probe
that runs no dispatch at all, on the exact path that was overflowing its
stack a day later. Another took `#[cfg(unix)]` off a test that shells out
to `/bin/kill`. Two more were triaged as healed and were not: one of them
put a `pub fn`'s rustdoc summary on a different function.

Reading the hunk is not enough to decide it. git anchors a `-U0` hunk one
line early when the insertion's tail matches the line above the insertion
point, and appending a `#[test] fn` before another `#[test] fn` produces
exactly that, so the guard compares the victim's block before and after
in the two files rather than trusting the diff's shape.

`scripts/check-attribute-theft.py --check` refuses that one shape and
nothing else. It is diff-scoped and needs a merge base, so it fails
closed rather than skipping when none resolves, and it lives in the
`guards` lane, whose checkout is full depth. `--self-test` replays the
two real hunks verbatim.

`scripts/check-attribute-placement.py --check` catches the same damage
from the other side, by parsing rather than grepping: an attribute that
cannot apply to the item it sits on. rustc refuses `#[test]` on a
`static`, a `const`, a `use`, or a function taking arguments, but only
in a configuration something compiles with `--test`, which leaves every
feature and target no lane enables. `#[ignore]` and `#[should_panic]` on
a function that is not a test are silent everywhere.

### A filtered test selection that matches nothing exits 0

`cargo test`, `--exact` and `--ignored` all exit 0 when the filter
selects no tests. The run prints `0 passed; 2857 filtered out` and the
step goes green having checked nothing. Three of those reached main in
one change on 2026-08-28.

Every selection that names individual tests goes through
`expect_tests <count> <label> -- <command>` from
`scripts/lib/expect-tests.sh`, which reads the count out of the libtest
or nextest summary the way `check.sh` reads the junit `tests="N"`
attribute, and fails when the count is wrong or unreadable. Use the
exact count, not `>=1`: a selection that names two tests and runs one is
as wrong as one that runs none.

### The gate validates the working tree; `git push` ships HEAD

`scripts/check.sh` records the working-tree state before the first phase
and re-checks it after the last one. An uncommitted file at the end
fails the run, and the message separates work that was already dirty
from files a generator rewrote during the gate. A green gate on a dirty
tree is a claim about a tree nobody is going to push: PR #837 shipped a
broken commit exactly that way, behind a gate that had passed against an
uncommitted fix.

Commit first, then run the gate. For a deliberate work-in-progress run,
set `SBPROXY_ALLOW_DIRTY_TREE=1`; the run then prints that the guard was
bypassed and lists the paths.

### Running the gate

The local runner is `scripts/check.sh`. The default path mirrors the
required PR lane's workspace jobs: non-e2e workspace tests in the dev
profile plus doctests. This keeps the local target directory materially
smaller than full release/e2e runs. The required e2e subset (see "A
small e2e subset is required per PR" below) is not in the default path;
`SBPROXY_CHECK_E2E=1` covers it, as does the five-file command in that
section.

| Variable | Effect |
|---|---|
| `SBPROXY_RELEASE_TESTS=1` | compile test binaries in release mode |
| `SBPROXY_CHECK_E2E=1` | include the `sbproxy-e2e` package |
| `SBPROXY_CHECK_PAYMENTS=0` | skip the settlement feature union (it runs by default) |
| `SBPROXY_CLEAN_AFTER_BUILD=0` | keep every build artifact after the run |
| `SBPROXY_ALLOW_DIRTY_TREE=1` | do not fail on an uncommitted working tree |
| `SBPROXY_ALLOW_CARGO_TEST_FALLBACK=1` | permit the serial `cargo test` fallback |
| `SBPROXY_CHECK_PRIVATE_DOCS=1` | extra rustdoc pass over private items |
| `SBPROXY_CHECK_CAPTURES=1` | replay every documented command and diff it against the block the doc shows |

Anything the runner could not run is reprinted as a `SKIPPED PHASES`
block just before the final result, so "All checks passed" cannot hide a
lane that never executed. `promtool` and `cargo-deny` are the two
optional tools; install prometheus, and `cargo install cargo-deny --locked`,
to close those two gaps.

**Always run the test lane through nextest.** `cargo-nextest` is
already installed at `~/.cargo/bin/cargo-nextest`. `check.sh` probes
`cargo nextest --version` and treats a miss as a hard error, because
serial `cargo test` turns a few-minute test lane into a ~90-minute one
and a local fallback is a misconfigured shell rather than an intended
path. If `~/.cargo/bin` is not already on your `PATH`, export it before
running the gate:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

By default, `scripts/check.sh` runs `scripts/cleanup-build-artifacts.sh`
on exit to prune `target/doc`, nextest output, incremental directories,
and other high-churn artifacts while keeping dependency build outputs
available for reuse. Set `SBPROXY_CLEAN_AFTER_BUILD=0` only when you
are deliberately preserving every artifact for local debugging.

## Faster inner-loop alternatives

For day-to-day editing, these run in seconds against just the slice
you're working in:

- `cargo check -p <crate>` - single-crate type check, ~1-5s
- `cargo test -p <crate> --lib <prefix>` - unit tests by name prefix
- `cargo test -p sbproxy-config --tests` - config tests + example +
  v1-compat refusal sweep, ~3s
- `cargo test -p sbproxy-modules --lib <policy_name>` - per-policy
  unit tests
- `cargo test -p sbproxy-e2e --release --test <name>` - one e2e test
  file (release build of the proxy is reused if present)

### A per-crate lint can fail while the workspace lint passes

`cargo clippy -p sbproxy-core` is a **stricter** check than
`cargo clippy --workspace`, not a faster subset of it, and CI only runs
the workspace form. If a per-crate invocation reports errors the CI lane
does not, the crate is probably fine and your invocation is the one
telling the truth.

The mechanism is feature unification. `crates/sbproxy` is a workspace
member and its `default` features enable things like
`sbproxy-core/inprocess-classify`. Under `resolver = "2"` a
`--workspace` build compiles one `sbproxy-core` with the union of
features the whole graph asks for, so those features are **on**. Build
`sbproxy-core` alone and it gets its own `default = []`, so they are
**off**.

That difference is visible for real. A helper function with no `#[cfg]`
gate whose only callers sit behind `#[cfg(feature = ...)]` compiles
clean workspace-wide (the callers exist) and fails per-crate with
`function ... is never used` (they do not). This happened in `#757` and
was fixed in `#759` by gating the helpers to match their callers.
Demonstrated at that commit: `cargo clippy --workspace --all-targets`
exits 0 while `cargo clippy -p sbproxy-core --all-targets` exits 101 on
the same source.

Two consequences worth remembering:

- A green CI run does **not** mean every crate lints in isolation. When
  you add a feature-gated caller, gate its helpers to match, and check
  with `cargo clippy -p <crate> --all-targets`.
- Do not conclude from a per-crate failure that `main` is red. Confirm
  with the documented workspace command before filing anything.

### The same mechanism sets CI's build time

Different feature unions mean different fingerprints, and different
fingerprints mean cargo rebuilds. Inside one CI job that is expensive:
adding a `cargo test -p sbproxy-e2e` step after a `--workspace` build
recompiled 179 crates to run two tests, and a `cargo test -p
sbproxy-platform` step cost another 2m07 the same way.

So `.github/workflows/ci.yml` holds one invariant: **every cargo
invocation in a job uses the same package selection.** The `test` lane
is `--workspace --exclude sbproxy-e2e` throughout; the `obs-budgets`
lane is `--workspace` throughout, in its own job with its own cache key
because it needs e2e's wider union.

When adding a check to CI, express it in the lane's existing selection.
Narrow the *targets* (`--test <name>`) or the *tests*
(nextest `-E 'test(...)'`), never the packages. If a check genuinely
needs a different package set, give it its own job rather than paying
the rebuild on the critical path. `scripts/lib/workspace-bin.sh` exists
for the same reason: it execs the already-built generator binaries
instead of re-entering cargo with a `-p` selection.

### A different feature union is a different job for the same reason

Fingerprints change with features, not just with packages, so a lane
that needs a feature no default set enables gets its own job on the same
grounds. `embed-admin-ui` and `payments` are both that, and the
`payments` lane shows how to keep the two rules from fighting.

Its package selection is the `test` lane's, `--workspace --exclude
sbproxy-e2e`, and only the union differs. It reaches that union through
the `sbproxy` binary's flags, `--features sbproxy/payment-x402,...`,
rather than `sbproxy-core`'s, which makes it a strict superset of what
`--workspace` already resolves. Going the other way and selecting `-p
sbproxy-core` would be narrower than CI on both axes at once: fewer
features, so dead-code failures CI never reports, and fewer packages, so
`sbproxy-billing`'s test targets would not be built at all. Reach for
`<binary-crate>/<feature>` when a lane needs a wider union, and let the
package selection stay where the rest of CI has it.

### Payments e2e is scheduled, not per-PR

`e2e/tests/settlement_gate.rs` and `e2e/tests/usage_bridge.rs` are the
only tests that drive a payment through a real proxy process.
`challenge_settle_allow_and_replay_refusal` is the one that asserts the
origin served exactly once for a settled payment and then refused the
replay. Both files spawn a binary no other lane builds: a release
`sbproxy` carrying
`payment-x402,payment-mpp,payment-stripe,payment-lightning-cln`, found
under `target/payments/` or named by `SBPROXY_E2E_PAYMENTS_BIN`.

That binary, plus a spawned child on real ports, is why these two files
are not in the required PR lane.
`.github/workflows/payments-e2e.yml` runs them nightly at 03:40 UTC
instead, with `workflow_dispatch` for a manual run. A red run opens or
comments on a "Payments e2e is failing" issue and names the tests that
failed. Two other scheduled lanes happen to run the same files,
`release-checks.yml`'s test-isolation job nightly and `e2e.yml` weekly,
but neither is named for them and neither says which payment test broke.

What that costs: a PR can merge green having never built the binary
these tests spawn, and the exactly-once property is confirmed the next
morning rather than before the merge. The `payments` lane in `ci.yml`
still runs on every PR, so the settlement code compiles and its unit
tests run there. What waits for the night is the proof that an assembled
proxy serves a paid request once.

So run the pair locally before merging anything that reaches settlement:

```bash
CARGO_TARGET_DIR=target/payments cargo build --release -p sbproxy --locked \
  --features payment-x402,payment-mpp,payment-stripe,payment-lightning-cln
cargo test -p sbproxy-e2e --locked --no-fail-fast \
  --test settlement_gate --test usage_bridge -- --test-threads=1
```

`--test-threads=1` is load bearing: settlement_gate is red under
parallelism (WOR-2295). Build that binary once and `SBPROXY_CHECK_E2E=1
bash scripts/check.sh` picks both files up on every later gate. Without
it the gate lists them under `SKIPPED PHASES`.

### A small e2e subset is required per PR (WOR-2469)

The rest of the e2e suite is scheduled, but a small set of offline e2e
files runs on every code PR as the required `e2e subset (required)`
lane in `ci.yml`, single-threaded, against a debug proxy the job builds
itself. The lane's own comment block carries the authoritative list and
the reason each file is there; at this writing it is `static_action`,
`body_routing`, `sessions`, `admin_reload`, and `transform_json`.

Why: PR #1049 changed 425 lines across `request_phase.rs` and
`proxy_http.rs`, merged with every required check green, altered four
documented end-to-end behaviors, and broke a shipped example outright
(WOR-2468). The only tests that would have caught any of it ran weekly,
so the break sat on main for three days. WOR-2469 weighed four
remedies: a required subset, making a scheduled red block the next
merge, path-triggered e2e for the shared request-path files, and
accepting the risk in writing. The subset shipped because it is the
only one that checks behavior before the merge instead of after, and it
runs on every code PR rather than behind a path filter because
end-to-end behavior breaks from modules, transport, and config
compilation just as well as from the two files #1049 touched.

The bar for adding a file to the subset: offline (MockUpstream or
static actions on loopback; no mesh, no websockets, no Redis, no
special binaries), absent from the known load-flake roster, and
covering a behavior a shipped example documents. `model_cluster_control`
stays out until its root-cause fix (#1142) has a quiet scheduled
history behind it.

What is still accepted, in writing: a red weekly e2e sweep or nightly
payments run files an issue and does not block merges. The full sweep
includes load-sensitive tests, and a merge gate that a known flake can
close is a repo-wide stop nobody ordered. Everything outside the subset
keeps the file-an-issue posture, and this paragraph is the record of
that decision.

Reproduce the lane locally:

```bash
cargo build --workspace --locked
cargo test --workspace --locked \
  --test static_action --test body_routing --test sessions \
  --test admin_reload --test transform_json -- --test-threads=1
```

## Code review

Every branch gets an adversarial review against
`.github/code-review-rubric.md` before it becomes a PR, run by an agent
with shell access, and a verification round on the fixes when the first
round finds anything. The rubric file carries its own "How to run it"
instructions (give the reviewer the diff and the worktree; require
findings with severity, file:line, and a failure scenario each). The
findings and their resolutions go into the PR body, so the review
history merges with the change it reviewed. The mechanical gates above
answer "does it compile, lint, and pass"; the rubric answers "is this
going to be a problem in six months".

The rule landed before anything enforced it, and a large batch merged
without it. Of the 31 pull requests merged between 2026-08-19 and
2026-08-20, 30 carried no GitHub review and 26 carried no review
evidence anywhere in the body; retrospective rubric runs against three
of those merged branches then turned up an auth forgery primitive, four
Blockers, and eight Majors. The `review-evidence` check below is what
makes the rule checkable rather than merely written.

Running the rubric is not optional, and neither is acting on it: every
finding it produces gets fixed in the same loop that surfaced it,
Blocker through Minor and nits included, before the PR merges. Do not
park a finding as a ticket unless its remedy is a separate product
feature (new scope rather than a defect in the change under review),
and record why in the PR body when that happens. A finding surfaced
after a merge gets fixed immediately on a fresh branch rather than
queued.

### Review evidence in the PR body

`.github/workflows/review-evidence.yml` reads the pull request body and
goes red when it carries no record of the review. It runs on `opened`,
`edited`, `synchronize`, `reopened`, and `ready_for_review`, so a body
corrected after opening re-checks without a push, and it reads the body
out of the event payload rather than building anything, so it reports in
seconds instead of behind the Rust lanes.

What it does *not* do yet is stop a merge. The `main-protection` ruleset
requires one status check, `build / test`, and adding a second is a
separate deliberate act; until `adversarial review evidence` is in that
list, this check is a visible red X and nothing more. Say it that way
rather than calling it a gate, because a rule everyone believes is
enforced and is not is how the paragraph above got written in the first
place.

Run the fixtures with `python3 scripts/check-review-evidence.py
--self-test` (`scripts/check.sh` does too), and check a draft body with
`--body-file FILE` or `--stdin` before opening the PR. The self-test
carries a mutation battery as well: every refusal the check relies on is
paired with a loosening of the parser that has to break a fixture, so a
refusal cannot quietly stop working behind fixtures that still pass.

The pull request template already carries an `## Adversarial review`
heading at the end, after "Notes for reviewers". Fill that one in.
Appending a second block is refused, because two records raise the
question of which one is the record.

Under the heading:

1. A `Reviewer:` line naming who or what ran the rubric. A placeholder
   (`TBD`, `TODO`, `N/A`, `none`) is refused.
2. A `Findings:` line carrying a count for each of Blocker, Major, and
   Minor, or the literal `Findings: none`. Those three are the whole
   severity set; the rubric has no Critical.
3. One entry per declared finding, either a list item leading with its
   severity or a table row with a whole cell that is the severity. In a
   table that names a `Disposition` column, that column is the one read
   for the disposition; a table without one has every cell in the row
   read. The entry count per severity has to match the declared count in
   both directions, so an undercounted summary fails the same way an
   undocumented finding does.
4. A `Verification:` line whenever the counts are not all zero, since a
   round that finds anything gets a second round on the fixes.

Each finding ends with a clause saying what happened to it. What the
check is after is that no finding was listed and then abandoned, so the
vocabulary is the outcomes people actually write:

- `Fixed`, `Addressed`, `Resolved`, `Mitigated`, `Reverted`, `Landed`,
  `Superseded`, `Accepted`, `Declined`, `Waived`, `Deferred`, `Filed`,
  `Withdrawn`.
- Any of those under `Not`, `Partly`, `Partially`, or `Already`: `Not
  fixed here, the remedy is separate scope.` `Partly addressed, the e2e
  is still absent.` `Already fixed in #1177.`
- `Not replicated`, `Not reproduced`, `Not applicable`, `Not reachable`.
  Those four are outcomes only in the negative. On their own they say
  the finding is real and nothing has happened to it, which is the
  abandonment the check exists to catch.

Write the honest one rather than the shortest one. "Not fixed here,
because it is pre-existing and the remedy is a separate change" tells
the next reader more than "Accepted." does.

Two shapes to know, both of them consequences of the capital and the
clause break being what separates a disposition from a description that
happens to use the word, as in "the endpoint accepted a forged token":

- Front the qualifier. `Already fixed by #1177.` counts; `This was
  already fixed by #1177.` does not, because the qualifier has to open
  the clause and carry the capital.
- End the claim before the disposition starts, with a period, comma,
  semicolon, or colon. The ` - ` that separates a finding's severity,
  path, and claim is a field separator here and does not open a clause,
  so `boom - Fixed here` is refused and `boom. Fixed here` is not.

Findings may be grouped under subheadings, which is what a review with
more than a handful of them wants; a `### Checked and sound` subsection
is exempt from the findings scan, since the things listed there are the
opposite of findings.

The checker reads only what renders as live prose, so a copy sitting
inside a fenced code block, inside an HTML comment, or indented as a
code block does not count, and neither does an empty or whitespace-only
section.

With findings:

```markdown
## Adversarial review

Reviewer: feature-dev:code-reviewer against .github/code-review-rubric.md
Findings: 1 Blocker, 1 Major, 0 Minor
Verification: second round by the same reviewer against the fixed tree

- Blocker - `crates/sbproxy-core/src/router.rs:214` - an upstream 5xx
  retries against the same dead peer forever. Fixed in this branch.
- Major - `crates/sbproxy-core/src/router.rs:301` - the retry budget is
  held by convention rather than by the type. Not fixed here, the type
  change is separate scope.
```

Without:

```markdown
## Adversarial review

Reviewer: feature-dev:code-reviewer against .github/code-review-rubric.md
Findings: none
```

Renovate and Dependabot skip the check: they raise lockfile and
action-digest bumps on a schedule and merge some of them automatically,
and a check no bot can ever satisfy would deadlock those rather than
gate them. The exemption is those two logins and no others, so this
repository's own `github-actions[bot]` automation, which opens PRs that
rewrite vendored fixtures, carries evidence like anyone else.

## Workspace layout

```
sbproxy/
  crates/
    sbproxy/            - binary entry point (cmd line, signal handling, server boot)
    sbproxy-core/       - request pipeline (request_filter, response_filter,
                          response_body_filter), Pingora glue
    sbproxy-config/     - config schema, compile_config(), example sweep,
                          v1 schema-compat regression test
    sbproxy-modules/    - all action / auth / policy / transform modules
                          (plugin-style registry, register-via-init pattern)
    sbproxy-plugin/     - public plugin trait surface
    sbproxy-httpkit/    - HTTP request/response helpers shared by plugin authors
    sbproxy-platform/   - circuit breaker, dns, health, kv storage
                          (redb embedded KV; SQLite for relational state)
    sbproxy-cache/      - response cache, KV stores (memory/file/memcached/redis)
    sbproxy-ai/         - AI gateway path (providers, routing, guardrails,
                          streaming, budgets, cost tracking)
    sbproxy-extension/  - scripting (CEL, Lua, JavaScript, WASM via
                          wasmtime + WASI preview-1), MCP server,
                          feature flags
    sbproxy-observe/    - metrics (sbproxy_*), events, structured logging
    sbproxy-security/   - crypto (HKDF), hostfilter, IP/CIDR utilities,
                          PII redactor, SSRF guard; optional headless-detect
                          (TLS fingerprint) and agent-verify (reverse DNS)
    sbproxy-tls/        - TLS config, mTLS
    sbproxy-transport/  - HTTP/1.1, H2, H3, websockets, gRPC, GraphQL
    sbproxy-vault/      - secret backends + interpolation
    sbproxy-middleware/ - middleware chain (CORS, HSTS, compression, ...)
    sbproxy-openapi/    - OpenAPI emission from live config
    sbproxy-k8s-operator/ - CRDs + reconcile loop
    sbproxy-classifiers/  - ONNX-backed text classifiers (prompt injection v2)
  e2e/
    Cargo.toml          - e2e harness crate (sbproxy-e2e)
    src/                - ProxyHarness lib used by e2e tests
    tests/              - Rust-native e2e (one file per feature)
    cases/              - per-feature config fixtures used by Rust tests
    conformance/        - vendored curl-and-bash conformance suite
                          (93 cases). See e2e/conformance/HOW-TO-RUN.md.
  examples/             - ~90 dir-style examples; every sb.yml here is
                          swept by validate_examples test
  scripts/              - dev-loop helpers (run-e2e.sh, perf-compare.sh,
                          install.sh, generate-certs.sh)
  docker/               - docker-compose stack (sbproxy + Redis +
                          Jaeger) for local dev
  dashboards/           - Grafana dashboards + Prometheus alerts that
                          consume the sbproxy_* metrics
  docs/                 - public per-feature docs (architecture, ai-gateway,
                          configuration, scripting, etc.)
```

## Module system

Built-in modules under `crates/sbproxy-modules/src/{action,
auth,policy,transform}/` are enum variants dispatched by explicit
match arms on the config `type` string in
`crates/sbproxy-modules/src/compile.rs`. There is no `init()`-time
registration, no `imports.rs`, and no `pkg/plugin` registry; those
were Go-era mechanisms. Adding a new built-in module:

1. Create the module file, define its config struct, implement the
   relevant trait (`PolicyEnforcer`, `ActionHandler`, `AuthProvider`,
   `TransformHandler`).
2. Add `pub mod my_module;` to the parent `mod.rs` and a variant to
   that kind's enum (`Policy`, `Action`, `Auth`, `Transform`).
3. Add a match arm for the `type` string in
   `crates/sbproxy-modules/src/compile.rs`.
4. Run the pre-commit checks.

A `type` string with no match arm falls through to the typed
inventory registrations in `sbproxy-plugin`
(`inventory::submit!` with `{Action,Auth,Policy,Transform}PluginRegistration`),
which is how linked third-party plugins load, and then to the
config-loaded JS/WASM extension-bundle registry. The generic
`PluginRegistration` channel (with `PluginKind` and a `Box<dyn Any>`
factory) is diagnostics/listing only; the compiler never builds
handlers from it.

## Compiled handler chain

`crates/sbproxy-config/src/compiler.rs` builds each origin's handler
chain inside-out (auth, response cache, transforms, callbacks,
modifiers, policies, etc.). The chain compiles once per origin and
caches; per-request execution does no allocation in the
chain-construction path.

## Conventions

- The public API surface is the following three crates, and only
  these three. Internal crates must not be imported from them, and
  no other crate in this workspace is part of the public surface
  today.
  - `sbproxy-plugin` - public plugin trait surface (`PolicyEnforcer`,
    `ActionHandler`, `AuthProvider`, `TransformHandler`, registry).
    Each of those four has a typed `inventory` registration channel the
    config compiler builds handlers from; that pairing is the bar for
    adding a fifth. `RequestEnricher` was declared here from the first
    commit without one and was removed rather than wired, because its
    only output channel was a `&mut dyn Any` no out-of-tree implementor
    can downcast. Early request annotation is `IdentityResolverHook`,
    `MlClassifierHook`, and `AnomalyDetectorHook`, which are dispatched
    and take a typed `RequestContextView`.
  - `sbproxy-config` - config schema and `compile_config()` entry
    point.
  - `sbproxy-httpkit` - HTTP request/response helpers shared by
    plugin authors.

  Two further public crates are planned but not yet shipped:
  - `sbproxy-events` (planned) - until it lands, events and metrics
    are reached through `sbproxy-observe`, which is treated as
    internal.
  - `sbproxy-proxy` (planned) - until it lands, the request
    pipeline lives in `sbproxy-core` plus the `sbproxy` binary,
    both also treated as internal.

  Do not advertise the two planned crates as available; reach for
  the `sbproxy-observe` / `sbproxy-core` analogs in the interim and
  expect the seam to move when the planned crates ship.
- Storage stack: `redb` for embedded KV, SQLite for relational, and
  `memory / file / memcached / redis` for the response cache. Pebble
  is Go-only and is not used in this workspace.
- All examples in `examples/` use `test.sbproxy.dev` as the upstream
  hostname placeholder.
- No em-dashes in any user-facing content (docs, README, CHANGELOG,
  rustdoc, commit messages).
- The marketing site at `www.sbproxy.dev` is language-agnostic; do
  not lead with "Rust" there. The README and technical docs in this
  repo can.
- Every feature in this repository ships under Apache-2.0. Do not add a
  direct dependency on a closed-source crate or name closed-source crate paths
  in this repository's docs or rustdoc.

## Docs convention

`docs/` is flat: lowercase-hyphenated filenames at the top level, no
subdirectories, no per-crate READMEs. Every doc starts with a level-1
title, then `*Last modified: YYYY-MM-DD*` on the next line. The index
of doc slugs lives in `docs/README.md` and in the marketing site's
`src/data/docsNavigation.js` and must stay in sync.

Buyer-facing reference docs live here: `architecture.md`,
`ai-gateway.md`, `configuration.md`, `scripting.md`,
`openapi-emission.md`, `glossary.md`. Keep archived-Go references to
useful migration or compatibility history only, and link each one to
[`https://github.com/soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go).

Public install + extension story is configuration, not Rust traits.
Surface curl, Homebrew, and Docker for install; surface CEL, Lua,
JavaScript, and WebAssembly for extension. Do not push readers at
`cargo install` or "implement this trait" from buyer-facing docs.

## Planning documents

Implementation plans, specs, and other internal working documents do not
belong in `docs/` - that tree is buyer-facing. Save planning artifacts
under `.claude/plans/` (already gitignored) unless a specific task
explicitly directs otherwise.

## Provider catalog

The AI provider list ships from `crates/sbproxy-ai/data/ai_providers.yml`.
When adding or changing a provider, update every surface in the same
commit:

1. Regenerate the embedded copy:
   `gzip -9 -n -c crates/sbproxy-ai/data/ai_providers.yml > crates/sbproxy-ai/data/ai_providers.yml.gz`
2. Mirror the change in `docs/providers.md`'s table (hand-maintained;
   nothing generates it).
3. Update the hardcoded provider count everywhere: grep the whole repo
   for the old number. It appears roughly 30 times across 20+ files
   (README, docs/ai-gateway.md, every use-case doc, the comparison
   table, root `llms.txt`); check each hit's context before editing so
   an unrelated number is not caught.
4. Leave `docs/llms-full.txt` alone on feature branches. The old
   push-to-main refresh workflow is gone (branch protection refused
   its pushes); the corpus is regenerated at release prep with
   `bash scripts/regen-llms-full.sh` and carried in the release-prep
   PR, which the docs lane accepts as long as the regen matches.
5. The sbproxy.dev site keeps its own copy of the provider docs; flag
   the change for the site repo.

## Cutover state

The active git history of this Rust implementation starts at `v1.0.0`.
The Go implementation shipped publicly as `v0.1.0` through `v0.1.2`
and is archived at [`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go).
See `MIGRATION.md` for upgrade guidance.

The internal config schema is independently versioned and is referred
to as `schema-v1`. Key names and their meanings carry over from the Go
`v0.1.x` line; the file's shape does not. Go compatibility is
deprecated (WOR-2706): the Rust line reads origin behavior only from
`origins.<hostname>:` and never translated the Go line's flat
single-origin file into it, so a flat file is refused with a message
naming `sbproxy-go` rather than compiled into a proxy with no origin
at all. `crates/sbproxy-config/tests/v1_compat.rs` pins that refusal
against the archived fixtures. Descriptive top-level leftovers (`id`,
`config_version`, `workspace_id`) still only warn. Do not conflate
`schema-v1` with binary `v1.0`; the schema label predates this rename
and is intentionally unchanged.

## Cutting a new version

Before tagging a new sbproxy release, update our pinned Pingora fork
first. All `pingora-*` crates are `[patch]`ed (see `Cargo.toml`) to
`github.com/soapbucket/pingora`, branch `sbproxy-0.8.0`. That fork carries
our local patches (for example the dynamic rustls cert resolver) on top of
Cloudflare's upstream, so a release built against a stale branch silently
ships without any upstream fixes landed since the last cut.

Re-sync it as the first step of every release:

1. In the `pingora` checkout, fetch upstream (`origin`,
   `github.com/cloudflare/pingora`) and rebase `sbproxy-0.8.0` onto a
   newer upstream **`main`**, keeping our patch commits on top. Resolve
   any conflicts against the new upstream.

   Never onto a release tag, even though the branch is named for one.
   Cloudflare cuts releases on a release branch, so a tag is not an
   ancestor of `main`: as of 2026-08-28, `0.8.1` holds 8 commits `main`
   does not have while `main` holds 190 that `0.8.1` does not. Rebasing
   onto a tag moves the fork to a different line rather than to an older
   point on the same one, and strands the fixes we have upstreamed,
   which land on `main`.

   The crates declare `0.8.0` and the branch is named `sbproxy-0.8.0`,
   but neither is a release we track. Read the version as an API
   generation.
2. Run `scripts/divergence.sh` in the fork before and after. It prints
   the merge base, how far ahead and behind the fork is, and which files
   we carry, which is the only honest before-and-after for a rebase that
   touches upstream history. The fork's CI prints the same report on
   every PR. Copy the after numbers into the comment above
   `[patch.crates-io]` in `Cargo.toml`.
3. Push the rebased branch to the `sb` remote
   (`git@github.com:soapbucket/pingora.git`).
4. Back in this workspace, refresh `Cargo.lock` so the build resolves to
   the new fork commit, then run the full gate. Diff the lockfile and
   revert anything that is not the `pingora-*` rev bumps: a `cargo update
   -p` on this workspace has silently downgraded unrelated dependencies
   before. Only cut the tag once it is green against the updated fork.

## License + attribution

Apache License 2.0 (`LICENSE`). Open source; free for any use,
including production and commercial, with no field-of-use restriction.

When adding or upgrading a dependency licensed **only** under Apache
2.0 (not dual MIT/Apache-2.0), update the `NOTICE` file in the same
commit; Apache 2.0 §4 requires those attribution entries. Easier to
keep the file correct as you go than to reconstruct it later.

### Verifying NOTICE coverage

`scripts/check-notice.sh` diffs the current Apache-2.0-only dep set
against the names already mentioned in `NOTICE` and fails on a gap.
`scripts/check.sh` and the CI lint job both run it. Zero output and
exit 0 means the file is current.

```bash
bash scripts/check-notice.sh
```

If it prints crate names, add an attribution stanza to `NOTICE` for
each (Apache 2.0 section 4(d) requires the copyright notice and the
URL of the project's source). Dev-dependencies that are Apache-only
should also be listed (mark them "Used as a dev-dependency in test
fixtures only" so the intent is clear). The check is conservative;
err on the side of attributing rather than skipping.

Commercial licensing inquiries: `legal@soapbucket.com`. Trademark
policy is in `TRADEMARKS.md`. Copyright holder is Soap Bucket LLC.
