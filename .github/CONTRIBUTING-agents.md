# Working on sbproxy as an agent

These are the rules every automated contributor follows in this repository. They exist because
each one has cost us a CI round trip or a bad merge. Read them once, then follow them exactly.

## Branches and worktrees

- Branch from `origin/main`, one worktree per task, never from another feature branch.
- Never `git stash`. Never force-push. Never merge on GitHub with `--auto`.
- Merge `origin/main` into your branch before you push, every time. If main moved while you
  worked, merge again. Resolve conflicts in generated files by regenerating them from the
  merged tree, never by taking one side (schema, `docs/metrics-stability.md`,
  `examples/README.md`, `docs/llms-full.txt` if the branch carries it, the ratchet baselines).
- Immediately after the merge, run `bash scripts/post-merge-rederive.sh`. It re-derives that
  whole list and prints what moved, in about thirty seconds. A merge leaves those files stale
  without ever conflicting on them, so nothing else asks you to look. `--check` reports
  without writing. Ratchet baselines only fall: a rise is refused with the delta rather than
  written.

## Audit before implementing

Reproduce the ticket's defect or gap on main first with a failing test, and keep the red run
in your notes. Scope goes stale between filing and merging; a ticket that no longer reproduces
gets a comment, not a fix.

For a design question, look at what LiteLLM, Portkey, Kong, APISIX, Envoy Gateway, and
Traefik do, pick the state of the art, and cite it in the PR. Decisions a ticket marks as
settled are not reopened.

## The delivery bar for a feature ticket

- The feature, with a red-first test named for the seam it covers.
- A `docs/` update. US English. No em dashes anywhere, including code comments and commit
  messages. No AI attribution anywhere.
- A runnable example under `examples/` when the feature is operator-configurable, validated
  by `python3 scripts/gen-examples-catalog.py --check`.
- Metrics with a Grafana panel; `scripts/check-metric-visibility.sh` stays green and its
  baseline only falls.
- A typed decision event or structured log where the feature decides. Never a secret, a
  credential, a payload, or a raw URL with userinfo in a log, an error, an event, or a label.
- An admin surface where an operator would look. A JSON route under the admin API counts; a
  console page may be deferred with a written note beside the route.
- A change fragment per user-visible behavior: `python3 scripts/changelog-fragments.py --new
  <added|changed|fixed|removed> '...'`. Never edit `CHANGELOG.md` by hand.
- Every config key documented in `docs/configuration.md` and read by production code
  (`scripts/check-config-readers.sh`). A covered function is not a wired one: trace config key
  to constructor to live call site.
- Any path-shaped config key goes on `HOST_FILE_KEYS` in
  `crates/sbproxy-config/src/confined_template.rs`, or on its allowlist with a true reason.
  `every_path_shaped_schema_key_is_covered_or_explained` must pass.
- A new dependency needs a NOTICE stanza (`bash scripts/check-notice.sh`) and a clean
  `cargo deny`.
- Secret-reference parsing goes through the shared classifier, never an ad-hoc prefix check
  (`python3 scripts/check-secret-resolver-drift.py`); do not add exemptions.

## What to run, by what you changed

Two commands cover nearly all of it.

```
bash scripts/check-fast.sh          # 38s. Every check that needs no build, in parallel.
bash scripts/check.sh               # the full gate, ~45 minutes. Before you push.
```

`check-fast.sh` is the one to run constantly: after every merge from main, after a docs edit,
before you go looking for why CI is red. It runs twenty-five checks and catches six of the
nine failures that cost a CI round trip on 2026-08-27, including the two that no local runner
covered at all (the `rust` code blocks in `docs/*.md`, and every in-tree anchor). It prints a
NOT COVERED block naming the three that need a compiler and the lane that catches each, so a
green run cannot be mistaken for a green gate.

### Scoping the gate to your diff

```
bash scripts/check.sh --explain            # what the diff selects, per changed path
bash scripts/check.sh --scope-to-diff      # run only the phases the diff can reach
```

`--scope-to-diff` skips the phases nothing in your diff can affect. A docs-only branch runs
the cheap tier plus `TAPES` and `DOCSCI` and skips the workspace build, test, doctest, clippy,
rustdoc, generated-artifact, UI, and payments phases.

Trust it in exactly one direction. An unrecognized path runs everything, and so does an empty
diff, a missing merge base, or a git call that fails: unclassified never means skip. What it
cannot do is narrow a package selection, because every cargo phase in `check.sh` is
`--workspace`; a phase either runs over the whole workspace or does not run. The mapping lives
in `scripts/gate-scope.py`, its `--self-test` carries a corpus of real CI failures asserting
each still selects the phase that catches it, and both `check.sh` and CI's `lint` lane run
that self-test unconditionally.

**The last run before you push is `bash scripts/check.sh` with no arguments.** Scoping is for
the iteration loop.

### Mid-iteration, while you are still editing Rust

Per-crate is the scoped shape. `check.sh` has no per-crate mode, so these are hand-run:

```
cargo check -p <crate>
cargo clippy -p <crate> --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p <crate> --no-deps
cargo nextest run -E 'rdeps(<crate>) + package(<crate>)'
```

That filterset is the scoped test command: the crate you touched plus every crate that depends
on it, which is the set a struct-literal or a changed string can break. It needs nothing newer
than nextest 0.9.137. Pair it with the payment union when you touch `sbproxy-core`:

```
cargo clippy -p sbproxy-core --all-targets \
  --features "<PAYMENT_FEATURES from .github/workflows/ci.yml>" -- -D warnings
```

None of that replaces the gate. `cargo nextest run -E` narrows a package selection, which is
exactly the thing `--scope-to-diff` refuses to do, so it is an iteration tool and never the
last word.

### Docs, examples, or dashboards only

`bash scripts/check-fast.sh` covers this whole case. It is the same set the docs lane checks,
plus the catalog, config, capture, and fragment scans, and it needs no workspace build. Two
traps live here: a `rust` code block in `docs/` must compile standalone or carry `rust,no_run`,
and renaming a heading needs a repo-wide grep for its anchor, because another page is linking
to it.

If the diff contains no `.rs` file, no `Cargo.toml`, no `Cargo.lock`, and no `build.rs`, there
is nothing for a cargo command to find. `bash scripts/check.sh --scope-to-diff` reaches the
same conclusion and prints its reasoning.

Add `python3 scripts/check-review-evidence.py --body-file <your PR body>` before you open the
pull request.

### UI only (`ui/`)

The npm typecheck and unit tests, plus the admin-UI build; touch `admin_ui.rs` after
`npm run build` so the embedded assets are rebuilt.

### Before you push

```
bash scripts/check.sh
```

The pinned toolchain is 1.98; Homebrew's 1.95 misses some lints, so CI on 1.98 is the
authoritative lint and doc run.

The payment settlement features run in that gate by default. They are the only place
`clippy::items_after_test_module` and the feature-gated majority of `sbproxy-billing` compile
at all, and they were opt-in until that cost a round trip. `SBPROXY_CHECK_PAYMENTS=0` still
skips them, and the run reprints that choice in `SKIPPED PHASES` naming the two CI lanes that
will catch what you missed.

Traps that only show up in the full run: a private intra-doc link fails the docs lane; the
smoke lane runs a DEBUG `sbproxy`, so anything that adds frames to the AI dispatch path must
keep the stack guard tests green under the dev profile; a merge from main can leave the
examples catalog or a nested lockfile stale even when nothing conflicted, which is what
`scripts/post-merge-rederive.sh` is for.

## Ratchets only fall

The seven `scripts/*-baseline.count` files may only go down. Use the workspace's
`LazyLock<Option<_>>` shape for metric registration instead of `expect`.
`bash scripts/post-merge-rederive.sh` lowers a baseline that fell and refuses one that would
rise, printing how many sites the merge added. Raising one by hand is the exception, not the
tool, and it needs its reason in the pull request.

## The PR

Follow `.github/PULL_REQUEST_TEMPLATE.md`. The `## Adversarial review` section is checked by
`python3 scripts/check-review-evidence.py --body-file <file>`: a Reviewer line, a Findings
count line, and one item per finding in this shape:

```
- Major - crates/sbproxy-core/src/server/proxy_http.rs:5334 - claim. Fixed in a1b2c3d4.
```

with backticks around the path and the hash. A declined item reads `Declined: <reason>` in
place of the `Fixed in` clause. The review
is run by someone other than the author against `.github/code-review-rubric.md`; a self-review
is not the review. Fix every finding in the loop; tickets are for decisions, not for defects
you found.

Commits: plain conventional messages, no trailers, no tool attribution. Linear tickets move to
In Progress when work starts and to Done at the merge, not at the end of the session.
