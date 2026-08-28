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

Scope the checks to the change. **If the diff contains no `.rs` file, no `Cargo.toml`, no
`Cargo.lock`, and no `build.rs`, run no cargo command at all**: not `cargo fmt`, not `clippy`,
not `cargo doc`, not `cargo test`, and not `scripts/check.sh`. There is nothing for them to
find, and the full gate takes about 40 minutes and rebuilds the world.

Anything that does touch Rust or a manifest runs the whole Rust tier below, including the
full gate before you push.

**Docs, examples, or dashboards only (no `.rs`, no manifest, no lockfile):**

```
bash scripts/docs-ci.sh                           # rustc (not cargo) on rust code blocks, offline anchor check
python3 scripts/gen-examples-catalog.py --check    # if examples/ changed
python3 scripts/sync-doc-configs.py --check        # if configuration.md changed
python3 scripts/check-doc-captures.py --check      # documented output still matches the code
python3 scripts/changelog-fragments.py --check
python3 scripts/check-review-evidence.py --body-file <your PR body>
```

That set is cheap, needs no workspace build, and covers what the docs lane checks. Two traps live here: a `rust` code
block in `docs/` must compile standalone or carry `rust,no_run`, and renaming a heading needs
a repo-wide grep for its anchor, because another page is linking to it.

**UI only (`ui/`):** the npm typecheck and unit tests, plus the admin-UI build; touch
`admin_ui.rs` after `npm run build` so the embedded assets are rebuilt.

**Rust, manifests, or lockfiles:** everything above that applies, plus

```
cargo fmt --all -- --check
cargo clippy -p <crate> --all-targets -- -D warnings           # per touched crate
cargo clippy -p sbproxy-core --all-targets --features "<PAYMENT_FEATURES from .github/workflows/ci.yml>" -- -D warnings
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p <crate> --no-deps
bash scripts/check-notice.sh
bash scripts/check-config-schema.sh
bash scripts/check-metrics-stability.sh
bash scripts/check-config-readers.sh               # if a config key was added or is newly read
python3 scripts/check-secret-resolver-drift.py
scripts/check-pub-item-ratchet.sh
scripts/check-unwrap-ratchet.sh
scripts/check-nested-lockfiles.sh
```

and then `bash scripts/check.sh` before you push. The pinned toolchain is 1.98; Homebrew's
1.95 misses some lints, so CI on 1.98 is the authoritative lint and doc run.

Traps that only show up in the full run: a private intra-doc link fails the docs lane; items
placed after `#[cfg(test)] mod tests` fail clippy under the payment features; the smoke lane
runs a DEBUG `sbproxy`, so anything that adds frames to the AI dispatch path must keep the
stack guard tests green under the dev profile; a merge from main can leave the examples
catalog or a nested lockfile stale even when nothing conflicted.

## Ratchets only fall

`scripts/check-unwrap-ratchet.sh` and `scripts/check-pub-item-ratchet.sh` may only go down.
Use the workspace's `LazyLock<Option<_>>` shape for metric registration instead of `expect`.
A raised pub-item baseline needs its reason written into `scripts/pub-item-ratchet-baseline.txt`
and is the exception, not the tool.

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
