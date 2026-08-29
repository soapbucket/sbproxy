# scripts/

*Last modified: 2026-08-28*

Helper scripts that wrap the day-to-day dev loop and the CI runners
the GitHub workflows invoke. Run from the repository root unless a
script's header says otherwise.

## Inventory

| Script | What it does | CI workflow |
|---|---|---|
| `check.sh` | Local CLAUDE.md gate. Mirrors the lanes in `ci.yml`, `docs-ci.yml`, and `doc-drift.yml`, cheapest phase first; requires cargo-nextest; guards that the working tree still matches HEAD at the end. | local |
| `check-fast.sh` | Every gate check that needs no workspace build and no network, run in parallel, in about 40 seconds. What to run before a push and after every merge from main. Prints a NOT COVERED block naming the checks that need a compiler and the lane that catches each. | local |
| `gate-scope.py` | The diff-to-phase classifier behind `check.sh --scope-to-diff` and `--explain`. An unrecognized path runs everything. `--self-test` carries a corpus of real CI failures. | local + `.github/workflows/ci.yml` (lint) |
| `post-merge-rederive.sh` | Re-derive every generated artifact after a merge from main and print what moved: schemas, generated docs, the examples catalog, the tape corpus, llms-full when the branch carries it, and the seven ratchet baselines. Baselines only fall; a rise is refused. `--check` reports without writing. | local |
| `check-attribute-theft.py` | Refuse an insertion that lands between an attribute block and the item it was attached to, which moves the rustdoc, the `#[test]` or the `#[derive]` onto the newcomer. Diff-scoped against the merge base; fails closed when no base resolves. `--self-test` replays the two real hunks it was written for. | local + `.github/workflows/ci.yml` (guards) |
| `check-attribute-placement.py` | Refuse an attribute that cannot apply to the item under it: `#[test]` on a `static`, a `const`, a `use`, or a function taking arguments, and `#[ignore]` or `#[should_panic]` on a function carrying no test attribute. Parses rather than greps, and reads every cfg rather than only the ones a lane compiles. | local + `.github/workflows/ci.yml` (guards) |
| `lib/expect-tests.sh` | `expect_tests <count> <label> -- <command>`. Assert how many tests a filtered selection actually ran, because `cargo test`, `--exact` and `--ignored` all exit 0 when the filter matches nothing. | sourced by the scripts and workflows that name individual tests |
| `cleanup-build-artifacts.sh` | Prune generated docs, nextest output, incremental dirs, and transient logs without deleting dependency build outputs. | local + CI |
| `run-e2e.sh` | Build the Rust proxy and run the maintained HTTP conformance smoke set. | local + CI |
| `run-all-e2e.sh` | Build the Rust proxy and audit all 93 cases in the historical HTTP catalog. | local + CI |
| `build-e2e.sh` | Just the proxy build step (release profile). | shared by other runners |
| `perf-compare.sh` | Two-bench delta comparison between branches. | nightly bench |
| `generate-certs.sh` | Mint a local CA + leaf cert for TLS tests. | local only |
| `install.sh` | One-command install of `sbproxy` from a release archive. | end-user |
| `docs-ci.sh` | Wave 1 / Q1.10 doc CI runner: lychee + code-block check. | `.github/workflows/docs-ci.yml` (B1.10) |
| `sync-doc-configs.py` | Sync strict documentation configs from compiler-validated examples, or report drift with `--check`. | local + `.github/workflows/docs-ci.yml` |
| `check-model-host-capabilities.sh` | Fail when the generated model-host capability matrix drifts from the executable registry. | `.github/workflows/ci.yml` |
| `examples-smoke.sh` | Local examples smoke runner. | local only: `make examples-smoke` |
| `bundle-digest.sh` | Print an extension bundle's `digest_scope: bundle_v1` SHA-256, covering `bundle.yaml` and every file it ships. | local only: bundle authoring |

Per-script usage and env knobs live in each script's leading comment
header. Run `<script> --help` to dump the header.

`check.sh` defaults to the same non-e2e test scope as the required PR
lane to keep local disk growth bounded. Set `SBPROXY_RELEASE_TESTS=1`
for release-profile test binaries and `SBPROXY_CHECK_E2E=1` when you
need to include the full e2e package locally.

The settlement feature union runs by default. No other phase compiles it,
because no payment feature is in any default set, and CI requires the
matching `payments` lane. It was opt-in until a
`clippy::items_after_test_module` failure landed on main from a lane no
local run had ever executed, which is what an env var everyone forgets
buys you. `SBPROXY_CHECK_PAYMENTS=0` still skips it, and the run reprints
that choice in `SKIPPED PHASES` naming the CI lanes that will catch what
was missed. The union recompiles the graph rather than reusing the rest of
the gate's artifacts, so `--scope-to-diff` drops it when no Rust file
changed.

It fails when the working tree is dirty at the end of the run, because
the gate validates the working tree while `git push` ships HEAD. Set
`SBPROXY_ALLOW_DIRTY_TREE=1` for a deliberate work-in-progress run.
Every phase it could not run is reprinted as a `SKIPPED PHASES` block
before the final result; `promtool` and `cargo-deny` are the two
optional tools that land there. The full env-var list is in `CLAUDE.md`.

`cleanup-build-artifacts.sh --aggressive` additionally removes
`target/release` after local release-profile experiments. The default
cleanup keeps release artifacts so deployment-oriented workflows do not
pay an unexpected rebuild cost.

## Fuzz harnesses

`fuzz/` is a standalone cargo-fuzz crate whose targets cover the Wave 4
parsers, the stateful proxy driver, and the scripting runtimes. Nothing
runs them for you. They had a CI lane, `.github/workflows/wave4-fuzz.yml`,
whose job was gated on a `run-fuzz` pull request label that was never
created in this repository, so the lane concluded `skipped` on every run
it ever had and a green pull request never meant the fuzzers ran. That
file is deleted rather than repaired: a lane that reads as coverage in
review and delivers none is worse than no lane. `check.sh` does not run
them either, so they are a deliberate manual job.

cargo-fuzz is nightly-only, and neither nightly nor cargo-fuzz ships with
a plain `cargo`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

`cargo install` rather than `cargo binstall`, for the reason under
"Naming the target" below.

Homebrew's rust and rustup both provide a `cargo`, and only rustup's
understands `+nightly`, so put rustup ahead of Homebrew on `PATH`, and
keep `~/.cargo/bin` on it so `cargo-fuzz` is found. Then, from `fuzz/`:

```bash
cargo +nightly fuzz list

mkdir -p ~/.cache/sbproxy/fuzz-corpus/<target>
cargo +nightly fuzz run \
  --target "$(rustc +nightly -vV | sed -n 's/^host: //p')" \
  <target> \
  ~/.cache/sbproxy/fuzz-corpus/<target> \
  -- -max_total_time=15
```

`+nightly` is doing real work on both lines. `fuzz/` sits under the
repository root, so rustup resolves the root `rust-toolchain.toml` there
and would otherwise hand cargo-fuzz the pinned stable, which cannot
build a sanitized target at all. It propagates into the `cargo` that
cargo-fuzz itself invokes. Dropping it produces a failure with nothing
in this document to explain it.

`cargo +nightly fuzz list` is the only complete list of targets. The
deleted CI matrix named nine by hand while `fuzz/Cargo.toml` declares
ten, so `cel_script`, the one target with a committed seed corpus, was
fuzzed nowhere.

### Naming the target

`--target` is not decoration there, and leaving it out is why the old CI
lane failed. Every manual dispatch of that lane, one on `main` and one on
a branch, died inside `cargo fuzz run` with the same pair of errors on
every target:

```
error: sanitizer is incompatible with statically linked libc,
       disable it using `-C target-feature=-crt-static`
error[E0463]: can't find crate for `std`
error[E0463]: can't find crate for `core`
error: could not compile `serde_core` (lib) due to 2 previous errors
```

cargo-fuzz builds with `-Zsanitizer=address` and passes cargo an explicit
`--target`, which is what keeps those RUSTFLAGS off build scripts and
proc macros. When you do not name one, it fills in
`current_platform::CURRENT_PLATFORM`, a constant baked in when the
cargo-fuzz binary itself was compiled. The default is therefore the
triple cargo-fuzz was *built* for, not the triple of the machine it is
running on.

That lane installed cargo-fuzz with `cargo binstall`, and as of 0.13.2
the only Linux binary cargo-fuzz publishes is
`x86_64-unknown-linux-musl`. So an `ubuntu-latest` runner ended up with a
cargo-fuzz that defaulted every build to musl. musl targets are
`+crt-static` by default and rustc refuses AddressSanitizer on a
statically linked libc, which is the first error. The nightly toolchain
the lane installed carried only the gnu standard library, and nothing had
installed a musl one, which is the rest of them. All of it comes out of
the same mismatch.

`-C target-feature=-crt-static` in the fuzz RUSTFLAGS is the other remedy
people reach for, and it answers only the first line. It does not put a
musl sysroot on disk, and the missing crate there is `core` as well as
`std`, which no codegen flag can conjure. Naming the target clears the
whole set, and it also stops the command depending on how cargo-fuzz was
installed. Deriving the triple from `rustc +nightly -vV` rather than
hardcoding one keeps it right on Apple Silicon too, where the only
published darwin binary is x86_64.

**What is verified and what is not.** The cause above is read off the
error text, the `default_value` on cargo-fuzz's `BuildOptions` triple,
and the asset list on its releases. It has not been confirmed by a
passing run. No target in this crate has been observed passing anywhere,
and the machine this was written on has no rustup, no nightly, and no
cargo-fuzz to try it on. Treat the command as a derived fix that nobody
has executed yet. If it still fails, check whether
`cargo +nightly fuzz build <target>` gets further than `run` does, which
separates a build problem from a libfuzzer one.

One more thing the evidence does not cover. The failure was only ever
seen with a binstalled cargo-fuzz. `cargo install` builds from source and
bakes in the host triple, so the install above may never have hit this at
all. Nobody has run it either way, which is the reason `--target` is in
the command regardless: it costs nothing and it removes the question.

A clean run ends with libfuzzer's own summary line, `Done N runs in M
second(s)`, and `cargo fuzz run` exits 0. A crash writes a reproducer
into `fuzz/artifacts/<target>/` and exits non-zero. That shape is
libfuzzer's documented output, not a transcript captured from this
repository.

### The corpus arguments

libfuzzer treats its first corpus argument as an output directory and
grows it with every interesting input it finds, and cargo-fuzz defaults
that argument to `fuzz/corpus/<target>/`. A default run therefore leaves
either a new untracked directory or new files inside the tree, and
`check.sh`'s working-tree guard fails on it afterwards. That is why the
command above points the writable corpus at `~/.cache/`.

`cel_script` is the only target with committed seeds, under
`fuzz/corpus/cel_script/`. Pass those as a second, read-only argument
for that target and no other:

```bash
cargo +nightly fuzz run \
  --target "$(rustc +nightly -vV | sed -n 's/^host: //p')" \
  cel_script \
  ~/.cache/sbproxy/fuzz-corpus/cel_script \
  corpus/cel_script \
  -- -max_total_time=15
```

The other nine have no corpus directory at all, and naming one that is
not there either stops the run or gets the directory created inside the
repository, which is what this section exists to avoid.

Crash reproducers land in `fuzz/artifacts/<target>/`, which is
gitignored for the same reason.

### If you want these on a schedule

A finished implementation of a seven-day cadence already exists, and it
was deliberately not merged: `check.sh` runs every target
`cargo fuzz list` reports for fifteen seconds each once the stamp is
older than a week, the stamp and the corpus live under XDG state and
cache so the repository's many worktrees do not each pay a cold nightly
build, and the phase prints install instructions and skips rather than
failing the gate when nightly or cargo-fuzz is missing. Scheduling
targets nobody has seen pass would repeat the mistake of the label that
never existed, so it stays unmerged until a target runs clean.

It is commit `5aa4a6f3` on the local branch `chore/fuzz-local-gate`,
which has never been pushed. A fresh clone will not have that object, so
treat the paragraph above as the durable record and the SHA as a pointer
that only resolves in a checkout that already carries the branch. Read
it before rebuilding any of that rather than after.

## Cross-cutting runners

`docs-ci.sh` is wrapped by GitHub Actions. `examples-smoke.sh` is a
local-only runner because it builds Docker images for example stacks and
is too expensive for the default CI lanes. Both scripts exit non-zero on
failure and print one line per checked artifact.

`docs-ci.sh` lints and link-checks every doc under `docs/`.

### Documentation configuration sources

Complete, copyable configuration blocks use files under `examples/` as their
source of truth. The existing `validate_examples` Rust test compiles those
files against the runtime schema. `sync-doc-configs.py` supplies the other
half of the contract by keeping opted-in documentation blocks identical to
their canonical source.

Delimit the complete body in the canonical example:

```yaml
# sbproxy-docs:begin
proxy:
  http_bind_port: 8080
# sbproxy-docs:end
```

Bind a documentation fence to that file by placing this marker immediately
before it:

```text
<!-- sbproxy-config: examples/basic-proxy/sb.yml -->
```

The next fence must be a `yaml` fence. Run `scripts/sync-doc-configs.py` to
refresh strict blocks, or `scripts/sync-doc-configs.py --check` to fail on
drift without writing. Canonical paths must use a compiler-swept
`examples/<name>/sb.yml` or one of the additional multi-file gateway configs
explicitly included in that sweep. Each source exposes exactly one ordered
begin/end pair.

Partial topology maps and field fragments are intentional excerpts, not
runnable files. Mark the immediately following YAML fence with
`<!-- sbproxy-config-excerpt -->`; the checker records but does not sync that
block. Unmarked legacy fences remain unchanged so pages can adopt this
contract incrementally. New or edited blocks presented as complete and
usable should use the strict source marker. Intentionally partial blocks
should use the excerpt marker.

`examples-smoke.sh` discovers every directory under `examples/` that
ships a `docker-compose.yml` and runs a smoke probe against the
running stack. Each example may add an optional `smoke.json`
declaring how to probe the running services.

### smoke.json schema

```json
{
  "admin_port":        9090,
  "data_plane_port":   8080,
  "health_path":       "/healthz",
  "cases": [
    {
      "name": "echo works",
      "request": {
        "method": "GET",
        "path": "/echo",
        "headers": { "Host": "app.localhost" },
        "body": { "message": "hello" }
      },
      "expect": {
        "status": 200,
        "headers": { "content-type": "application/json" },
        "body": {
          "type": "jsonShape",
          "shape": { "method": "GET" }
        }
      }
    }
  ],
  "feature_endpoints": ["/preview/x", "/api/v1/foo"],
  "audit_check":       false
}
```

Field-by-field:

| Field | Default | Notes |
|---|---|---|
| `admin_port` | same as `data_plane_port` | The port the runner polls for liveness. The proxy serves `/healthz` on its admin listener (default 9090) only when `proxy.admin.enabled: true`; examples that do not enable the admin listener can point this at the data-plane port and set `health_path: "/health"`. |
| `data_plane_port` | discovered from the first `published:` port in `docker-compose.yml` | The port the runner hits for `feature_endpoints[]`. |
| `health_path` | `/healthz` | The path used for the liveness probe. Use `/health` for examples that do not enable the admin listener. |
| `cases` | `[]` | Preferred assertion format. Each case can assert method, path, request headers, an optional JSON request `body` sent with `curl --data-binary`, expected status, expected response headers as regexes, and `body.type: "jsonShape"` subset matches. Add `requires_env` to skip a case unless one or more env vars are set. |
| `feature_endpoints` | `[]` | Legacy shorthand. Each entry is a path on the data-plane port that the runner GETs and asserts returns 2xx. |
| `audit_check` | `false` | When `true`, the runner additionally hits `/api/audit/recent` on the admin port and asserts at least one entry. The OSS in-memory adapter does not ship this endpoint until Wave 2 (R1.2); leave `false` for Wave 1 examples. |

Legacy fields `port` and `endpoints` are still accepted as aliases
for `data_plane_port` and `feature_endpoints` respectively.

Examples with `docker-compose.yml` must ship `smoke.json`. This keeps new
examples from silently skipping README/runtime drift coverage. Set
`SBPROXY_SMOKE_REQUIRE_MANIFEST=false` only for local migration work.
