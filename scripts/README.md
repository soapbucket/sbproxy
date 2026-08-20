# scripts/

*Last modified: 2026-08-20*

Helper scripts that wrap the day-to-day dev loop and the CI runners
the GitHub workflows invoke. Run from the repository root unless a
script's header says otherwise.

## Inventory

| Script | What it does | CI workflow |
|---|---|---|
| `check.sh` | Local CLAUDE.md gate. Mirrors the lanes in `ci.yml`, `docs-ci.yml`, and `doc-drift.yml`, cheapest phase first; requires cargo-nextest; guards that the working tree still matches HEAD at the end. | local |
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

`SBPROXY_CHECK_PAYMENTS=1` adds the settlement feature union, which no
other phase compiles because no payment feature is in any default set.
CI requires the matching `payments` lane, so leaving it off is a real
gap rather than a shortcut, and the run says so in `SKIPPED PHASES`. It
is opt-in only because that union recompiles the graph instead of
reusing the rest of the gate's artifacts.

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

Homebrew's rust and rustup both provide a `cargo`, and only rustup's
understands `+nightly`, so put rustup ahead of Homebrew on `PATH`, and
keep `~/.cargo/bin` on it so `cargo-fuzz` is found. Then, from `fuzz/`:

```bash
cargo +nightly fuzz list
cargo +nightly fuzz run <target> -- -max_total_time=15
```

`cargo +nightly fuzz list` is the only complete list of targets. The
deleted CI matrix named nine by hand while `fuzz/Cargo.toml` declares
ten, so `cel_script`, the one target with a committed seed corpus, was
fuzzed nowhere.

Two things to know before the first run.

libfuzzer treats its first corpus argument as an output directory and
grows it with every interesting input it finds, and cargo-fuzz defaults
that argument to `fuzz/corpus/<target>/`. A default run therefore leaves
either a new untracked directory or new files inside the tree, and
`check.sh`'s working-tree guard fails on it afterwards. Point the
writable corpus somewhere outside the repository and pass the committed
seeds as a second, read-only argument:

```bash
mkdir -p ~/.cache/sbproxy/fuzz-corpus/<target>
cargo +nightly fuzz run <target> \
  ~/.cache/sbproxy/fuzz-corpus/<target> \
  corpus/<target> \
  -- -max_total_time=15
```

Crash reproducers land in `fuzz/artifacts/<target>/`, which is
gitignored for the same reason.

And expect a failure that is not yours. No target here has been observed
passing anywhere. The only manual dispatches of the old CI lane, one on
`main` and one on a branch, failed every target identically inside
`cargo fuzz run`:

```
error: sanitizer is incompatible with statically linked libc,
       disable it using `-C target-feature=-crt-static`
error[E0463]: can't find crate for `std`
```

`main` fails that way with no local change involved, so this is
pre-existing rot rather than anything a caller did. WOR-2594 owns the
fix and wants the failure reproduced before a remedy is picked, which is
why neither this document nor the crate carries a speculative
`-C target-feature=-crt-static`. Whether the same break happens on macOS
is not yet known: nobody has had a nightly toolchain on a Mac to try.

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
