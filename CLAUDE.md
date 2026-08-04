# sbproxy (Rust workspace)
*Last modified: 2026-08-01*

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
| Spec citations | `bash scripts/check-spec-citations.sh` |
| Env mutation | `bash scripts/check-env-mutation.sh` |
| Doc drift | `bash scripts/check-doc-drift.sh` |
| Tapes + GIF wiring | `make tapes-check` |
| Doc configs | `python3 scripts/sync-doc-configs.py --check` |
| Documented output | `python3 scripts/check-doc-captures.py --check --stackless-only` |
| Installer | `sh scripts/tests/install_verify.sh` |
| Format | `cargo fmt --all -- --check` |
| Nested lockfiles | `bash scripts/check-nested-lockfiles.sh` |
| Supply chain | `cargo deny --all-features check` |
| UI | `cd ui && npm ci && npm run typecheck && npm run test -- --run` |
| Build | `cargo build --workspace --exclude sbproxy-e2e --locked` |
| Test | `cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci` |
| Doctest | `cargo test --workspace --exclude sbproxy-e2e --locked --doc` |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` |
| Docs | `RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc --workspace --no-deps --locked` |
| Payment features (opt-in) | `SBPROXY_CHECK_PAYMENTS=1 bash scripts/check.sh` |

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
required PR lane: non-e2e workspace tests in the dev profile plus
doctests. This keeps the local target directory materially smaller than
full release/e2e runs.

| Variable | Effect |
|---|---|
| `SBPROXY_RELEASE_TESTS=1` | compile test binaries in release mode |
| `SBPROXY_CHECK_E2E=1` | include the `sbproxy-e2e` package |
| `SBPROXY_CHECK_PAYMENTS=1` | clippy + test the settlement feature union |
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
  v1-compat sweep, ~3s
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
    sbproxy-platform/   - circuit breaker, dns, health, messenger, kv storage
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

Caddy-style. Each module under `crates/sbproxy-modules/src/{action,
auth,policy,transform}/` registers itself via `init()` into the
`pkg/plugin` registry. The config compiler discovers modules by name
at config-load time. Adding a new module:

1. Create the module file, define its config struct, implement the
   relevant trait (`PolicyEnforcer`, `ActionHandler`, `AuthProvider`,
   `TransformHandler`, `RequestEnricher`).
2. Register via `plugin::Register{Policy,Action,Auth,Transform,Enricher}`
   in `init()`.
3. Add a blank import to `crates/sbproxy-modules/src/imports.rs`.
4. Run the four pre-commit checks.

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
    `ActionHandler`, `AuthProvider`, `TransformHandler`,
    `RequestEnricher`, registry).
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
4. Leave `docs/llms-full.txt` alone. CI regenerates it on `main`
   after the merge (`.github/workflows/llms-full-refresh.yml`); a
   branch that commits it fails the docs lane.
5. The sbproxy.dev site keeps its own copy of the provider docs; flag
   the change for the site repo.

## Cutover state

The active git history of this Rust implementation starts at `v1.0.0`.
The Go implementation shipped publicly as `v0.1.0` through `v0.1.2`
and is archived at [`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go).
See `MIGRATION.md` for upgrade guidance.

The internal config schema is independently versioned and is referred
to as `schema-v1`; the same schema is supported by both the Go
`v0.1.x` line and the Rust `v1.x` line. The compatibility promise is
pinned by the `v1_compat::v1_fixtures_compile_unmodified` test in
`crates/sbproxy-config/`. Do not conflate `schema-v1` with binary
`v1.0`; the schema label predates this rename and is intentionally
unchanged.

## Cutting a new version

Before tagging a new sbproxy release, update our pinned Pingora fork
first. All `pingora-*` crates are `[patch]`ed (see `Cargo.toml`) to
`github.com/soapbucket/pingora`, branch `sbproxy-0.8.0`. That fork carries
our local patches (for example the dynamic rustls cert resolver) on top of
Cloudflare's upstream, so a release built against a stale branch silently
ships without any upstream fixes landed since the last cut.

Re-sync it as the first step of every release:

1. In the `pingora` checkout, fetch upstream (`origin`,
   `github.com/cloudflare/pingora`) and rebase `sbproxy-0.8.0` onto the
   target upstream tag, keeping our patch commits on top. Resolve any
   conflicts against the new upstream.
2. Push the rebased branch to the `sb` remote
   (`git@github.com:soapbucket/pingora.git`).
3. Back in this workspace, refresh `Cargo.lock` so the build resolves to
   the new fork commit, then run the full gate. Only cut the tag once it
   is green against the updated fork.

## License + attribution

Apache License 2.0 (`LICENSE`). Open source; free for any use,
including production and commercial, with no field-of-use restriction.

When adding or upgrading a dependency licensed **only** under Apache
2.0 (not dual MIT/Apache-2.0), update the `NOTICE` file in the same
commit; Apache 2.0 §4 requires those attribution entries. Easier to
keep the file correct as you go than to reconstruct it later.

### Verifying NOTICE coverage

Run this from the workspace root before opening a PR that touches
`Cargo.toml` or `Cargo.lock`. It diffs the current Apache-2.0-only
dep set against the names already mentioned in `NOTICE` and prints any
gap. Zero output means the file is current.

```bash
cargo metadata --format-version 1 --all-features 2>/dev/null \
  | python3 -c '
import json, sys, re
m = json.load(sys.stdin)
ws = set(m["workspace_members"])
notice = open("NOTICE").read().lower()
for p in m["packages"]:
    if p["id"] in ws: continue
    lic = (p.get("license") or "").strip()
    parts = [x.strip() for x in re.split(r"\s+(?:OR|/)\s+", lic.replace("/", " OR "))]
    apache_only = ("Apache-2.0" in parts and "MIT" not in parts
                   and not any(x.startswith("Apache-2.0 WITH") for x in parts)
                   and "BSL-1.0" not in parts and "CC0-1.0" not in parts)
    if apache_only and p["name"].lower() not in notice:
        print(f"  {p[\"name\"]:<40} {p[\"version\"]:<14} {lic}")
'
```

If any line prints, add an attribution stanza to `NOTICE` for each
named crate (Apache 2.0 §4(d) requires the copyright notice and the
URL of the project's source). Dev-dependencies that are Apache-only
should also be listed (mark them "Used as a dev-dependency in test
fixtures only" so the intent is clear). The check is conservative;
err on the side of attributing rather than skipping.

Commercial licensing inquiries: `legal@soapbucket.com`. Trademark
policy is in `TRADEMARKS.md`. Copyright holder is Soap Bucket LLC.
