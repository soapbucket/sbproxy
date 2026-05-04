# sbproxy (Rust workspace)
*Last modified: 2026-05-03*

The active implementation of sbproxy. Cargo workspace with ~20
crates under `crates/`, an e2e suite under `e2e/`, examples under
`examples/`, and an internal observability/cache/AI/security stack.

## Pre-commit checks

Before committing any change, run all five. Each one corresponds to a
required CI gate; if any fails locally, CI will fail too.

| Check | Command |
|---|---|
| Format | `cargo fmt --all -- --check` |
| Build | `cargo build --workspace` |
| Test | `cargo test --workspace --release --tests` |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` |
| Docs | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items` |

Fix the issue before pushing. Do not paper over with `#[allow(...)]`
unless you also write a one-line comment explaining the deliberate
exception.

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

## Workspace layout

```
sbproxy-rust/
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
    sbproxy-extension/  - scripting (CEL, Lua, JavaScript, WASM stub),
                          MCP server, feature flags
    sbproxy-observe/    - metrics (sbproxy_*), events, structured logging
    sbproxy-security/   - WAF, PII redactor, certpin, hostfilter
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

- The public API surface lives in `sbproxy-plugin`, `sbproxy-config`,
  and `sbproxy-httpkit`. Internal crates must not be imported from
  these. Two further public crates (`sbproxy-events` and
  `sbproxy-proxy`) are planned but not yet implemented; until they
  ship, the closest analogs are `sbproxy-observe` (events / metrics)
  and `sbproxy-core` (request pipeline) plus the `sbproxy` binary.
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
- Enterprise features live in `../sbproxy-enterprise/`. Do not import
  enterprise crates from OSS code; use the `sbproxy-plugin` traits.
  The `sbproxy-enterprise` name must not appear anywhere in this
  repo's `docs/` (with the single exception of `docs/enterprise.md`,
  which is the canonical landing page) or rustdoc comments.

## Docs convention

`docs/` is flat: lowercase-hyphenated filenames at the top level, no
subdirectories, no per-crate READMEs. Every doc starts with a level-1
title, then `*Last modified: YYYY-MM-DD*` on the next line. The index
of doc slugs lives in `docs/README.md` and in the marketing site's
`src/data/docsNavigation.js` and must stay in sync.

Buyer-facing reference docs live here: `architecture.md`,
`ai-gateway.md`, `configuration.md`, `config-reference.md`,
`scripting.md`, `openapi-emission.md`, `glossary.md`,
`wave-history.md`, plus per-feature ADRs prefixed `adr-`. The
`upgrade.md` file is the only place archived-Go references are
allowed.

Public install + extension story is configuration, not Rust traits.
Surface curl, Homebrew, and Docker for install; surface CEL, Lua,
JavaScript, and WebAssembly for extension. Do not push readers at
`cargo install` or "implement this trait" from buyer-facing docs.

## Cutover state

The active git history of this Rust implementation starts at `v1.0.0`.
The Go implementation shipped publicly as `v0.1.0` through `v0.1.2`
and is archived at `github.com/soapbucket/sbproxy-go`. See
`MIGRATION.md` for upgrade guidance.

The internal config schema is independently versioned and is referred
to as `schema-v1`; the same schema is supported by both the Go
`v0.1.x` line and the Rust `v1.x` line. The compatibility promise is
pinned by the `v1_compat::v1_fixtures_compile_unmodified` test in
`crates/sbproxy-config/`. Do not conflate `schema-v1` with binary
`v1.0`; the schema label predates this rename and is intentionally
unchanged.

## License + attribution

Business Source License 1.1 (`LICENSE`). Source-available; production
use is allowed for everything except offering SBproxy as a competing
hosted or managed service.

When adding or upgrading a dependency licensed **only** under Apache
2.0 (not dual MIT/Apache-2.0), update the `NOTICE` file in the same
commit; the BSL Change License is Apache 2.0, and Apache 2.0 §4 will
require those entries once the license flips. Easier to keep the file
correct as you go than to reconstruct it later.

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
