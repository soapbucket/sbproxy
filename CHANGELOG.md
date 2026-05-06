# Changelog

All notable changes to SBproxy v1.x. Versions before v1.0 shipped as the
Go implementation and now live in the archived
[`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go)
repository.

## [Unreleased]

Work that has merged to `main` since the v1.0.1 tag and is queued for
the next version cut. No promises about backward compatibility for any
of the new YAML fields below until the version that ships them.

### Added

- **Operator first-24-hours quickstart.** Added a concise
  `docs/quickstart-operator.md` covering deploy, `/readyz`, metrics,
  Grafana, logs, and rollback, linked from the README and Kubernetes
  docs.
  ([docs/quickstart-operator.md])

- **Hostname cardinality override for metrics.** `proxy.metrics.cardinality.hostname_cap`
  can lower the `hostname` label budget independently from the default
  per-label cap, enabling deterministic overflow tests and tighter
  multi-tenant Prometheus budgets.
  ([crates/sbproxy-config/src/types.rs],
  [crates/sbproxy-observe/src/cardinality.rs])

- **`release-fast` build profile for CI images.** Docker-based CI and
  local kind smoke-test builds can now use `CARGO_PROFILE=release-fast`
  to skip fat LTO and use more codegen units, cutting link memory/time
  while leaving production release artifacts on the existing `release`
  profile.
  ([Cargo.toml], [Dockerfile.ci], [Dockerfile.cloudbuild])

- **Reproducible build probe workflow.** CI now has an informational
  double-build lane that builds the release binary twice on independent
  GitHub-hosted runners, uploads each binary and SHA-256, and publishes
  a comparison report without yet treating non-identical output as a
  failure.
  ([.github/workflows/reproducible-build.yml], [SUPPLY-CHAIN.md])

- **WOR-114 Phase 2: CEL `features[...]` namespace.** Per-request
  flags parsed from the `x-sb-flags` header and `?_sb.<key>` query
  prefix are now exposed to CEL expressions. Built-in flags surface
  as bools (`features.debug`, `features.trace`,
  `features["no-cache"]`, `features.any_set`); free-form `k=v` extras
  surface as strings (`features["env"]`). Wired into the rate-limit
  CEL evaluator and `ExpressionPolicy::evaluate_with_views`.
  ([crates/sbproxy-extension/src/cel/context.rs])

- **`SB_WORKER_THREADS` env var.** Positive integer overrides the
  auto-detected Pingora worker thread count
  (`std::thread::available_parallelism()`). Useful for benchmarking
  with a fixed worker count or capping the pool below a cgroup quota.
  ([crates/sbproxy-core/src/server.rs])

- **`/live`, `/livez`, `/ready`, `/healthz`, and rich `/health`
  admin endpoints.**
  `/livez` returns `{"alive":true}` on every call and never 503s, so
  K8s liveness probes don't trip on transient readiness failures.
  `/live` is a bare alias. `/ready` is an alias for `/readyz`.
  `/healthz` stays a fixed liveness body, while `/health` now returns
  version, build hash, timestamp, uptime, and readiness checks for
  dashboards / SIEM ingestion. Existing `/readyz` behavior unchanged.
  ([crates/sbproxy-observe/src/health.rs],
  [crates/sbproxy-core/src/admin.rs])

- **`--request-log-level` and `SB_REQUEST_LOG_LEVEL`.** Operators can
  now tune request/access logging independently from application logs.
  The setting appends an `access_log=<level>` target directive to the
  effective `tracing-subscriber` filter while preserving the existing
  per-target `RUST_LOG` escape hatch.
  ([crates/sbproxy/src/main.rs])

- **Access-log forced emission and file output.** `access_log` now
  supports `slow_request_threshold_ms` and `always_log_errors` so slow
  requests and 5xxs bypass sampling after status/method filters match.
  It also supports `output: { type: file, path, max_size_mb,
  max_backups, compress }` for direct JSON-line access-log files with
  size-based rotation and optional gzip compression of rotated files.
  ([crates/sbproxy-config/src/types.rs],
  [crates/sbproxy-core/src/server.rs],
  [crates/sbproxy-observe/src/access_log.rs])

- **OCSP stapling for the manual fallback cert.** `OcspStapler`
  (which previously existed but was unwired) now does an immediate
  fetch on startup, refreshes every 12 hours, and pushes the bytes
  into `CertResolver::update_fallback_ocsp` so subsequent rustls
  handshakes staple the response on the wire. No-op when no manual
  cert is configured or when the cert lacks an AIA extension.
  ([crates/sbproxy-tls/src/ocsp.rs],
  [crates/sbproxy-tls/src/cert_resolver.rs])

- **Readiness synthetic probe primitive.** `sbproxy-observe` now ships a
  `SyntheticProbe` type so startup or test wiring can register an
  in-process readiness probe that exercises a caller-provided path and
  reports through the same `/readyz` component model as built-in probes.
  ([crates/sbproxy-observe/src/health.rs])

### Changed

- **mTLS now wired on the ACME path.** Previously, an operator who
  configured `mtls:` alongside `acme:` got plain TLS until they
  noticed clients reaching the upstream without the expected cert
  headers. The ACME branch now mirrors the manual-cert branch:
  builds `TlsSettings` with the configured `ClientCertVerifier` and
  falls back to plain TLS only when mTLS setup itself fails.
  ([crates/sbproxy-core/src/server.rs])

- **Examples and Kubernetes smoke checks are local-only.** The
  Docker-backed examples smoke lane and kind-based Kubernetes operator
  smoke lane no longer run automatically on pull requests. They remain
  available as `make examples-smoke` and `make k8s-operator-smoke` for
  explicit local / release validation.
  ([Makefile], [docs/kubernetes.md])

- **Reload drain state is now one coherent atomic snapshot.** The
  drain flag and active request count are packed into one `AtomicU64`,
  so `is_draining()` no longer combines two independent relaxed loads.
  Added loom coverage for the last-request-finish interleaving.
  ([crates/sbproxy-core/src/reload.rs])

- **Optional readiness dependencies no longer fail `/readyz` by
  default.** The default admin health registry now registers absent
  ledger and bot-auth-directory probes as `not_configured`, matching the
  existing future-wave stubs and keeping `/readyz` green when those
  optional services are not wired in a deployment.
  ([crates/sbproxy-observe/src/health.rs],
  [crates/sbproxy-core/src/admin.rs])

- **`docs/manual.md` rewrites** matching what actually ships:
  - §6 Health checks: `/livez`, `/readyz`, `/healthz`, and rich
    `/health` semantics, replacing the old per-endpoint URL fork
    diagram and stale `/health` alias wording.
  - §10 Feature flags: CEL accessor table, kill-switch note, and
    a "planned, not yet wired" note for Lua / JS / WASM features
    namespaces and workspace-level pub/sub flags.
  - §3 CPU detection: documents the new `SB_WORKER_THREADS` knob.
  - §13 env-var table: adds `SB_WORKER_THREADS` and
    `SB_DISABLE_SB_FLAGS`; later updates add
    `SB_REQUEST_LOG_LEVEL` and access-log file/forced-emit examples.

### Fixed

- **E2E proxy startup flake under CPU contention.** The e2e
  `ProxyHarness` keeps its HTTP-level readiness probe, but now gives
  release/debug proxy boots a 10-second window instead of 5 seconds so
  tests like `action_graphql` do not fail spuriously while cargo is
  competing for CPU.
  ([e2e/src/lib.rs])

- **Docs CI Rust snippet failures.** Workspace-dependent documentation
  examples that cannot compile as standalone `rust-script` programs are
  now tagged `rust,no_run`, keeping docs-ci focused on executable
  snippets instead of illustrative API fragments.
  ([docs/architecture.md], [docs/audit-log.md], [docs/cache-reserve.md])

- **Unsafe-code drift guardrails.** Crates that do not need unsafe now
  forbid it at the crate root, while `sbproxy-vault` explicitly allows
  its narrowly-scoped volatile zeroization unsafe with an inline
  justification.
  ([crates/sbproxy-*/src/lib.rs])

- **Outbound webhook delivery identity headers.** Signed customer
  webhooks now include `Sbproxy-Subscription-Id`,
  `Sbproxy-Delivery-Id`, and 1-based `Sbproxy-Attempt` headers, with a
  fresh delivery ULID on every retry attempt.
  ([crates/sbproxy-observe/src/notify.rs])

- **AI client retry resilience.** `MemoryBatchStore` now uses
  `parking_lot::Mutex` so a panic in one worker cannot poison the
  in-memory batch map for every later operation. Provider retries now
  honor `provider.max_retries` as same-provider retry attempts with
  bounded jittered exponential backoff before recording provider
  failure and moving to the next eligible provider.
  ([crates/sbproxy-ai/src/batch.rs],
  [crates/sbproxy-ai/src/client.rs])

- **Dynamic Web Bot Auth directory dispatch.** The main request auth
  path now invokes `BotAuthProvider::verify_async` when a configured
  hosted directory and `Signature-Agent` header are present, so dynamic
  directory failures surface distinctly instead of falling through the
  static inline-agent verifier.
  ([crates/sbproxy-core/src/server.rs])

- **ACME/Pebble order polling.** Certificate issuance now polls the
  authorization to `valid` after responding to the HTTP-01 challenge
  before polling the order to `ready`, matching Pebble's stricter state
  progression. Finalization also parses the order returned by the
  finalize response and falls back to polling the original order URL,
  avoiding accidental POST-as-GET polling of the finalize URL when
  `Location` is absent.
  ([crates/sbproxy-tls/src/acme.rs])

- **JWKS unknown-`kid` key rotation.** JWTs that reference an unseen
  `kid` now trigger one rate-limited JWKS refetch before failing
  closed, with a Prometheus counter for success / failure /
  rate-limited outcomes. This avoids requiring operator intervention
  for routine IdP key rotation.
  ([crates/sbproxy-modules/src/auth/jwks.rs],
  [crates/sbproxy-modules/src/auth/mod.rs],
  [crates/sbproxy-observe/src/metrics.rs])

- **Rate-limit LRU pollution bypass.** Per-key local token buckets now
  preserve deny state in a bounded cold tier after hot LRU eviction, so
  a spray of attacker keys cannot reset an already-throttled
  legitimate client.
  ([crates/sbproxy-modules/src/policy/mod.rs])

### Open follow-ups

Tracked in Linear, not in this changeset:

- [WOR-27](https://linear.app/12345r/issue/WOR-27) full configurable
  synthetic transaction through the live request pipeline. The
  `SyntheticProbe` readiness primitive has landed; config and pipeline
  execution remain.
- WOR-114 Phase 2.5: Lua / JS / WASM `features` namespace, plus
  workspace-level flags via messenger pub/sub
- [WOR-15](https://linear.app/12345r/issue/WOR-15) remaining
  rate-limiter proptest coverage. The reload-drain loom portion has
  landed.

## [1.0.1] - 2026-05-04

Patch release. No runtime behavior changes.

### Fixed

- **Container image publish**: the `release.yml` workflow's docker
  prepare step extracted the flat-layout tarballs into `/tmp/`
  directly, which tripped a sticky-bit `Cannot utime` error on the
  archive's `./` entry and caused `ghcr.io/soapbucket/sbproxy:1.0.0`
  to never publish. Each platform tarball now extracts to a per-arch
  staging dir before the binary moves into the docker context.

## [1.0.0] - 2026-05-03

First Rust release of SBproxy on this repository.

### What changed

- **Implementation**: SBproxy is now written in Rust on Cloudflare's
  Pingora. The Go implementation that previously occupied this repo
  (`v0.1.0` through `v0.1.2`) has moved to
  [`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go),
  preserved as the `v0.1.2-go-final` branch and tag, and is now in
  maintenance-only mode.
- **Data plane**: routing, AI gateway, MCP gateway, guardrails, security
  policies, and scripting (CEL, Lua, JavaScript, WebAssembly) all ship
  open source in this release. See [`docs/architecture.md`](docs/architecture.md)
  for the request pipeline shape.
- **Enterprise tier**: see [`docs/enterprise.md`](docs/enterprise.md) for
  what enterprise adds on top of the OSS data plane and how to request
  access.

### Upgrading from v0.1.x (Go)

The internal config schema (`schema-v1`) is supported by both the Go
`v0.1.x` line and this Rust `v1.x` line, so existing `sb.yml` files
should compile unchanged. See [`MIGRATION.md`](MIGRATION.md) for the
full upgrade path.
