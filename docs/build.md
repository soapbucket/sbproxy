# Build pipeline
*Last modified: 2026-04-30*

How the proxy container images are built, what stays warm between
runs, and what the expected wall-clock numbers are. Companion to
`docs/architecture.md` (request pipeline) and the workspace
`CLAUDE.md` (pre-commit local loop).

## Container image layout

Two Dockerfiles live at the repo root and share the same layered
cargo-chef layout:

| File | Purpose | Consumer |
|---|---|---|
| `Dockerfile.cloudbuild` | Cloud Build / GCR amd64 image. | `gcloud builds submit`; bench loadtest stack. |
| `Dockerfile.ci` | Kind-based smoke-test image. | `.github/workflows/k8s-operator-smoke.yml`. |

Both files have six stages:

1. **chef-base**: `rust:1.94-bookworm` plus the apt deps (`pkg-config`,
   `libclang-dev`, `build-essential`, `cmake`, `perl`) plus a pinned
   `cargo-chef@0.1.71`. Reused by every later Rust stage.
2. **planner**: copies the workspace, runs `cargo chef prepare`, emits
   `recipe.json`. The recipe captures every `Cargo.toml` and
   `Cargo.lock` digest in the workspace; nothing under
   `crates/*/src/` affects it.
3. **cacher**: `cargo chef cook --release --bin sbproxy
   --recipe-path recipe.json`. Compiles every dependency from
   crates.io. This is the layer the warm-rebuild path reuses.
4. **builder**: copies `/src/target` from cacher, then the workspace
   source, then runs `cargo build --release --bin sbproxy --locked`.
   The dep `target/` from the cacher stage is the entire reason this
   step does not have to recompile crates like `pingora`,
   `aws-lc-sys`, or `tokio` again.
5. **cert-gen** (cloudbuild only): self-signed loadtest cert.
   Production deploys mount real certs over `/etc/sbproxy/` at
   runtime.
6. **runtime**: `gcr.io/distroless/cc-debian12`. Carries the binary
   and (cloudbuild) the loadtest cert pair.

## Build-time numbers

Cold = empty BuildKit cache (`docker buildx prune -f` first). Warm =
touch a file under `crates/sbproxy/src/` and rebuild without
clearing the cache.

| Build | Before chef | After chef |
|---|---|---|
| Cold (Cloud Build amd64) | ~12 min | ~3-4 min |
| Warm (only first-party source changed) | ~12 min (no caching) | <90s |

The warm path's win comes from the `cacher` layer: as long as
`recipe.json` is byte-identical to the previous build, Docker
short-circuits stages 1-3 and only re-runs stages 4 + 6.

The cold path's win comes from BuildKit `--mount=type=cache` on
`/usr/local/cargo/{registry,git}`: even when the layer cache is cold
(e.g. a fresh Cloud Build worker), the cargo registry tarballs are
re-used across builds of the same Cloud Build trigger.

## BuildKit requirement

Both Dockerfiles use the cache-mount syntax (`RUN
--mount=type=cache,...`). That syntax is BuildKit-only.

- Local: `export DOCKER_BUILDKIT=1` or use `docker buildx build`.
- Cloud Build: builders that consume these Dockerfiles must set
  `DOCKER_BUILDKIT=1` in the build step env, or use a `docker buildx
  build` invocation. Cloud Build's standard `gcr.io/cloud-builders/docker`
  step honors `DOCKER_BUILDKIT=1`. If a build step ever drops back to
  the legacy builder, the `--mount=type=cache` directives silently
  no-op; the build still succeeds, just slower.

## Validating a build

The fast smoke test, locally:

```bash
DOCKER_BUILDKIT=1 docker build \
  -f Dockerfile.cloudbuild \
  --target builder \
  -t sbproxy:builder-smoke .
```

The `--target builder` short-circuits before the runtime stage so the
test does not pay for the cert-gen + distroless copy. To validate the
runtime image:

```bash
DOCKER_BUILDKIT=1 docker build -f Dockerfile.cloudbuild -t sbproxy:rt .
docker run --rm sbproxy:rt --version
```

## Warm-path verification

To prove the chef layer is doing its job, after a cold build, touch a
file under `crates/sbproxy/src/`:

```bash
touch crates/sbproxy/src/main.rs
DOCKER_BUILDKIT=1 docker build -f Dockerfile.cloudbuild --target builder -t sbproxy:warm .
```

The output should show stages `chef-base`, `planner`, and `cacher`
all `CACHED`, and only `builder` running. Wall-clock time on a
modern amd64 worker should be under 90s.

## Troubleshooting

- **The cacher stage rebuilds every time.** Some change touched a
  `Cargo.toml` or `Cargo.lock` (added a dep, bumped a version,
  changed a feature flag). The recipe digest is keyed on those
  files; the cacher stage cooks fresh.
- **`cargo build` in the builder stage refuses to use the cooked
  artifacts.** Symptom: stage 4 takes ~12 min, ignoring the COPY
  from cacher. Most likely cause: `--locked` and a stale
  `Cargo.lock` in cacher's COPY. Re-run `cargo update` and rebuild.
- **OOM on Cloud Build.** Set `machineType` on the build step to
  `E2_HIGHCPU_8` or higher; the chef cacher stage holds the full
  `target/` of cooked deps in memory while linking.
