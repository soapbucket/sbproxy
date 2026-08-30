# Build pipeline
*Last modified: 2026-08-29*

How the proxy container images are built, what stays warm between
runs, and what the expected wall-clock numbers are. Companion to
`docs/architecture.md` (request pipeline) and the workspace
`CLAUDE.md` (pre-commit local loop).

## Container image layout

Four Dockerfiles live at the repo root and share the same layered
cargo-chef layout:

| File | Purpose | Consumer |
|---|---|---|
| `Dockerfile.cloudbuild` | Cloud Build / GCR amd64 image. | `gcloud builds submit`; bench loadtest stack. |
| `Dockerfile.ci` | Kind-based smoke-test image. | `make k8s-operator-smoke`. |
| `Dockerfile.gateway` | Gateway/authority fleet image: no CUDA. | `ClusterRole::Gateway` and `ClusterRole::Authority` nodes. |
| `Dockerfile.worker` | Worker fleet image: CUDA runtime + version-pinned vLLM, booting behind the startup gate. | `ClusterRole::Worker` nodes. |

Two things about the worker image are load-bearing:

- **vLLM is pinned**, via the `VLLM_VERSION` build arg, to the same version
  `DEFAULT_VLLM_VERSION` names in
  `crates/sbproxy-model-host/src/vllm_driver.rs`. An unpinned
  `pip install vllm` resolves to whatever is newest at build time, so the
  image would drift off the version the fit planner, the argv builder, and
  the recorded NVIDIA certification all target. Bump both together, re-run
  the NVIDIA lane, and record the result in
  [`docs/model-host-certification.md`](model-host-certification.md).
- **The entrypoint is `docker/worker-entrypoint.sh`**, which runs
  `sbproxy doctor --strict` before exec'ing the proxy. A worker handed a
  container with no devices, a `/dev/shm` smaller than the engine asked for,
  an undersized cache mount, or unreadable model-plane identity refuses to
  start with a named blocker, rather than joining gossip, advertising itself
  as eligible, and failing every dispatch. Set
  `SBPROXY_SKIP_STARTUP_GATE=1` to bypass it while debugging a box the gate
  is wrong about.

`Dockerfile.gateway` and `Dockerfile.worker` are forks of
`Dockerfile.cloudbuild`: identical through the `builder` stage, and
diverge only in the final runtime stage (gateway keeps cloudbuild's
distroless base; worker swaps in a CUDA base with vLLM installed). They
build the two image shapes a `proxy.cluster` fleet needs, split along
`ClusterRole` (see `crates/sbproxy-config/src/cluster.rs`): a
containerized rollout is separate work from the curl-install VM path in
[`deploy/aws/README.md`](../deploy/aws/README.md) and
[`deploy/azure/README.md`](../deploy/azure/README.md).

### Official release artifacts include the admin UI

The standard GitHub release workflow builds `ui/dist`, then compiles every
published `sbproxy` binary with `--features embed-admin-ui`. The release
tarballs therefore serve the dashboard at `/admin/ui/` when the admin server
is enabled. The multi-architecture `docker.io/soapbucket/sbproxy` image copies
those same release binaries into its distroless runtime, so the Docker Hub
image includes the dashboard too. This is not limited to
`Dockerfile.cloudbuild`.

A local default Cargo build remains lean and does not embed the UI unless you
build the frontend and pass the feature explicitly. See
[admin-ui.md](admin-ui.md#build-and-enable-it).

`Dockerfile.cloudbuild` and `Dockerfile.ci` share a five-stage Rust
spine; `Dockerfile.ci` is exactly that spine, and `Dockerfile.cloudbuild`
adds two stages of its own (**admin-ui** and **cert-gen**) for seven
total. `Dockerfile.gateway` and `Dockerfile.worker` reuse the same spine
through `builder` (see above) rather than repeating it here:

1. **chef-base**: `rust:1.95-bookworm` plus the apt deps (`pkg-config`,
   `libclang-dev`, `build-essential`, `cmake`, `perl`,
   `protobuf-compiler`) plus a pinned `cargo-chef@0.1.71`. Reused by
   every later Rust stage.
2. **admin-ui** (cloudbuild only): `node:22-slim`, `npm ci` and
   `npm run build` under `ui/`. `ui/dist` is gitignored, so the image
   build must produce it; the builder stage copies it in before cargo
   compiles with `--features embed-admin-ui`.
3. **planner**: copies the workspace, runs `cargo chef prepare`, emits
   `recipe.json`. The recipe captures every `Cargo.toml` and
   `Cargo.lock` digest in the workspace; nothing under
   `crates/*/src/` affects it.
4. **cacher**: `cargo chef cook --profile release-fast --bin sbproxy
   --recipe-path recipe.json` (cloudbuild adds `--features
   embed-admin-ui`). Compiles every dependency from crates.io. This is
   the layer the warm-rebuild path reuses.
5. **builder**: copies `/src/target` from cacher, then the workspace
   source (cloudbuild also copies `ui/dist` from admin-ui), then runs
   `cargo build --profile release-fast --bin sbproxy --locked`, with
   `--features embed-admin-ui` in the cloudbuild file.
   The dep `target/` from the cacher stage is the entire reason this
   step does not have to recompile crates like `pingora`,
   `aws-lc-sys`, or `tokio` again.
6. **cert-gen** (cloudbuild only): self-signed loadtest cert.
   Production deploys mount real certs over `/etc/sbproxy/` at
   runtime.
7. **runtime**: `gcr.io/distroless/cc-debian13` (the `:nonroot`
   variant in `Dockerfile.ci`). Debian 13 ships glibc 2.41, so fetched
   engine binaries that need GLIBC_2.38 or newer (mistral.rs) can start.
   The sbproxy binary itself is still built on bookworm and must require
   glibc 2.36 or older so Linux tarballs run on Debian 12. Carries the
   binary and (cloudbuild) the loadtest cert pair.

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
short-circuits `chef-base`, `planner`, and `cacher` (plus `admin-ui`
when `ui/` is untouched) and only re-runs `builder` + `runtime`.
The Dockerfiles default to `CARGO_PROFILE=release-fast`, which inherits
the production release settings but disables fat LTO and raises
`codegen-units` for lower link time and memory. Pass
`--build-arg CARGO_PROFILE=release` when you intentionally want the
full production release profile inside these Dockerfiles.

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
  artifacts.** Symptom: the builder stage takes ~12 min, ignoring the
  COPY from cacher. Most likely cause: `--locked` and a stale
  `Cargo.lock` in cacher's COPY. Re-run `cargo update` and rebuild.
- **OOM on Cloud Build.** Set `machineType` on the build step to
  `E2_HIGHCPU_8` or higher; the chef cacher stage holds the full
  `target/` of cooked deps in memory while linking.
