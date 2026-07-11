# Self-Hosted OpenRouter Local Runtime Implementation Plan

*Last modified: 2026-07-10*

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver PR 2 of the self-hosted OpenRouter program: typed managed engine drivers, a process-wide reconcileable model runtime, per-deployment admission and lifecycle, a complete local operator CLI, and CUDA-capable llama.cpp acquisition without allowing an engine to read unverified model bytes.

**Architecture:** `sbproxy-model-host` becomes the single worker-local lifecycle authority. A replaceable `RuntimeDesiredState` compiles `proxy.model_host`, `provider_type: managed_model`, and legacy provider `serve:` blocks into one validated deployment revision. A `ModelRuntimeManager` owns per-deployment slots, engine drivers, per-device residency, admission queues, operation jobs, and reconciliation; `sbproxy-core`, the CLI, and the existing admin routes remain adapters over that manager.

**Tech Stack:** Rust 1.82, Tokio, arc-swap, async-trait, reqwest, serde/schemars, ULID jobs, existing artifact and deployment services, NVML with `nvidia-smi` fallback, allowlisted Docker/Podman argv, CMake for the opt-in Linux CUDA source build, clap, and cargo-nextest.

## Global Constraints

- Primary Linear scope is WOR-1841, WOR-1843, WOR-1844, WOR-1848, WOR-1684, and WOR-1813.
- PR 2 is stacked on PR #676 and changes only the local-runtime slice. Cluster membership, placement, peer transport, cluster CLI commands, admin model-management UI, and fleet operations remain later pull requests.
- `proxy.model_host` plus `provider_type: managed_model` is the new stable configuration. Existing provider `serve:` blocks lower to deterministic compatibility deployments for one documented migration window.
- A process that starts with no managed model must accept one on reload. No origin, provider, or reload path may retain first-config or first-origin precedence.
- A desired revision is swapped only after complete schema, catalog, capability, engine, and artifact validation. A failure leaves the prior working desired state and unrelated resident engines intact.
- Engine identity and argv remain typed or allowlisted. Existing `extra_args` are rejected unless every flag is allowlisted or the operator explicitly enables unsafe argv for that engine.
- Managed llama.cpp receives one verified local GGUF path. Managed vLLM receives one verified read-only snapshot. Neither driver may fall back to a repository ID after artifact resolution.
- vLLM containers use digest-pinned images, selected GPU devices, validated shared memory, a read-only artifact mount, and a loopback-only published port on a private container network.
- GPU compute utilization and memory occupancy are different measurements and different status or metric fields. Unknown compute utilization is represented as unknown, never as idle.
- Admission accounts for weight bytes, KV bytes, runtime overhead, configured safety margin, and the selected device. It must not use the largest device as a process-wide substitute for per-device capacity.
- Priority queues are FIFO within a class and prefer interactive, then standard, then batch. PR 2 does not cancel an in-flight generation to implement preemption.
- Keep-alive begins after the last completed request. Active, queued, pinned, preparing, or draining deployments cannot be idle-evicted.
- Stable capacity failures use bounded reason codes: `insufficient_capacity`, `queue_full`, `queue_timeout`, `engine_unhealthy`, `crash_loop`, and `draining`.
- `sbproxy run` enables an authenticated loopback admin endpoint with a generated bootstrap credential and prints copyable endpoint, curl, and SDK configuration after readiness.
- `models pull`, `list`, `show`, `remove`, `ps`, and `stop` use shared artifact or runtime contracts and accept `--format` in the same subcommand position. JSON output contains no progress control characters.
- The PR 2 live gate is one real Apple Silicon request through the managed gateway path. Linux/NVIDIA behavior is covered by deterministic simulated tests; live T4, L4, multi-GPU, and three-node GCP validation remains PR 7 per user direction.
- User-facing content, rustdoc, commit messages, and generated capability documentation contain no em dash characters.
- Every behavior change follows red, green, refactor. Each task ends at a reviewable commit checkpoint.
- Before publication, run every repository gate in `AGENTS.md`, docs CI, schema drift, capability drift, and the real Mac smoke test.

---

## File Map

- `crates/sbproxy-config/src/model_host.rs`: public `proxy.model_host` DTOs and schema types that do not depend on internal runtime crates.
- `crates/sbproxy-config/src/types.rs`: adds `ProxyServerConfig::model_host` and default wiring.
- `crates/sbproxy-ai/src/provider.rs`: recognizes `provider_type: managed_model` as a local runtime adapter while preserving legacy `serve:`.
- `crates/sbproxy-ai/src/handler.rs`: provider-shape validation and managed-model route validation.
- `crates/sbproxy-model-host/src/desired.rs`: normalized runtime input, deterministic legacy lowering, route map, deployment fingerprints, and complete validation.
- `crates/sbproxy-model-host/src/engine_driver.rs`: typed engine detection, provisioning, capability, launch, health, shutdown, and stable error contracts.
- `crates/sbproxy-model-host/src/llama_driver.rs`: managed llama.cpp detection, provisioning, verified GGUF launch, health, and shutdown.
- `crates/sbproxy-model-host/src/vllm_driver.rs`: vLLM binary, uv, and digest-pinned container drivers plus compatibility reports.
- `crates/sbproxy-model-host/src/process.rs`: process and container execution, log capture, group shutdown, and injectable command execution.
- `crates/sbproxy-model-host/src/cuda_build.rs`: pinned on-box Linux CUDA llama.cpp source build with locking and atomic publication.
- `crates/sbproxy-model-host/src/admission.rs`: per-deployment priority queue, active and queued counts, permits, drain, and stable rejection codes.
- `crates/sbproxy-model-host/src/device_residency.rs`: per-device memory accounting and protected eviction planning.
- `crates/sbproxy-model-host/src/runtime_manager.rs`: process-wide desired-state swap, deployment slots, prepare, reconcile, rollback, keep-alive, and job retention.
- `crates/sbproxy-model-host/src/runtime.rs`: verified artifact and fit preparation helpers retained behind the new manager; no process-global authority.
- `crates/sbproxy-model-host/src/supervisor.rs`: bounded crash-loop state, real backoff, retained failure, and reset.
- `crates/sbproxy-model-host/src/fit.rs`: explicit weight, KV, overhead, safety-margin, total, and device estimate fields.
- `crates/sbproxy-model-host/src/probe_nvidia.rs`: separate NVML or `nvidia-smi` compute utilization and memory measurements.
- `crates/sbproxy-model-host/src/config.rs`: legacy `serve:` conversion, allowlisted extra-argv validation, and compatibility diagnostics.
- `crates/sbproxy-core/src/server/model_host.rs`: one always-installed production manager, desired-state compilation, request admission, and managed-provider resolution.
- `crates/sbproxy-core/src/server/lifecycle.rs`: shared startup and hot-reload prepare-then-commit flow.
- `crates/sbproxy-core/src/admin.rs`: routes admin reload through the same runtime reconciliation transaction.
- `crates/sbproxy-core/src/admin_model_host.rs`: status, drain, stop, and crash-loop reset adapters over the shared manager.
- `crates/sbproxy-core/src/server/ai_dispatch.rs`: per-deployment admission permit and stable local failure handling.
- `crates/sbproxy-core/src/context.rs`: holds the shared model admission permit through the full stream lifecycle.
- `crates/sbproxy-observe/src/metrics.rs`: deployment lifecycle, active, queued, memory occupancy, compute utilization, reconcile, and rejection metrics.
- `crates/sbproxy/src/main.rs`: one-command run workflow and complete local model lifecycle CLI.
- `crates/sbproxy-model-host/tests/engine_drivers.rs`: typed driver, provisioning, argv, container isolation, and compatibility contracts.
- `crates/sbproxy-model-host/tests/runtime_reconcile.rs`: desired-state add, change, remove, rollback, concurrency, and unaffected-engine preservation.
- `crates/sbproxy-model-host/tests/local_admission.rs`: per-device fit, priority FIFO, queue limits, drain, keep-alive, and reason-code contracts.
- `crates/sbproxy-model-host/tests/cuda_build.rs`: simulated Linux/NVIDIA CUDA acquisition and atomic build publication.
- `crates/sbproxy-core/tests/model_host_reload.rs`: startup-empty reload, multi-origin lowering, admin reload, and rollback integration.
- `crates/sbproxy/tests/models_lifecycle_cli.rs`: real CLI JSON/text contracts over a fixture admin endpoint and artifact cache.
- `examples/model-host-managed/`: canonical `proxy.model_host` and `managed_model` provider example.
- `docs/model-host.md`, `docs/quickstart-serve.md`, `docs/admin.md`, `docs/manual.md`, and `docs/security-model-host.md`: stable PR 2 operator behavior and compatibility guidance.
- `docs/model-host-capabilities.md`, `schemas/sb-config.schema.json`, `schemas/ai-proxy-provider.schema.json`, and `docs/llms-full.txt`: generated outputs updated only from their source generators.

### Task 1: Canonical local-runtime configuration and deterministic lowering

**Files:**
- Create: `crates/sbproxy-config/src/model_host.rs`
- Create: `crates/sbproxy-model-host/src/desired.rs`
- Modify: `crates/sbproxy-config/src/lib.rs`
- Modify: `crates/sbproxy-config/src/types.rs`
- Modify: `crates/sbproxy-ai/src/provider.rs`
- Modify: `crates/sbproxy-ai/src/handler.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Test: `crates/sbproxy-config/src/model_host.rs`
- Test: `crates/sbproxy-model-host/tests/runtime_reconcile.rs`

**Interfaces:**
- Consumes: PR 1 `DeploymentRevisionDraft`, `ModelDeployment`, `DeploymentSourceMode`, `ModelHostConfig`, `Catalog`, and `ServeEntry::effective_name()`.
- Produces: `ModelHostControlConfig`, `ManagedDeploymentConfig`, `ManagedEngineConfig`, `RuntimeDesiredInput`, `RuntimeDesiredState`, `CompiledDeployment`, `DeploymentRoute`, and `compile_desired_state(input, catalog) -> Result<RuntimeDesiredState, DesiredStateError>`.

- [ ] **Step 1: Add failing public-config and schema tests**

Require the canonical YAML shape to deserialize and round-trip, require `model_host` in the generated proxy schema, and reject an empty deployment, zero concurrency, an unpinned stable container image, or an admin-managed mode without a store path:

```rust,no_run
#[test]
fn canonical_model_host_config_round_trips() {
    let proxy: ProxyServerConfig = serde_yaml::from_str(r#"
model_host:
  authority: file_managed
  max_parallel_prepares: 2
  safety_margin: 0.10
  deployments:
    coder:
      model: qwen2.5-0.5b-instruct
      variant: q4_k_m
      warm: true
      max_concurrency: 4
      queue_timeout_ms: 30000
"#).unwrap();
    let host = proxy.model_host.expect("typed model host");
    assert_eq!(host.deployments["coder"].max_concurrency, Some(4));
    host.validate().expect("complete canonical config");
}
```

- [ ] **Step 2: Run the config tests and verify red**

Run: `cargo test -p sbproxy-config model_host -- --nocapture`

Expected: FAIL because `ProxyServerConfig::model_host` and the canonical DTOs do not exist.

- [ ] **Step 3: Implement the public DTOs without an internal crate dependency**

Define serde and schemars types in `sbproxy-config` for authority, engines, deployments, queue limits, cache settings, prepare limits, safety margin, shutdown deadline, and admin store path. Add `model_host: Option<ModelHostControlConfig>` to `ProxyServerConfig` and its `Default` implementation. Keep runtime behavior out of this public crate.

- [ ] **Step 4: Add failing normalized-lowering tests**

Cover canonical deployments, `provider_type: managed_model` references, deterministic legacy IDs, equivalent duplicate legacy definitions, conflicting duplicates, all origins, and a route map from public model name to deployment ID:

```rust,no_run
#[test]
fn legacy_ids_are_stable_and_conflicts_are_rejected() {
    let a = legacy_input("origin-a", "local", "coder", "qwen3-8b");
    let b = legacy_input("origin-b", "local", "coder", "qwen3-14b");
    let first = compile_desired_state(input(vec![a.clone()]), &catalog()).unwrap();
    let again = compile_desired_state(input(vec![a]), &catalog()).unwrap();
    assert_eq!(first.revision.deployments.keys().collect::<Vec<_>>(), again.revision.deployments.keys().collect::<Vec<_>>());
    assert!(compile_desired_state(input(vec![b, legacy_input("origin-a", "local", "coder", "qwen3-8b")]), &catalog()).is_err());
}
```

- [ ] **Step 5: Run the lowering tests and verify red**

Run: `cargo test -p sbproxy-model-host --test runtime_reconcile desired -- --nocapture`

Expected: FAIL because normalized desired-state compilation does not exist.

- [ ] **Step 6: Implement complete lowering and validation**

Canonical deployments become `ModelDeployment` values directly. Legacy entries receive a deterministic `legacy-<provider>-<name>-<digest8>` deployment ID and a `DeploymentRoute` preserving the public served name. Equivalent duplicates deduplicate; conflicting public routes, engine provisioning, cache roots, or host policies return `DesiredStateError::Conflict`. Managed providers may reference only declared deployment IDs. Compute one `DeploymentRevisionDraft` only after the full input validates.

- [ ] **Step 7: Run focused config, AI, and lowering suites**

Run: `cargo test -p sbproxy-config model_host && cargo test -p sbproxy-ai managed_model && cargo test -p sbproxy-model-host --test runtime_reconcile desired`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/sbproxy-config crates/sbproxy-ai crates/sbproxy-model-host/src/desired.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/runtime_reconcile.rs
git commit -m "feat: normalize managed model desired state"
```

### Task 2: Typed managed-engine contract

**Files:**
- Create: `crates/sbproxy-model-host/src/engine_driver.rs`
- Create: `crates/sbproxy-model-host/src/process.rs`
- Create: `crates/sbproxy-model-host/tests/engine_drivers.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Modify: `crates/sbproxy-model-host/src/supervisor.rs`
- Modify: `crates/sbproxy-model-host/src/launch.rs`

**Interfaces:**
- Consumes: `EngineKind`, `ResolvedArtifact`, `ReadyArtifact`, `FitPlan`, `EngineProvisioning`, and `OperationJobStore`.
- Produces: `EngineDriver`, `EngineAvailability`, `EngineDetection`, `EngineCapabilities`, `ProvisionRequest`, `ProvisionedEngine`, `LaunchRequest`, `RunningEngine`, `EngineHealth`, `EngineDriverError`, `EngineProcess`, `EngineProcessRunner`, and `CommandExecutor`.

- [ ] **Step 1: Add failing object-safe driver contract tests**

Require both managed kinds to expose the same typed lifecycle, require every error to carry a stable reason and remediation, and require a fake driver to run through detect, provision, launch, health, and shutdown without a subprocess:

```rust,no_run
#[tokio::test]
async fn driver_contract_is_complete_and_object_safe() {
    let driver: Arc<dyn EngineDriver> = Arc::new(FixtureDriver::available());
    assert_eq!(driver.detect(&host()).availability, EngineAvailability::Available);
    let provisioned = driver.provision(&provision_request()).await.unwrap();
    let running = driver.launch(&provisioned, &launch_request()).await.unwrap();
    assert_eq!(driver.health(&running).await.unwrap(), EngineHealth::Ready);
    driver.shutdown(running, Duration::from_secs(1)).await.unwrap();
}
```

- [ ] **Step 2: Run the driver test and verify red**

Run: `cargo test -p sbproxy-model-host --test engine_drivers driver_contract -- --nocapture`

Expected: FAIL because `EngineDriver` and its typed results do not exist.

- [ ] **Step 3: Implement the contract and low-level process boundary**

Use `async_trait` for object-safe async methods. `EngineDriver` owns engine-specific validation and argv; `EngineProcessRunner` is the only component allowed to spawn or kill. `CommandExecutor` accepts an executable plus an already-tokenized argv and environment, never a shell string. `RunningEngine` records deployment, generation, engine kind, port, selected devices, start time, and an opaque process handle.

- [ ] **Step 4: Add failing unsafe-argument and verified-path tests**

Reject flags that can replace model, host, port, API key, network, mount, or device selection. Require the launch request to contain a `ReadyArtifact`; a repository reference alone cannot construct one.

- [ ] **Step 5: Implement the allowlist and compatibility adapter**

Move generic process-group handling, early-exit detection, bounded stderr tails, readiness polling, and graceful-then-forced shutdown from `ProcessEngineLauncher` into `process.rs`. Keep a temporary `EngineLauncher` adapter only for existing tests while Tasks 3 through 7 move runtime authority to drivers.

- [ ] **Step 6: Run focused driver and legacy launcher suites**

Run: `cargo test -p sbproxy-model-host --test engine_drivers && cargo test -p sbproxy-model-host launch::tests supervisor::tests`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/sbproxy-model-host/src/engine_driver.rs crates/sbproxy-model-host/src/process.rs crates/sbproxy-model-host/src/launch.rs crates/sbproxy-model-host/src/supervisor.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/engine_drivers.rs
git commit -m "feat: add typed managed engine contract"
```

### Task 3: Managed llama.cpp driver

**Files:**
- Create: `crates/sbproxy-model-host/src/llama_driver.rs`
- Modify: `crates/sbproxy-model-host/src/acquire.rs`
- Modify: `crates/sbproxy-model-host/src/llama_release.rs`
- Modify: `crates/sbproxy-model-host/src/launch.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Test: `crates/sbproxy-model-host/tests/engine_drivers.rs`

**Interfaces:**
- Consumes: Task 2 `EngineDriver`, `EngineProcessRunner`, `ProvisionRequest`, and `LaunchRequest`.
- Produces: `LlamaCppDriver`, `LlamaDetection`, `LlamaProvisioned`, and an exact verified-GGUF launch plan.

- [ ] **Step 1: Add failing detection and provisioning tests**

Cover compatible PATH binary preference, explicit path, pinned release, unsupported platform, accelerator mismatch, missing digest warning, and blocked status. Detection must distinguish `available`, `acquirable`, `incompatible`, and `blocked`.

- [ ] **Step 2: Add failing launch-argv tests**

Require exactly one `--model <verified-path>`, loopback host, allocated port, context, selected GPU layers, and typed KV flags. Assert no `--hf-repo`, `--hf-file`, shell token, or undeclared extra flag survives.

- [ ] **Step 3: Run the llama driver tests and verify red**

Run: `cargo test -p sbproxy-model-host --test engine_drivers llama -- --nocapture`

Expected: FAIL because `LlamaCppDriver` does not exist.

- [ ] **Step 4: Implement detection, provision, launch, health, and shutdown**

PATH wins only when the binary is executable and compatible. Otherwise use the typed acquisition plan. Provisioning failure is returned as `EngineDriverError`, never logged and ignored in favor of an unverified PATH fallback. Build the launch spec from the `ReadyArtifact` GGUF file and the fit plan, then delegate only process mechanics to `EngineProcessRunner`.

- [ ] **Step 5: Run the focused suite**

Run: `cargo test -p sbproxy-model-host --test engine_drivers llama && cargo test -p sbproxy-model-host acquire::tests llama_release::tests launch::tests`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/sbproxy-model-host/src/llama_driver.rs crates/sbproxy-model-host/src/acquire.rs crates/sbproxy-model-host/src/llama_release.rs crates/sbproxy-model-host/src/launch.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/engine_drivers.rs
git commit -m "feat: add managed llama cpp driver"
```

### Task 4: Managed vLLM binary, uv, and container drivers

**Files:**
- Create: `crates/sbproxy-model-host/src/vllm_driver.rs`
- Modify: `crates/sbproxy-model-host/src/config.rs`
- Modify: `crates/sbproxy-model-host/src/uv_release.rs`
- Modify: `crates/sbproxy-model-host/src/launch.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Test: `crates/sbproxy-model-host/tests/engine_drivers.rs`

**Interfaces:**
- Consumes: Task 2 `EngineDriver`, `EngineProcessRunner`, `ProvisionRequest`, and `LaunchRequest`.
- Produces: `VllmDriver`, `VllmLaunchMode`, `VllmCompatibilityReport`, `ContainerRuntime`, and digest-pinned binary, uv, or container launch plans.

- [ ] **Step 1: Add failing vLLM detection and compatibility tests**

Use an injected `CommandExecutor` to cover a PATH vLLM, managed uv, Docker, Podman, missing Python, torch/CUDA mismatch, unsupported compute capability, and an absent runtime. The compatibility report must contain Python, torch, CUDA, and vLLM versions or a bounded unavailable reason for each.

- [ ] **Step 2: Add failing container isolation tests**

Require a digest-pinned image, one selected GPU device list, validated `--shm-size`, a read-only `/models/model` bind mount, container port 8000 published only to `127.0.0.1:<allocated>`, and a private bridge network. Reject `:latest`, a tag without a digest on the stable path, `--privileged`, host networking, writable model mounts, and `--gpus all`.

```rust,no_run
#[test]
fn container_launch_is_private_read_only_and_device_scoped() {
    let argv = container_plan(&request_with_gpu(1)).unwrap().argv;
    assert!(argv.windows(2).any(|w| w == ["--gpus", "device=1"]));
    assert!(argv.iter().any(|v| v == "127.0.0.1:8123:8000"));
    assert!(argv.iter().any(|v| v.contains("dst=/models/model") && v.contains("readonly")));
    assert!(!argv.iter().any(|v| v == "--privileged" || v == "host"));
}
```

- [ ] **Step 3: Run vLLM tests and verify red**

Run: `cargo test -p sbproxy-model-host --test engine_drivers vllm -- --nocapture`

Expected: FAIL because the typed vLLM modes and container plan do not exist.

- [ ] **Step 4: Implement vLLM provisioning modes**

Binary mode verifies the installed executable. Uv mode pins the uv binary and vLLM package, prepares its environment, then records compatibility before launch. Container mode detects Docker or Podman, validates the image digest and shared memory against host limits, and emits the exact private launch plan. All modes launch the verified snapshot path and set the served model name.

- [ ] **Step 5: Implement bounded compatibility probes**

Run only fixed allowlisted commands with timeouts. Parse machine-readable or version-only output, redact paths and environment values from errors, and return `EngineAvailability::Incompatible` when Python, torch, CUDA, vLLM, or the selected GPU cannot work together.

- [ ] **Step 6: Run focused vLLM, config, and uv suites**

Run: `cargo test -p sbproxy-model-host --test engine_drivers vllm && cargo test -p sbproxy-model-host config::tests uv_release::tests launch::tests`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/sbproxy-model-host/src/vllm_driver.rs crates/sbproxy-model-host/src/config.rs crates/sbproxy-model-host/src/uv_release.rs crates/sbproxy-model-host/src/launch.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/engine_drivers.rs
git commit -m "feat: add managed vllm drivers"
```

### Task 5: CUDA-capable Linux llama.cpp acquisition

**Files:**
- Create: `crates/sbproxy-model-host/src/cuda_build.rs`
- Create: `crates/sbproxy-model-host/tests/cuda_build.rs`
- Modify: `crates/sbproxy-model-host/src/acquire.rs`
- Modify: `crates/sbproxy-model-host/src/config.rs`
- Modify: `crates/sbproxy-model-host/src/llama_driver.rs`
- Modify: `crates/sbproxy-model-host/src/llama_release.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`

**Interfaces:**
- Consumes: Task 3 `LlamaCppDriver`, PR 1 cache locking and atomic-publication patterns, and Task 2 `CommandExecutor`.
- Produces: `CudaBuildPlan`, `CudaBuildPrerequisites`, `CudaLlamaBuilder`, and `BinaryAcquirePlan::BuildCuda`.

- [ ] **Step 1: Add failing platform and prerequisite tests**

Simulate Linux x86-64 with an NVIDIA descriptor and cover `nvcc`, CMake, compiler, source pin, cache hit, missing toolkit, non-NVIDIA Linux, and explicit CPU or Vulkan choices. `EngineAccel::Auto` selects CUDA build only when prerequisites are acquirable; an explicit `cuda` request is blocked with remediation when they are not.

- [ ] **Step 2: Add failing atomic-build tests**

Use a fixture source archive and fake command executor. Concurrent builders for the same tag must share one lock and one published binary. A source digest mismatch, failed CMake configure, failed build, or missing output must leave no ready binary. A successful build publishes only after an executable `llama-server` exists.

- [ ] **Step 3: Run CUDA acquisition tests and verify red**

Run: `cargo test -p sbproxy-model-host --test cuda_build -- --nocapture`

Expected: FAIL because the CUDA build plan and builder do not exist.

- [ ] **Step 4: Implement the pinned on-box build path**

Download a pinned llama.cpp source archive through the existing HTTP stack, verify the configured or built-in source SHA-256, extract into a staging directory, run fixed argv equivalent to `cmake -S <src> -B <build> -DGGML_CUDA=ON -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF -DCMAKE_BUILD_TYPE=Release`, build only `llama-server`, then atomically publish the executable under the engine cache. Do not invoke a shell and do not inherit arbitrary CMake flags.

- [ ] **Step 5: Wire the plan into llama provisioning and doctor output**

`LlamaCppDriver::detect` reports the PATH or ready-cache binary as available, a complete source-build environment as acquirable, a missing toolkit as blocked, and non-NVIDIA CUDA as incompatible. Runtime provisioning consumes `BuildCuda`; it does not map CUDA to Vulkan.

- [ ] **Step 6: Run acquisition and driver suites**

Run: `cargo test -p sbproxy-model-host --test cuda_build && cargo test -p sbproxy-model-host --test engine_drivers llama && cargo test -p sbproxy-model-host acquire::tests llama_release::tests`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/sbproxy-model-host/src/cuda_build.rs crates/sbproxy-model-host/src/acquire.rs crates/sbproxy-model-host/src/config.rs crates/sbproxy-model-host/src/llama_driver.rs crates/sbproxy-model-host/src/llama_release.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/cuda_build.rs crates/sbproxy-model-host/tests/engine_drivers.rs
git commit -m "feat: build cuda llama cpp engines on linux"
```

### Task 6: Supervisor crash-loop truth and durable lifecycle jobs

**Files:**
- Modify: `crates/sbproxy-model-host/src/supervisor.rs`
- Modify: `crates/sbproxy-model-host/src/jobs.rs`
- Modify: `crates/sbproxy-model-host/src/engine_driver.rs`
- Test: `crates/sbproxy-model-host/src/supervisor.rs`
- Test: `crates/sbproxy-model-host/tests/engine_drivers.rs`

**Interfaces:**
- Consumes: Task 2 `RunningEngine`, `EngineDriverError`, and PR 1 `OperationJobStore`.
- Produces: `EngineSupervisor`, `CrashLoopState`, `reset()`, real bounded retry delays, retained terminal error, and provision, launch, load, drain, stop, and reset job events.

- [ ] **Step 1: Add failing paused-time retry tests**

Use millisecond test backoff to prove attempts happen after `base`, `2 * base`, and the cap, never in a tight loop. Prove the terminal state retains attempts, stable reason, bounded stderr tail, first failure, last failure, and next remediation.

- [ ] **Step 2: Add failing reset and job-history tests**

After the retry budget is exhausted, another readiness request must return `crash_loop` without spawning. `reset()` clears the loop and records a reset job; the next request may launch again. Terminal job details remain readable after the request returns.

- [ ] **Step 3: Run supervisor tests and verify red**

Run: `cargo test -p sbproxy-model-host supervisor::tests -- --nocapture`

Expected: FAIL because retries are currently immediate and there is no retained resettable crash-loop contract.

- [ ] **Step 4: Implement real backoff, retention, reset, and jobs**

Sleep through an injectable clock between attempts, cap attempts and delay, preserve the last error, and refuse implicit restart after terminal failure. Emit state transitions through `OperationJobStore` without placing stderr, secrets, prompts, or environment values in job metadata.

- [ ] **Step 5: Run focused supervisor and job suites**

Run: `cargo test -p sbproxy-model-host supervisor::tests && cargo test -p sbproxy-model-host --test operation_jobs && cargo test -p sbproxy-model-host --test engine_drivers crash_loop`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/sbproxy-model-host/src/supervisor.rs crates/sbproxy-model-host/src/jobs.rs crates/sbproxy-model-host/src/engine_driver.rs crates/sbproxy-model-host/tests/engine_drivers.rs
git commit -m "feat: retain bounded engine crash loops"
```

### Task 7: Process-wide runtime manager and atomic reconciliation

**Files:**
- Create: `crates/sbproxy-model-host/src/runtime_manager.rs`
- Modify: `crates/sbproxy-model-host/src/runtime.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Modify: `crates/sbproxy-model-host/src/deployment.rs`
- Modify: `crates/sbproxy-model-host/src/deployment_store.rs`
- Test: `crates/sbproxy-model-host/tests/runtime_reconcile.rs`

**Interfaces:**
- Consumes: Task 1 `RuntimeDesiredState`, Tasks 3 and 4 engine drivers, Task 6 supervisor, PR 1 artifact manager, deployment store, and jobs.
- Produces: `ModelRuntimeManager`, `PreparedRevision`, `ReconcilePlan`, `ReconcileReport`, `DeploymentRuntimeStatus`, `prepare_revision()`, `commit_revision()`, `reconcile()`, `ensure_ready()`, `drain()`, `stop()`, and `reset()`.

- [ ] **Step 1: Add failing empty-start and atomic-swap tests**

Construct one manager with an empty initial state, reconcile a first model later, and assert the same manager handle serves it. Require `current_revision()` to remain old until preparation completes and to remain old after catalog, artifact, driver, or warm failure.

- [ ] **Step 2: Add failing add, change, remove, and preservation tests**

Start deployments `a` and `b`. Reconcile a revision that leaves `a` unchanged, changes `b`, and adds `c`; assert `a` keeps the same running generation and port. Reconcile removal of `b`; assert new admissions stop, active work drains, and only `b` shuts down.

```rust,no_run
#[tokio::test]
async fn reconcile_preserves_unaffected_generation() {
    let manager = fixture_manager(initial_revision(&["a", "b"]));
    let a = manager.ensure_ready("a").await.unwrap();
    manager.reconcile(changed_revision_keep_a()).await.unwrap();
    assert_eq!(manager.ensure_ready("a").await.unwrap().port, a.port);
    assert_eq!(manager.status("a").generation, a.generation);
}
```

- [ ] **Step 3: Add failing per-deployment concurrency tests**

Two callers for one cold deployment share one prepare and launch job. Two different cold deployments prepare concurrently up to `max_parallel_prepares`; they do not serialize behind one process-wide spawn lock.

- [ ] **Step 4: Run reconciliation tests and verify red**

Run: `cargo test -p sbproxy-model-host --test runtime_reconcile manager -- --nocapture`

Expected: FAIL because the runtime has immutable config, an optional first-install global, and one spawn lock.

- [ ] **Step 5: Implement manager state and prepare-then-commit**

Store desired state behind `ArcSwap`. Keep deployment slots in a manager-owned map keyed by deployment ID and generation fingerprint. Preparation validates the full revision, resolves artifacts, provisions drivers, and stages warm generations without changing routes. Commit swaps the desired state once, installs new routes, preserves identical slots, and drains removed or superseded slots after the swap. Tear down staged resources on any prepare error.

- [ ] **Step 6: Consume admin-managed revisions**

When authority is `admin_managed`, load and validate the PR 1 deployment store before preparation. File-managed config never writes the store. A stale or invalid store revision is a prepare failure and does not replace the live desired state.

- [ ] **Step 7: Remove runtime authority from the legacy wrapper**

Move artifact resolution and fit helpers needed by the manager into focused internal functions. Keep only source-compatible adapters needed by existing tests; no static `Option<ModelHostRuntime>` or first-config behavior remains.

- [ ] **Step 8: Run runtime, artifact, store, and reconciliation suites**

Run: `cargo test -p sbproxy-model-host --test runtime_reconcile && cargo test -p sbproxy-model-host --test runtime_artifacts && cargo test -p sbproxy-model-host --test deployment_store && cargo test -p sbproxy-model-host runtime::tests`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/sbproxy-model-host/src/runtime_manager.rs crates/sbproxy-model-host/src/runtime.rs crates/sbproxy-model-host/src/deployment.rs crates/sbproxy-model-host/src/deployment_store.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/runtime_reconcile.rs
git commit -m "feat: reconcile process wide model runtime"
```

### Task 8: Per-device admission, priority queues, drain, and keep-alive

**Files:**
- Create: `crates/sbproxy-model-host/src/admission.rs`
- Create: `crates/sbproxy-model-host/src/device_residency.rs`
- Create: `crates/sbproxy-model-host/tests/local_admission.rs`
- Modify: `crates/sbproxy-model-host/src/fit.rs`
- Modify: `crates/sbproxy-model-host/src/residency.rs`
- Modify: `crates/sbproxy-model-host/src/runtime_manager.rs`
- Modify: `crates/sbproxy-model-host/src/scheduling.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`

**Interfaces:**
- Consumes: Task 7 deployment slots, `PriorityClass`, `FitPlan`, `GpuDescriptor`, and `EvictionPolicy`.
- Produces: `MemoryEstimate`, `AdmissionGate`, `AdmissionPermit`, `AdmissionRejection`, `AdmissionReason`, `DrainReport`, `DeviceResidencySet`, and `ModelRuntimeManager::admit()`.

- [ ] **Step 1: Add failing memory-breakdown and per-device tests**

Require each fit plan to report weight bytes, KV bytes, runtime overhead, safety margin, total bytes, and selected GPU. On two unequal GPUs, load and eviction affect only the selected device. A model that fits the largest device cannot be admitted to a smaller selected device.

- [ ] **Step 2: Add failing priority and queue-bound tests**

At full concurrency, interactive waiters precede standard and batch; equal classes remain FIFO. `max_queue_depth` rejects without waiting as `queue_full`. Timeout returns `queue_timeout`. Active and queued counts update at enqueue, admission, timeout, cancellation, and permit drop.

- [ ] **Step 3: Add failing drain and keep-alive tests**

Drain rejects new work as `draining`, cancels queued work, waits for active permits through the deadline, and then stops. Keep-alive starts when the last permit completes, not when it begins. Active, queued, pinned, preparing, or draining deployments are never reaped.

```rust,no_run
#[tokio::test(start_paused = true)]
async fn keep_alive_starts_after_last_completion() {
    let permit = gate.admit(PriorityClass::Standard).await.unwrap();
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(!slot.is_idle_expired());
    drop(permit);
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(!slot.is_idle_expired());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(slot.is_idle_expired());
}
```

- [ ] **Step 4: Run admission tests and verify red**

Run: `cargo test -p sbproxy-model-host --test local_admission -- --nocapture`

Expected: FAIL because admission is process-global, memory is not per device, and keep-alive is not enforced.

- [ ] **Step 5: Implement memory estimates and per-device residency**

Extend fit planning without changing its quant selection rules. Create one residency manager per GPU index, reserve the configured safety margin, track each resident generation on exactly one device, and produce a deterministic eviction plan that never selects pinned, active, queued, preparing, or draining slots.

- [ ] **Step 6: Implement admission and lifecycle permits**

Use one mutex-protected queue per deployment plus `oneshot` wakeups. Permit drop records last-completed time and wakes the highest-priority live waiter. Drain changes state before waking waiters. Every rejection carries a stable `AdmissionReason`, bounded detail, retryability, and optional retry-after.

- [ ] **Step 7: Add manager maintenance**

Expose deterministic `maintenance_tick(now)` for tests and a bounded background interval for production. It reaps only expired eligible deployments, records a stop job, frees per-device residency, and updates status atomically.

- [ ] **Step 8: Run admission, fit, residency, and runtime suites**

Run: `cargo test -p sbproxy-model-host --test local_admission && cargo test -p sbproxy-model-host fit::tests residency::tests scheduling::tests && cargo test -p sbproxy-model-host --test runtime_reconcile`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/sbproxy-model-host/src/admission.rs crates/sbproxy-model-host/src/device_residency.rs crates/sbproxy-model-host/src/fit.rs crates/sbproxy-model-host/src/residency.rs crates/sbproxy-model-host/src/runtime_manager.rs crates/sbproxy-model-host/src/scheduling.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/local_admission.rs
git commit -m "feat: enforce local model admission lifecycle"
```

### Task 9: Accurate hardware and deployment telemetry

**Files:**
- Modify: `crates/sbproxy-model-host/src/fit.rs`
- Modify: `crates/sbproxy-model-host/src/probe_nvidia.rs`
- Modify: `crates/sbproxy-model-host/src/probe_metal.rs`
- Modify: `crates/sbproxy-model-host/src/probe_cpu.rs`
- Modify: `crates/sbproxy-model-host/src/runtime_manager.rs`
- Modify: `crates/sbproxy-model-host/src/runtime.rs`
- Modify: `crates/sbproxy-observe/src/metrics.rs`
- Modify: `crates/sbproxy-core/src/server/model_host.rs`
- Test: `crates/sbproxy-model-host/tests/local_admission.rs`
- Test: `crates/sbproxy-observe/src/metrics.rs`

**Interfaces:**
- Consumes: Task 8 counts and memory estimates plus platform probes.
- Produces: `GpuDescriptor::compute_utilization`, `GpuDescriptor::memory_occupancy`, complete configured-through-failed deployment status, and bounded `sbproxy_model_host_*` metrics.

- [ ] **Step 1: Add failing NVIDIA parsing tests**

Parse separate NVML or `nvidia-smi` values for GPU compute utilization, total memory, free memory, and memory occupancy. A missing compute field yields `None`; it must not reuse memory occupancy or zero.

- [ ] **Step 2: Add failing status and metric tests**

Require status rows for `configured`, `assigned`, `cached`, `preparing`, `ready`, `draining`, `stopped`, and `failed`. Each row includes active, queued, generation, driver availability, artifact digest, selected devices, bounded reason code, and the retained job ID. Require separate gauges for compute utilization and memory occupancy plus per-deployment active and queued requests.

- [ ] **Step 3: Run telemetry tests and verify red**

Run: `cargo test -p sbproxy-model-host probe_nvidia::tests && cargo test -p sbproxy-model-host --test local_admission status && cargo test -p sbproxy-observe model_host`

Expected: FAIL because compute utilization is absent, current utilization is derived from memory, and status lists only resident engines.

- [ ] **Step 4: Implement truthful probe and status fields**

NVML reads `utilization_rates().gpu`; the CLI fallback requests `utilization.gpu`. Apple and CPU probes return unknown compute unless a platform API reports it. Memory occupancy is derived only from total and free memory. Serialize unknown compute as `null` and skip its gauge update rather than writing zero.

- [ ] **Step 5: Implement bounded metrics and lifecycle observation**

Use deployment ID, engine, state, device, priority, and reason from closed sets or validated bounded identifiers. Do not label with artifact path, raw model source, job error, prompt, key, tenant, or private address. Update metrics on every queue and lifecycle transition.

- [ ] **Step 6: Run focused telemetry suites**

Run: `cargo test -p sbproxy-model-host probe_nvidia::tests && cargo test -p sbproxy-model-host --test local_admission status && cargo test -p sbproxy-observe model_host`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/sbproxy-model-host/src/fit.rs crates/sbproxy-model-host/src/probe_nvidia.rs crates/sbproxy-model-host/src/probe_metal.rs crates/sbproxy-model-host/src/probe_cpu.rs crates/sbproxy-model-host/src/runtime_manager.rs crates/sbproxy-model-host/src/runtime.rs crates/sbproxy-observe/src/metrics.rs crates/sbproxy-core/src/server/model_host.rs crates/sbproxy-model-host/tests/local_admission.rs
git commit -m "feat: report truthful model runtime telemetry"
```

### Task 10: Core startup, reload, routing, and admin reconciliation

**Files:**
- Create: `crates/sbproxy-core/tests/model_host_reload.rs`
- Modify: `crates/sbproxy-core/src/server/model_host.rs`
- Modify: `crates/sbproxy-core/src/server/lifecycle.rs`
- Modify: `crates/sbproxy-core/src/server/ai_dispatch.rs`
- Modify: `crates/sbproxy-core/src/context.rs`
- Modify: `crates/sbproxy-core/src/admin.rs`
- Modify: `crates/sbproxy-core/src/admin_model_host.rs`
- Modify: `crates/sbproxy-ai/src/local_host.rs`
- Modify: `crates/sbproxy-ai/src/provider.rs`

**Interfaces:**
- Consumes: Task 7 `ModelRuntimeManager`, Task 8 admission permit, Task 1 canonical and legacy lowering, and the compiled pipeline reload flow.
- Produces: `model_runtime_manager() -> Arc<ProductionModelRuntimeManager>`, `prepare_model_runtime(pipeline, config_dir)`, `commit_model_runtime(prepared)`, and one shared reload transaction used by file watch, SIGHUP, and admin reload.

- [ ] **Step 1: Add failing first-empty and multi-origin integration tests**

Start the manager with a pipeline containing no managed model, reload a canonical managed deployment, and serve through the same handle. Compile two AI actions from distinct origins and assert both deployments exist. Conflicting routes fail the reload and retain the prior pipeline plus runtime revision.

- [ ] **Step 2: Add failing unaffected-engine and admin-reload tests**

Load two fixture deployments, reload a change to one, and assert the other keeps its generation and port. Drive `/admin/reload` through the same helper and assert it reconciles rather than only swapping the pipeline.

- [ ] **Step 3: Add failing request-admission lifecycle tests**

For a managed provider, acquire a deployment-specific permit before `ensure_ready`, retain it through a simulated streaming response, and release on context drop. Assert queue timeout, draining, engine unhealthy, and crash loop follow normal provider failover with stable reasons and without leaking a permit.

- [ ] **Step 4: Run core integration tests and verify red**

Run: `cargo test -p sbproxy-core --test model_host_reload -- --nocapture`

Expected: FAIL because startup installs an optional first-config runtime, admin reload bypasses model reconciliation, and the queue is process-global.

- [ ] **Step 5: Install one manager unconditionally**

The process-global is a non-optional manager created before the first pipeline becomes requestable. Every startup or reload compiles and prepares a complete desired revision. Commit the prepared revision before the infallible pipeline swap; on preparation failure, return an error with both old pipeline and old runtime untouched.

- [ ] **Step 6: Route canonical and legacy managed providers**

Treat `provider_type: managed_model` and legacy `serve:` as local. Resolve the requested public model through the desired-state route map, acquire its admission permit, bring its generation ready, then set only a loopback engine URL on the cloned provider. Unmanaged local endpoints remain ordinary private providers.

- [ ] **Step 7: Unify reload entrypoints**

Refactor the duplicated admin reload body to call the same parse, compile, prepare, enterprise hook, runtime commit, and pipeline swap transaction as file watch and SIGHUP. Preserve existing status codes, single-flight behavior, config hashes, and audit events.

- [ ] **Step 8: Adapt admin runtime actions**

Status reads the manager snapshot. Load calls `ensure_ready`; evict becomes bounded drain plus stop; add crash-loop reset. Return operation job IDs and stable reason codes. Persistent deployment mutation remains PR 6.

- [ ] **Step 9: Run core, AI, and admin suites**

Run: `cargo test -p sbproxy-core --test model_host_reload && cargo test -p sbproxy-core server::model_host admin_model_host && cargo test -p sbproxy-ai local_host managed_model`

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add crates/sbproxy-core crates/sbproxy-ai/src/local_host.rs crates/sbproxy-ai/src/provider.rs
git commit -m "feat: reconcile models across startup and reload"
```

### Task 11: One-command run and complete local model lifecycle CLI

**Files:**
- Create: `crates/sbproxy/tests/models_lifecycle_cli.rs`
- Modify: `crates/sbproxy/src/main.rs`
- Modify: `crates/sbproxy/Cargo.toml`
- Modify: `crates/sbproxy-model-host/src/artifact/mod.rs`
- Modify: `crates/sbproxy-model-host/src/artifact/cache.rs`
- Modify: `crates/sbproxy-core/src/admin_model_host.rs`

**Interfaces:**
- Consumes: shared artifact manager, engine-driver detection and provisioning, runtime status and stop endpoints, and canonical config from Tasks 1 through 10.
- Produces: `models remove`, `models ps`, `models stop`, stable lifecycle output envelopes, and a readiness-first `sbproxy run` workflow.

- [ ] **Step 1: Add failing clap and JSON contract tests**

Parse `models pull/list/show/remove/ps/stop` with `--format` after the subcommand. Require stable JSON objects with `schema_version`, command, operation job ID when applicable, and no ANSI or carriage-return progress bytes. Require `ps` and `stop` to accept admin URL and credential through CLI or environment without printing the password.

- [ ] **Step 2: Add failing artifact removal tests**

Remove one verified artifact atomically. Reject removal while it is pinned, configured, resident, preparing, or referenced by a nonterminal job. A missing artifact is an idempotent success. Partial staging remains separately collectible.

- [ ] **Step 3: Add failing run-output and readiness tests**

With fixture driver and artifact transport, require model and variant selection to be runnable on the detected worker, progress within five seconds, warm readiness before the success banner, generated loopback admin credential, base URL, model alias, admin URL, curl, `OPENAI_BASE_URL`, and `OPENAI_API_KEY` guidance. Ctrl-C drains the active deployment and preserves verified artifacts.

```rust,no_run
#[test]
fn run_success_output_is_copyable_and_secret_bounded() {
    let out = run_fixture("qwen2.5-0.5b-instruct");
    assert!(out.contains("OPENAI_BASE_URL=http://127.0.0.1:"));
    assert!(out.contains("Admin: http://127.0.0.1:"));
    assert!(out.contains("curl "));
    assert!(!out.contains("changeme"));
}
```

- [ ] **Step 4: Run CLI tests and verify red**

Run: `cargo test -p sbproxy --test models_lifecycle_cli -- --nocapture`

Expected: FAIL because remove, ps, and stop do not exist and run reports success before engine readiness.

- [ ] **Step 5: Implement shared output and admin client adapters**

Keep progress on stderr through the existing observer. Use a bounded blocking HTTP client for local admin status and stop. Basic credentials come from explicit flags or `SB_ADMIN_USERNAME` and `SB_ADMIN_PASSWORD`; secret values are zeroized after header construction and omitted from debug or error output.

- [ ] **Step 6: Implement safe artifact removal**

Resolve the exact artifact from config or explicit model and variant, build protection from configured and live references, acquire its digest lock, revalidate protection, then atomically remove the ready snapshot and metadata. Return reclaimed bytes and job ID.

- [ ] **Step 7: Make run readiness-first**

Resolve the catalog v2 variant against the real worker profile, pull and verify through the artifact manager, detect and provision the exact driver, synthesize canonical `proxy.model_host` plus a `managed_model` provider, enable admin on loopback with a generated high-entropy bootstrap password, set `warm: true`, boot, and print success only after the runtime reports ready. A non-runnable variant fails before the gateway listener claims success.

- [ ] **Step 8: Run CLI, artifact, and shutdown suites**

Run: `cargo test -p sbproxy --test models_lifecycle_cli && cargo test -p sbproxy models_ run_ && cargo test -p sbproxy-model-host --test artifact_manager`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/sbproxy/src/main.rs crates/sbproxy/Cargo.toml crates/sbproxy/tests/models_lifecycle_cli.rs crates/sbproxy-model-host/src/artifact crates/sbproxy-core/src/admin_model_host.rs
git commit -m "feat: complete local model lifecycle cli"
```

### Task 12: Capabilities, schemas, examples, and operator documentation

**Files:**
- Create: `examples/model-host-managed/sb.yml`
- Create: `examples/model-host-managed/README.md`
- Modify: `crates/sbproxy-model-host/src/capabilities.rs`
- Modify: `crates/sbproxy-model-host/tests/capability_contract.rs`
- Modify: `docs/model-host.md`
- Modify: `docs/quickstart-serve.md`
- Modify: `docs/admin.md`
- Modify: `docs/manual.md`
- Modify: `docs/security-model-host.md`
- Modify: `docs/model-host-capabilities.md`
- Modify: `docs/README.md`
- Modify: `schemas/sb-config.schema.json`
- Modify: `schemas/ai-proxy-provider.schema.json`
- Modify: `docs/llms-full.txt`

**Interfaces:**
- Consumes: all stable PR 2 behavior and the existing schema, capability, example, docs, and llms-full generators.
- Produces: truthful stable capability claims, canonical configuration guidance, migration guidance, and generated files that pass drift checks.

- [ ] **Step 1: Add failing capability evidence tests**

Require executable consumers for managed llama.cpp, vLLM binary/uv/container, runtime reconciliation, keep-alive, priority admission, lifecycle status, model lifecycle CLI, and Mac local-runtime certification. Keep admin mutation/UI, cluster behavior, live NVIDIA certification, and cluster CLI unsupported or preview as appropriate.

- [ ] **Step 2: Run capability and schema checks and verify red**

Run: `cargo test -p sbproxy-model-host --test capability_contract && scripts/check-config-schema.sh && scripts/check-model-host-capabilities.sh`

Expected: FAIL because PR 2 fields and evidence are absent and generated outputs are stale.

- [ ] **Step 3: Update the executable registry from real evidence**

Add consumer probes that execute driver plan construction, reconcile add/change/remove, priority FIFO, keep-alive expiry, and stable CLI schema behavior. Promote only behavior exercised end to end. Do not promote cluster, UI, persistent admin mutation, or live NVIDIA certification.

- [ ] **Step 4: Write canonical and migration documentation**

Document `proxy.model_host`, `provider_type: managed_model`, authority modes, engine availability states, vLLM container isolation, uv compatibility, CUDA source-build prerequisites, per-device admission, reason codes, reload rollback, CLI lifecycle commands, generated run credentials, and the one-window legacy `serve:` lowering. State that GCP certification is reserved for PR 7.

- [ ] **Step 5: Add and validate the canonical example**

The example uses the built-in pinned Qwen bootstrap variant, file-managed desired state, a managed-model provider, loopback admin, bounded concurrency and queue, and copyable pull/run/status/stop commands. Validate it through the normal example sweep.

- [ ] **Step 6: Regenerate sources in dependency order**

Run:

```bash
cargo run --quiet -p sbproxy-config --bin generate-schema > schemas/sb-config.schema.json
cargo run --quiet -p sbproxy-ai --bin generate-ai-provider-schema > schemas/ai-proxy-provider.schema.json
cargo run --quiet -p sbproxy-model-host --bin generate-model-host-capabilities > docs/model-host-capabilities.md
./scripts/regen-llms-full.sh
```

Expected: only the declared generated schema, capability, and flattened-doc outputs change.

- [ ] **Step 7: Run docs, schema, capability, and example checks**

Run: `bash scripts/docs-ci.sh && bash scripts/check-spec-citations.sh && scripts/check-config-schema.sh && scripts/check-model-host-capabilities.sh && ./scripts/regen-llms-full.sh --check && cargo test -p sbproxy-config validate_examples`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add examples/model-host-managed docs schemas crates/sbproxy-model-host/src/capabilities.rs crates/sbproxy-model-host/tests/capability_contract.rs
git commit -m "docs: complete managed local runtime workflow"
```

### Task 13: Real Mac gate, full repository verification, review, and stacked PR

**Files:**
- Modify if evidence requires: `docs/model-host-certification.md`
- Modify if evidence requires: PR description only

**Interfaces:**
- Consumes: every PR 2 implementation, generated output, Linear acceptance criterion, and PR 1 base contract.
- Produces: exact local and CI evidence, a clean stacked branch, and PR 2 targeting `rickcrawford/wor-1835-foundations` until PR #676 merges.

- [ ] **Step 1: Run focused deterministic PR 2 suites**

Run:

```bash
cargo test -p sbproxy-model-host --test engine_drivers
cargo test -p sbproxy-model-host --test cuda_build
cargo test -p sbproxy-model-host --test runtime_reconcile
cargo test -p sbproxy-model-host --test local_admission
cargo test -p sbproxy-core --test model_host_reload
cargo test -p sbproxy --test models_lifecycle_cli
```

Expected: PASS with no ignored failure path required for loopback or subprocess behavior.

- [ ] **Step 2: Run the real Apple Silicon managed request gate**

On the current Mac, use the built-in `qwen2.5-0.5b-instruct:q4_k_m` artifact and managed llama.cpp Metal driver. Start `sbproxy run qwen2.5-0.5b-instruct` with isolated cache and ports, wait for the readiness output, send one OpenAI-compatible chat completion through the gateway, assert nonempty assistant content, query model status, stop the model through the lifecycle CLI, and confirm the verified artifact remains reusable without another weight download.

If the host lacks Apple Silicon or required network access, do not replace this gate with a fixture and do not claim the PR exit condition. Record the concrete environmental blocker and keep the PR draft until it can run on an eligible Mac.

- [ ] **Step 3: Run every repository gate from `AGENTS.md`**

Run:

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci
cargo test --workspace --exclude sbproxy-e2e --locked --doc
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
```

Expected: every command exits 0. Record the exact nextest passed and skipped counts.

- [ ] **Step 4: Run generated, security, and diff gates**

Run:

```bash
bash scripts/docs-ci.sh
bash scripts/check-spec-citations.sh
scripts/check-config-schema.sh
scripts/check-model-host-capabilities.sh
./scripts/regen-llms-full.sh --check
git diff --check origin/rickcrawford/wor-1835-foundations...HEAD
```

Scan added lines for secret-like tokens and the forbidden em dash. If Cargo files changed, run the `NOTICE` coverage command from `AGENTS.md` and resolve every output line.

- [ ] **Step 5: Review the complete stacked diff against scope**

Confirm:

- No engine can receive a repository source after managed artifact resolution.
- No runtime, queue, or config path uses first-install or first-origin precedence.
- Container argv cannot expose a public engine port, writable artifact mount, all-GPU access, host network, or unpinned image.
- Per-device admission uses the selected device and reports weight, KV, overhead, safety margin, and total separately.
- Reload failure preserves the prior pipeline, desired revision, and unrelated resident engines.
- Status and metrics distinguish memory occupancy from compute utilization and preserve unknown compute.
- CLI JSON is stable and contains no progress control bytes or credentials.
- PR 3 cluster work, PR 6 admin UI and persistent mutation, and PR 7 GCP certification did not leak into this branch.

- [ ] **Step 6: Commit any evidence-only documentation update**

```bash
git add docs/model-host-certification.md
git commit -m "test: record local runtime certification"
```

Skip this commit when the certification document already records the exact evidence and no file changes.

- [ ] **Step 7: Push and open PR 2**

Push `rickcrawford/wor-1835-local-runtime`. Open a ready PR against `rickcrawford/wor-1835-foundations` while PR #676 is open, then retarget it to `main` after #676 merges. The PR body lists WOR-1841, WOR-1843, WOR-1844, WOR-1848, WOR-1684, and WOR-1813; architecture and migration notes; exact local and CI evidence; and the explicit GCP PR 7 boundary.

## Plan Self-Review

- Spec coverage: Tasks 2 through 6 cover SH-04; Task 7 and Task 10 cover SH-05; Tasks 8 and 9 cover SH-07; Task 11 covers the PR 2 portion of SH-17; Task 5 covers implementation for WOR-1813; Task 12 covers docs, schema, and capability truth; Task 13 covers the PR 2 exit gates.
- Dependency order: canonical desired state precedes drivers; drivers and artifact verification precede the manager; the manager precedes admission and core integration; core integration precedes lifecycle CLI and live certification.
- Scope boundary: SH-17 cluster commands remain PR 3 because their token and certificate acceptance depends on node identity and `ClusterHandle`. Persistent admin mutation and UI remain PR 6. Live GCP T4/L4 and multi-node evidence remains PR 7.
- Type consistency: `RuntimeDesiredState`, `EngineDriver`, `ModelRuntimeManager`, `AdmissionPermit`, and `MemoryEstimate` are defined before their consumers and keep the same names throughout the plan.
- Placeholder scan: the plan contains no TBD, TODO, unspecified error-handling step, or unowned acceptance criterion.
