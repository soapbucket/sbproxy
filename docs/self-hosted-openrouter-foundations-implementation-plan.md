# Self-Hosted OpenRouter Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver PR 1 of the self-hosted OpenRouter program: truthful capabilities, catalog v2, durable desired state and jobs, safe artifact acquisition, enforced pull policy, and an end-to-end `sbproxy models pull` workflow that never launches an inference engine.

**Architecture:** `sbproxy-model-host` owns the executable capability registry, typed catalog and artifact resolution, deployment revision contract, durable operation jobs, and artifact cache service. The binary and runtime consume those services through one interface, while existing `serve:` configuration remains a one-window compatibility input. Artifact bytes become visible only after cross-process locking, resumable staging, exact verification, and atomic snapshot finalization.

**Tech Stack:** Rust 1.82, Tokio, reqwest, futures, fs2 advisory locks, ULID job identifiers, SHA-256, canonical JSON, serde/schemars, clap, cargo-nextest, shell-based documentation gates.

## Global Constraints

- Primary Linear scope is WOR-1836, WOR-1837, WOR-1840, WOR-1842, WOR-1681, WOR-1682, and WOR-1666.
- Keep the existing unmanaged provider behavior and the legacy `serve:` compatibility path working for one documented migration window.
- Never silently rewrite `sb.yml`; `admin_managed`, `file_managed`, and `cluster_authority` remain distinct authorities.
- Stable catalog variants require an immutable source revision, exact files, SHA-256 digests, and byte sizes.
- Pickle artifacts are refused unless the selected logical model explicitly sets `allow_pickle: true`; safetensors win when both safe and pickle variants are compatible.
- `on_boot`, `on_demand`, `manual`, `file:`, and denied-network behavior must be enforced by the shared artifact service, not only parsed.
- A digest mismatch must leave no ready snapshot and must never fall back to an engine-managed download.
- Resolved credentials may be used only in transport authorization; they must not appear in debug output, job records, cache metadata, CLI JSON, or logs.
- The built-in catalog may mark uncertified variants `preview`; it must not advertise an unpinned or unverified variant as `stable`.
- CLI pull, startup warming, admin operations, and runtime acquisition must use the same job and artifact interfaces.
- GCP T4, L4, multi-GPU, and three-node live validation remains in PR 7; PR 1 uses deterministic fixtures and mock artifact servers.
- User-facing content, rustdoc, commit messages, and generated capability documentation contain no em dash characters.
- Every implementation step follows red, green, refactor and ends at a reviewable commit checkpoint.
- Before the PR is published, run every repository gate listed in `AGENTS.md`, including docs, schema, and generated-file checks.

---

## File Map

- `crates/sbproxy-model-host/src/capabilities.rs`: versioned registry, support levels, config-field coverage, consumer-contract identifiers, Markdown rendering.
- `crates/sbproxy-model-host/src/bin/generate-model-host-capabilities.rs`: deterministic registry-to-Markdown adapter.
- `crates/sbproxy-model-host/src/artifact_spec.rs`: catalog v2 artifact types, worker requirements, deterministic selection, canonical artifact digest.
- `crates/sbproxy-model-host/src/catalog.rs`: catalog document loading, v1 compatibility diagnostics, logical-model lookup, legacy `ModelRef` adapter.
- `crates/sbproxy-model-host/src/deployment.rs`: normalized deployment revision and validation contract shared by all authority modes.
- `crates/sbproxy-model-host/src/deployment_store.rs`: cross-process compare-and-swap file store for admin-managed revisions.
- `crates/sbproxy-model-host/src/jobs.rs`: durable operation job state machine and bounded terminal history.
- `crates/sbproxy-model-host/src/artifact/mod.rs`: artifact manager orchestration and public API.
- `crates/sbproxy-model-host/src/artifact/cache.rs`: cache layout, ready-manifest verification, staging, locks, atomic finalization.
- `crates/sbproxy-model-host/src/artifact/http.rs`: range-aware HTTP transport and redacted source credential.
- `crates/sbproxy-model-host/src/artifact/gc.rs`: budget accounting and protected LRU collection.
- `crates/sbproxy-model-host/src/pull.rs`: pull-intent planning over resolved artifacts.
- `crates/sbproxy-model-host/src/runtime.rs`: exact-artifact preflight and verified-local-path handoff before engine launch.
- `crates/sbproxy-model-host/src/launch.rs`: helpers that retarget llama.cpp and vLLM to verified local paths.
- `crates/sbproxy-core/src/server/model_host.rs`: one catalog loader and artifact manager for the live runtime.
- `crates/sbproxy/src/main.rs`: `models pull`, richer `list`/`show`, credential wiring, stable JSON output.
- `crates/sbproxy/tests/models_pull_cli.rs`: real binary, mock HTTP, restart, resume, corruption, and cross-process lock coverage.
- `crates/sbproxy-model-host/tests/`: contract-level catalog, store, job, artifact, policy, and GC tests.
- `crates/sbproxy-model-host/data/models.yaml`: versioned built-in catalog with truthful pinned variant metadata.
- `examples/model-manifest/`: runnable catalog v2 pull example and migration notes.
- `docs/model-host-capabilities.md`: generated capability matrix.
- `docs/model-host.md`: stable operator behavior, cache layout, policy, errors, and migration.
- `scripts/check-model-host-capabilities.sh`: generated matrix drift gate.
- `.github/workflows/ci.yml`: capability matrix and stable-contract gate.

### Task 1: Executable capability registry

**Files:**
- Create: `crates/sbproxy-model-host/src/capabilities.rs`
- Create: `crates/sbproxy-model-host/src/bin/generate-model-host-capabilities.rs`
- Create: `crates/sbproxy-model-host/tests/capability_contract.rs`
- Create: `scripts/check-model-host-capabilities.sh`
- Create: `docs/model-host-capabilities.md`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `ModelHostConfig`, `ServeEntry`, and the existing runtime helpers used by consumer probes.
- Produces: `capability_registry() -> &'static CapabilityRegistry`, `CapabilityRegistry::validate()`, `CapabilityRegistry::validate_config()`, `CapabilityRegistry::render_markdown()`, `CapabilityFinding`, and `ConsumerContract::assert_behavior()`.

- [ ] **Step 1: Add failing registry contract tests**

Create integration tests that require all eight domains, reject a stable entry without executable evidence, execute every stable consumer probe, and cover every property emitted by the `ModelHostConfig` and `ServeEntry` schemas:

```rust,no_run
#[test]
fn registry_covers_domains_and_stable_evidence_executes() {
    let registry = sbproxy_model_host::capability_registry();
    registry.validate().expect("registry is internally consistent");
    for domain in [
        CapabilityDomain::Manifest,
        CapabilityDomain::Artifact,
        CapabilityDomain::Engine,
        CapabilityDomain::Lifecycle,
        CapabilityDomain::Cluster,
        CapabilityDomain::Policy,
        CapabilityDomain::Admin,
        CapabilityDomain::Platform,
    ] {
        assert!(registry.entries().iter().any(|entry| entry.domain == domain));
    }
    for field in registry
        .config_fields()
        .iter()
        .filter(|field| field.status == SupportLevel::Stable)
    {
        field
            .consumer
            .expect("stable field has a consumer contract")
            .assert_behavior()
            .unwrap_or_else(|error| panic!("{}: {error}", field.path));
    }
}
```

- [ ] **Step 2: Run the focused test and verify red**

Run: `cargo test -p sbproxy-model-host --test capability_contract`

Expected: compilation fails because `capability_registry`, `CapabilityDomain`, and `SupportLevel` do not exist.

- [ ] **Step 3: Implement the versioned registry and executable contracts**

Use these public shapes and closed enums. `ConsumerContract` stays non-serializable and is converted to a stable test ID in rendered output:

```rust,no_run
pub const CAPABILITY_REGISTRY_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDomain {
    Manifest,
    Artifact,
    Engine,
    Lifecycle,
    Cluster,
    Policy,
    Admin,
    Platform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    Stable,
    Preview,
    ConfigOnly,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerContract {
    CatalogFileChangesResolution,
    CacheDirectoryChangesArtifactPath,
    CacheBudgetCollectsUnprotectedArtifacts,
    ServeModelsChangeDesiredDeployments,
    EvictionChangesAdmission,
    PriorityGateChangesDispatch,
}

#[derive(Debug, Clone, Copy)]
pub struct ConfigFieldCapability {
    pub path: &'static str,
    pub status: SupportLevel,
    pub capability_id: &'static str,
    pub consumer: Option<ConsumerContract>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CapabilityEntry {
    pub id: &'static str,
    pub domain: CapabilityDomain,
    pub status: SupportLevel,
    pub summary: &'static str,
    pub evidence: &'static [&'static str],
    #[serde(skip)]
    pub consumer: Option<ConsumerContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityFinding {
    pub path: String,
    pub status: SupportLevel,
    pub message: String,
}
```

`CapabilityRegistry::validate` must reject duplicate IDs, missing domains, stable entries without an executable consumer and matching evidence, stable fields without consumers, stable fields owned by non-stable capabilities, fields pointing at unknown capabilities, and any schema property absent from the field registry. `validate_config` returns findings for every configured preview, config-only, or unsupported field; `ModelHostConfig::validate` rejects unsupported fields and returns preview findings to CLI planning and startup logging. Prefix preview/config-only schema descriptions with their support label so generated JSON schema is truthful without consulting a separate document. Mark keep-alive enforcement and container launch `preview`, arbitrary admin model load and multi-node behavior `unsupported`, and the PR 1 catalog/artifact/pull contracts `stable` only after their tests land.

- [ ] **Step 4: Generate and gate the Markdown matrix**

The binary prints only `capability_registry().render_markdown()`. The shell gate writes to `mktemp`, compares with `docs/model-host-capabilities.md`, and prints the regeneration command on drift. Add this CI step after the existing config-schema check:

```yaml
- name: model-host capability matrix is current
  run: bash scripts/check-model-host-capabilities.sh
```

- [ ] **Step 5: Run registry, generator, and drift tests**

Run:

```bash
cargo test -p sbproxy-model-host --test capability_contract
cargo run -q -p sbproxy-model-host --bin generate-model-host-capabilities
bash scripts/check-model-host-capabilities.sh
```

Expected: all commands exit 0; the generated document contains each domain and the explicit `stable`, `preview`, `config_only`, and `unsupported` labels.

- [ ] **Step 6: Commit the capability contract**

```bash
git add crates/sbproxy-model-host/src/capabilities.rs crates/sbproxy-model-host/src/bin/generate-model-host-capabilities.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/capability_contract.rs scripts/check-model-host-capabilities.sh docs/model-host-capabilities.md .github/workflows/ci.yml
git commit -m "feat: make model-host capabilities executable"
```

### Task 2: Catalog v2 and deterministic artifact selection

**Files:**
- Create: `crates/sbproxy-model-host/src/artifact_spec.rs`
- Create: `crates/sbproxy-model-host/tests/catalog_v2.rs`
- Modify: `crates/sbproxy-model-host/src/catalog.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Modify: `crates/sbproxy-model-host/data/models.yaml`
- Modify: `crates/sbproxy-model-host/src/manifest.rs`
- Modify: `crates/sbproxy-model-host/src/runtime.rs`
- Modify: `crates/sbproxy/src/main.rs`

**Interfaces:**
- Consumes: `EngineChoice`, `EngineKind`, current catalog IDs, `SourceScheme`, and GPU descriptors.
- Produces: `ArtifactVariant`, `ResolvedArtifact`, `WorkerProfile`, `ResolveArtifactRequest`, `Catalog::resolve_artifact`, `CatalogLoad`, and `CatalogDiagnostic`.

- [ ] **Step 1: Write catalog v2 selection and migration tests**

Cover exact metadata, deterministic catalog order, explicit variant pinning, replicated pin requirements, Apple rejecting a vLLM-only variant, CUDA compute-capability gates, safetensors preference over pickle, pickle opt-in, canonical digest stability, compatible v1 diagnostics, and actionable rejection of incomplete v1 entries.

The central assertion uses these exact request shapes:

```rust,no_run
let resolved = catalog.resolve_artifact(
    &ResolveArtifactRequest {
        model: "coder".into(),
        variant: None,
        engine: EngineChoice::Auto,
        replicas: 1,
        heterogeneous_variants: false,
    },
    &WorkerProfile {
        accelerator: AcceleratorKind::Metal,
        compute_capability: None,
        memory_bytes: 24 * 1024 * 1024 * 1024,
        engines: BTreeSet::from([EngineKind::LlamaCpp]),
    },
)?;
assert_eq!(resolved.variant_id, "q4_k_m");
assert_eq!(resolved.engine, EngineKind::LlamaCpp);
assert_eq!(resolved.files[0].sha256.len(), 64);
```

- [ ] **Step 2: Run catalog tests and verify red**

Run: `cargo test -p sbproxy-model-host --test catalog_v2`

Expected: compilation fails because the v2 artifact types and `resolve_artifact` do not exist.

- [ ] **Step 3: Add exact artifact types and validation**

Implement these serializable types in `artifact_spec.rs`:

```rust,no_run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat { Safetensors, Gguf, Pickle }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorKind { Cpu, Metal, Cuda }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactFile {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactVariant {
    pub id: String,
    pub format: ArtifactFormat,
    pub quant: String,
    pub engines: Vec<EngineKind>,
    pub source: String,
    pub revision: String,
    pub files: Vec<ArtifactFile>,
    pub requirements: VariantRequirements,
    pub stability: SupportLevel,
    pub certification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedArtifact {
    pub catalog_revision: String,
    pub logical_model: String,
    pub variant_id: String,
    pub artifact_digest: String,
    pub format: ArtifactFormat,
    pub quant: String,
    pub engine: EngineKind,
    pub source: String,
    pub revision: String,
    pub files: Vec<ArtifactFile>,
    pub context_length: u64,
    pub license: String,
    pub stability: SupportLevel,
}
```

Validate IDs and path components, require 40-character hexadecimal revisions for `stable` Hugging Face variants, require nonempty exact files, require 64-character SHA-256 values, refuse duplicate file paths and variants, and compute `artifact_digest` from canonical JSON excluding the digest field itself.

- [ ] **Step 4: Extend catalog documents without breaking v1 loading**

Add `schema_version`, `catalog_revision`, `context_length`, `variants`, and `allow_pickle` while retaining the old entry fields as a compatibility projection. `Catalog::from_yaml_with_diagnostics` returns:

```rust,no_run
pub struct CatalogLoad {
    pub catalog: Catalog,
    pub diagnostics: Vec<CatalogDiagnostic>,
}

pub enum CatalogDiagnostic {
    MigratedV1 { model: String },
    PreviewIncomplete { model: String, reason: String },
}
```

V1 entries continue through `Catalog::resolve` for the migration window. They become preview-only for v2 artifact resolution unless the legacy manifest supplies enough exact data to synthesize a complete variant. V2 validation errors must name the model, variant, and missing or malformed field.

- [ ] **Step 5: Replace the optimistic built-in catalog with truthful v2 data**

Set `schema_version: 2` and an immutable `catalog_revision`. Include the pinned Qwen bootstrap GGUF variant as `preview` until the PR 2 real-engine gate passes, using:

```yaml
source: hf:Qwen/Qwen2.5-0.5B-Instruct-GGUF
revision: 9217f5db79a29953eb74d5343926648285ec7e67
path: qwen2.5-0.5b-instruct-q4_k_m.gguf
size_bytes: 491400032
sha256: 74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db
```

Do not carry forward catalog rows whose listed quant does not exist in the named repository. Uncertified rows may be restored only as `preview` variants with the same exact metadata requirements.

- [ ] **Step 6: Update compatibility call sites and run tests**

Update list/show, doctor, fit planning, and runtime helpers to use catalog metadata methods rather than assuming `hf_repo` and `quants` are the whole artifact contract.

Run:

```bash
cargo test -p sbproxy-model-host --test catalog_v2
cargo test -p sbproxy-model-host --lib catalog
cargo test -p sbproxy-model-host --lib runtime
cargo test -p sbproxy --bin sbproxy models
```

Expected: all commands pass; Apple selects no vLLM-only artifact, replicated auto-selection is rejected without heterogeneous opt-in, and built-in resolution returns the exact pinned GGUF.

- [ ] **Step 7: Commit catalog v2**

```bash
git add crates/sbproxy-model-host/src/artifact_spec.rs crates/sbproxy-model-host/src/catalog.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/data/models.yaml crates/sbproxy-model-host/src/manifest.rs crates/sbproxy-model-host/src/runtime.rs crates/sbproxy-model-host/tests/catalog_v2.rs crates/sbproxy/src/main.rs
git commit -m "feat: add deterministic model catalog v2"
```

### Task 3: Deployment revision contract and durable admin store

**Files:**
- Create: `crates/sbproxy-model-host/src/deployment.rs`
- Create: `crates/sbproxy-model-host/src/deployment_store.rs`
- Create: `crates/sbproxy-model-host/tests/deployment_store.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Modify: `crates/sbproxy-model-host/Cargo.toml`

**Interfaces:**
- Consumes: `EngineChoice`, `PullPolicy`, catalog revision, and v2 variant IDs.
- Produces: `DeploymentRevisionDraft`, `DeploymentRevision`, `ModelDeployment`, `DeploymentSourceMode`, and `FileDeploymentRevisionStore::compare_and_swap`.

- [ ] **Step 1: Write failing desired-state and restart tests**

Test all three source modes, canonical digest repeatability, duplicate and invalid deployment rejection, replica pin rules, failed validation preserving the last-good bytes, restart hydration, and stale optimistic revision conflicts. Assert that the store path is the only mutated path and a neighboring `sb.yml` remains byte-for-byte unchanged.

- [ ] **Step 2: Run deployment tests and verify red**

Run: `cargo test -p sbproxy-model-host --test deployment_store`

Expected: compilation fails because the deployment contract and store do not exist.

- [ ] **Step 3: Implement normalized deployment types**

Use these stable shapes:

```rust,no_run
pub const DEPLOYMENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentSourceMode { AdminManaged, FileManaged, ClusterAuthority }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModelDeployment {
    pub model: String,
    #[serde(default)] pub variant: Option<String>,
    #[serde(default)] pub heterogeneous_variants: bool,
    #[serde(default = "one_replica")] pub replicas: u32,
    #[serde(default)] pub required_labels: BTreeMap<String, String>,
    #[serde(default)] pub pull: PullPolicy,
    #[serde(default)] pub warm: bool,
    #[serde(default)] pub keep_alive_secs: Option<u64>,
    #[serde(default)] pub max_concurrency: Option<u32>,
    #[serde(default = "default_queue_timeout_ms")] pub queue_timeout_ms: u64,
    #[serde(default)] pub engine: EngineChoice,
    #[serde(default)] pub rollout: RolloutPolicy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentRevision {
    pub schema_version: u32,
    pub revision: u64,
    pub source_mode: DeploymentSourceMode,
    pub source_revision: String,
    pub catalog_revision: String,
    pub deployments: BTreeMap<String, ModelDeployment>,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentRevisionDraft {
    pub source_mode: DeploymentSourceMode,
    pub source_revision: String,
    pub catalog_revision: String,
    pub deployments: BTreeMap<String, ModelDeployment>,
}
```

Validation requires nonempty IDs, `replicas >= 1`, positive concurrency, a pinned variant for replicated deployments unless `heterogeneous_variants` is true, a nonempty source revision and catalog revision, and a recomputed matching digest.

- [ ] **Step 4: Implement atomic compare-and-swap persistence**

`FileDeploymentRevisionStore` uses `<path>.lock`, `fs2::FileExt::lock_exclusive`, a same-directory temp file, `sync_all`, `rename`, and parent-directory `sync_all`. Expose:

```rust,no_run
impl FileDeploymentRevisionStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DeploymentStoreError>;
    pub fn load(&self) -> Result<Option<DeploymentRevision>, DeploymentStoreError>;
    pub fn compare_and_swap(
        &self,
        expected_revision: Option<u64>,
        candidate: DeploymentRevisionDraft,
    ) -> Result<DeploymentRevision, DeploymentStoreError>;
}
```

The store validates the complete draft before locking, accepts only `AdminManaged`, assigns revision 1 for an empty store or current plus one for an update, computes the content digest after assigning the revision, and returns `Conflict { expected, actual }` without writing on a stale request.

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p sbproxy-model-host --test deployment_store`

Expected: all tests pass, including restart and no-`sb.yml`-rewrite assertions.

```bash
git add crates/sbproxy-model-host/Cargo.toml crates/sbproxy-model-host/src/deployment.rs crates/sbproxy-model-host/src/deployment_store.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/deployment_store.rs Cargo.lock
git commit -m "feat: persist admin-managed deployment revisions"
```

### Task 4: Durable operation jobs

**Files:**
- Create: `crates/sbproxy-model-host/src/jobs.rs`
- Create: `crates/sbproxy-model-host/tests/operation_jobs.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Modify: `crates/sbproxy-model-host/Cargo.toml`

**Interfaces:**
- Consumes: canonical subject IDs and cache state transitions.
- Produces: `OperationJob`, `OperationState`, `OperationProgress`, and `FileJobStore`.

- [ ] **Step 1: Add failing state-machine and durability tests**

Test stable ULID IDs, allowed pull transitions, rejected backward transitions, terminal timestamps, redacted errors, atomic restart hydration, progress persistence, and pruning oldest terminal jobs without deleting active jobs.

- [ ] **Step 2: Run the job tests and verify red**

Run: `cargo test -p sbproxy-model-host --test operation_jobs`

Expected: compilation fails because job types are absent.

- [ ] **Step 3: Implement the durable job model**

Use these states and methods:

```rust,no_run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Downloading,
    Verifying,
    Ready,
    Failed,
    Deleting,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationProgress {
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub current_file: Option<String>,
}

impl FileJobStore {
    pub fn open(root: impl Into<PathBuf>, terminal_history_limit: usize) -> Result<Self, JobError>;
    pub fn create(&self, kind: OperationKind, subject: String) -> Result<OperationJob, JobError>;
    pub fn transition(&self, id: &str, next: OperationState, progress: OperationProgress, error: Option<&str>) -> Result<OperationJob, JobError>;
    pub fn get(&self, id: &str) -> Result<Option<OperationJob>, JobError>;
    pub fn list(&self) -> Result<Vec<OperationJob>, JobError>;
}
```

Store one JSON file per job under `jobs/`, use atomic replacement, replace bearer-looking strings in persisted errors with `[REDACTED]`, and prune only terminal jobs after a terminal transition.

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p sbproxy-model-host --test operation_jobs`

Expected: all tests pass and reopen returns identical terminal jobs.

```bash
git add crates/sbproxy-model-host/Cargo.toml crates/sbproxy-model-host/src/jobs.rs crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/tests/operation_jobs.rs Cargo.lock
git commit -m "feat: add durable model operation jobs"
```

### Task 5: Atomic content-addressed artifact manager

**Files:**
- Create: `crates/sbproxy-model-host/src/artifact/mod.rs`
- Create: `crates/sbproxy-model-host/src/artifact/cache.rs`
- Create: `crates/sbproxy-model-host/src/artifact/http.rs`
- Create: `crates/sbproxy-model-host/tests/artifact_manager.rs`
- Modify: `crates/sbproxy-model-host/src/lib.rs`
- Modify: `crates/sbproxy-model-host/src/weights.rs`
- Modify: `crates/sbproxy-model-host/Cargo.toml`

**Interfaces:**
- Consumes: `ResolvedArtifact`, `FileJobStore`, resolved source credential, and pull intent.
- Produces: `ArtifactManager::ensure`, `ReadyArtifact`, `ArtifactTransport`, `HttpArtifactTransport`, `ArtifactObserver`, and cache inspection.

- [ ] **Step 1: Add failing atomicity, cache-hit, and concurrency tests**

Use an in-memory fake `ArtifactTransport` with a shared request counter. Cover a successful multi-file pull, no ready path before verification, zero-request verified cache hit, tampered ready snapshot failure, digest mismatch cleanup, concurrent managers sharing one cache, stable job progress, and vLLM snapshot layout preserving relative filenames.

- [ ] **Step 2: Run the artifact tests and verify red**

Run: `cargo test -p sbproxy-model-host --test artifact_manager`

Expected: compilation fails because `ArtifactManager`, `ArtifactTransport`, and `ReadyArtifact` do not exist.

- [ ] **Step 3: Implement cache layout and lock guard**

The root layout is fixed:

```text
<root>/blobs/sha256/<file-sha256>
<root>/snapshots/<artifact-digest>/<relative-file-path>
<root>/metadata/<artifact-digest>.json
<root>/partials/<artifact-digest>/<relative-file-path>.part
<root>/partials/<artifact-digest>/<relative-file-path>.resume.json
<root>/locks/<artifact-digest>.lock
<root>/jobs/<job-id>.json
```

Reject absolute paths, `..`, backslashes, empty components, and duplicate paths before touching disk. Acquire an exclusive `fs2` lock in `spawn_blocking`; keep the file handle alive until cache-hit validation or finalization completes. Build snapshots in `snapshots/.staging-<digest>-<pid>`, hard-link verified blobs when supported, copy only on cross-device or unsupported-link errors, write `artifact.json`, sync, and atomically rename the directory.

- [ ] **Step 4: Implement the manager and transport seam**

Use a dyn-safe async transport and a credential whose `Debug` and `Display` are always redacted:

```rust,no_run
#[async_trait::async_trait]
pub trait ArtifactTransport: Send + Sync {
    async fn get(&self, request: TransportRequest) -> Result<TransportResponse, ArtifactError>;
}

pub struct TransportRequest {
    pub url: String,
    pub offset: u64,
    pub if_range: Option<String>,
    pub credential: Option<SourceCredential>,
}

pub struct TransportResponse {
    pub disposition: ResponseDisposition,
    pub etag: Option<String>,
    pub total_size: Option<u64>,
    pub body: Pin<Box<dyn Stream<Item = Result<Bytes, ArtifactError>> + Send>>,
}

pub trait ArtifactObserver: Send + Sync {
    fn on_job(&self, job: &OperationJob);
}

pub struct AcquisitionContext {
    pub intent: PullIntent,
    pub network: NetworkPolicy,
    pub pull_policy: PullPolicy,
    pub credential: Option<SourceCredential>,
}

impl ArtifactManager {
    pub async fn ensure(
        &self,
        artifact: &ResolvedArtifact,
        context: AcquisitionContext,
    ) -> Result<ReadyArtifact, ArtifactError>;
    pub fn inspect(&self, artifact_digest: &str) -> Result<ArtifactCacheState, ArtifactError>;
}
```

The cache-hit path hashes every declared file and compares its size before returning. Pulls transition the same durable job through queued, downloading, verifying, and ready. While bytes advance, update the durable progress record and call `ArtifactObserver::on_job` at phase boundaries, completion, and no less often than every two seconds. Any error transitions to failed, removes staging, preserves a safe resumable partial when applicable, and never creates ready metadata.

- [ ] **Step 5: Implement the reqwest transport**

`HttpArtifactTransport` follows redirects, uses `Range: bytes=<offset>-` plus `If-Range` when resuming, accepts only 200 for replacement and 206 for append, captures ETag and total length, and adds a bearer header only from `SourceCredential`. Error messages include repo, revision, and file but never headers or credentials.

- [ ] **Step 6: Route legacy weight helpers through the safe preview path**

Keep `weights::cache_file` for the compatibility metadata reader. Change `ensure_weight_file` to call `ArtifactManager::ensure_legacy_file`, which uses the same lock, partial, verification, and atomic-finalization machinery. A legacy call with a digest is verified; a call without one records `preview_unpinned` trust metadata and may be consumed only by the documented v1 compatibility path, never by a managed v2 launch.

- [ ] **Step 7: Run focused tests and commit**

Run:

```bash
cargo test -p sbproxy-model-host --test artifact_manager
cargo test -p sbproxy-model-host --features weights --lib weights
```

Expected: all tests pass, cache-hit request count remains zero, digest mismatches have no ready snapshot, and concurrent callers share one finalized artifact.

```bash
git add crates/sbproxy-model-host/Cargo.toml crates/sbproxy-model-host/src/artifact crates/sbproxy-model-host/src/lib.rs crates/sbproxy-model-host/src/weights.rs crates/sbproxy-model-host/tests/artifact_manager.rs Cargo.lock
git commit -m "feat: build atomic verified model artifacts"
```

### Task 6: Resume, pull policy, file sources, credentials, and offline guarantees

**Files:**
- Create: `crates/sbproxy-model-host/tests/artifact_policy.rs`
- Modify: `crates/sbproxy-model-host/src/artifact/mod.rs`
- Modify: `crates/sbproxy-model-host/src/artifact/cache.rs`
- Modify: `crates/sbproxy-model-host/src/artifact/http.rs`
- Modify: `crates/sbproxy-model-host/src/pull.rs`
- Modify: `crates/sbproxy-model-host/src/supply_chain.rs`

**Interfaces:**
- Consumes: `PullPolicy`, `ArtifactFormat`, `SourceScheme`, partial metadata, and explicit operator pull intent.
- Produces: `PullIntent`, `NetworkPolicy`, deterministic pull plans, actionable `ManualArtifactMissing`, `OfflineArtifactMissing`, `DigestMismatch`, and `PickleRefused` errors.

- [ ] **Step 1: Write failing resume and denied-network tests**

Cover safe partial append, changed ETag forcing a clean restart, mismatched recorded URL forcing restart, exact-size 416 completion, two-second advancing-progress publication, `manual` cache hit, missing manual artifact with zero transport calls, `file:` source with zero transport calls, denied network with zero transport calls, explicit CLI pull overriding manual, on-boot selecting only on-boot entries, on-demand acquisition, gated credential use without serialization, safetensors preference, pickle-only refusal, opted-in pickle scan, and tampered bytes failing before any launch seam is invoked.

- [ ] **Step 2: Run policy tests and verify red**

Run: `cargo test -p sbproxy-model-host --test artifact_policy`

Expected: new policy and resume cases fail against the basic manager.

- [ ] **Step 3: Implement explicit acquisition intent**

```rust,no_run
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullIntent {
    Startup,
    Runtime,
    Explicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    Allowed,
    Denied,
}
```

After a verified cache check, enforce:

- `Runtime + Manual` returns `ManualArtifactMissing`.
- `Startup` selects only `OnBoot`.
- `Explicit` permits any pull policy.
- `file:` always verifies and stages local bytes without constructing an HTTP request.
- `NetworkPolicy::Denied` returns `OfflineArtifactMissing` before transport on an HTTP cache miss.

- [ ] **Step 4: Persist and validate resume metadata**

Store URL, ETag, expected digest, expected size, and current byte count beside each partial. Resume only when all immutable fields match. Append only on a consistent 206. Treat 200, a changed ETag, or inconsistent total size as replacement: truncate the partial, rewrite metadata, and hash only the new body. Never combine bytes from two source generations.

- [ ] **Step 5: Enforce format and credential safety**

Variant resolution filters pickle unless the logical model opts in. On the opt-in path, run `scan_pickle` before blob finalization. `SourceCredential` owns resolved secret bytes, zeroes them on drop, exposes only a crate-private `bearer()` accessor, and serializes nowhere. Add assertions that `format!("{credential:?}")`, job JSON, and ready metadata contain neither the secret nor its reference.

- [ ] **Step 6: Run tests and commit**

Run:

```bash
cargo test -p sbproxy-model-host --test artifact_policy
cargo test -p sbproxy-model-host --lib pull
cargo test -p sbproxy-model-host --lib supply_chain
```

Expected: all tests pass and every denied-network/manual/file assertion observes zero transport calls.

```bash
git add crates/sbproxy-model-host/src/artifact crates/sbproxy-model-host/src/pull.rs crates/sbproxy-model-host/src/supply_chain.rs crates/sbproxy-model-host/tests/artifact_policy.rs
git commit -m "feat: enforce model artifact supply-chain policy"
```

### Task 7: Cache budget and safe garbage collection

**Files:**
- Create: `crates/sbproxy-model-host/src/artifact/gc.rs`
- Create: `crates/sbproxy-model-host/tests/artifact_gc.rs`
- Modify: `crates/sbproxy-model-host/src/artifact/mod.rs`
- Modify: `crates/sbproxy-model-host/src/artifact/cache.rs`

**Interfaces:**
- Consumes: ready metadata, artifact last-access times, lock state, active jobs, resident and pinned digest sets, and byte budget.
- Produces: `ArtifactManager::enforce_budget` and `GcReport`.

- [ ] **Step 1: Write failing collection tests**

Create three ready artifacts with deterministic last-access timestamps. Verify LRU eviction to budget, shared blob preservation, and skips for resident, pinned, externally locked, downloading, verifying, and deleting artifacts. Verify a budget smaller than all protected artifacts returns a nonfatal `budget_unsatisfied_bytes` count.

- [ ] **Step 2: Run GC tests and verify red**

Run: `cargo test -p sbproxy-model-host --test artifact_gc`

Expected: compilation fails because `enforce_budget` and `GcReport` are absent.

- [ ] **Step 3: Implement protected LRU collection**

```rust,no_run
#[derive(Debug, Clone, Default)]
pub struct CacheProtection {
    pub resident: BTreeSet<String>,
    pub pinned: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcReport {
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub reclaimed_bytes: u64,
    pub deleted_artifacts: Vec<String>,
    pub skipped_artifacts: BTreeMap<String, String>,
    pub budget_unsatisfied_bytes: u64,
}
```

Sort candidates by last access then digest. Try-lock each candidate, re-read metadata under the lock, skip active jobs and protected digests, transition a deletion job through deleting/deleted, remove snapshot and metadata, and remove a blob only when no remaining ready manifest references it.

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p sbproxy-model-host --test artifact_gc`

Expected: all tests pass and no protected artifact is deleted.

```bash
git add crates/sbproxy-model-host/src/artifact/gc.rs crates/sbproxy-model-host/src/artifact/mod.rs crates/sbproxy-model-host/src/artifact/cache.rs crates/sbproxy-model-host/tests/artifact_gc.rs
git commit -m "feat: enforce safe model cache budgets"
```

### Task 8: Runtime handoff and exact pull-policy enforcement

**Files:**
- Create: `crates/sbproxy-model-host/tests/runtime_artifacts.rs`
- Modify: `crates/sbproxy-model-host/src/runtime.rs`
- Modify: `crates/sbproxy-model-host/src/launch.rs`
- Modify: `crates/sbproxy-model-host/src/config.rs`
- Modify: `crates/sbproxy-core/src/server/model_host.rs`
- Modify: `crates/sbproxy-core/Cargo.toml`

**Interfaces:**
- Consumes: `Catalog::resolve_artifact`, `ArtifactManager`, `PullIntent::Startup` and `Runtime`, plus existing `EngineLauncher`.
- Produces: `ModelHostRuntime::warm_on_boot`, exact prelaunch acquisition, and local-path launch specs.

- [ ] **Step 1: Write failing prelaunch contract tests**

Use a fake artifact transport and fake launcher that records `LaunchSpec`. Assert:

- on-boot warming downloads without calling the launcher;
- on-demand pulls once before the launcher receives a spec;
- missing manual and denied-network artifacts return named errors and call neither transport nor launcher;
- digest mismatch calls no launcher and has no repository fallback;
- llama.cpp receives `--model <verified-file>` with no `--hf-repo`;
- vLLM receives `serve <verified-snapshot>` rather than `serve <repo>`;
- a custom catalog file changes both planning and live resolution.

- [ ] **Step 2: Run runtime artifact tests and verify red**

Run: `cargo test -p sbproxy-model-host --test runtime_artifacts`

Expected: tests fail because the runtime still guesses a repo/quant and may fall back to engine download.

- [ ] **Step 3: Inject the shared artifact service**

Add `ModelHostRuntime::with_artifact_manager(Arc<ArtifactManager>)` and store the manager as an optional field so existing pure runtime construction remains source-compatible. A v2 deployment without the manager returns `RuntimeError::Artifact("managed artifact service is not configured")`. Resolve one `ResolvedArtifact` before metadata and fit planning, call the manager with `AcquisitionContext`, and derive fit quant, engine, revision, and files only from that artifact. Preserve the v1 compatibility path as preview with a warning; do not describe it as verified managed acquisition.

- [ ] **Step 4: Retarget both managed engines to verified paths**

Add:

```rust,no_run
pub fn vllm_use_local_snapshot(args: &mut [String], snapshot: &Path) {
    if args.first().map(String::as_str) == Some("serve") && args.len() > 1 {
        args[1] = snapshot.display().to_string();
    }
}
```

The llama.cpp helper receives the exact declared GGUF file from `ReadyArtifact`. Remove the digest-failure fallback to `--hf-repo` or `--hf-file`. A failure to produce verified local bytes is a `RuntimeError::Artifact` and happens before residency admission and engine launch.

- [ ] **Step 5: Load custom catalogs once in core and warm on boot**

Resolve `catalog_file` relative to the config file directory, parse it once, use the same `Arc<Catalog>` for doctor/runtime/artifact planning, and make startup warming complete before the host reports the affected deployments warm. `warm_on_boot` must not allocate a GPU port or construct an engine launcher.

- [ ] **Step 6: Run tests and commit**

Run:

```bash
cargo test -p sbproxy-model-host --test runtime_artifacts
cargo test -p sbproxy-model-host --lib runtime
cargo test -p sbproxy-model-host --lib launch
cargo test -p sbproxy-core model_host
```

Expected: all tests pass and every managed launch spec names only verified local bytes.

```bash
git add crates/sbproxy-model-host/src/runtime.rs crates/sbproxy-model-host/src/launch.rs crates/sbproxy-model-host/src/config.rs crates/sbproxy-model-host/tests/runtime_artifacts.rs crates/sbproxy-core/src/server/model_host.rs crates/sbproxy-core/Cargo.toml Cargo.lock
git commit -m "feat: require verified artifacts before model launch"
```

### Task 9: End-to-end `sbproxy models pull`

**Files:**
- Create: `crates/sbproxy/tests/models_pull_cli.rs`
- Modify: `crates/sbproxy/src/main.rs`
- Modify: `crates/sbproxy/Cargo.toml`
- Modify: `crates/sbproxy-model-host/src/pull.rs`

**Interfaces:**
- Consumes: config-relative catalog loading, secret resolver, worker-independent artifact resolution, `ArtifactManager`, `FileJobStore`, and GC.
- Produces: `sbproxy models pull -f <sb.yml> [--model <name>] [--all] [--offline] [--format text|json]`.

- [ ] **Step 1: Add failing clap and handler tests**

Assert exact parsing, mutual exclusion of `--model` and `--all`, required `-f` unless `--catalog-file` plus `--cache-dir` are supplied, stable JSON fields, no GPU or engine probe, and nonzero handler results for resolution, policy, network, and digest errors.

- [ ] **Step 2: Add failing real-binary mock HTTP tests**

`models_pull_cli.rs` starts a minimal range-capable `TcpListener`, writes a catalog/config fixture, and launches `env!("CARGO_BIN_EXE_sbproxy")`. Cover:

1. first pull downloads and returns a ready job;
2. second pull performs zero additional HTTP requests;
3. two child processes racing one artifact produce one ready snapshot and one body download;
4. interrupted first pull resumes with `Range`;
5. changed ETag restarts from byte zero;
6. corrupt ready bytes fail with a digest message and nonzero exit;
7. manual and file-source denied-network runs make no connection;
8. a bearer token reaches the mock `Authorization` header but is absent from stdout, stderr, jobs, and metadata.

- [ ] **Step 3: Run CLI tests and verify red**

Run:

```bash
cargo test -p sbproxy --bin sbproxy models_pull
cargo test -p sbproxy --test models_pull_cli
```

Expected: clap rejects `pull` as an unknown models subcommand.

- [ ] **Step 4: Implement the CLI adapter**

Add:

```rust,no_run
Pull(ModelsPullArgs),

struct ModelsPullArgs {
    config: Option<PathBuf>,
    catalog_file: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
    model: Option<String>,
    all: bool,
    offline: bool,
    format: OutputFormat,
}
```

When `-f` is present, load and merge `serve:` blocks, resolve `catalog_file` relative to the config, install the config secret resolver, inherit cache settings, and select configured models plus manifest `on_boot` entries. `--model` selects exactly one logical name, `--all` selects every catalog entry, and the default pulls configured plus on-boot entries. Resolve source credentials immediately before acquisition. Attach a CLI `ArtifactObserver` that renders phase and byte progress to stderr no less often than every two seconds while work advances. After successful pulls, enforce `cache_budget_gib` and include the GC report in JSON.

Stable JSON is:

```json
{
  "schema_version": 1,
  "catalog_revision": "...",
  "cache_dir": "...",
  "jobs": [{"id":"...","subject":"...","state":"ready","progress":{"completed_bytes":1,"total_bytes":1,"current_file":null}}],
  "gc": {"before_bytes":1,"after_bytes":1,"reclaimed_bytes":0,"deleted_artifacts":[],"skipped_artifacts":{},"budget_unsatisfied_bytes":0}
}
```

- [ ] **Step 5: Make list/show report v2 truth**

`models list` shows logical model, selected compatible variant, format, engine, stability, exact size, cache state, and fit. `models show` includes catalog revision and every exact variant. Legacy incomplete entries show `preview-incomplete` with their migration diagnostic, never `cached` based on a nonempty directory heuristic.

- [ ] **Step 6: Run CLI tests and commit**

Run:

```bash
cargo test -p sbproxy --bin sbproxy models
cargo test -p sbproxy --test models_pull_cli
```

Expected: all tests pass; racing processes issue one artifact body download; second pull is a verified zero-network hit.

```bash
git add crates/sbproxy/Cargo.toml crates/sbproxy/src/main.rs crates/sbproxy/tests/models_pull_cli.rs crates/sbproxy-model-host/src/pull.rs Cargo.lock
git commit -m "feat: add atomic models pull workflow"
```

### Task 10: Public docs, examples, schemas, and generated contracts

**Files:**
- Modify: `examples/model-manifest/models.yaml`
- Modify: `examples/model-manifest/sb.yml`
- Modify: `examples/model-manifest/README.md`
- Modify: `docs/model-host.md`
- Modify: `docs/self-hosting.md`
- Modify: `docs/troubleshooting.md`
- Modify: `docs/README.md`
- Modify: `schemas/ai-proxy-provider.schema.json`
- Modify: `docs/model-host-capabilities.md`
- Modify: `docs/llms-full.txt`

**Interfaces:**
- Consumes: stable CLI JSON, generated capability registry, catalog v2 schema, cache layout, and exact errors.
- Produces: runnable operator instructions, migration guidance, troubleshooting, and current generated artifacts.

- [ ] **Step 1: Add documentation and example smoke assertions**

Extend the existing examples/schema gates so the catalog v2 example parses, resolves its pinned artifact, `models pull --offline` on a prepared file source performs no network, and all documented CLI flags appear in `--help`.

- [ ] **Step 2: Run docs/example checks and verify red**

Run:

```bash
bash scripts/examples-smoke.sh
bash scripts/check-config-schema.sh
bash scripts/check-model-host-capabilities.sh
./scripts/regen-llms-full.sh --check
```

Expected: at least the generated matrix, schemas, or flattened docs report drift.

- [ ] **Step 3: Write the operator documentation**

Document:

- catalog v2 logical models and exact variants;
- v1 migration diagnostics and preview compatibility;
- `pull` selection modes, JSON, progress, exit behavior, and no-GPU guarantee;
- content-addressed layout, verified cache hits, resume semantics, and safe GC;
- manual, on-boot, on-demand, file, offline, pickle, and credential behavior;
- admin-managed deployment persistence without `sb.yml` rewrites;
- current capability status and explicit PR 2/PR 3/PR 6/PR 7 boundaries;
- recovery for digest mismatch, stale partials, disk pressure, denied network, gated repos, and lock contention.

The example must use an immutable revision and real SHA-256/size metadata. Any local-file example must include commands that produce the exact digest rather than a zero or symbolic digest.

- [ ] **Step 4: Regenerate checked-in artifacts**

Run:

```bash
cargo run -q -p sbproxy-ai --bin generate-ai-provider-schema > /tmp/ai-proxy-provider.schema.json
cp /tmp/ai-proxy-provider.schema.json schemas/ai-proxy-provider.schema.json
cargo run -q -p sbproxy-model-host --bin generate-model-host-capabilities > /tmp/model-host-capabilities.md
cp /tmp/model-host-capabilities.md docs/model-host-capabilities.md
./scripts/regen-llms-full.sh
```

The generation commands are mechanical outputs from typed sources. Inspect the diffs and verify no stable claim lacks executable evidence.

- [ ] **Step 5: Run docs and schema gates**

Run:

```bash
bash scripts/examples-smoke.sh
bash scripts/check-config-schema.sh
bash scripts/check-model-host-capabilities.sh
./scripts/regen-llms-full.sh --check
```

Expected: every command exits 0.

- [ ] **Step 6: Commit documentation**

```bash
git add examples/model-manifest docs/model-host.md docs/self-hosting.md docs/troubleshooting.md docs/README.md docs/model-host-capabilities.md docs/llms-full.txt schemas/ai-proxy-provider.schema.json
git commit -m "docs: document verified model artifact operations"
```

### Task 11: Full verification, review, and PR publication

**Files:**
- Modify only files required by failures found during verification.

**Interfaces:**
- Consumes: all PR 1 code, examples, generated outputs, and Linear acceptance criteria.
- Produces: a clean branch, pushed commits, a large draft PR, and evidence-linked Linear updates.

- [ ] **Step 1: Run formatting and targeted supply-chain gates**

Run:

```bash
cargo fmt --all -- --check
cargo test -p sbproxy-model-host --all-features
cargo test -p sbproxy --test models_pull_cli
bash scripts/check-model-host-capabilities.sh
bash scripts/check-config-schema.sh
./scripts/regen-llms-full.sh --check
```

Expected: every command exits 0.

- [ ] **Step 2: Run the complete repository gate**

Run:

```bash
cargo build --workspace
cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci
cargo test --workspace --exclude sbproxy-e2e --locked --doc
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
```

Expected: build succeeds, all non-e2e tests and doctests pass, clippy emits no warnings, and rustdoc emits no warnings. Run socket-using nextest outside the filesystem sandbox if loopback access is denied.

- [ ] **Step 3: Audit the exact acceptance matrix**

Record command evidence for:

- registry coverage and generated matrix drift;
- catalog v2 exact selection on Metal, CUDA, and replicated requests;
- cache restart, zero-network hit, cross-process race, resume, ETag replacement, and digest mismatch;
- manual, file, offline, on-boot, on-demand, credential redaction, and pickle refusal;
- deployment CAS restart and no `sb.yml` rewrite;
- CLI first pull, second no-op, stable JSON, corruption failure, and no engine launch.

Keep SH-06 engine-specific acceptance open only if PR 2 is still required to prove a real engine consumes the staged path. Do not close a Linear issue on unit evidence that does not satisfy its end-to-end wording.

- [ ] **Step 4: Inspect branch scope and generated-file hygiene**

Run:

```bash
git status --short
git diff --check origin/main...HEAD
git log --oneline origin/main..HEAD
git diff --stat origin/main...HEAD
```

Expected: worktree is clean, `git diff --check` exits 0, commits match the checkpoints above, and no unrelated primary-checkout files appear.

- [ ] **Step 5: Push and open the PR**

```bash
git push -u origin rickcrawford/wor-1835-foundations
gh pr create --draft --base main --head rickcrawford/wor-1835-foundations --title "Self-hosted OpenRouter foundations: catalog, artifacts, and pull" --body-file /tmp/wor-1835-pr1.md
```

The PR body lists the Linear issues, architecture, stable/preview boundaries, migration notes, test evidence, and the explicit note that GCP certification runs in PR 7.

- [ ] **Step 6: Update Linear with evidence**

Move only acceptance criteria proven by this PR to completed state, link the PR and exact test commands, and leave engine-live or GCP-live criteria open for their owning PR. Add one progress comment to WOR-1835 summarizing PR 1 scope and the next branch base.

## Self-Review Record

- Spec coverage: all PR 1 deliverables map to Tasks 1 through 10; Task 11 maps each exit criterion to command evidence.
- Scope boundary: live GCP validation is explicitly reserved for PR 7, and admin UI work remains PR 6 while its durable ownership contract lands here.
- Placeholder scan: the plan contains no unresolved implementation marker, symbolic digest, or unnamed error-handling step.
- Type consistency: `ResolvedArtifact`, `ArtifactManager`, `FileJobStore`, `DeploymentRevision`, `PullIntent`, `NetworkPolicy`, `ReadyArtifact`, and capability types use the same names across producers and consumers.
- Truthfulness: v1 compatibility is preview, stable variants require exact immutable metadata, and Linear issues remain open when a real engine or cloud environment is still needed.
