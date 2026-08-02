use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use jsonschema::{Draft, JSONSchema};
use sbproxy_config::{
    is_full_commit_sha, materialize_git_tree, redact_repo, BundleBodyMode, BundleHook,
    BundleHookKind, BundleManifest, BundleManifestError, BundleRuntime, BundleSourceConfig,
    ConfigSourceError, ExtensionBundlesConfig, FetchContext, GitTreeRequest,
    MAX_BUNDLE_MANIFEST_BYTES,
};
use sbproxy_plugin::{
    ExtensionBodyMode, ExtensionBundleRecord, ExtensionDispatch, ExtensionExecution,
    ExtensionHookKind, ExtensionHookRecord, ExtensionInventoryScope, ExtensionInventorySnapshot,
    ExtensionInventorySummary, ExtensionLoadRecord, ExtensionRegistrationSource, ExtensionRuntime,
    ExtensionScopeMode, ExtensionState, EXTENSION_INVENTORY_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};

use super::registry::{lookup, BundleProvenance, BundleRegistry, LoadedBundleHook};

/// Largest executable artifact accepted by the bundle loader.
pub const MAX_BUNDLE_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

/// A bounded, sanitized candidate-loading failure.
pub struct BundleLoadError {
    stage: &'static str,
    detail: String,
}

impl BundleLoadError {
    fn new(stage: &'static str, detail: impl AsRef<str>) -> Self {
        let prefix_len = "bundle.: ".len() + stage.len();
        Self {
            stage,
            detail: sanitize_detail(detail.as_ref(), 512usize.saturating_sub(prefix_len)),
        }
    }
}

impl std::fmt::Display for BundleLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "bundle.{}: {}", self.stage, self.detail)
    }
}

impl std::fmt::Debug for BundleLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for BundleLoadError {}

impl From<ConfigSourceError> for BundleLoadError {
    fn from(error: ConfigSourceError) -> Self {
        let detail = match error {
            ConfigSourceError::Invalid(message) if message.contains("credential") => {
                "configured Git credential was not resolved"
            }
            ConfigSourceError::Invalid(_) => "Git source request is invalid",
            ConfigSourceError::MissingGitBinary(_) => "Git executable is unavailable",
            ConfigSourceError::Clone(_) => "Git source is unreachable",
            ConfigSourceError::Timeout(_) => "Git source timed out",
            ConfigSourceError::RevisionMismatch(_) => "Git revision verification failed",
            ConfigSourceError::Signature(_) => "Git signature verification failed",
            ConfigSourceError::Read(_) => "Git tree could not be read",
            ConfigSourceError::Merge(_) | ConfigSourceError::RecursionLimit => {
                "Git source materialization failed"
            }
        };
        Self::new("source", detail)
    }
}

pub(crate) fn sanitize_detail(detail: &str, maximum: usize) -> String {
    let mut safe = detail
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    if safe.len() > maximum {
        let mut boundary = maximum;
        while !safe.is_char_boundary(boundary) {
            boundary -= 1;
        }
        safe.truncate(boundary);
    }
    safe
}

/// A complete immutable registry built before pipeline publication.
pub struct DynamicBundleRegistry {
    hooks: BTreeMap<(BundleHookKind, String), Arc<LoadedBundleHook>>,
    inventory: ExtensionInventorySnapshot,
}

impl std::fmt::Debug for DynamicBundleRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicBundleRegistry")
            .field("hooks", &self.hooks.len())
            .field("inventory", &self.inventory)
            .finish()
    }
}

impl DynamicBundleRegistry {
    /// Load an immutable candidate with the production Git implementation.
    ///
    /// This convenience path supports local sources and credential-free Git
    /// sources. A declared credential fails closed because no secret resolver
    /// is consulted here. Pipeline compilation should use
    /// [`Self::load_with_context`] after resolving credentials.
    ///
    /// # Errors
    ///
    /// Returns a bounded load error when any source, manifest, artifact,
    /// digest, schema, or registration is invalid. No partial registry is
    /// returned and no global registry is changed.
    pub fn load(
        config: &ExtensionBundlesConfig,
        base_dir: &Path,
        reserved_names: &BTreeSet<(BundleHookKind, String)>,
    ) -> Result<Arc<Self>, BundleLoadError> {
        let context = FetchContext::with_git_binary();
        Self::load_with_context(config, base_dir, reserved_names, &context)
    }

    /// Load an immutable candidate with injected Git and credential context.
    ///
    /// Sources retain declaration order. `bundles_dir` is processed first,
    /// then each `sources` item. Bundle directories and hook declarations are
    /// processed lexically inside each source.
    ///
    /// # Errors
    ///
    /// Returns a bounded load error under the same all-or-nothing contract as
    /// [`Self::load`].
    pub fn load_with_context(
        config: &ExtensionBundlesConfig,
        base_dir: &Path,
        reserved_names: &BTreeSet<(BundleHookKind, String)>,
        fetch_context: &FetchContext,
    ) -> Result<Arc<Self>, BundleLoadError> {
        config
            .validate()
            .map_err(|error| BundleLoadError::new("config", error.to_string()))?;
        let mut candidate = Candidate::new(reserved_names);
        let mut source_index = 0u32;

        if let Some(path) = config.bundles_dir.as_deref() {
            let path = resolve_local_path(base_dir, path);
            candidate.load_source_root(
                &path,
                BundleProvenance::Directory { source_index },
                false,
            )?;
            source_index += 1;
        }

        for source in &config.sources {
            match source {
                BundleSourceConfig::Directory { path } => {
                    let path = resolve_local_path(base_dir, path);
                    candidate.load_source_root(
                        &path,
                        BundleProvenance::Directory { source_index },
                        false,
                    )?;
                }
                BundleSourceConfig::Git {
                    repo,
                    revision,
                    path,
                    credential,
                    verify_signature,
                    timeout_secs,
                    ..
                } => {
                    if !is_full_commit_sha(revision) && !verify_signature {
                        return Err(BundleLoadError::new(
                            "source",
                            "Git revision is mutable; use a full commit SHA or verified signature",
                        ));
                    }
                    validate_relative_path(path, "Git bundle source")?;
                    let request = GitTreeRequest {
                        repo,
                        revision: Some(revision),
                        credential: credential.as_deref(),
                        verify_signature: *verify_signature,
                        timeout: Duration::from_secs(*timeout_secs),
                        fetch_context,
                    };
                    materialize_git_tree(request, |tree| {
                        let checkout = canonical_root(tree.root(), "Git checkout")?;
                        let source_root = tree.root().join(path);
                        let source_root = source_root.canonicalize().map_err(|_| {
                            BundleLoadError::new("source", "Git bundle directory is unavailable")
                        })?;
                        if !source_root.starts_with(&checkout) {
                            return Err(BundleLoadError::new(
                                "path",
                                "Git bundle directory escapes the verified checkout",
                            ));
                        }
                        candidate.load_canonical_source_root(
                            &source_root,
                            BundleProvenance::Git {
                                source_index,
                                repo: redact_repo(&tree.revision().repo),
                                reference: tree.revision().reference.clone(),
                                commit: tree.revision().commit.clone(),
                            },
                            true,
                        )
                    })?;
                }
            }
            source_index += 1;
        }

        candidate.finish().map(Arc::new)
    }

    /// Return the deterministic preliminary inventory for this candidate.
    #[must_use]
    pub const fn inventory(&self) -> &ExtensionInventorySnapshot {
        &self.inventory
    }
}

impl BundleRegistry for DynamicBundleRegistry {
    fn policy(&self, type_name: &str) -> Option<&LoadedBundleHook> {
        lookup(&self.hooks, BundleHookKind::Policy, type_name)
    }

    fn transform(&self, type_name: &str) -> Option<&LoadedBundleHook> {
        lookup(&self.hooks, BundleHookKind::Transform, type_name)
    }

    fn action(&self, type_name: &str) -> Option<&LoadedBundleHook> {
        lookup(&self.hooks, BundleHookKind::Action, type_name)
    }

    fn proxy_wasm_filter(&self, type_name: &str) -> Option<&LoadedBundleHook> {
        lookup(&self.hooks, BundleHookKind::ProxyWasm, type_name)
    }

    fn ai_hooks(&self, kind: BundleHookKind) -> Vec<&LoadedBundleHook> {
        if !is_ai_kind(kind) {
            return Vec::new();
        }
        self.hooks
            .iter()
            .filter_map(|((hook_kind, _), hook)| (*hook_kind == kind).then_some(hook.as_ref()))
            .collect()
    }
}

struct Candidate<'a> {
    reserved_names: &'a BTreeSet<(BundleHookKind, String)>,
    hooks: BTreeMap<(BundleHookKind, String), Arc<LoadedBundleHook>>,
    bundles: Vec<ExtensionBundleRecord>,
    inventory_hooks: Vec<ExtensionHookRecord>,
}

impl<'a> Candidate<'a> {
    fn new(reserved_names: &'a BTreeSet<(BundleHookKind, String)>) -> Self {
        Self {
            reserved_names,
            hooks: BTreeMap::new(),
            bundles: Vec::new(),
            inventory_hooks: Vec::new(),
        }
    }

    fn load_source_root(
        &mut self,
        root: &Path,
        provenance: BundleProvenance,
        require_digest: bool,
    ) -> Result<(), BundleLoadError> {
        let root = canonical_root(root, "directory source")?;
        self.load_canonical_source_root(&root, provenance, require_digest)
    }

    fn load_canonical_source_root(
        &mut self,
        root: &Path,
        provenance: BundleProvenance,
        require_digest: bool,
    ) -> Result<(), BundleLoadError> {
        let mut entries = std::fs::read_dir(root)
            .map_err(|_| BundleLoadError::new("source", "bundle directory is unreadable"))?
            .map(|entry| {
                entry
                    .map(|entry| (entry.file_name(), entry.path()))
                    .map_err(|_| {
                        BundleLoadError::new("source", "bundle directory entry is unreadable")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        for (_, path) in entries {
            if !path.is_dir() {
                continue;
            }
            let bundle_root = path
                .canonicalize()
                .map_err(|_| BundleLoadError::new("path", "bundle directory cannot be resolved"))?;
            if !bundle_root.starts_with(root) {
                return Err(BundleLoadError::new(
                    "path",
                    "bundle directory symlink escapes its source root",
                ));
            }
            self.load_bundle(root, &bundle_root, provenance.clone(), require_digest)?;
        }
        Ok(())
    }

    fn load_bundle(
        &mut self,
        source_root: &Path,
        bundle_root: &Path,
        provenance: BundleProvenance,
        require_digest: bool,
    ) -> Result<(), BundleLoadError> {
        let manifest_path = canonical_contained_file(
            source_root,
            bundle_root,
            &bundle_root.join("bundle.yaml"),
            "manifest",
        )?;
        let manifest_bytes = read_capped(
            &manifest_path,
            MAX_BUNDLE_MANIFEST_BYTES,
            "manifest",
            "256 KiB",
        )?;
        let manifest =
            BundleManifest::parse_yaml(&manifest_bytes).map_err(|error| match error {
                BundleManifestError::TooLarge { .. } => {
                    BundleLoadError::new("manifest", "bundle manifest exceeds 256 KiB")
                }
                BundleManifestError::Yaml(_) | BundleManifestError::Invalid(_) => {
                    BundleLoadError::new("manifest", "bundle manifest is invalid")
                }
            })?;
        let mut hooks = manifest.hooks.clone();
        hooks.sort_by(|left, right| {
            (left.kind, left.type_name.as_str()).cmp(&(right.kind, right.type_name.as_str()))
        });
        for hook in &hooks {
            let key = (hook.kind, hook.type_name.clone());
            if self.reserved_names.contains(&key) {
                return Err(BundleLoadError::new(
                    "collision",
                    format!(
                        "{} hook `{}` is reserved by a built-in or linked-static registration",
                        hook_kind_label(hook.kind),
                        hook.type_name
                    ),
                ));
            }
            if let Some(existing) = self.hooks.get(&key) {
                return Err(BundleLoadError::new(
                    "collision",
                    format!(
                        "bundle `{}` and bundle `{}` both declare {} hook `{}`",
                        existing.manifest.name,
                        manifest.name,
                        hook_kind_label(hook.kind),
                        hook.type_name
                    ),
                ));
            }
        }
        validate_relative_path(&manifest.entry, "bundle entry")?;
        if require_digest && manifest.sha256.is_none() {
            return Err(BundleLoadError::new(
                "digest",
                format!("Git bundle `{}` must declare sha256", manifest.name),
            ));
        }

        let entry = canonical_contained_file(
            source_root,
            bundle_root,
            &bundle_root.join(&manifest.entry),
            "artifact",
        )?;
        let artifact = Arc::<[u8]>::from(
            read_capped(&entry, MAX_BUNDLE_ARTIFACT_BYTES, "artifact", "16 MiB")?
                .into_boxed_slice(),
        );
        let digest = hex::encode(Sha256::digest(&artifact));
        if let Some(expected) = manifest.sha256.as_deref() {
            if expected != digest {
                return Err(BundleLoadError::new(
                    "digest",
                    format!(
                        "bundle `{}` executable digest does not match sha256",
                        manifest.name
                    ),
                ));
            }
        }

        let manifest = Arc::new(manifest);
        let mut prepared = Vec::with_capacity(hooks.len());
        for hook in hooks {
            let key = (hook.kind, hook.type_name.clone());
            let validator = compile_schema(&manifest.name, &hook)?;
            prepared.push((key, hook, validator));
        }

        let source = provenance.source();
        let runtime = inventory_runtime(manifest.runtime);
        let mut hook_ids = Vec::with_capacity(prepared.len());
        for (key, hook, validator) in prepared {
            let id = format!(
                "{}:{}:{}",
                manifest.name,
                hook_kind_label(hook.kind),
                hook.type_name
            );
            hook_ids.push(id.clone());
            let loaded = Arc::new(LoadedBundleHook {
                manifest: manifest.clone(),
                hook: hook.clone(),
                artifact: artifact.clone(),
                sha256: digest.clone(),
                config_validator: validator,
                provenance: provenance.clone(),
            });
            self.inventory_hooks
                .push(hook_inventory(id, &manifest, &hook, source, runtime));
            self.hooks.insert(key, loaded);
        }

        self.bundles.push(ExtensionBundleRecord {
            id: manifest.name.clone(),
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            package: Path::new(&manifest.entry)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned),
            source,
            runtime,
            state: ExtensionState::Available,
            hook_ids,
            load: ExtensionLoadRecord {
                phase: "candidate_load".to_owned(),
                status: "ok".to_owned(),
                detail: None,
            },
        });
        Ok(())
    }

    fn finish(self) -> Result<DynamicBundleRegistry, BundleLoadError> {
        let bundle_count = u32::try_from(self.bundles.len()).unwrap_or(u32::MAX);
        let hook_count = u32::try_from(self.inventory_hooks.len()).unwrap_or(u32::MAX);
        let mut inventory = ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Running,
                proxy_version: env!("CARGO_PKG_VERSION").to_owned(),
                config_revision: None,
            },
            summary: ExtensionInventorySummary {
                bundles: bundle_count,
                hooks: hook_count,
                active: 0,
                available: hook_count,
                failed: 0,
                collisions: 0,
            },
            bundles: self.bundles,
            hooks: self.inventory_hooks,
            collisions: Vec::new(),
        };
        inventory
            .sort_stably()
            .map_err(|_| BundleLoadError::new("inventory", "duplicate stable inventory id"))?;
        Ok(DynamicBundleRegistry {
            hooks: self.hooks,
            inventory,
        })
    }
}

fn resolve_local_path(base_dir: &Path, configured: &str) -> PathBuf {
    let path = Path::new(configured);
    if path.is_absolute() {
        path.to_owned()
    } else {
        base_dir.join(path)
    }
}

fn canonical_root(path: &Path, label: &str) -> Result<PathBuf, BundleLoadError> {
    let root = path
        .canonicalize()
        .map_err(|_| BundleLoadError::new("source", format!("{label} is unavailable")))?;
    if !root.is_dir() {
        return Err(BundleLoadError::new(
            "source",
            format!("{label} is not a directory"),
        ));
    }
    Ok(root)
}

fn validate_relative_path(path: &str, label: &str) -> Result<(), BundleLoadError> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(BundleLoadError::new(
            "traversal",
            format!("{label} must stay inside its bundle root"),
        ));
    }
    Ok(())
}

fn canonical_contained_file(
    source_root: &Path,
    bundle_root: &Path,
    path: &Path,
    label: &'static str,
) -> Result<PathBuf, BundleLoadError> {
    let canonical = path
        .canonicalize()
        .map_err(|_| BundleLoadError::new(label, format!("bundle {label} is unavailable")))?;
    if !canonical.starts_with(source_root) || !canonical.starts_with(bundle_root) {
        return Err(BundleLoadError::new(
            "path",
            format!("bundle {label} symlink escape leaves its bundle root"),
        ));
    }
    if !canonical.is_file() {
        return Err(BundleLoadError::new(
            label,
            format!("bundle {label} is not a regular file"),
        ));
    }
    Ok(canonical)
}

fn read_capped(
    path: &Path,
    maximum: usize,
    stage: &'static str,
    display_limit: &str,
) -> Result<Vec<u8>, BundleLoadError> {
    let file = File::open(path)
        .map_err(|_| BundleLoadError::new(stage, format!("bundle {stage} is unreadable")))?;
    let length = file
        .metadata()
        .map_err(|_| BundleLoadError::new(stage, format!("bundle {stage} metadata is unreadable")))?
        .len();
    if length > maximum as u64 {
        return Err(BundleLoadError::new(
            stage,
            format!("bundle {stage} exceeds {display_limit}"),
        ));
    }
    let capacity = usize::try_from(length).unwrap_or(maximum).min(maximum);
    let mut bytes = Vec::with_capacity(capacity);
    let mut capped: Take<File> = file.take(maximum as u64 + 1);
    capped
        .read_to_end(&mut bytes)
        .map_err(|_| BundleLoadError::new(stage, format!("bundle {stage} is unreadable")))?;
    if bytes.len() > maximum {
        return Err(BundleLoadError::new(
            stage,
            format!("bundle {stage} exceeds {display_limit}"),
        ));
    }
    Ok(bytes)
}

fn compile_schema(
    bundle_name: &str,
    hook: &BundleHook,
) -> Result<Option<Arc<JSONSchema>>, BundleLoadError> {
    hook.config_schema
        .as_ref()
        .map(|schema| {
            JSONSchema::options()
                .with_draft(Draft::Draft7)
                .compile(schema)
                .map(Arc::new)
                .map_err(|_| {
                    BundleLoadError::new(
                        "schema",
                        format!(
                            "bundle `{bundle_name}` hook `{}` has an invalid Draft 7 schema",
                            hook.type_name
                        ),
                    )
                })
        })
        .transpose()
}

fn hook_inventory(
    id: String,
    manifest: &BundleManifest,
    hook: &BundleHook,
    source: ExtensionRegistrationSource,
    runtime: ExtensionRuntime,
) -> ExtensionHookRecord {
    ExtensionHookRecord {
        id,
        bundle_id: manifest.name.clone(),
        kind: inventory_hook_kind(hook.kind),
        registration: source,
        dispatch: if is_ai_kind(hook.kind) {
            ExtensionDispatch::Chain
        } else {
            ExtensionDispatch::Exclusive
        },
        match_key: hook.type_name.clone(),
        position: None,
        state: ExtensionState::Available,
        detail: None,
        runtime,
        execution: ExtensionExecution {
            phase: hook_phase(hook.kind).to_owned(),
            body_mode: match hook.execution.body_mode {
                BundleBodyMode::Buffered => ExtensionBodyMode::Buffered,
                BundleBodyMode::Streamed => ExtensionBodyMode::Streamed,
            },
            timeout_ms: Some(manifest.sandbox.budget_ms),
            max_buffer_bytes: Some(manifest.sandbox.max_buffer_bytes),
        },
        capabilities: Vec::new(),
    }
}

const fn inventory_runtime(runtime: BundleRuntime) -> ExtensionRuntime {
    match runtime {
        BundleRuntime::Javascript => ExtensionRuntime::Javascript,
        BundleRuntime::Wasm => ExtensionRuntime::Wasm,
        BundleRuntime::ProxyWasm => ExtensionRuntime::ProxyWasm,
    }
}

const fn inventory_hook_kind(kind: BundleHookKind) -> ExtensionHookKind {
    match kind {
        BundleHookKind::Policy => ExtensionHookKind::Policy,
        BundleHookKind::Transform => ExtensionHookKind::Transform,
        BundleHookKind::Action => ExtensionHookKind::Action,
        BundleHookKind::AiToolCall => ExtensionHookKind::AiToolCall,
        BundleHookKind::AiGuardrailInput => ExtensionHookKind::AiGuardrailInput,
        BundleHookKind::AiGuardrailOutput => ExtensionHookKind::AiGuardrailOutput,
        BundleHookKind::AiStreamEvent => ExtensionHookKind::AiStreamEvent,
        BundleHookKind::AiClose => ExtensionHookKind::AiClose,
        BundleHookKind::ProxyWasm => ExtensionHookKind::ProxyWasmFilter,
    }
}

const fn hook_phase(kind: BundleHookKind) -> &'static str {
    match kind {
        BundleHookKind::Policy | BundleHookKind::Action => "request",
        BundleHookKind::Transform => "body",
        BundleHookKind::ProxyWasm => "http",
        BundleHookKind::AiToolCall
        | BundleHookKind::AiGuardrailInput
        | BundleHookKind::AiGuardrailOutput
        | BundleHookKind::AiStreamEvent
        | BundleHookKind::AiClose => "ai",
    }
}

const fn is_ai_kind(kind: BundleHookKind) -> bool {
    matches!(
        kind,
        BundleHookKind::AiToolCall
            | BundleHookKind::AiGuardrailInput
            | BundleHookKind::AiGuardrailOutput
            | BundleHookKind::AiStreamEvent
            | BundleHookKind::AiClose
    )
}

const fn hook_kind_label(kind: BundleHookKind) -> &'static str {
    match kind {
        BundleHookKind::Policy => "policy",
        BundleHookKind::Transform => "transform",
        BundleHookKind::Action => "action",
        BundleHookKind::AiToolCall => "ai_tool_call",
        BundleHookKind::AiGuardrailInput => "ai_guardrail_input",
        BundleHookKind::AiGuardrailOutput => "ai_guardrail_output",
        BundleHookKind::AiStreamEvent => "ai_stream_event",
        BundleHookKind::AiClose => "ai_close",
        BundleHookKind::ProxyWasm => "proxy_wasm",
    }
}
