//! Configuration and manifest contracts for dynamically loaded extension bundles.
//!
//! This module owns parsing and validation only. It does not inspect the
//! filesystem, resolve paths, clone repositories, or read executable artifacts.
//! The extension runtime performs those operations while building a candidate
//! registry.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{EnforcementMode, FailureMode};

/// API version accepted in extension bundle manifests.
pub const BUNDLE_API_VERSION: &str = "sbproxy.dev/v1alpha1";
/// Required `kind` value in extension bundle manifests.
pub const BUNDLE_KIND: &str = "Bundle";
/// Envelope ABI accepted for native sbproxy WebAssembly bundles.
pub const BUNDLE_ENVELOPE_ABI: &str = "sbproxy-envelope/v1";
/// Proxy-Wasm ABI accepted for HTTP filter bundles.
pub const PROXY_WASM_ABI_VERSION: &str = "0.2.1";
/// Largest accepted `bundle.yaml`, in bytes.
pub const MAX_BUNDLE_MANIFEST_BYTES: usize = 256 * 1024;
/// Largest number of hooks one manifest may declare.
pub const MAX_BUNDLE_HOOKS: usize = 128;
/// Largest total number of JSON Schema properties one hook may declare.
pub const MAX_SCHEMA_PROPERTIES_PER_HOOK: usize = 64;
/// Largest JSON nesting depth accepted in one hook schema.
pub const MAX_SCHEMA_DEPTH: usize = 32;
/// Largest enabled Git bundle refresh cadence, in seconds.
pub const MAX_BUNDLE_REFRESH_SECS: u64 = 86_400;

/// Top-level extension bundle discovery configuration from `sb.yml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtensionBundlesConfig {
    /// Short local-directory form. Relative paths remain relative here and are
    /// interpreted by the runtime that loads the configuration.
    #[serde(default)]
    pub bundles_dir: Option<String>,
    /// Additional bundle sources, consumed in declaration order.
    #[serde(default)]
    pub sources: Vec<BundleSourceConfig>,
}

impl ExtensionBundlesConfig {
    /// Validate source fields without touching the filesystem or network.
    ///
    /// # Errors
    ///
    /// Returns an error when a path or repository field is empty, a Git source
    /// is neither commit-pinned nor signature-verified, or its fetch timeout is
    /// outside the supported range.
    pub fn validate(&self) -> Result<(), ExtensionConfigError> {
        if self
            .bundles_dir
            .as_deref()
            .is_some_and(|path| path.trim().is_empty())
        {
            return Err(ExtensionConfigError::Invalid(
                "extensions.bundles_dir cannot be empty".into(),
            ));
        }

        for source in &self.sources {
            match source {
                BundleSourceConfig::Directory { path } => {
                    if path.trim().is_empty() {
                        return Err(ExtensionConfigError::Invalid(
                            "an extension directory source needs a non-empty path".into(),
                        ));
                    }
                }
                BundleSourceConfig::Git {
                    repo,
                    revision,
                    path,
                    verify_signature,
                    timeout_secs,
                    refresh_interval_secs,
                    ..
                } => {
                    if repo.trim().is_empty() {
                        return Err(ExtensionConfigError::Invalid(
                            "an extension Git source needs a repository URL".into(),
                        ));
                    }
                    if revision.trim().is_empty() {
                        return Err(ExtensionConfigError::Invalid(
                            "an extension Git source needs a pinned revision".into(),
                        ));
                    }
                    if !crate::source::is_full_commit_sha(revision) && !verify_signature {
                        return Err(ExtensionConfigError::Invalid(
                            "an extension Git revision is mutable; use a full commit SHA or set verify_signature for a signed tag".into(),
                        ));
                    }
                    if path.trim().is_empty() {
                        return Err(ExtensionConfigError::Invalid(
                            "an extension Git source needs a non-empty path".into(),
                        ));
                    }
                    if !(1..=3_600).contains(timeout_secs) {
                        return Err(ExtensionConfigError::Invalid(format!(
                            "extension Git timeout_secs must be between 1 and 3600, got {timeout_secs}"
                        )));
                    }
                    if *refresh_interval_secs > MAX_BUNDLE_REFRESH_SECS {
                        return Err(ExtensionConfigError::Invalid(format!(
                            "extension Git refresh_interval_secs must be 0 or between 1 and {MAX_BUNDLE_REFRESH_SECS}, got {refresh_interval_secs}"
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Return the shortest enabled Git source refresh cadence.
    ///
    /// All Git sources form one immutable candidate, so they refresh together
    /// at the shortest positive interval any source requested. Zero disables
    /// timed refresh for that source.
    #[must_use]
    pub fn refresh_interval(&self) -> Option<std::time::Duration> {
        self.sources
            .iter()
            .filter_map(BundleSourceConfig::refresh_interval)
            .filter(|interval| !interval.is_zero())
            .min()
    }
}

/// One ordered source of extension bundle directories.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum BundleSourceConfig {
    /// A directory on the local filesystem.
    Directory {
        /// Directory containing bundle subdirectories.
        path: String,
    },
    /// A directory materialized from a pinned or signed Git revision.
    Git {
        /// Repository URL accepted by the system Git client.
        repo: String,
        /// Full commit SHA or signed tag selected for this source.
        revision: String,
        /// Bundle directory inside the repository.
        path: String,
        /// Optional secret reference used to authenticate the fetch.
        #[serde(default)]
        credential: Option<String>,
        /// Require a valid signature on the selected tag or commit.
        #[serde(default)]
        verify_signature: bool,
        /// Hard timeout for one fetch, in seconds.
        #[serde(default = "default_source_timeout_secs")]
        timeout_secs: u64,
        /// Refresh cadence in seconds. Zero resolves only during ordinary
        /// startup and reload operations.
        #[serde(default = "default_source_refresh_secs")]
        refresh_interval_secs: u64,
    },
}

impl BundleSourceConfig {
    /// Return the optional secret reference for a Git source.
    ///
    /// Directory sources and public Git sources return `None`. The runtime
    /// resolves the reference before it asks the Git materializer to fetch.
    #[must_use]
    pub fn credential_reference(&self) -> Option<&str> {
        match self {
            Self::Directory { .. } => None,
            Self::Git { credential, .. } => credential.as_deref(),
        }
    }

    /// Return the configured refresh cadence for a Git source.
    ///
    /// Directory sources return `None`. A zero duration on a Git source means
    /// the source refreshes only during ordinary startup and reload operations.
    #[must_use]
    pub fn refresh_interval(&self) -> Option<std::time::Duration> {
        match self {
            Self::Directory { .. } => None,
            Self::Git {
                refresh_interval_secs,
                ..
            } => Some(std::time::Duration::from_secs(*refresh_interval_secs)),
        }
    }
}

const fn default_source_timeout_secs() -> u64 {
    60
}

const fn default_source_refresh_secs() -> u64 {
    60
}

/// Runtime selected by an extension bundle.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BundleRuntime {
    /// JavaScript executed directly, or TypeScript transpiled once at load.
    Javascript,
    /// WebAssembly using the native sbproxy JSON envelope ABI.
    Wasm,
    /// WebAssembly using the Proxy-Wasm HTTP filter ABI.
    ProxyWasm,
}

/// Typed hook exported by a bundle.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BundleHookKind {
    /// Request policy hook.
    Policy,
    /// Buffered body transform hook.
    Transform,
    /// Request action hook.
    Action,
    /// AI tool-call hook.
    AiToolCall,
    /// AI input guardrail hook.
    AiGuardrailInput,
    /// AI output guardrail hook.
    AiGuardrailOutput,
    /// AI normalized stream-event hook.
    AiStreamEvent,
    /// AI stream-close hook.
    AiClose,
    /// AI call-failure hook.
    AiFailure,
    /// Payment lifecycle event hook.
    Payment,
    /// Proxy-Wasm HTTP lifecycle filter.
    ProxyWasm,
}

/// Body access mode declared for a bundle hook.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BundleBodyMode {
    /// The hook receives no request or response body.
    None,
    /// The host supplies a complete buffered body.
    #[default]
    Buffered,
    /// The host supplies body chunks as they arrive. Dynamic bundles may use
    /// this only with the Proxy-Wasm runtime.
    Streamed,
}

/// Hook execution behavior that affects pipeline planning.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleExecution {
    /// Body access mode required by this hook.
    #[serde(default)]
    pub body_mode: BundleBodyMode,
    /// Whether this hook may return a `mutate` decision.
    ///
    /// Default false, and false is the cheap path: an inspect-only
    /// hook's payload never needs re-validation, and the host reads
    /// this declaration rather than inferring intent from whether a
    /// payload came back changed, which would make the cost depend on
    /// the data instead of the config. Only the content-bearing AI
    /// hooks may declare it; validation refuses it elsewhere.
    #[serde(default)]
    pub mutates: bool,
}

/// One hook declared by a bundle manifest.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleHook {
    /// Interface implemented by this hook.
    pub kind: BundleHookKind,
    /// Stable `type:` name used to attach the hook from `sb.yml`.
    #[serde(rename = "type")]
    pub type_name: String,
    /// JavaScript export invoked for this hook. WebAssembly runtimes dispatch
    /// through their ABI and must omit this field.
    #[serde(default)]
    pub export: Option<String>,
    /// Optional Draft 7 JSON Schema for per-attachment configuration.
    #[serde(default)]
    pub config_schema: Option<Value>,
    /// Top-level `config_schema` property names that hold a secret.
    /// Resolved through the central secret resolver before the guest
    /// runs; an unresolvable reference refuses the candidate. Always
    /// masked wherever the config is rendered. Every name must also
    /// appear in `config_schema`'s top-level `properties`, and a name
    /// cannot appear in both `secret_vars` and `masked_vars`.
    #[serde(default)]
    pub secret_vars: Vec<String>,
    /// Top-level `config_schema` property names to mask wherever the
    /// config is rendered, without resolving them through the secret
    /// resolver. For a literal value (a tenant id, an internal
    /// hostname) that is sensitive but not a secret reference. Subject
    /// to the same `properties` membership rule as `secret_vars`.
    #[serde(default)]
    pub masked_vars: Vec<String>,
    /// Whether a successful AI hook verdict blocks or only observes.
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
    /// Body access requirements used by pipeline planning.
    #[serde(default)]
    pub execution: BundleExecution,
}

/// Resource limits enforced by bundle runtimes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleSandbox {
    /// Wall-clock budget for one hook invocation, in milliseconds.
    #[serde(default = "default_budget_ms")]
    pub budget_ms: u64,
    /// Maximum guest heap memory, in mebibytes.
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,
    /// Maximum guest native stack, in kibibytes.
    #[serde(default = "default_stack_kb")]
    pub stack_kb: u64,
    /// Maximum body bytes buffered for one hook invocation.
    #[serde(default = "default_max_buffer_bytes")]
    pub max_buffer_bytes: u64,
    /// Maximum serialized bytes accepted from one hook invocation.
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: u64,
    /// Maximum WebAssembly fuel consumed by one hook invocation.
    #[serde(default = "default_max_fuel")]
    pub max_fuel: u64,
}

impl Default for BundleSandbox {
    fn default() -> Self {
        Self {
            budget_ms: default_budget_ms(),
            memory_mb: default_memory_mb(),
            stack_kb: default_stack_kb(),
            max_buffer_bytes: default_max_buffer_bytes(),
            max_output_bytes: default_max_output_bytes(),
            max_fuel: default_max_fuel(),
        }
    }
}

const fn default_budget_ms() -> u64 {
    50
}
const fn default_memory_mb() -> u64 {
    16
}
const fn default_stack_kb() -> u64 {
    512
}
const fn default_max_buffer_bytes() -> u64 {
    1_048_576
}
const fn default_max_output_bytes() -> u64 {
    1_048_576
}
const fn default_max_fuel() -> u64 {
    100_000_000
}

/// What a manifest's `sha256` field is a digest of.
///
/// The scope is written in the manifest rather than inferred, because the two
/// scopes make materially different promises and a loader that guessed would
/// have to guess in favor of the weaker one. A manifest that says nothing
/// keeps the original scope, so every bundle written before this field existed
/// still loads and still says, in its own text, exactly how much of itself the
/// digest covers.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    Serialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BundleDigestScope {
    /// `sha256` covers the exact bytes of the single file named by `entry`.
    ///
    /// Nothing else in the bundle is covered, including `bundle.yaml` itself.
    /// This is the original scope and stays the default so existing bundles
    /// keep loading.
    #[default]
    Entry,
    /// `sha256` covers `bundle.yaml` and every other regular file in the
    /// bundle directory, under version 1 of the canonical bundle index.
    ///
    /// A manifest that declares this scope must also declare `sha256`.
    BundleV1,
}

/// Strict, versioned contents of one `bundle.yaml` file.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    /// Manifest API version. The wire key follows Kubernetes-style casing.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Manifest kind. This release accepts only [`BUNDLE_KIND`].
    pub kind: String,
    /// Stable bundle identifier.
    pub name: String,
    /// Operator-visible bundle version.
    pub version: String,
    /// Runtime used by the executable artifact.
    pub runtime: BundleRuntime,
    /// Runtime ABI. JavaScript omits this; WebAssembly runtimes require their
    /// exact versioned ABI.
    #[serde(default)]
    pub abi: Option<String>,
    /// Executable artifact path relative to the bundle directory.
    pub entry: String,
    /// Optional SHA-256 digest. [`Self::digest_scope`] says what it covers.
    /// Remote loaders require this field before materializing a runnable
    /// bundle.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Scope covered by [`Self::sha256`]. Omitting it means
    /// [`BundleDigestScope::Entry`], which is what every manifest written
    /// before this field existed meant.
    #[serde(default)]
    pub digest_scope: BundleDigestScope,
    /// Hooks exported by this bundle.
    pub hooks: Vec<BundleHook>,
    /// Posture used when a hook errors, times out, or exceeds a limit.
    #[serde(default)]
    pub failure_posture: FailureMode,
    /// Runtime resource limits.
    #[serde(default)]
    pub sandbox: BundleSandbox,
    /// Reserved capability names. This release has no active bundle
    /// permissions, so validation requires the list to stay empty.
    #[serde(default)]
    pub permissions: Vec<String>,
}

impl BundleManifest {
    /// Parse and validate a manifest from a byte-capped YAML document.
    ///
    /// This check intentionally happens before YAML parsing so an oversized
    /// document cannot spend parser memory first. Reserved built-in and static
    /// hook names are supplied later by the candidate registry through
    /// [`Self::validate`].
    ///
    /// # Errors
    ///
    /// Returns an error for oversized or malformed YAML and for every invalid
    /// manifest contract enforced by [`Self::validate`].
    pub fn parse_yaml(bytes: &[u8]) -> Result<Self, BundleManifestError> {
        if bytes.len() > MAX_BUNDLE_MANIFEST_BYTES {
            return Err(BundleManifestError::TooLarge {
                actual: bytes.len(),
            });
        }
        let manifest: Self = serde_yaml::from_slice(bytes)
            .map_err(|error| BundleManifestError::Yaml(sanitize_detail(&error.to_string())))?;
        manifest.validate(&BTreeSet::new())?;
        Ok(manifest)
    }

    /// Validate this manifest against kind-aware reserved hook names.
    ///
    /// The reservation key is `(hook kind, type name)`, matching runtime
    /// dispatch. A policy and transform may deliberately share a type name,
    /// while two policies may not.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong version or kind, invalid identifiers,
    /// duplicate or reserved hooks, incompatible runtime fields, unsafe JSON
    /// Schemas, inactive permissions, unsafe failure posture, a declared
    /// digest scope with no digest, or a resource limit outside its documented
    /// ceiling.
    pub fn validate(
        &self,
        reserved_names: &BTreeSet<(BundleHookKind, String)>,
    ) -> Result<(), BundleManifestError> {
        if self.api_version != BUNDLE_API_VERSION {
            return invalid(format!(
                "apiVersion must be `{BUNDLE_API_VERSION}`, got `{}`",
                self.api_version
            ));
        }
        if self.kind != BUNDLE_KIND {
            return invalid(format!("kind must be `{BUNDLE_KIND}`, got `{}`", self.kind));
        }
        validate_bundle_name(&self.name)?;
        validate_version(&self.version)?;
        if self.hooks.is_empty() {
            return invalid("a bundle needs at least one hook");
        }
        if self.hooks.len() > MAX_BUNDLE_HOOKS {
            return invalid(format!(
                "a bundle may declare at most {MAX_BUNDLE_HOOKS} hooks, got {}",
                self.hooks.len()
            ));
        }
        if !self.permissions.is_empty() {
            return invalid(format!(
                "permissions are inactive in this release; remove `{}`",
                self.permissions.join(", ")
            ));
        }
        if let Some(sha256) = self.sha256.as_deref() {
            if sha256.len() != 64
                || !sha256
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
            {
                return invalid("sha256 must contain exactly 64 lowercase hexadecimal characters");
            }
        }
        if self.digest_scope == BundleDigestScope::BundleV1 && self.sha256.is_none() {
            return invalid("digest_scope bundle_v1 requires sha256");
        }
        validate_limit("sandbox.budget_ms", self.sandbox.budget_ms, 1_000)?;
        validate_limit("sandbox.memory_mb", self.sandbox.memory_mb, 64)?;
        validate_limit("sandbox.stack_kb", self.sandbox.stack_kb, 2_048)?;
        validate_limit(
            "sandbox.max_buffer_bytes",
            self.sandbox.max_buffer_bytes,
            16_777_216,
        )?;
        validate_limit(
            "sandbox.max_output_bytes",
            self.sandbox.max_output_bytes,
            16_777_216,
        )?;
        validate_limit("sandbox.max_fuel", self.sandbox.max_fuel, 1_000_000_000)?;

        let mut declared = BTreeSet::new();
        for hook in &self.hooks {
            validate_hook_type(&hook.type_name)?;
            let key = (hook.kind, hook.type_name.clone());
            if !declared.insert(key.clone()) {
                return invalid(format!(
                    "duplicate {} hook type `{}`",
                    hook_kind_label(hook.kind),
                    hook.type_name
                ));
            }
            if reserved_names.contains(&key) {
                return invalid(format!(
                    "{} hook type `{}` is reserved by a built-in or linked extension",
                    hook_kind_label(hook.kind),
                    hook.type_name
                ));
            }
            if hook.kind == BundleHookKind::Action && self.failure_posture != FailureMode::Closed {
                return invalid("action hooks are terminal and require failure_posture closed");
            }
            if matches!(
                hook.kind,
                BundleHookKind::Transform | BundleHookKind::Action
            ) && matches!(
                self.failure_posture,
                FailureMode::Observe | FailureMode::Degraded
            ) {
                return invalid(format!(
                    "{} failure_posture is not defined for {} hooks",
                    failure_mode_label(self.failure_posture),
                    hook_kind_label(hook.kind)
                ));
            }
            if hook.execution.body_mode == BundleBodyMode::Streamed
                && self.runtime != BundleRuntime::ProxyWasm
            {
                return invalid("body_mode streamed is available only for runtime proxy_wasm");
            }
            if hook.kind == BundleHookKind::Payment
                && hook.execution.body_mode != BundleBodyMode::None
            {
                return invalid("payment hooks require body_mode none");
            }
            if hook.execution.mutates
                && !matches!(
                    hook.kind,
                    BundleHookKind::AiGuardrailInput
                        | BundleHookKind::AiGuardrailOutput
                        | BundleHookKind::AiToolCall
                )
            {
                // Stream chunks are content-bearing too, but their
                // wire write-back does not exist yet: the relay would
                // apply the rewrite to the in-memory event and ship
                // the original frames, which is worse than a refusal
                // at config load. Guardrail and tool-call hooks have
                // end-to-end write-back and accept the declaration.
                return invalid(format!(
                    "mutates is not supported for {} hooks; ai.guardrail_input, \
                     ai.guardrail_output, and ai.tool_call hooks may mutate",
                    hook_kind_label(hook.kind)
                ));
            }
            if hook.execution.mutates && hook.enforcement_mode == EnforcementMode::Observe {
                // Observation hooks receive a cloned event and their
                // decisions are discarded, so a declared mutation
                // would load cleanly and silently never apply.
                return invalid(
                    "mutates requires enforcement_mode block; an observe hook's \
                     decisions are discarded, so its mutation could never apply",
                );
            }
            if let Some(schema) = &hook.config_schema {
                validate_schema(schema)?;
            }
            validate_secret_and_masked_vars(hook)?;
        }

        self.validate_runtime_contract()
    }

    fn validate_runtime_contract(&self) -> Result<(), BundleManifestError> {
        match self.runtime {
            BundleRuntime::Javascript => {
                if self.abi.is_some() {
                    return invalid("runtime javascript must omit abi");
                }
                if !self.entry.ends_with(".ts") && !self.entry.ends_with(".js") {
                    return invalid("runtime javascript entry must end in .ts or .js");
                }
                for hook in &self.hooks {
                    match hook.kind {
                        BundleHookKind::ProxyWasm => {
                            return invalid("runtime javascript cannot declare a proxy_wasm hook");
                        }
                        BundleHookKind::AiStreamEvent => {
                            return invalid(
                                "runtime javascript cannot declare an ai_stream_event hook",
                            );
                        }
                        _ => {}
                    }
                    let export = hook.export.as_deref().ok_or_else(|| {
                        BundleManifestError::Invalid(sanitize_detail(&format!(
                            "javascript hook `{}` needs an export",
                            hook.type_name
                        )))
                    })?;
                    validate_export(export)?;
                }
            }
            BundleRuntime::Wasm => {
                if self.abi.as_deref() != Some(BUNDLE_ENVELOPE_ABI) {
                    return invalid(format!("runtime wasm requires abi `{BUNDLE_ENVELOPE_ABI}`"));
                }
                validate_wasm_entry(&self.entry)?;
                for hook in &self.hooks {
                    match hook.kind {
                        BundleHookKind::ProxyWasm => {
                            return invalid("runtime wasm cannot declare a proxy_wasm hook");
                        }
                        BundleHookKind::AiStreamEvent => {
                            return invalid("runtime wasm cannot declare an ai_stream_event hook");
                        }
                        _ => {}
                    }
                    if hook.export.is_some() {
                        return invalid(format!(
                            "envelope WASM hook `{}` must omit export",
                            hook.type_name
                        ));
                    }
                }
            }
            BundleRuntime::ProxyWasm => {
                if self.abi.as_deref() != Some(PROXY_WASM_ABI_VERSION) {
                    return invalid(format!(
                        "runtime proxy_wasm requires abi `{PROXY_WASM_ABI_VERSION}`"
                    ));
                }
                validate_wasm_entry(&self.entry)?;
                for hook in &self.hooks {
                    if !matches!(
                        hook.kind,
                        BundleHookKind::ProxyWasm | BundleHookKind::AiStreamEvent
                    ) {
                        return invalid(
                            "runtime proxy_wasm may declare proxy_wasm or ai_stream_event hooks",
                        );
                    }
                    if hook.export.is_some() {
                        return invalid(format!(
                            "Proxy-Wasm hook `{}` must omit export",
                            hook.type_name
                        ));
                    }
                    if hook.config_schema.is_some() {
                        return invalid(format!(
                            "Proxy-Wasm hook `{}` must use plugin configuration instead of config_schema",
                            hook.type_name
                        ));
                    }
                    if hook.kind == BundleHookKind::AiStreamEvent
                        && hook.execution.body_mode != BundleBodyMode::Streamed
                    {
                        return invalid("ai_stream_event hooks require body_mode streamed");
                    }
                }
            }
        }
        Ok(())
    }
}

/// Parse or validation error for extension bundle configuration.
#[derive(Debug, Error)]
pub enum ExtensionConfigError {
    /// One source field has no safe, deterministic meaning.
    #[error("extension configuration is invalid: {0}")]
    Invalid(String),
}

/// Parse or validation error for one bundle manifest.
#[derive(Debug, Error)]
pub enum BundleManifestError {
    /// The manifest exceeded the byte cap before parsing.
    #[error(
        "bundle manifest is {actual} bytes; keep bundle.yaml at or below 256 KiB ({MAX_BUNDLE_MANIFEST_BYTES} bytes)"
    )]
    TooLarge {
        /// Number of bytes supplied by the caller.
        actual: usize,
    },
    /// YAML parsing or strict-field validation failed.
    #[error("bundle manifest YAML is invalid: {0}")]
    Yaml(String),
    /// A typed manifest field violates the bundle contract.
    #[error("bundle manifest is invalid: {0}")]
    Invalid(String),
}

fn invalid<T>(message: impl Into<String>) -> Result<T, BundleManifestError> {
    Err(BundleManifestError::Invalid(sanitize_detail(
        &message.into(),
    )))
}

fn sanitize_detail(detail: &str) -> String {
    // The longest BundleManifestError display prefix is 33 bytes, so a
    // 479-byte detail keeps the complete public error at or below 512 bytes.
    const MAX_DETAIL_BYTES: usize = 479;
    let mut sanitized = detail
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    if sanitized.len() > MAX_DETAIL_BYTES {
        let mut boundary = MAX_DETAIL_BYTES;
        while !sanitized.is_char_boundary(boundary) {
            boundary -= 1;
        }
        sanitized.truncate(boundary);
    }
    sanitized
}

fn validate_bundle_name(name: &str) -> Result<(), BundleManifestError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_lowercase()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        || name.ends_with('-')
        || name.contains("--")
    {
        return invalid(
            "name must be 1 to 64 lowercase ASCII letters, digits, or single hyphens, starting with a letter",
        );
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), BundleManifestError> {
    let bytes = version.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'+'))
    {
        return invalid(
            "version must be 1 to 64 ASCII letters, digits, dots, hyphens, or plus signs",
        );
    }
    Ok(())
}

fn validate_hook_type(type_name: &str) -> Result<(), BundleManifestError> {
    let bytes = type_name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_lowercase()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return invalid(format!(
            "hook type `{type_name}` must be 1 to 64 lowercase ASCII letters, digits, or underscores, starting with a letter"
        ));
    }
    Ok(())
}

fn validate_export(export: &str) -> Result<(), BundleManifestError> {
    let bytes = export.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !(bytes[0].is_ascii_alphabetic() || matches!(bytes[0], b'_' | b'$'))
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'$'))
    {
        return invalid(format!(
            "export `{export}` must be a JavaScript identifier no longer than 128 bytes"
        ));
    }
    Ok(())
}

fn validate_wasm_entry(entry: &str) -> Result<(), BundleManifestError> {
    if !entry.ends_with(".wasm") {
        return invalid("a WebAssembly entry must end in .wasm");
    }
    Ok(())
}

fn validate_limit(field: &str, value: u64, maximum: u64) -> Result<(), BundleManifestError> {
    if value == 0 || value > maximum {
        return invalid(format!(
            "{field} must be between 1 and {maximum}, got {value}"
        ));
    }
    Ok(())
}

/// Validate a hook's `secret_vars`/`masked_vars` declarations: every
/// name must be a top-level `config_schema` property, and a name
/// cannot appear in both lists (WOR-2289). Declaring either list with
/// no `config_schema` is invalid, since there is no property for the
/// name to refer to.
fn validate_secret_and_masked_vars(hook: &BundleHook) -> Result<(), BundleManifestError> {
    if hook.secret_vars.is_empty() && hook.masked_vars.is_empty() {
        return Ok(());
    }
    let properties = hook
        .config_schema
        .as_ref()
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object);
    for name in hook.secret_vars.iter().chain(&hook.masked_vars) {
        let declared = properties.is_some_and(|properties| properties.contains_key(name));
        if !declared {
            return invalid(format!(
                "{} hook `{}` declares secret_vars/masked_vars `{name}`, which is not a config_schema property",
                hook_kind_label(hook.kind),
                hook.type_name
            ));
        }
    }
    for name in &hook.secret_vars {
        if hook.masked_vars.contains(name) {
            return invalid(format!(
                "{} hook `{}` lists `{name}` in both secret_vars and masked_vars; a var cannot be both",
                hook_kind_label(hook.kind),
                hook.type_name
            ));
        }
    }
    Ok(())
}

fn validate_schema(schema: &Value) -> Result<(), BundleManifestError> {
    let mut properties = 0usize;
    walk_schema(schema, 1, &mut properties)?;
    if properties > MAX_SCHEMA_PROPERTIES_PER_HOOK {
        return invalid(format!(
            "config_schema may declare at most {MAX_SCHEMA_PROPERTIES_PER_HOOK} properties per hook, got {properties}"
        ));
    }
    Ok(())
}

fn walk_schema(
    value: &Value,
    depth: usize,
    properties: &mut usize,
) -> Result<(), BundleManifestError> {
    if depth > MAX_SCHEMA_DEPTH {
        return invalid(format!(
            "config_schema nesting exceeds depth {MAX_SCHEMA_DEPTH}"
        ));
    }
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                if !reference.starts_with('#') {
                    return invalid("remote $ref is not allowed in config_schema");
                }
            }
            if let Some(property_map) = object.get("properties").and_then(Value::as_object) {
                *properties = properties.saturating_add(property_map.len());
            }
            for child in object.values() {
                walk_schema(child, depth + 1, properties)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                walk_schema(child, depth + 1, properties)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

const fn failure_mode_label(mode: FailureMode) -> &'static str {
    match mode {
        FailureMode::Closed => "closed",
        FailureMode::Open => "open",
        FailureMode::Degraded => "degraded",
        FailureMode::Observe => "observe",
    }
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
        BundleHookKind::AiFailure => "ai_failure",
        BundleHookKind::Payment => "payment",
        BundleHookKind::ProxyWasm => "proxy_wasm",
    }
}
