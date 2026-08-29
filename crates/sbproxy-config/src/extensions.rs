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
    /// Capability grants, keyed by bundle manifest `name`.
    ///
    /// A bundle's hooks may declare capabilities in their manifest
    /// (`net:outbound=<scheme>://<host>[:port]`); nothing is granted by
    /// declaration alone. The operator grants here, with the same
    /// entry syntax, and a candidate whose declared set exceeds its
    /// granted set refuses at load naming both sets. An empty or
    /// absent grant list means the bundle gets no capabilities, which
    /// is the default every bundle had before this key existed.
    #[serde(default)]
    pub grants: std::collections::BTreeMap<String, Vec<String>>,
}

impl ExtensionBundlesConfig {
    /// Whether this document names any place an extension bundle could
    /// come from.
    ///
    /// One function rather than the same two-clause expression at every
    /// call site. Two things ask it and they must not drift: config
    /// compile decides whether an unrecognized policy `type:` in
    /// `origin_defaults` is a typo or a bundle-provided type, and the
    /// aggregator decides the same thing about the same document. A
    /// detector narrower than the enforcer would have `sbproxy validate`
    /// warn where the aggregator hard-refuses, which is the
    /// far-end-of-a-GitOps-loop failure those checks exist to move
    /// earlier.
    ///
    /// # What this cannot see
    ///
    /// Whether any bundle actually loads. `bundles_dir` may be empty and
    /// a source may 404. The question is deliberately the weaker one: a
    /// document with nowhere to get a type from could not have acquired
    /// it, and that is answerable without fetching anything.
    #[must_use]
    pub fn declares_any_source(&self) -> bool {
        self.bundles_dir.is_some() || !self.sources.is_empty()
    }

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

        for (bundle, entries) in &self.grants {
            if bundle.trim().is_empty() {
                return Err(ExtensionConfigError::Invalid(
                    "extensions.grants keys are bundle manifest names and cannot be empty".into(),
                ));
            }
            for entry in entries {
                if let Err(reason) = parse_permission_entry(entry) {
                    return Err(ExtensionConfigError::Invalid(format!(
                        "extensions.grants.{bundle}: {reason}"
                    )));
                }
            }
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
    /// Rego evaluated directly on the Regorus interpreter (WOR-2482).
    ///
    /// No export, no ABI, no host call surface: a Rego module performs
    /// no I/O during evaluation, matching `policy: rego`'s own
    /// constraint. Only `kind: policy` and `kind: transform` hooks are
    /// valid on this runtime (transforms since WOR-2493 item 6).
    Rego,
}

/// Typed hook exported by a bundle.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BundleHookKind {
    /// Request policy hook.
    Policy,
    /// Request authentication hook.
    Auth,
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
    /// AI routing-decision hook (WOR-2366).
    ///
    /// An attach-by-type hook that authors the AI routing decision: the
    /// host sends the `ai` decision document through the envelope ABI
    /// and the hook returns a routing-plan document, or declines by
    /// returning none. Available only to the envelope WebAssembly
    /// runtime, so the decision stays a pure function of its input.
    AiRouting,
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
    /// When this inspect-only hook runs relative to the upstream call.
    ///
    /// `serial` (the default) waits for the hook before the provider is
    /// dialed. `parallel` starts the hook alongside the upstream call and
    /// cancels that call if the hook blocks. Only `ai_guardrail_input`
    /// hooks may declare it, and it cannot combine with `mutates: true`.
    #[serde(default)]
    pub mode: BundleExecutionMode,
}

/// When an inspect-only hook evaluates relative to the upstream call.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BundleExecutionMode {
    /// Wait for the hook before dialing the provider.
    #[default]
    Serial,
    /// Run alongside the upstream call; a block cancels it (WOR-2421).
    Parallel,
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
    /// Rego rule reference evaluated per request, for example
    /// `data.sbproxy.allow`. Only valid on `runtime: rego`; every other
    /// runtime must omit it. Defaults to `data.sbproxy.allow`, matching
    /// `policy: rego`'s own default, when a `runtime: rego` hook omits
    /// it (WOR-2482).
    #[serde(default)]
    pub query: Option<String>,
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
    /// Capabilities this hook asks for, each naming its full grant.
    ///
    /// The only recognized capability is outbound HTTP to a declared
    /// destination: `net:outbound=https://host` or
    /// `net:outbound=http://host:port`. Declaring is asking, not
    /// having: the operator grants per bundle in `sb.yml`
    /// (`extensions.grants`), and a declared set exceeding the granted
    /// set refuses the candidate at load. The declaration lives here,
    /// inside the digest-covered manifest, so the grant an operator
    /// audits is the grant the artifact was signed with.
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// One parsed `net:outbound` destination from a hook's `permissions`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutboundDestination {
    /// `http` or `https`; nothing else parses.
    pub scheme: String,
    /// Exact hostname; no wildcards.
    pub host: String,
    /// Explicit port, or the scheme default (80/443).
    pub port: u16,
}

impl std::fmt::Display for OutboundDestination {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// Parse one `permissions` entry.
///
/// # Errors
///
/// Returns a message naming the malformed part: an unrecognized
/// capability, a scheme other than http/https, an empty or
/// wildcarded host, or an unparseable port.
pub fn parse_permission_entry(entry: &str) -> Result<OutboundDestination, String> {
    let Some(destination) = entry.strip_prefix("net:outbound=") else {
        return Err(format!(
            "unrecognized capability `{entry}`; the only capability this release \
             grants is `net:outbound=<scheme>://<host>[:port]`"
        ));
    };
    let (scheme, rest) = destination
        .split_once("://")
        .ok_or_else(|| format!("destination `{destination}` is missing `<scheme>://`"))?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        other => {
            return Err(format!(
                "destination scheme `{other}` is not grantable; use http or https"
            ));
        }
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port_text)) => {
            let port: u16 = port_text
                .parse()
                .map_err(|_| format!("destination port `{port_text}` is not a port"))?;
            (host, port)
        }
        None => (rest, default_port),
    };
    if host.is_empty() || host.contains('*') || host.contains('/') {
        return Err(format!(
            "destination host `{host}` must be one exact hostname; wildcards and \
             paths are not grantable"
        ));
    }
    Ok(OutboundDestination {
        scheme: scheme.to_owned(),
        host: host.to_ascii_lowercase(),
        port,
    })
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
            // WOR-2426: a failed auth hook always denies at runtime, so a
            // non-closed posture would be silently inert. Refuse it at load
            // rather than let an operator believe `open` fails a request open.
            if hook.kind == BundleHookKind::Auth && self.failure_posture != FailureMode::Closed {
                return invalid("auth hooks always fail closed and require failure_posture closed");
            }
            // WOR-2366: a routing hook observes by declining to return a
            // plan, so enforcement_mode observe would load cleanly and
            // change nothing. Refuse the inert knob at load rather than
            // let an operator believe it softened the decision.
            if hook.kind == BundleHookKind::AiRouting
                && hook.enforcement_mode == EnforcementMode::Observe
            {
                return invalid(
                    "enforcement_mode observe is not defined for ai_routing hooks; \
                     declining to return a plan already is the observe posture",
                );
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
            // An ai_routing hook is invoked with the ai decision document,
            // never a request or response body, so a richer declaration
            // would promise data the host will not deliver. Buffered is
            // the field default, so the hook must declare none explicitly.
            if hook.kind == BundleHookKind::AiRouting
                && hook.execution.body_mode != BundleBodyMode::None
            {
                return invalid(
                    "ai_routing hooks require body_mode none; the hook receives \
                     the ai decision document, never a request or response body",
                );
            }
            if hook.execution.mutates
                && !matches!(
                    hook.kind,
                    BundleHookKind::AiGuardrailInput
                        | BundleHookKind::AiGuardrailOutput
                        | BundleHookKind::AiToolCall
                        | BundleHookKind::AiStreamEvent
                )
            {
                // WOR-2365: stream chunks gained their wire write-back,
                // so they join the content-bearing set. A stream hook
                // may rewrite content text only; usage and the control
                // frames are refused at the hook seam rather than here,
                // because the refusal depends on which chunk arrived
                // rather than on how the hook was declared.
                return invalid(format!(
                    "mutates is not supported for {} hooks; ai_guardrail_input, \
                     ai_guardrail_output, ai_tool_call, and ai_stream_event hooks may mutate",
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
            if hook.execution.mode == BundleExecutionMode::Parallel {
                if hook.kind != BundleHookKind::AiGuardrailInput {
                    return invalid(
                        "execution.mode parallel is only supported for ai_guardrail_input hooks",
                    );
                }
                if hook.execution.mutates {
                    return invalid(
                        "execution.mode parallel cannot combine with mutates: true; \
                         a rewrite must land before dispatch",
                    );
                }
                if hook.enforcement_mode == EnforcementMode::Observe {
                    return invalid(
                        "execution.mode parallel requires enforcement_mode block; \
                         observe hooks already run off the request path",
                    );
                }
            }
            if let Some(schema) = &hook.config_schema {
                validate_schema(schema)?;
            }
            validate_secret_and_masked_vars(hook)?;
            if !hook.permissions.is_empty() {
                // WOR-2366: the routing decision is a pure function of the
                // ai document on every runtime, so this rule sits at the
                // kind, ahead of the runtime-level refusal below, and
                // survives any runtime that later grows a host call
                // surface.
                if hook.kind == BundleHookKind::AiRouting {
                    return invalid(
                        "an ai_routing hook cannot declare capabilities: the \
                         routing decision must not do I/O (WOR-2366); everything \
                         the decision needs arrives in the ai document",
                    );
                }
                // The envelope-WASM ABI is stdin/stdout with no host
                // imports, and Proxy-Wasm registers no outbound host
                // function; a capability neither runtime can deliver
                // must refuse at load, not read as granted.
                if self.runtime != BundleRuntime::Javascript {
                    return invalid(format!(
                        "hook `{}` declares capabilities, but runtime {} has no host \
                         call surface; net:outbound is available to javascript bundles",
                        hook.type_name,
                        match self.runtime {
                            BundleRuntime::Javascript => "javascript",
                            BundleRuntime::Wasm => "wasm",
                            BundleRuntime::ProxyWasm => "proxy_wasm",
                            BundleRuntime::Rego => "rego",
                        }
                    ));
                }
                for entry in &hook.permissions {
                    if let Err(reason) = parse_permission_entry(entry) {
                        return invalid(format!("hook `{}`: {reason}", hook.type_name));
                    }
                }
            }
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
                        // WOR-2366: routing hooks are envelope-WASM only. A
                        // javascript hook with a granted net:outbound gains
                        // the sbproxy_fetch host function, and the routing
                        // decision must stay a pure function of its input.
                        BundleHookKind::AiRouting => {
                            return invalid(
                                "runtime javascript cannot declare an ai_routing hook: a \
                                 javascript hook with net:outbound gains sbproxy_fetch, \
                                 which would put I/O inside the routing decision",
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
                    if hook.query.is_some() {
                        return invalid(format!(
                            "hook `{}` declares query, which only applies to runtime rego",
                            hook.type_name
                        ));
                    }
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
                        // WOR-2426: bundle auth hooks ship JavaScript-only
                        // this release. Refuse a wasm auth hook at load so
                        // the failure is a named manifest error rather than
                        // a compile-time bail with no adapter behind it.
                        BundleHookKind::Auth => {
                            return invalid("runtime wasm cannot declare an auth hook");
                        }
                        _ => {}
                    }
                    if hook.export.is_some() {
                        return invalid(format!(
                            "envelope WASM hook `{}` must omit export",
                            hook.type_name
                        ));
                    }
                    if hook.query.is_some() {
                        return invalid(format!(
                            "hook `{}` declares query, which only applies to runtime rego",
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
                    if hook.query.is_some() {
                        return invalid(format!(
                            "hook `{}` declares query, which only applies to runtime rego",
                            hook.type_name
                        ));
                    }
                }
            }
            // WOR-2482: a Rego module performs no I/O and has no
            // export or ABI, so the contract is narrower than every
            // other runtime rather than a variant of one of them.
            BundleRuntime::Rego => {
                if self.abi.is_some() {
                    return invalid("runtime rego must omit abi");
                }
                if !self.entry.ends_with(".rego") {
                    return invalid("runtime rego entry must end in .rego");
                }
                // A Rego hook evaluates on the Regorus interpreter in
                // this process, with no guest heap and no guest stack to
                // bound: `memory_mb` and `stack_kb` reach the Wasmtime
                // store and the JavaScript runtime, and there is nothing
                // equivalent to hand them to here. Refuse a non-default
                // value rather than accept a number that reads as a
                // sandbox bound and does nothing, the same posture
                // `enforcement_mode: observe` on an ai_routing hook and
                // a non-closed `failure_posture` on an auth hook already
                // take. A bundle that never mentions either field keeps
                // loading; only writing one is refused, which is
                // precisely the case where an operator believes it
                // bounds something.
                if self.sandbox.memory_mb != default_memory_mb() {
                    return invalid(
                        "runtime rego does not honor sandbox.memory_mb; a Rego hook has no \
                         guest heap to bound, and is bounded by sandbox.budget_ms plus \
                         sandbox.max_buffer_bytes and max_output_bytes. Remove the field",
                    );
                }
                if self.sandbox.stack_kb != default_stack_kb() {
                    return invalid(
                        "runtime rego does not honor sandbox.stack_kb; a Rego hook has no \
                         guest stack to bound, and is bounded by sandbox.budget_ms plus \
                         sandbox.max_buffer_bytes and max_output_bytes. Remove the field",
                    );
                }
                for hook in &self.hooks {
                    match hook.kind {
                        // A policy hook evaluates the request line,
                        // headers, and its own config, never a
                        // buffered body.
                        BundleHookKind::Policy => {
                            if hook.execution.body_mode != BundleBodyMode::None {
                                return invalid(format!(
                                    "rego hook `{}` requires body_mode none; a bundled Rego \
                                     policy evaluates the request line, headers, and its own \
                                     config, never a buffered body",
                                    hook.type_name
                                ));
                            }
                        }
                        // WOR-2493 item 6: a transform hook is the
                        // opposite case. The whole point is the
                        // buffered response body, so the declaration
                        // must promise exactly that, the same
                        // body-mode contract a JavaScript or WASM
                        // transform hook carries implicitly via the
                        // field default.
                        BundleHookKind::Transform => {
                            if hook.execution.body_mode != BundleBodyMode::Buffered {
                                return invalid(format!(
                                    "rego transform hook `{}` requires body_mode buffered; \
                                     a bundled Rego transform evaluates the complete \
                                     buffered response body",
                                    hook.type_name
                                ));
                            }
                        }
                        other => {
                            return invalid(format!(
                                "runtime rego may declare only policy and transform hooks, \
                                 got a {} hook",
                                hook_kind_label(other)
                            ));
                        }
                    }
                    if hook.export.is_some() {
                        return invalid(format!(
                            "rego hook `{}` must omit export; a Rego module has no \
                             export, only the query it evaluates",
                            hook.type_name
                        ));
                    }
                    if let Some(query) = &hook.query {
                        validate_rego_query(query)?;
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

/// Make caller-supplied text safe to render into an error or a log
/// line: every control character becomes a space, and the result is
/// capped on a char boundary.
///
/// Shared rather than reimplemented. `crate::source`'s unconfined-source
/// warning renders a config key path assembled from a fetched document's
/// own mapping key names, and YAML allows a newline or an ANSI escape
/// inside a quoted key, so an externally authored repository could
/// otherwise forge a complete log line under the default fmt layer
/// (WOR-2433 re-review round 3). Same shape, same cap, one
/// implementation.
pub(crate) fn sanitize_detail(detail: &str) -> String {
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

/// Validate a `runtime: rego` hook's declared `query`.
///
/// This is a bound on the field, not a Rego syntax check: Regorus
/// itself refuses a query naming no rule (and every other semantic
/// fault) when the module compiles, matching how a malformed
/// `policy: rego` `query` fails at config load rather than here.
fn validate_rego_query(query: &str) -> Result<(), BundleManifestError> {
    if query.is_empty() || query.len() > 256 || query.bytes().any(|byte| byte.is_ascii_control()) {
        return invalid(format!(
            "query `{query}` must be 1 to 256 bytes with no control characters"
        ));
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
        BundleHookKind::Auth => "auth",
        BundleHookKind::Transform => "transform",
        BundleHookKind::Action => "action",
        BundleHookKind::AiToolCall => "ai_tool_call",
        BundleHookKind::AiGuardrailInput => "ai_guardrail_input",
        BundleHookKind::AiGuardrailOutput => "ai_guardrail_output",
        BundleHookKind::AiStreamEvent => "ai_stream_event",
        BundleHookKind::AiClose => "ai_close",
        BundleHookKind::AiFailure => "ai_failure",
        BundleHookKind::AiRouting => "ai_routing",
        BundleHookKind::Payment => "payment",
        BundleHookKind::ProxyWasm => "proxy_wasm",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AI_ROUTING_WASM_MANIFEST: &str = r#"
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: cost-quality-router
version: 0.1.0
runtime: wasm
abi: sbproxy-envelope/v1
entry: dist/router.wasm
hooks:
  - kind: ai_routing
    type: cost_quality_router
    execution:
      body_mode: none
    config_schema:
      type: object
      additionalProperties: false
      properties:
        threshold: { type: number, default: 0.3 }
failure_posture: closed
sandbox:
  budget_ms: 50
  memory_mb: 16
  stack_kb: 512
permissions: []
"#;

    const AI_INPUT_JS_MANIFEST: &str = r#"
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: input-moderation
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_input
    type: inspect_input
    export: inspect
    execution:
      body_mode: none
failure_posture: closed
sandbox:
  budget_ms: 50
  memory_mb: 16
  stack_kb: 512
permissions: []
"#;

    fn parse_manifest(yaml: &str) -> BundleManifest {
        BundleManifest::parse_yaml(yaml.as_bytes()).expect("manifest parses")
    }

    fn manifest_error(yaml: &str) -> String {
        BundleManifest::parse_yaml(yaml.as_bytes())
            .expect_err("manifest must be rejected")
            .to_string()
    }

    fn replace_once(source: &str, from: &str, to: &str) -> String {
        assert!(source.contains(from), "fixture must contain {from:?}");
        source.replacen(from, to, 1)
    }

    #[test]
    fn a_wasm_ai_routing_hook_validates() {
        // WOR-2366: the envelope WebAssembly runtime is the one runtime
        // an ai_routing hook may declare.
        let manifest = parse_manifest(AI_ROUTING_WASM_MANIFEST);
        assert_eq!(manifest.hooks[0].kind, BundleHookKind::AiRouting);
        assert_eq!(manifest.hooks[0].execution.body_mode, BundleBodyMode::None);
    }

    #[test]
    fn an_ai_routing_hook_cannot_declare_capabilities() {
        // The kind-level refusal must fire even under runtime wasm, where
        // the runtime-level capability refusal would otherwise cover it,
        // so the no-I/O invariant survives a runtime that later grows a
        // host call surface.
        let yaml = replace_once(
            AI_ROUTING_WASM_MANIFEST,
            "    execution:",
            "    permissions:\n      - net:outbound=https://pricing.example\n    execution:",
        );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("ai_routing hook cannot declare capabilities")
                && error.contains("must not do I/O"),
            "{error}"
        );
    }

    #[test]
    fn an_ai_routing_hook_requires_body_mode_none() {
        let explicit_buffered = replace_once(
            AI_ROUTING_WASM_MANIFEST,
            "      body_mode: none",
            "      body_mode: buffered",
        );
        // Buffered is the field default, so omitting `execution` entirely
        // must refuse the same way an explicit declaration does.
        let omitted = replace_once(
            AI_ROUTING_WASM_MANIFEST,
            "    execution:\n      body_mode: none\n",
            "",
        );
        for yaml in [explicit_buffered, omitted] {
            let error = manifest_error(&yaml);
            assert!(
                error.contains("ai_routing") && error.contains("body_mode none"),
                "{error}"
            );
        }
    }

    #[test]
    fn an_ai_routing_hook_cannot_run_in_observe_mode() {
        // Declining to return a plan already is the observe posture, so
        // the mode would load cleanly and change nothing.
        let yaml = replace_once(
            AI_ROUTING_WASM_MANIFEST,
            "    execution:",
            "    enforcement_mode: observe\n    execution:",
        );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("ai_routing") && error.contains("observe posture"),
            "{error}"
        );
    }

    #[test]
    fn an_ai_routing_hook_cannot_declare_mutates() {
        // Covered by the existing content-hook allowlist rather than a
        // dedicated rule; asserted here so the routing invariant does not
        // ride silently on that list.
        let yaml = replace_once(
            AI_ROUTING_WASM_MANIFEST,
            "      body_mode: none",
            "      body_mode: none\n      mutates: true",
        );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("mutates is not supported for ai_routing"),
            "{error}"
        );
    }

    #[test]
    fn runtime_javascript_rejects_ai_routing_hooks() {
        // The kind refusal fires before the export requirement, so the
        // converted hook does not need one.
        let yaml = AI_ROUTING_WASM_MANIFEST
            .replace(
                "runtime: wasm\nabi: sbproxy-envelope/v1",
                "runtime: javascript",
            )
            .replace("entry: dist/router.wasm", "entry: src/index.ts");
        let error = manifest_error(&yaml);
        assert!(
            error.contains("javascript") && error.contains("ai_routing"),
            "{error}"
        );
    }

    #[test]
    fn runtime_proxy_wasm_rejects_ai_routing_hooks() {
        // The proxy_wasm arm allows hooks by whitelist, so a new kind is
        // refused without naming it; this assertion keeps that true.
        let yaml = AI_ROUTING_WASM_MANIFEST
            .replace("runtime: wasm", "runtime: proxy_wasm")
            .replace("abi: sbproxy-envelope/v1", "abi: 0.2.1");
        let error = manifest_error(&yaml);
        assert!(
            error.contains("proxy_wasm may declare proxy_wasm or ai_stream_event hooks"),
            "{error}"
        );
    }

    // --- runtime: rego (WOR-2482) ---

    const REGO_POLICY_MANIFEST: &str = r#"
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: rego-authz
version: 1.0.0
runtime: rego
entry: policy.rego
hooks:
  - kind: policy
    type: rego_authz
    execution:
      body_mode: none
failure_posture: closed
sandbox:
  budget_ms: 50
permissions: []
"#;

    #[test]
    fn a_rego_policy_hook_validates() {
        let manifest = parse_manifest(REGO_POLICY_MANIFEST);
        assert_eq!(manifest.runtime, BundleRuntime::Rego);
        assert_eq!(manifest.hooks[0].kind, BundleHookKind::Policy);
        assert_eq!(manifest.hooks[0].query, None);
    }

    #[test]
    fn a_rego_hook_may_declare_a_query() {
        let yaml = replace_once(
            REGO_POLICY_MANIFEST,
            "    type: rego_authz\n",
            "    type: rego_authz\n    query: data.sbproxy.allow\n",
        );
        let manifest = parse_manifest(&yaml);
        assert_eq!(
            manifest.hooks[0].query.as_deref(),
            Some("data.sbproxy.allow")
        );
    }

    #[test]
    fn runtime_rego_refuses_the_sandbox_memory_knobs_it_cannot_honor() {
        // Retrospective review of PR #1153: `sandbox.memory_mb` and
        // `stack_kb` were documented as bounding a Rego bundle and never
        // reached `compile_rego_hook`. Regorus's own allocator guards
        // compile to `Ok(())` unless the `allocator-memory-limits`
        // feature is on, which this workspace does not enable, so the
        // number an operator wrote bounded nothing at all.
        for (field, value) in [("memory_mb", "32"), ("stack_kb", "1024")] {
            let yaml = replace_once(
                REGO_POLICY_MANIFEST,
                "sandbox:\n  budget_ms: 50\n",
                &format!("sandbox:\n  budget_ms: 50\n  {field}: {value}\n"),
            );
            let error = manifest_error(&yaml);
            assert!(
                error.contains(field) && error.contains("does not honor"),
                "a rego manifest setting {field} must be refused, got: {error}"
            );
        }

        // Writing nothing keeps loading, which is every shipped bundle.
        parse_manifest(REGO_POLICY_MANIFEST);
    }

    #[test]
    fn runtime_rego_requires_an_entry_ending_in_rego() {
        let yaml = REGO_POLICY_MANIFEST.replace("entry: policy.rego", "entry: policy.js");
        let error = manifest_error(&yaml);
        assert!(
            error.contains("runtime rego entry must end in .rego"),
            "{error}"
        );
    }

    #[test]
    fn runtime_rego_must_omit_abi() {
        let yaml = replace_once(
            REGO_POLICY_MANIFEST,
            "entry: policy.rego\n",
            "entry: policy.rego\nabi: sbproxy-envelope/v1\n",
        );
        let error = manifest_error(&yaml);
        assert!(error.contains("runtime rego must omit abi"), "{error}");
    }

    #[test]
    fn a_rego_hook_cannot_declare_export() {
        let yaml = replace_once(
            REGO_POLICY_MANIFEST,
            "    type: rego_authz\n",
            "    type: rego_authz\n    export: run\n",
        );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("rego hook `rego_authz` must omit export"),
            "{error}"
        );
    }

    #[test]
    fn a_rego_hook_requires_body_mode_none() {
        let yaml = replace_once(
            REGO_POLICY_MANIFEST,
            "      body_mode: none",
            "      body_mode: buffered",
        );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("rego hook `rego_authz` requires body_mode none"),
            "{error}"
        );
    }

    #[test]
    fn a_rego_transform_hook_validates() {
        // WOR-2493 item 6: `kind: transform` joined `kind: policy` as
        // a valid hook kind on runtime rego. A transform hook receives
        // the buffered response body, so its body_mode contract is
        // `buffered`, the opposite of the policy hook's `none`.
        let yaml = REGO_POLICY_MANIFEST
            .replace("kind: policy", "kind: transform")
            .replace("body_mode: none", "body_mode: buffered");
        let manifest = parse_manifest(&yaml);
        assert_eq!(manifest.hooks[0].kind, BundleHookKind::Transform);
    }

    #[test]
    fn a_rego_transform_hook_requires_body_mode_buffered() {
        let yaml = REGO_POLICY_MANIFEST.replace("kind: policy", "kind: transform");
        let error = manifest_error(&yaml);
        assert!(
            error.contains("rego transform hook `rego_authz` requires body_mode buffered"),
            "{error}"
        );
    }

    #[test]
    fn only_policy_and_transform_hooks_are_valid_on_runtime_rego() {
        let yaml = REGO_POLICY_MANIFEST.replace("kind: policy", "kind: action");
        let error = manifest_error(&yaml);
        assert!(
            error.contains("runtime rego may declare only policy and transform hooks"),
            "{error}"
        );
    }

    #[test]
    fn a_rego_hook_cannot_declare_capabilities() {
        let yaml = replace_once(
            REGO_POLICY_MANIFEST,
            "    execution:",
            "    permissions:\n      - net:outbound=https://pricing.example\n    execution:",
        );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("runtime rego has no host call surface"),
            "{error}"
        );
    }

    #[test]
    fn query_is_rejected_on_a_non_rego_runtime() {
        let yaml = AI_ROUTING_WASM_MANIFEST.replace(
            "    type: cost_quality_router\n",
            "    type: cost_quality_router\n    query: data.sbproxy.allow\n",
        );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("declares query, which only applies to runtime rego"),
            "{error}"
        );
    }

    #[test]
    fn parallel_mode_is_accepted_on_an_inspect_only_input_hook() {
        let yaml = replace_once(
            AI_INPUT_JS_MANIFEST,
            "      body_mode: none",
            "      body_mode: none\n      mode: parallel",
        );
        let manifest = parse_manifest(&yaml);
        assert_eq!(
            manifest.hooks[0].execution.mode,
            BundleExecutionMode::Parallel
        );
        assert!(!manifest.hooks[0].execution.mutates);
    }

    #[test]
    fn parallel_mode_cannot_combine_with_mutates() {
        let yaml = replace_once(
            AI_INPUT_JS_MANIFEST,
            "      body_mode: none",
            "      body_mode: none\n      mutates: true\n      mode: parallel",
        );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("parallel") && error.contains("mutates"),
            "{error}"
        );
    }

    #[test]
    fn parallel_mode_is_refused_on_output_hooks() {
        let yaml = AI_INPUT_JS_MANIFEST
            .replace("kind: ai_guardrail_input", "kind: ai_guardrail_output")
            .replace("export: inspect", "export: inspect")
            .replace(
                "      body_mode: none",
                "      body_mode: none\n      mode: parallel",
            );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("parallel") && error.contains("ai_guardrail_input"),
            "{error}"
        );
    }

    #[test]
    fn parallel_mode_cannot_combine_with_observe() {
        let yaml = replace_once(
            AI_INPUT_JS_MANIFEST,
            "    export: inspect\n    execution:",
            "    export: inspect\n    enforcement_mode: observe\n    execution:",
        );
        let yaml = replace_once(
            &yaml,
            "      body_mode: none",
            "      body_mode: none\n      mode: parallel",
        );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("parallel") && error.contains("observe"),
            "{error}"
        );
    }
}
