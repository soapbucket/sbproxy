use std::collections::BTreeMap;
use std::sync::Arc;

use jsonschema::JSONSchema;
use sbproxy_config::{BundleHook, BundleHookKind, BundleManifest};
use sbproxy_plugin::ExtensionRegistrationSource;
use thiserror::Error;

use super::proxy_wasm::ProxyWasmRuntime;
use crate::wasm::WasmRuntime;

/// Safe source provenance retained by one loaded bundle hook.
///
/// Directory provenance records only declaration position. Git provenance
/// keeps a redacted repository URL and verified revision, never credentials or
/// checkout paths.
#[derive(Clone, PartialEq, Eq)]
pub enum BundleProvenance {
    /// A configured local directory source.
    Directory {
        /// Zero-based candidate source position.
        source_index: u32,
    },
    /// A verified Git source.
    Git {
        /// Zero-based candidate source position.
        source_index: u32,
        /// Repository URL with user information removed.
        repo: String,
        /// Commit or signed reference requested by the operator.
        reference: String,
        /// Commit resolved and verified by the Git materializer.
        commit: String,
    },
}

impl std::fmt::Debug for BundleProvenance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Directory { source_index } => formatter
                .debug_struct("Directory")
                .field("source_index", source_index)
                .finish(),
            Self::Git {
                source_index,
                repo,
                reference,
                commit,
            } => formatter
                .debug_struct("Git")
                .field("source_index", source_index)
                .field("repo", repo)
                .field("reference", reference)
                .field("commit", commit)
                .finish(),
        }
    }
}

impl BundleProvenance {
    /// Return the public registration-source category.
    #[must_use]
    pub const fn source(&self) -> ExtensionRegistrationSource {
        match self {
            Self::Directory { .. } => ExtensionRegistrationSource::Directory,
            Self::Git { .. } => ExtensionRegistrationSource::Git,
        }
    }
}

/// One immutable executable hook in a candidate registry.
pub struct LoadedBundleHook {
    pub(crate) manifest: Arc<BundleManifest>,
    pub(crate) hook: BundleHook,
    pub(crate) artifact: Arc<[u8]>,
    pub(crate) javascript_source: Option<Arc<str>>,
    pub(crate) wasm_runtime: Option<Arc<WasmRuntime>>,
    pub(crate) proxy_wasm_runtime: Option<Arc<ProxyWasmRuntime>>,
    pub(crate) sha256: String,
    pub(crate) config_validator: Option<Arc<JSONSchema>>,
    pub(crate) provenance: BundleProvenance,
}

impl std::fmt::Debug for LoadedBundleHook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedBundleHook")
            .field("bundle", &self.manifest.name)
            .field("kind", &self.hook.kind)
            .field("type_name", &self.hook.type_name)
            .field("sha256", &self.sha256)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl LoadedBundleHook {
    /// Return the validated bundle manifest shared by this hook.
    #[must_use]
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    /// Return this hook's validated declaration.
    #[must_use]
    pub const fn hook(&self) -> &BundleHook {
        &self.hook
    }

    /// Return the executable bytes captured when the candidate loaded.
    #[must_use]
    pub fn artifact(&self) -> &[u8] {
        &self.artifact
    }

    /// Return the source prepared once for a JavaScript runtime hook.
    pub(crate) fn prepared_javascript_source(&self) -> Option<&Arc<str>> {
        self.javascript_source.as_ref()
    }

    /// Return the module compiled once for all hooks in a WASM bundle.
    pub(crate) fn prepared_wasm_runtime(&self) -> Option<&Arc<WasmRuntime>> {
        self.wasm_runtime.as_ref()
    }

    /// Return the module compiled once for all filters in a Proxy-Wasm bundle.
    pub(crate) fn prepared_proxy_wasm_runtime(&self) -> Option<&Arc<ProxyWasmRuntime>> {
        self.proxy_wasm_runtime.as_ref()
    }

    /// Return the lowercase SHA-256 digest computed from [`Self::artifact`].
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Return the compiled Draft 7 configuration validator, when declared.
    #[must_use]
    pub fn config_validator(&self) -> Option<&JSONSchema> {
        self.config_validator.as_deref()
    }

    /// Validate one attachment configuration against the compiled schema.
    ///
    /// # Errors
    ///
    /// Returns a bounded validation error when the hook declared a schema and
    /// the supplied value does not satisfy it.
    pub fn validate_config(
        &self,
        value: &serde_json::Value,
    ) -> Result<(), BundleConfigValidationError> {
        let Some(validator) = &self.config_validator else {
            return Ok(());
        };
        validator.validate(value).map_err(|mut errors| {
            let detail = errors.next().map_or_else(
                || "schema validation failed".to_owned(),
                |error| {
                    format!(
                        "value at `{}` violates the Draft 7 rule at `{}`",
                        error.instance_path, error.schema_path
                    )
                },
            );
            BundleConfigValidationError::new(detail)
        })
    }

    /// Return safe source provenance for this hook.
    #[must_use]
    pub const fn provenance(&self) -> &BundleProvenance {
        &self.provenance
    }
}

/// A bounded configuration validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("bundle hook configuration is invalid: {detail}")]
pub struct BundleConfigValidationError {
    detail: String,
}

impl BundleConfigValidationError {
    fn new(detail: String) -> Self {
        Self {
            detail: super::loader::sanitize_detail(&detail, 470),
        }
    }
}

/// Immutable kind-aware lookup surface used during pipeline compilation.
pub trait BundleRegistry {
    /// Look up one dynamic policy by its `type:` value.
    fn policy(&self, type_name: &str) -> Option<&LoadedBundleHook>;
    /// Look up one dynamic transform by its `type:` value.
    fn transform(&self, type_name: &str) -> Option<&LoadedBundleHook>;
    /// Look up one dynamic action by its `type:` value.
    fn action(&self, type_name: &str) -> Option<&LoadedBundleHook>;
    /// Look up one Proxy-Wasm filter by its `type:` value.
    fn proxy_wasm_filter(&self, type_name: &str) -> Option<&LoadedBundleHook>;
    /// Return all hooks of one AI event kind in deterministic order.
    fn ai_hooks(&self, kind: BundleHookKind) -> Vec<&LoadedBundleHook>;
    /// Return payment hooks in deterministic order.
    fn payment_hooks(&self) -> Vec<&LoadedBundleHook>;
}

pub(crate) fn lookup<'a>(
    hooks: &'a BTreeMap<(BundleHookKind, String), Arc<LoadedBundleHook>>,
    kind: BundleHookKind,
    type_name: &str,
) -> Option<&'a LoadedBundleHook> {
    hooks.get(&(kind, type_name.to_owned())).map(AsRef::as_ref)
}
