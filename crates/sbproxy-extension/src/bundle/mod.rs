//! Immutable extension bundle discovery and lookup.
//!
//! Candidate registries own executable bytes, parsed manifests, compiled
//! configuration schemas, and safe provenance. Loading never mutates the
//! process-wide static plugin registries.

mod javascript;
mod loader;
mod registry;
#[cfg(test)]
mod tests;

pub use javascript::{
    build_javascript_action, build_javascript_policy, build_javascript_transform,
    transpile_typescript, JavascriptActionAdapter, JavascriptPolicyAdapter,
    JavascriptTransformAdapter, JAVASCRIPT_ENVELOPE_VERSION,
};
pub use loader::{BundleLoadError, DynamicBundleRegistry, MAX_BUNDLE_ARTIFACT_BYTES};
pub use registry::{
    BundleConfigValidationError, BundleProvenance, BundleRegistry, LoadedBundleHook,
};
