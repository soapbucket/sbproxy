//! Immutable extension bundle discovery and lookup.
//!
//! Candidate registries own executable bytes, parsed manifests, compiled
//! configuration schemas, and safe provenance. Loading never mutates the
//! process-wide static plugin registries.

mod envelope;
mod envelope_wasm;
mod javascript;
mod loader;
mod proxy_wasm;
mod registry;
#[cfg(test)]
mod tests;

pub use envelope_wasm::{
    build_wasm_action, build_wasm_policy, build_wasm_transform, WasmActionAdapter,
    WasmPolicyAdapter, WasmTransformAdapter,
};
pub use javascript::{
    build_javascript_action, build_javascript_policy, build_javascript_transform,
    transpile_typescript, JavascriptActionAdapter, JavascriptPolicyAdapter,
    JavascriptTransformAdapter, JAVASCRIPT_ENVELOPE_VERSION,
};
pub use loader::{BundleLoadError, DynamicBundleRegistry, MAX_BUNDLE_ARTIFACT_BYTES};
pub use proxy_wasm::{
    build_proxy_wasm_filter, ProxyWasmAction, ProxyWasmBodyResult, ProxyWasmCallFailure,
    ProxyWasmFilter, ProxyWasmHeaderResult, ProxyWasmLocalResponse, ProxyWasmSession,
};
pub use registry::{
    BundleConfigValidationError, BundleProvenance, BundleRegistry, LoadedBundleHook,
};
