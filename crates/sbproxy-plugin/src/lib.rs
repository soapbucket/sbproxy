//! Plugin traits, registry, and lifecycle management for SBproxy.
//!
//! This crate defines the public API every module depends on.
//!
//! - [`traits`] - Dynamic dispatch interfaces for third-party plugins.
//! - [`lifecycle`] - Provision, validate, init, cleanup phases.
//! - [`context`] - Plugin context passed during provisioning.
//! - [`registry`] - Inventory-based plugin discovery at link time.
//! - [`identity`] - Identity, classification, and anomaly hook surface.
//! - [`mcp`] - MCP pre-tool-call policy hook trait surface.
//! - [`audit`] - Admin-action audit emitter trait surface.
//! - [`verdict_combine`] - Combine multiple `PolicyDecision` votes
//!   into a single terminal verdict per the combination matrix.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod context;
pub mod error;
pub mod extensions;
pub mod identity;
pub mod lifecycle;
pub mod mcp;
pub mod principal;
pub mod registry;
pub mod traits;
pub mod verdict_combine;

pub use audit::{
    current_admin_audit_emitter, install_admin_audit_emitter, AdminAuditEmitter,
    NoOpAdminAuditEmitter, ProjectionRefreshEvent,
};
pub use context::*;
pub use error::{PluginError, PluginResult};
pub use extensions::*;
pub use identity::{
    anomaly_hooks, identity_hooks, ml_classifier_hooks, register_anomaly_hook,
    register_identity_hook, register_ml_classifier_hook, AgentIdSourceLabel, AnomalyDetectorHook,
    AnomalyVerdict, IdentityHeaderLookup, IdentityRequest, IdentityResolverHook, IdentityVerdict,
    MlClassificationResult, MlClassifierHook, RequestContextView, RequestSnapshotView,
};
pub use lifecycle::*;
pub use mcp::{
    default_no_op_hook, mcp_policy_hooks, register_mcp_policy_hook, McpPolicyHook,
    McpPolicyHookEntry, McpToolCallCtx, NoOpMcpPolicyHook,
};
pub use principal::{
    Credential, DelegationSubject, McpExecutionContext, Principal, PrincipalAttrs, PrincipalSource,
    SecretRef, TenantId, VirtualKeyRef,
};
pub use registry::*;
pub use traits::*;
pub use verdict_combine::{combine_verdicts, CombinedVerdict};

#[cfg(test)]
mod extension_contract_tests {
    use super::*;

    inventory::submit! {
        ExtensionBundleDeclaration {
            id: "fixture-z",
            name: "Fixture Z",
            version: "1.0.0",
            package: None,
            runtime: ExtensionRuntime::Rust,
            hooks: &[],
        }
    }

    inventory::submit! {
        ExtensionBundleDeclaration {
            id: "fixture-a",
            name: "Fixture A",
            version: "1.0.0",
            package: Some("fixture-a-package"),
            runtime: ExtensionRuntime::Rust,
            hooks: &[],
        }
    }

    #[test]
    fn linked_extension_declarations_are_sorted_by_bundle_id() {
        let declarations = collect_linked_extension_declarations();
        assert!(declarations.windows(2).all(|pair| pair[0].id <= pair[1].id));
        assert!(declarations.iter().any(|bundle| bundle.id == "fixture-a"));
        assert!(declarations.iter().any(|bundle| bundle.id == "fixture-z"));
    }

    #[test]
    fn extension_inventory_enums_serialize_as_snake_case() {
        assert_eq!(
            serde_json::to_value(ExtensionRuntime::ProxyWasm).unwrap(),
            "proxy_wasm"
        );
        assert_eq!(
            serde_json::to_value(ExtensionHookKind::AiGuardrailInput).unwrap(),
            "ai_guardrail_input"
        );
        assert_eq!(
            serde_json::to_value(ExtensionDispatch::Exclusive).unwrap(),
            "exclusive"
        );
        assert_eq!(
            serde_json::to_value(ExtensionBodyMode::Streamed).unwrap(),
            "streamed"
        );
        assert_eq!(
            serde_json::to_value(ExtensionRegistrationSource::LinkTime).unwrap(),
            "link_time"
        );
        assert_eq!(
            serde_json::to_value(ExtensionState::NotEvaluated).unwrap(),
            "not_evaluated"
        );
        assert_eq!(
            serde_json::to_value(ExtensionScopeMode::Running).unwrap(),
            "running"
        );
    }
}
