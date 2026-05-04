//! Plugin traits, registry, and lifecycle management for SBproxy.
//!
//! This crate defines the public API every module depends on.
//!
//! - [`traits`] - Dynamic dispatch interfaces for third-party plugins.
//! - [`lifecycle`] - Provision, validate, init, cleanup phases.
//! - [`context`] - Plugin context passed during provisioning.
//! - [`registry`] - Inventory-based plugin discovery at link time.
//! - [`identity`] - Identity, classification, and anomaly hook surface.
//! - [`audit`] - Admin-action audit emitter trait surface.

#![warn(missing_docs)]

pub mod audit;
pub mod context;
pub mod identity;
pub mod lifecycle;
pub mod registry;
pub mod traits;

pub use audit::{
    current_admin_audit_emitter, install_admin_audit_emitter, AdminAuditEmitter,
    NoOpAdminAuditEmitter, ProjectionRefreshEvent,
};
pub use context::*;
pub use identity::{
    anomaly_hooks, identity_hooks, ml_classifier_hooks, register_anomaly_hook,
    register_identity_hook, register_ml_classifier_hook, AgentIdSourceLabel, AnomalyDetectorHook,
    AnomalyVerdict, IdentityHeaderLookup, IdentityRequest, IdentityResolverHook, IdentityVerdict,
    MlClassificationResult, MlClassifierHook, RequestContextView, RequestSnapshotView,
};
pub use lifecycle::*;
pub use registry::*;
pub use traits::*;
