//! OSS Kubernetes operator library for sbproxy.
//!
//! This crate exposes the CRD types ([`SBProxy`] and [`SBProxyConfig`]) and the
//! reconciliation logic so external tooling (tests, kubectl plugins, the operator
//! binary itself) can depend on a single source of truth.
//!
//! The binary entrypoint lives in `src/main.rs` and wires these pieces into a
//! `kube_runtime::Controller` watcher.
//!
//! # Custom Resources
//!
//! Two CRDs are defined:
//!
//! - [`SBProxy`] (`sbproxy.dev/v1alpha1`): a desired proxy deployment. Spec carries
//!   replica count, image, resource requests/limits, and the name of an
//!   [`SBProxyConfig`] to mount as the proxy's `sb.yml`.
//! - [`SBProxyConfig`] (`sbproxy.dev/v1alpha1`): a versioned `sb.yml` document.
//!   Spec.config is a YAML string. The operator does not deeply validate it; the
//!   proxy itself is the source of truth at reload time.
//!
//! # Reconcile model
//!
//! Idempotent. Each reconcile renders a desired Deployment / Service / ConfigMap
//! triple and applies it server-side. Config changes trigger a rollout-restart
//! by stamping `sbproxy.dev/config-hash` on the Deployment's pod template.

#![deny(missing_docs)]

/// CRD type definitions.
pub mod crd;

/// Reconciliation logic. Pure functions where possible; the kube-runtime wiring
/// lives in `main.rs`.
pub mod reconcile;

/// Leader-election helpers. Implements a manual `coordination.k8s.io/v1.Lease`
/// loop. `kube-runtime` 0.95 has no built-in helper at the pinned version, so
/// we drive the well-trodden Lease pattern by hand. See module docs for the
/// timing constants and the step-down semantics.
pub mod leader;

pub use crd::{SBProxy, SBProxyConfig, SBProxyConfigSpec, SBProxySpec};
