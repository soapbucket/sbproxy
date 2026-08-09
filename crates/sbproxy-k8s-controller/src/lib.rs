// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Kubernetes Gateway API controller for sbproxy.
//!
//! Watches `gateway.networking.k8s.io/v1` `GatewayClass`, `Gateway`,
//! `HTTPRoute`, and `GRPCRoute` resources and renders them into a single
//! `sb.yml` document the sbproxy data plane reads.
//!
//! This implements a subset of Gateway API v1 and is **not conformance
//! tested**. `docs/gateway-api.md` lists exactly what is supported, what
//! is not, and what an unsupported field does when it appears.
//!
//! # Shape
//!
//! The binary in `main.rs` is a thin entry point. Everything worth
//! testing lives here so the translation runs without a cluster:
//!
//! * [`gateway_api`] declares the upstream CRDs as kube-rs resources.
//! * [`config_writer`] is a pure function from those resources to a
//!   config document. Its tests feed every generated document through the
//!   real `sbproxy_config::compile_config`, so a shape the data plane
//!   would reject fails in this crate rather than in a pod that will not
//!   start.
//! * [`status`] holds the Gateway API condition vocabulary and the JSON
//!   merge patches the controller sends to each `/status` subresource.
//! * [`reconciler`] is one pure pass: snapshot in, document written,
//!   status reports out.
//! * [`controller`] owns the watch streams, the reconcile queue, and the
//!   status writes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config_writer;
pub mod controller;
pub mod gateway_api;
pub mod health;
pub mod metrics;
pub mod reconciler;
pub mod shutdown;
pub mod status;

/// The `spec.controllerName` this controller claims.
///
/// A `GatewayClass` naming this string is owned by this controller;
/// a `Gateway` referencing any other class is ignored entirely, along
/// with the routes attached to it. Changing this value orphans every
/// `GatewayClass` already in the field, so treat it as a wire constant.
pub const CONTROLLER_NAME: &str = "sbproxy.dev/gateway-controller";
