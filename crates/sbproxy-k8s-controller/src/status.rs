// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Gateway API status conditions.
//!
//! Every Gateway API resource carries a `status` subresource whose
//! `conditions` array is the only channel an operator has for finding out
//! whether the controller looked at their manifest and what it decided.
//! Without it `kubectl describe gateway` shows nothing and a typo in a
//! `backendRef` is indistinguishable from a healthy route.
//!
//! This module owns three things:
//!
//! * [`Condition`], a wire-compatible mirror of `metav1.Condition`. It is
//!   declared here rather than reused from `k8s-openapi` so the JSON
//!   shape the controller writes is visible in one place and does not
//!   move with a dependency bump.
//! * The condition `type` and `reason` string constants Gateway API
//!   defines. These are part of the contract with `kubectl` and with
//!   anything scripting against the resource, so they are constants
//!   rather than inline literals.
//! * [`merge_conditions`], which preserves `lastTransitionTime` across a
//!   reconcile that did not change a condition's `status`. Rewriting the
//!   timestamp on every pass would make "how long has this been broken"
//!   unanswerable and would churn the resource on every resync.
//!
//! Patch construction lives on the report types ([`GatewayClassReport`],
//! [`GatewayReport`], [`RouteReport`]) as `to_patch()`, which returns the
//! JSON merge patch body the controller sends to the `/status`
//! subresource.

use serde::{Deserialize, Serialize};

use crate::gateway_api::ParentReference;

/// `status: "True"` on a condition.
const CONDITION_TRUE: &str = "True";
/// `status: "False"` on a condition.
const CONDITION_FALSE: &str = "False";

/// `Accepted` condition type. Set on `GatewayClass`, `Gateway`, each
/// Gateway listener, and each route parent. True means the controller
/// understood the resource and took ownership of it.
pub const TYPE_ACCEPTED: &str = "Accepted";
/// `Programmed` condition type. Set on `Gateway` and each listener. True
/// means the controller has written the listener into a data plane
/// configuration document.
pub const TYPE_PROGRAMMED: &str = "Programmed";
/// `ResolvedRefs` condition type. Set on each listener and each route
/// parent. True means every reference the resource makes (TLS secrets,
/// backend services) was understood.
pub const TYPE_RESOLVED_REFS: &str = "ResolvedRefs";

/// Generic success reason, valid for `Accepted` and `ResolvedRefs`.
pub const REASON_ACCEPTED: &str = "Accepted";
/// Success reason for `Programmed`.
pub const REASON_PROGRAMMED: &str = "Programmed";
/// Success reason for `ResolvedRefs`.
pub const REASON_RESOLVED_REFS: &str = "ResolvedRefs";
/// `Gateway`/listener could not be programmed because its configuration
/// is not something this controller can render.
pub const REASON_INVALID: &str = "Invalid";
/// A listener's `protocol` is one this controller does not implement.
pub const REASON_UNSUPPORTED_PROTOCOL: &str = "UnsupportedProtocol";
/// A listener names a TLS certificate this controller cannot use.
pub const REASON_INVALID_CERTIFICATE_REF: &str = "InvalidCertificateRef";
/// A route rule names a backend this controller cannot resolve.
pub const REASON_BACKEND_NOT_FOUND: &str = "BackendNotFound";
/// A route's `parentRefs` did not select any listener on this Gateway.
pub const REASON_NO_MATCHING_PARENT: &str = "NoMatchingParent";
/// A route's hostnames did not intersect the listener's hostname.
pub const REASON_NO_MATCHING_LISTENER_HOSTNAME: &str = "NoMatchingListenerHostname";
/// The route uses a Gateway API feature this controller does not
/// implement. Not a Gateway API standard reason; it is namespaced by the
/// spec's rule that implementations may add their own.
pub const REASON_UNSUPPORTED_VALUE: &str = "UnsupportedValue";

/// A single status condition, wire-compatible with `metav1.Condition`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Condition type, for example `Accepted`.
    #[serde(rename = "type")]
    pub type_: String,
    /// `"True"` or `"False"`.
    pub status: String,
    /// `metadata.generation` this condition was computed from. An
    /// operator compares it against the live generation to tell a stale
    /// condition from a current one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// RFC 3339 timestamp of the last `status` flip, not of the last
    /// reconcile.
    pub last_transition_time: String,
    /// Machine-readable reason, one of the `REASON_*` constants.
    pub reason: String,
    /// Human-readable detail. Shown by `kubectl describe`.
    pub message: String,
}

impl Condition {
    /// Build a condition observed at `generation`, stamped `now`.
    ///
    /// `now` is passed in rather than read from the clock so tests get a
    /// deterministic timestamp and [`merge_conditions`] stays the only
    /// place that decides whether a timestamp moves.
    pub fn new(
        type_: &str,
        ok: bool,
        reason: &str,
        message: impl Into<String>,
        generation: Option<i64>,
        now: &str,
    ) -> Self {
        Self {
            type_: type_.to_string(),
            status: if ok { CONDITION_TRUE } else { CONDITION_FALSE }.to_string(),
            observed_generation: generation,
            last_transition_time: now.to_string(),
            reason: reason.to_string(),
            message: message.into(),
        }
    }
}

/// Current wall clock as an RFC 3339 string with second precision.
///
/// Second precision matches what the API server stores for
/// `metav1.Time`; sub-second digits are dropped on the round trip and
/// would make every comparison look like a change.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Carry `lastTransitionTime` forward for any desired condition whose
/// `status` matches the one already stored.
///
/// Everything else on the condition (reason, message, observedGeneration)
/// is taken from `desired`, because those describe the current pass even
/// when the boolean outcome did not move.
pub fn merge_conditions(existing: &[Condition], desired: Vec<Condition>) -> Vec<Condition> {
    desired
        .into_iter()
        .map(|mut want| {
            let held = existing
                .iter()
                .find(|c| c.type_ == want.type_ && c.status == want.status);
            if let Some(prev) = held {
                want.last_transition_time
                    .clone_from(&prev.last_transition_time);
            }
            want
        })
        .collect()
}

/// Status the controller wants to publish on one `GatewayClass`.
#[derive(Debug, Clone)]
pub struct GatewayClassReport {
    /// Cluster-scoped resource name.
    pub name: String,
    /// Conditions to publish, already merged.
    pub conditions: Vec<Condition>,
}

impl GatewayClassReport {
    /// JSON merge patch body for the `/status` subresource.
    pub fn to_patch(&self) -> serde_json::Value {
        serde_json::json!({ "status": { "conditions": self.conditions } })
    }
}

/// Status the controller wants to publish on one Gateway listener.
#[derive(Debug, Clone)]
pub struct ListenerReport {
    /// Listener `name`, unique within the Gateway.
    pub name: String,
    /// Route kinds this listener accepts, as `(group, kind)` pairs.
    pub supported_kinds: Vec<(String, String)>,
    /// How many routes bound to this listener on this pass.
    pub attached_routes: i32,
    /// Conditions to publish, already merged.
    pub conditions: Vec<Condition>,
}

/// Status the controller wants to publish on one `Gateway`.
#[derive(Debug, Clone)]
pub struct GatewayReport {
    /// Gateway namespace.
    pub namespace: String,
    /// Gateway name.
    pub name: String,
    /// Top-level conditions (`Accepted`, `Programmed`), already merged.
    pub conditions: Vec<Condition>,
    /// Per-listener status, in the order the listeners are declared.
    pub listeners: Vec<ListenerReport>,
}

impl GatewayReport {
    /// JSON merge patch body for the `/status` subresource.
    pub fn to_patch(&self) -> serde_json::Value {
        let listeners: Vec<serde_json::Value> = self
            .listeners
            .iter()
            .map(|l| {
                let kinds: Vec<serde_json::Value> = l
                    .supported_kinds
                    .iter()
                    .map(|(group, kind)| serde_json::json!({ "group": group, "kind": kind }))
                    .collect();
                serde_json::json!({
                    "name": l.name,
                    "supportedKinds": kinds,
                    "attachedRoutes": l.attached_routes,
                    "conditions": l.conditions,
                })
            })
            .collect();
        serde_json::json!({
            "status": {
                "conditions": self.conditions,
                "listeners": listeners,
            }
        })
    }
}

/// Status for one `parentRef` on one route.
#[derive(Debug, Clone)]
pub struct RouteParentReport {
    /// The `parentRef` this entry answers for, echoed back verbatim as
    /// Gateway API requires.
    pub parent_ref: ParentReference,
    /// Conditions (`Accepted`, `ResolvedRefs`), already merged.
    pub conditions: Vec<Condition>,
}

/// Which route kind a [`RouteReport`] belongs to, so the caller can pick
/// the right typed API handle to patch through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// `HTTPRoute`.
    Http,
    /// `GRPCRoute`.
    Grpc,
}

/// Status the controller wants to publish on one route.
#[derive(Debug, Clone)]
pub struct RouteReport {
    /// Which kind this route is.
    pub kind: RouteKind,
    /// Route namespace.
    pub namespace: String,
    /// Route name.
    pub name: String,
    /// One entry per `parentRef` this controller owns.
    pub parents: Vec<RouteParentReport>,
    /// The `parents` entries written by other controllers, read off the
    /// live object and carried through untouched.
    ///
    /// A route can be attached to several Gateways run by different
    /// implementations, and a JSON merge patch replaces an array
    /// wholesale. Dropping these would delete another controller's status
    /// on every reconcile.
    pub foreign_parents: Vec<serde_json::Value>,
}

impl RouteReport {
    /// JSON merge patch body for the `/status` subresource.
    pub fn to_patch(&self) -> serde_json::Value {
        let mut parents: Vec<serde_json::Value> = self.foreign_parents.clone();
        for p in &self.parents {
            parents.push(serde_json::json!({
                "parentRef": p.parent_ref,
                "controllerName": crate::CONTROLLER_NAME,
                "conditions": p.conditions,
            }));
        }
        serde_json::json!({ "status": { "parents": parents } })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-08-09T00:00:00Z";
    const T1: &str = "2026-08-09T01:00:00Z";

    fn cond(type_: &str, ok: bool, at: &str) -> Condition {
        Condition::new(type_, ok, REASON_ACCEPTED, "because", Some(3), at)
    }

    #[test]
    fn condition_serializes_with_the_kubernetes_field_names() {
        let value = serde_json::to_value(cond(TYPE_ACCEPTED, true, T0))
            .expect("condition serializes to JSON");
        assert_eq!(value["type"], "Accepted");
        assert_eq!(value["status"], "True");
        assert_eq!(value["observedGeneration"], 3);
        assert_eq!(value["lastTransitionTime"], T0);
        assert_eq!(value["reason"], "Accepted");
        assert_eq!(value["message"], "because");
    }

    #[test]
    fn observed_generation_is_omitted_when_absent() {
        let c = Condition::new(TYPE_ACCEPTED, true, REASON_ACCEPTED, "m", None, T0);
        let value = serde_json::to_value(c).expect("condition serializes to JSON");
        assert!(
            value.get("observedGeneration").is_none(),
            "an absent generation must not serialize as null: {value}"
        );
    }

    #[test]
    fn unchanged_status_keeps_the_original_transition_time() {
        let existing = vec![cond(TYPE_ACCEPTED, true, T0)];
        let merged = merge_conditions(&existing, vec![cond(TYPE_ACCEPTED, true, T1)]);
        assert_eq!(merged[0].last_transition_time, T0);
    }

    #[test]
    fn flipped_status_takes_the_new_transition_time() {
        let existing = vec![cond(TYPE_ACCEPTED, true, T0)];
        let merged = merge_conditions(&existing, vec![cond(TYPE_ACCEPTED, false, T1)]);
        assert_eq!(merged[0].last_transition_time, T1);
        assert_eq!(merged[0].status, CONDITION_FALSE);
    }

    #[test]
    fn merge_refreshes_reason_and_message_even_when_status_holds() {
        let existing = vec![Condition::new(
            TYPE_PROGRAMMED,
            false,
            REASON_INVALID,
            "old message",
            Some(1),
            T0,
        )];
        let desired = vec![Condition::new(
            TYPE_PROGRAMMED,
            false,
            REASON_UNSUPPORTED_PROTOCOL,
            "new message",
            Some(2),
            T1,
        )];
        let merged = merge_conditions(&existing, desired);
        assert_eq!(
            merged[0].last_transition_time, T0,
            "status held, so time holds"
        );
        assert_eq!(merged[0].reason, REASON_UNSUPPORTED_PROTOCOL);
        assert_eq!(merged[0].message, "new message");
        assert_eq!(merged[0].observed_generation, Some(2));
    }

    #[test]
    fn a_condition_with_no_prior_entry_keeps_its_own_time() {
        let merged = merge_conditions(&[], vec![cond(TYPE_RESOLVED_REFS, true, T1)]);
        assert_eq!(merged[0].last_transition_time, T1);
    }

    #[test]
    fn gateway_patch_carries_listeners_and_supported_kinds() {
        let report = GatewayReport {
            namespace: "default".to_string(),
            name: "gw".to_string(),
            conditions: vec![cond(TYPE_ACCEPTED, true, T0)],
            listeners: vec![ListenerReport {
                name: "http".to_string(),
                supported_kinds: vec![
                    (
                        "gateway.networking.k8s.io".to_string(),
                        "HTTPRoute".to_string(),
                    ),
                    (
                        "gateway.networking.k8s.io".to_string(),
                        "GRPCRoute".to_string(),
                    ),
                ],
                attached_routes: 2,
                conditions: vec![cond(TYPE_PROGRAMMED, true, T0)],
            }],
        };
        let patch = report.to_patch();
        assert_eq!(patch["status"]["conditions"][0]["type"], "Accepted");
        assert_eq!(patch["status"]["listeners"][0]["name"], "http");
        assert_eq!(patch["status"]["listeners"][0]["attachedRoutes"], 2);
        assert_eq!(
            patch["status"]["listeners"][0]["supportedKinds"][1]["kind"],
            "GRPCRoute"
        );
    }

    #[test]
    fn route_patch_preserves_another_controllers_parent_entry() {
        let foreign = vec![serde_json::json!({
            "parentRef": { "name": "nginx-gw" },
            "controllerName": "k8s.io/nginx-gateway-controller",
            "conditions": [],
        })];
        let report = RouteReport {
            kind: RouteKind::Http,
            namespace: "default".to_string(),
            name: "api".to_string(),
            parents: vec![RouteParentReport {
                parent_ref: ParentReference {
                    name: "sbproxy-gw".to_string(),
                    namespace: None,
                    section_name: None,
                    port: None,
                    group: None,
                    kind: None,
                },
                conditions: vec![cond(TYPE_ACCEPTED, true, T0)],
            }],
            foreign_parents: foreign,
        };
        let patch = report.to_patch();
        let parents = patch["status"]["parents"]
            .as_array()
            .expect("parents is an array");
        assert_eq!(parents.len(), 2);
        assert_eq!(
            parents[0]["controllerName"],
            "k8s.io/nginx-gateway-controller"
        );
        assert_eq!(parents[1]["controllerName"], crate::CONTROLLER_NAME);
        assert_eq!(parents[1]["parentRef"]["name"], "sbproxy-gw");
    }

    #[test]
    fn gateway_class_patch_is_conditions_only() {
        let report = GatewayClassReport {
            name: "sbproxy".to_string(),
            conditions: vec![cond(TYPE_ACCEPTED, true, T0)],
        };
        let patch = report.to_patch();
        assert_eq!(patch["status"]["conditions"][0]["reason"], "Accepted");
        assert!(patch["status"].get("listeners").is_none());
    }

    #[test]
    fn now_rfc3339_has_second_precision_and_a_z_suffix() {
        let now = now_rfc3339();
        assert!(now.ends_with('Z'), "expected a UTC Z suffix: {now}");
        assert!(
            !now.contains('.'),
            "expected second precision, got sub-second digits: {now}"
        );
    }
}
