// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Gateway API v1 resources as kube-rs types.
//!
//! `gateway.networking.k8s.io/v1` is not part of the core Kubernetes API
//! and so is absent from `k8s-openapi`. The kinds this controller reads
//! are declared here with `kube`'s `CustomResource` derive, which gives
//! the watcher a `Resource` impl and gives the client a typed handle on
//! the `/status` subresource.
//!
//! These are deliberately partial. Fields the controller does not act on
//! are simply not modeled, and serde ignores them on read, so a real
//! cluster object carrying `addresses`, `allowedRoutes`, or `infrastructure`
//! deserializes cleanly and those values are dropped. `docs/gateway-api.md`
//! lists what that costs.
//!
//! Everything here is `camelCase` on the wire and snake_case in Rust,
//! matching the upstream CRD schemas.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::status::Condition;

/// API group every kind in this module belongs to.
pub const GROUP: &str = "gateway.networking.k8s.io";

// --- GatewayClass ----------------------------------------------------

/// `gateway.networking.k8s.io/v1` `GatewayClass`. Cluster scoped.
///
/// A `GatewayClass` is how an implementation announces itself. The
/// controller claims every class whose `spec.controllerName` equals
/// [`crate::CONTROLLER_NAME`] and ignores `Gateway` resources pointing at
/// any other class.
#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "GatewayClass",
    plural = "gatewayclasses",
    status = "GatewayClassStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassSpec {
    /// Fully qualified name of the controller that manages Gateways of
    /// this class. Immutable once set, per the upstream CRD.
    pub controller_name: String,
    /// Free-form description surfaced by `kubectl describe`.
    #[serde(default)]
    pub description: Option<String>,
}

/// `status` subresource of a `GatewayClass`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassStatus {
    /// `Accepted` is the only condition defined for this kind.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

// --- Gateway ---------------------------------------------------------

/// `gateway.networking.k8s.io/v1` `Gateway`.
#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "Gateway",
    plural = "gateways",
    namespaced,
    status = "GatewayStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    /// Name of the `GatewayClass` that should manage this Gateway.
    pub gateway_class_name: String,
    /// Listeners exposed by the Gateway.
    #[serde(default)]
    pub listeners: Vec<Listener>,
}

/// One listener on a Gateway.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
    /// Listener name, unique within the Gateway. Routes select a
    /// listener by this value through `parentRefs[].sectionName`.
    pub name: String,
    /// Port the listener binds to.
    pub port: u16,
    /// Wire protocol. This controller implements `HTTP` and `HTTPS`.
    pub protocol: String,
    /// Hostname this listener answers for. When set, it intersects with
    /// each attached route's `hostnames`; when absent, the route's own
    /// hostnames stand alone.
    #[serde(default)]
    pub hostname: Option<String>,
    /// TLS termination configuration. Required for an `HTTPS` listener.
    #[serde(default)]
    pub tls: Option<GatewayTlsConfig>,
}

/// TLS block of a Gateway listener.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayTlsConfig {
    /// `Terminate` (default) or `Passthrough`. This controller
    /// implements `Terminate` only.
    #[serde(default)]
    pub mode: Option<String>,
    /// References to Secrets holding the certificate and key.
    #[serde(default)]
    pub certificate_refs: Vec<SecretObjectRef>,
}

/// Reference to a Secret holding a TLS certificate and key pair.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretObjectRef {
    /// Secret name.
    pub name: String,
    /// Secret namespace. Defaults to the Gateway's namespace; a
    /// cross-namespace reference additionally requires a `ReferenceGrant`,
    /// which this controller does not read.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// `status` subresource of a `Gateway`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatus {
    /// Gateway-scoped conditions: `Accepted` and `Programmed`.
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// Per-listener status, one entry per declared listener.
    #[serde(default)]
    pub listeners: Vec<ListenerStatus>,
}

/// One entry in `Gateway.status.listeners`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListenerStatus {
    /// Listener name this entry answers for.
    pub name: String,
    /// Conditions: `Accepted`, `Programmed`, `ResolvedRefs`.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

// --- Shared route pieces ---------------------------------------------

/// Reference from a route back to a Gateway.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ParentReference {
    /// API group of the parent. Defaults to `gateway.networking.k8s.io`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Parent kind. Defaults to `Gateway`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Parent namespace. Defaults to the route's own namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Parent Gateway name.
    pub name: String,
    /// Listener `name` to attach to. When absent the route attaches to
    /// every listener on the Gateway that its hostnames are compatible
    /// with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    /// Listener port to attach to. Modeled so it round-trips into
    /// status; this controller matches on `sectionName`, not port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl ParentReference {
    /// Whether this reference points at a `Gateway`.
    ///
    /// `group` and `kind` default to `gateway.networking.k8s.io` and
    /// `Gateway` respectively when omitted, which is the overwhelmingly
    /// common case. A reference to anything else is not ours.
    pub fn targets_a_gateway(&self) -> bool {
        let group = self.group.as_deref().unwrap_or(GROUP);
        let kind = self.kind.as_deref().unwrap_or("Gateway");
        (group == GROUP || group.is_empty()) && kind == "Gateway"
    }
}

/// Backend service reference shared by `HTTPRoute` and `GRPCRoute`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    /// Backend Service name.
    pub name: String,
    /// Service port.
    #[serde(default)]
    pub port: Option<u16>,
    /// Service namespace. Defaults to the route's namespace; a
    /// cross-namespace backend additionally requires a `ReferenceGrant`,
    /// which this controller does not read.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Relative share of traffic. Defaults to 1. A weight of 0 means the
    /// backend receives no traffic.
    #[serde(default)]
    pub weight: Option<u32>,
}

/// One entry in a route's filter chain.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteFilter {
    /// Filter discriminator, for example `RequestHeaderModifier`.
    #[serde(rename = "type")]
    pub filter_type: String,
    /// `RequestHeaderModifier` body.
    #[serde(default)]
    pub request_header_modifier: Option<HeaderFilter>,
}

/// `RequestHeaderModifier` filter body.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeaderFilter {
    /// Headers to set, replacing any existing value.
    #[serde(default)]
    pub set: Vec<HttpHeader>,
    /// Headers to append, preserving existing values.
    #[serde(default)]
    pub add: Vec<HttpHeader>,
    /// Header names to remove.
    #[serde(default)]
    pub remove: Vec<String>,
}

/// A header name and value pair.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HttpHeader {
    /// Header name.
    pub name: String,
    /// Header value.
    pub value: String,
}

/// Header predicate, shared by `HTTPRoute` and `GRPCRoute` matches.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeaderMatch {
    /// `Exact` (default) or `RegularExpression`.
    #[serde(rename = "type", default = "default_exact")]
    pub match_type: String,
    /// Header name. Matched case-insensitively per RFC 7230.
    pub name: String,
    /// Header value.
    pub value: String,
}

/// Query parameter predicate.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct QueryParamMatch {
    /// `Exact` (default) or `RegularExpression`.
    #[serde(rename = "type", default = "default_exact")]
    pub match_type: String,
    /// Parameter name. Case sensitive.
    pub name: String,
    /// Parameter value.
    pub value: String,
}

fn default_exact() -> String {
    "Exact".to_string()
}

/// `status` subresource shared by `HTTPRoute` and `GRPCRoute`.
///
/// `parents` is held as raw JSON rather than a typed list on purpose. A
/// route can be attached to Gateways run by several implementations at
/// once, and this controller must write its own entry back without
/// discarding or reshaping anyone else's. Round-tripping a foreign entry
/// through a partial Rust type would silently drop the fields this crate
/// does not model.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteStatus {
    /// One entry per `parentRef`, each tagged with its `controllerName`.
    #[serde(default)]
    pub parents: Vec<serde_json::Value>,
}

impl RouteStatus {
    /// The `parents` entries written by some other controller.
    ///
    /// Anything whose `controllerName` is not ours is foreign, including
    /// an entry with no `controllerName` at all: dropping an unlabeled
    /// entry would be a guess, and the safe guess is to leave it alone.
    pub fn foreign_parents(&self) -> Vec<serde_json::Value> {
        self.parents
            .iter()
            .filter(|p| {
                p.get("controllerName").and_then(|c| c.as_str()) != Some(crate::CONTROLLER_NAME)
            })
            .cloned()
            .collect()
    }

    /// Conditions this controller previously published for `parent_name`,
    /// used to hold `lastTransitionTime` steady across a reconcile.
    pub fn own_conditions(&self, parent_name: &str) -> Vec<Condition> {
        self.parents
            .iter()
            .find(|p| {
                p.get("controllerName").and_then(|c| c.as_str()) == Some(crate::CONTROLLER_NAME)
                    && p.get("parentRef")
                        .and_then(|r| r.get("name"))
                        .and_then(|n| n.as_str())
                        == Some(parent_name)
            })
            .and_then(|p| p.get("conditions"))
            .and_then(|c| serde_json::from_value::<Vec<Condition>>(c.clone()).ok())
            .unwrap_or_default()
    }
}

// --- HTTPRoute -------------------------------------------------------

/// `gateway.networking.k8s.io/v1` `HTTPRoute`.
#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "HTTPRoute",
    plural = "httproutes",
    namespaced,
    status = "RouteStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteSpec {
    /// Gateways this route attaches to.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,
    /// Hostnames this route answers for. May carry a leading `*.` label.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Routing rules, evaluated by Gateway API precedence rather than
    /// declaration order.
    #[serde(default)]
    pub rules: Vec<HTTPRouteRule>,
}

/// One rule in an `HTTPRoute`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteRule {
    /// Match predicates, ORed together. An empty list matches every
    /// request for the route's hostnames.
    #[serde(default)]
    pub matches: Vec<HTTPRouteMatch>,
    /// Filter chain applied before forwarding.
    #[serde(default)]
    pub filters: Vec<RouteFilter>,
    /// Backends to forward to.
    #[serde(default)]
    pub backend_refs: Vec<BackendRef>,
}

/// Predicate matched against an incoming HTTP request. Every field
/// present must match; the fields are ANDed.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteMatch {
    /// Path predicate. Defaults to a `PathPrefix` of `/`.
    #[serde(default)]
    pub path: Option<PathMatch>,
    /// Header predicates.
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
    /// Query parameter predicates.
    #[serde(default)]
    pub query_params: Vec<QueryParamMatch>,
    /// HTTP method predicate.
    #[serde(default)]
    pub method: Option<String>,
}

/// Path predicate.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PathMatch {
    /// `Exact`, `PathPrefix` (default), or `RegularExpression`.
    #[serde(rename = "type", default = "default_path_prefix")]
    pub match_type: String,
    /// Match value. Defaults to `/`.
    #[serde(default = "default_root_path")]
    pub value: String,
}

fn default_path_prefix() -> String {
    "PathPrefix".to_string()
}

fn default_root_path() -> String {
    "/".to_string()
}

// --- GRPCRoute -------------------------------------------------------

/// `gateway.networking.k8s.io/v1` `GRPCRoute`.
#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "GRPCRoute",
    plural = "grpcroutes",
    namespaced,
    status = "RouteStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct GRPCRouteSpec {
    /// Gateways this route attaches to.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,
    /// Hostnames this route answers for.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Routing rules.
    #[serde(default)]
    pub rules: Vec<GRPCRouteRule>,
}

/// One rule in a `GRPCRoute`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GRPCRouteRule {
    /// Match predicates, ORed together.
    #[serde(default)]
    pub matches: Vec<GRPCRouteMatch>,
    /// Filter chain applied before forwarding.
    #[serde(default)]
    pub filters: Vec<RouteFilter>,
    /// Backends to forward to.
    #[serde(default)]
    pub backend_refs: Vec<BackendRef>,
}

/// Predicate matched against an incoming gRPC call.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GRPCRouteMatch {
    /// Service and method predicate.
    #[serde(default)]
    pub method: Option<GRPCMethodMatch>,
    /// Header predicates.
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
}

/// gRPC service and method predicate.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GRPCMethodMatch {
    /// `Exact` (default) or `RegularExpression`.
    #[serde(rename = "type", default = "default_exact")]
    pub match_type: String,
    /// Fully qualified gRPC service name.
    #[serde(default)]
    pub service: Option<String>,
    /// gRPC method name.
    #[serde(default)]
    pub method: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_deserializes_from_the_camel_case_wire_shape() {
        let json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "sbproxy-sample", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "hostname": "api.example.com",
                    "allowedRoutes": { "namespaces": { "from": "All" } },
                    "tls": {
                        "mode": "Terminate",
                        "certificateRefs": [{ "kind": "Secret", "name": "api-cert" }]
                    }
                }]
            }
        });
        let gw: Gateway = serde_json::from_value(json).expect("Gateway deserializes");
        assert_eq!(gw.spec.gateway_class_name, "sbproxy");
        let l = &gw.spec.listeners[0];
        assert_eq!(l.port, 443);
        assert_eq!(l.hostname.as_deref(), Some("api.example.com"));
        let tls = l.tls.as_ref().expect("listener carries tls");
        assert_eq!(tls.mode.as_deref(), Some("Terminate"));
        assert_eq!(tls.certificate_refs[0].name, "api-cert");
    }

    #[test]
    fn unmodeled_fields_are_ignored_rather_than_failing_the_watch() {
        // A real cluster object carries `addresses` and `infrastructure`.
        // Rejecting them would take the whole watch stream down.
        let json = serde_json::json!({
            "metadata": { "name": "gw" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [],
                "addresses": [{ "type": "IPAddress", "value": "10.0.0.1" }],
                "infrastructure": { "labels": { "a": "b" } }
            }
        });
        let gw: Gateway = serde_json::from_value(json).expect("unknown spec fields are ignored");
        assert!(gw.spec.listeners.is_empty());
    }

    #[test]
    fn http_route_match_defaults_fill_in_the_upstream_defaults() {
        let json = serde_json::json!({
            "metadata": { "name": "api" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-sample" }],
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{ "headers": [{ "name": "X-Canary", "value": "1" }] }],
                    "backendRefs": [{ "name": "api-svc", "port": 8080 }]
                }]
            }
        });
        let route: HTTPRoute = serde_json::from_value(json).expect("HTTPRoute deserializes");
        let m = &route.spec.rules[0].matches[0];
        assert!(
            m.path.is_none(),
            "an omitted path stays absent, not defaulted"
        );
        assert_eq!(m.headers[0].match_type, "Exact");
        assert!(m.query_params.is_empty());
        let backend = &route.spec.rules[0].backend_refs[0];
        assert_eq!(backend.weight, None);
    }

    #[test]
    fn a_path_match_with_only_a_value_defaults_to_path_prefix() {
        let pm: PathMatch =
            serde_json::from_value(serde_json::json!({ "value": "/api" })).expect("PathMatch");
        assert_eq!(pm.match_type, "PathPrefix");
        assert_eq!(pm.value, "/api");
    }

    #[test]
    fn parent_ref_defaults_identify_a_gateway() {
        let plain = ParentReference {
            group: None,
            kind: None,
            namespace: None,
            name: "gw".to_string(),
            section_name: None,
            port: None,
        };
        assert!(plain.targets_a_gateway());

        let mesh = ParentReference {
            kind: Some("Service".to_string()),
            ..plain.clone()
        };
        assert!(
            !mesh.targets_a_gateway(),
            "a Service parentRef is the mesh binding, which we do not implement"
        );

        let other_group = ParentReference {
            group: Some("networking.example.io".to_string()),
            ..plain
        };
        assert!(!other_group.targets_a_gateway());
    }

    #[test]
    fn parent_ref_omits_absent_optionals_when_echoed_into_status() {
        let value = serde_json::to_value(ParentReference {
            group: None,
            kind: None,
            namespace: None,
            name: "gw".to_string(),
            section_name: Some("http".to_string()),
            port: None,
        })
        .expect("ParentReference serializes");
        assert_eq!(value["name"], "gw");
        assert_eq!(value["sectionName"], "http");
        assert!(value.get("namespace").is_none());
        assert!(value.get("port").is_none());
    }

    #[test]
    fn route_status_separates_foreign_parents_from_our_own() {
        let status = RouteStatus {
            parents: vec![
                serde_json::json!({
                    "parentRef": { "name": "nginx-gw" },
                    "controllerName": "k8s.io/nginx-gateway-controller",
                    "conditions": [],
                    "somethingWeDoNotModel": true
                }),
                serde_json::json!({
                    "parentRef": { "name": "sbproxy-gw" },
                    "controllerName": crate::CONTROLLER_NAME,
                    "conditions": [{
                        "type": "Accepted",
                        "status": "True",
                        "lastTransitionTime": "2026-08-09T00:00:00Z",
                        "reason": "Accepted",
                        "message": "ok"
                    }]
                }),
            ],
        };

        let foreign = status.foreign_parents();
        assert_eq!(foreign.len(), 1);
        assert_eq!(
            foreign[0]["somethingWeDoNotModel"], true,
            "a foreign entry must round-trip byte for byte"
        );

        let ours = status.own_conditions("sbproxy-gw");
        assert_eq!(ours.len(), 1);
        assert_eq!(ours[0].last_transition_time, "2026-08-09T00:00:00Z");

        assert!(
            status.own_conditions("some-other-gw").is_empty(),
            "conditions are keyed by parent name"
        );
    }

    #[test]
    fn an_unlabeled_parent_entry_is_treated_as_foreign() {
        let status = RouteStatus {
            parents: vec![serde_json::json!({ "parentRef": { "name": "mystery" } })],
        };
        assert_eq!(status.foreign_parents().len(), 1);
    }

    #[test]
    fn grpc_route_deserializes_a_method_match() {
        let json = serde_json::json!({
            "metadata": { "name": "chat" },
            "spec": {
                "parentRefs": [{ "name": "gw", "sectionName": "grpc" }],
                "hostnames": ["grpc.example.com"],
                "rules": [{
                    "matches": [{ "method": { "service": "chat.v1.Chat", "method": "Send" } }],
                    "backendRefs": [{ "name": "chat-svc", "port": 50051, "weight": 3 }]
                }]
            }
        });
        let route: GRPCRoute = serde_json::from_value(json).expect("GRPCRoute deserializes");
        assert_eq!(
            route.spec.parent_refs[0].section_name.as_deref(),
            Some("grpc")
        );
        let m = route.spec.rules[0].matches[0]
            .method
            .as_ref()
            .expect("method match present");
        assert_eq!(m.match_type, "Exact");
        assert_eq!(m.service.as_deref(), Some("chat.v1.Chat"));
        assert_eq!(route.spec.rules[0].backend_refs[0].weight, Some(3));
    }

    #[test]
    fn gateway_class_is_cluster_scoped_and_carries_a_controller_name() {
        let json = serde_json::json!({
            "metadata": { "name": "sbproxy" },
            "spec": { "controllerName": crate::CONTROLLER_NAME }
        });
        let class: GatewayClass = serde_json::from_value(json).expect("GatewayClass deserializes");
        assert_eq!(class.spec.controller_name, crate::CONTROLLER_NAME);
        assert!(class.metadata.namespace.is_none());
    }
}
