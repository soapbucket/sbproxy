// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! One reconcile pass: cluster snapshot in, config document and status
//! reports out.
//!
//! The reconciler owns two decisions the renderer deliberately does not.
//!
//! First, ownership. A `Gateway` belongs to this controller only when its
//! `gatewayClassName` names a `GatewayClass` whose `spec.controllerName`
//! is [`crate::CONTROLLER_NAME`]. Nothing else is looked at, and a
//! Gateway pointing at somebody else's class contributes no origins and
//! gets no status written. Until a matching `GatewayClass` exists in the
//! cluster the controller owns nothing, which is the Gateway API model:
//! the class is how an implementation announces itself.
//!
//! Second, status. The renderer reports per-listener and per-parentRef
//! outcomes as plain data; this module turns them into `Accepted`,
//! `Programmed`, and `ResolvedRefs` conditions stamped with
//! `observedGeneration`, merged against whatever is already on the object
//! so `lastTransitionTime` only moves when the answer changes.
//!
//! Writing the document is the only side effect. Patching the status
//! reports back is the controller's job, because that needs a client.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::config_writer::{self, WriterOptions};
use crate::gateway_api::{GRPCRoute, Gateway, GatewayClass, HTTPRoute, RouteStatus, GROUP};
use crate::status::{
    self, Condition, GatewayClassReport, GatewayReport, ListenerReport, RouteKind,
    RouteParentReport, RouteReport,
};

/// Route kinds a listener on this controller accepts.
const SUPPORTED_ROUTE_KINDS: [&str; 2] = ["HTTPRoute", "GRPCRoute"];

/// Everything the reconciler needs that is not cluster state.
#[derive(Debug, Clone)]
pub struct ReconcilerConfig {
    /// Path the rendered `sb.yml` is written to.
    pub output_path: PathBuf,
    /// Narrow this replica to a single `GatewayClass` name. `None`, the
    /// default, serves every class that names our `controllerName`.
    pub gateway_class: Option<String>,
    /// Rendering knobs.
    pub writer: WriterOptions,
    /// Leadership fence (WOR-2614). Every reconcile checks this before
    /// writing the document, and the controller checks it again before
    /// publishing status, so a replica that lost its Lease stops writing
    /// the moment the loss is observed. [`crate::leader::WriteGate::always`]
    /// (the `Default`) is the single-replica, no-election posture.
    pub write_gate: crate::leader::WriteGate,
}

/// What one reconcile pass produced.
#[derive(Debug)]
pub struct ReconcileOutcome {
    /// Origins in the document that was written.
    pub origins: usize,
    /// Gateways that belonged to a class this controller owns.
    pub gateways_owned: usize,
    /// Status to publish on each owned `GatewayClass`.
    pub gateway_classes: Vec<GatewayClassReport>,
    /// Status to publish on each owned `Gateway`.
    pub gateways: Vec<GatewayReport>,
    /// Status to publish on each route with at least one Gateway parent.
    pub routes: Vec<RouteReport>,
}

/// Holds the latest snapshot of every watched kind and renders on demand.
pub struct Reconciler {
    config: ReconcilerConfig,
    classes: Vec<GatewayClass>,
    gateways: Vec<Gateway>,
    http_routes: Vec<HTTPRoute>,
    grpc_routes: Vec<GRPCRoute>,
}

impl Reconciler {
    /// Build a reconciler that writes to `config.output_path`.
    pub fn new(config: ReconcilerConfig) -> Self {
        Self {
            config,
            classes: Vec::new(),
            gateways: Vec::new(),
            http_routes: Vec::new(),
            grpc_routes: Vec::new(),
        }
    }

    /// Replace the `GatewayClass` snapshot.
    pub fn set_gateway_classes(&mut self, classes: Vec<GatewayClass>) {
        self.classes = classes;
    }

    /// Replace the `Gateway` snapshot.
    pub fn set_gateways(&mut self, gateways: Vec<Gateway>) {
        self.gateways = gateways;
    }

    /// Replace the `HTTPRoute` snapshot.
    pub fn set_http_routes(&mut self, routes: Vec<HTTPRoute>) {
        self.http_routes = routes;
    }

    /// Replace the `GRPCRoute` snapshot.
    pub fn set_grpc_routes(&mut self, routes: Vec<GRPCRoute>) {
        self.grpc_routes = routes;
    }

    /// Names of the `GatewayClass` resources this controller claims.
    pub fn owned_classes(&self) -> BTreeSet<String> {
        let scope = self.config.gateway_class.as_deref();
        self.classes
            .iter()
            .filter(|c| c.spec.controller_name == crate::CONTROLLER_NAME)
            .filter_map(|c| c.metadata.name.clone())
            .filter(|name| scope.is_none_or(|want| want == name.as_str()))
            .collect()
    }

    /// Render the current snapshot, write the document, and return the
    /// status to publish.
    ///
    /// Refuses to write while the leadership gate is closed (WOR-2614):
    /// a replica that lost its Lease must not race the new leader over
    /// `sb.yml`, however far into a pass it already was.
    pub fn reconcile(&self) -> anyhow::Result<ReconcileOutcome> {
        let cfg = &self.config;
        if !cfg.write_gate.allows() {
            anyhow::bail!(
                "not the leader: refusing to write {} or publish status",
                cfg.output_path.display()
            );
        }
        let now = status::now_rfc3339();
        let owned = self.owned_classes();

        let gateways: Vec<Gateway> = self
            .gateways
            .iter()
            .filter(|g| owned.contains(&g.spec.gateway_class_name))
            .cloned()
            .collect();

        let render =
            config_writer::render(&gateways, &self.http_routes, &self.grpc_routes, &cfg.writer);
        config_writer::write_config(&render.config, &cfg.output_path)?;

        Ok(ReconcileOutcome {
            origins: render.config.origin_count(),
            gateways_owned: gateways.len(),
            gateway_classes: self.class_reports(&owned, &now),
            gateways: gateway_reports(&gateways, &render, &now),
            routes: route_reports(&self.http_routes, &self.grpc_routes, &render, &now),
        })
    }

    fn class_reports(&self, owned: &BTreeSet<String>, now: &str) -> Vec<GatewayClassReport> {
        // Only classes this replica claims get status. A class carrying
        // our controllerName that a `--gateway-class` scope excluded is
        // presumably served by another replica; writing Accepted=False on
        // it from here would fight that replica's own status write.
        self.classes
            .iter()
            .filter_map(|class| {
                let name = class.metadata.name.clone()?;
                if !owned.contains(&name) {
                    return None;
                }
                let existing = class
                    .status
                    .as_ref()
                    .map(|s| s.conditions.as_slice())
                    .unwrap_or_default();
                let accepted = Condition::new(
                    status::TYPE_ACCEPTED,
                    true,
                    status::REASON_ACCEPTED,
                    "claimed by sbproxy-k8s-controller",
                    class.metadata.generation,
                    now,
                );
                Some(GatewayClassReport {
                    name,
                    conditions: status::merge_conditions(existing, vec![accepted]),
                })
            })
            .collect()
    }
}

fn gateway_reports(
    gateways: &[Gateway],
    render: &config_writer::Render,
    now: &str,
) -> Vec<GatewayReport> {
    let mut reports = Vec::new();
    for gw in gateways {
        let Some(name) = gw.metadata.name.clone() else {
            continue;
        };
        let namespace = gw.metadata.namespace.clone().unwrap_or_default();
        let generation = gw.metadata.generation;
        let existing = gw.status.as_ref();

        let outcomes: Vec<&config_writer::ListenerOutcome> = render
            .listeners
            .iter()
            .filter(|l| l.gateway_namespace == namespace && l.gateway_name == name)
            .collect();

        let programmed_count = outcomes.iter().filter(|l| l.programmed).count();
        let any_programmed = programmed_count > 0;
        let all_programmed = programmed_count == outcomes.len();
        let programmed_message = if outcomes.is_empty() {
            "the Gateway declares no listeners".to_string()
        } else if all_programmed {
            format!("{programmed_count} listener(s) programmed")
        } else {
            format!(
                "{programmed_count} of {} listener(s) programmed; see the per-listener conditions",
                outcomes.len()
            )
        };

        let gateway_conditions = status::merge_conditions(
            existing
                .map(|s| s.conditions.as_slice())
                .unwrap_or_default(),
            vec![
                Condition::new(
                    status::TYPE_ACCEPTED,
                    true,
                    status::REASON_ACCEPTED,
                    format!(
                        "gatewayClassName {} is claimed by this controller",
                        gw.spec.gateway_class_name
                    ),
                    generation,
                    now,
                ),
                Condition::new(
                    status::TYPE_PROGRAMMED,
                    any_programmed,
                    if all_programmed && any_programmed {
                        status::REASON_PROGRAMMED
                    } else {
                        status::REASON_INVALID
                    },
                    programmed_message,
                    generation,
                    now,
                ),
            ],
        );

        let listeners = outcomes
            .iter()
            .map(|outcome| {
                let prior = existing
                    .and_then(|s| s.listeners.iter().find(|l| l.name == outcome.listener_name))
                    .map(|l| l.conditions.as_slice())
                    .unwrap_or_default();
                let accepted_reason = if outcome.accepted {
                    status::REASON_ACCEPTED
                } else {
                    outcome.reason
                };
                let accepted_message = if outcome.accepted {
                    "listener configuration is supported".to_string()
                } else {
                    outcome.message.clone()
                };
                ListenerReport {
                    name: outcome.listener_name.clone(),
                    supported_kinds: SUPPORTED_ROUTE_KINDS
                        .iter()
                        .map(|k| (GROUP.to_string(), (*k).to_string()))
                        .collect(),
                    attached_routes: outcome.attached_routes,
                    conditions: status::merge_conditions(
                        prior,
                        vec![
                            Condition::new(
                                status::TYPE_ACCEPTED,
                                outcome.accepted,
                                accepted_reason,
                                accepted_message,
                                generation,
                                now,
                            ),
                            Condition::new(
                                status::TYPE_PROGRAMMED,
                                outcome.programmed,
                                outcome.reason,
                                outcome.message.clone(),
                                generation,
                                now,
                            ),
                            Condition::new(
                                status::TYPE_RESOLVED_REFS,
                                outcome.resolved_refs,
                                outcome.refs_reason,
                                outcome.refs_message.clone(),
                                generation,
                                now,
                            ),
                        ],
                    ),
                }
            })
            .collect();

        reports.push(GatewayReport {
            namespace,
            name,
            conditions: gateway_conditions,
            listeners,
        });
    }
    reports
}

fn route_reports(
    http_routes: &[HTTPRoute],
    grpc_routes: &[GRPCRoute],
    render: &config_writer::Render,
    now: &str,
) -> Vec<RouteReport> {
    let mut reports = Vec::new();
    for route in http_routes {
        if let Some(report) = one_route_report(
            RouteKind::Http,
            route.metadata.namespace.as_deref(),
            route.metadata.name.as_deref(),
            route.metadata.generation,
            &route.spec.parent_refs,
            route.status.as_ref(),
            render,
            now,
        ) {
            reports.push(report);
        }
    }
    for route in grpc_routes {
        if let Some(report) = one_route_report(
            RouteKind::Grpc,
            route.metadata.namespace.as_deref(),
            route.metadata.name.as_deref(),
            route.metadata.generation,
            &route.spec.parent_refs,
            route.status.as_ref(),
            render,
            now,
        ) {
            reports.push(report);
        }
    }
    reports
}

#[allow(clippy::too_many_arguments)] // one argument per piece of the route; a
                                     // wrapper struct here would only move the
                                     // same list one call frame further out.
fn one_route_report(
    kind: RouteKind,
    namespace: Option<&str>,
    name: Option<&str>,
    generation: Option<i64>,
    parent_refs: &[crate::gateway_api::ParentReference],
    existing: Option<&RouteStatus>,
    render: &config_writer::Render,
    now: &str,
) -> Option<RouteReport> {
    let namespace = namespace.unwrap_or_default();
    let name = name?;
    let outcomes: Vec<&config_writer::RouteOutcome> = render
        .routes
        .iter()
        .filter(|r| r.namespace == namespace && r.name == name)
        .collect();
    if outcomes.is_empty() {
        // Every parentRef points at some other implementation, or there
        // are none. Publishing a status entry would be claiming a route
        // that was never offered to us.
        return None;
    }

    let empty = RouteStatus::default();
    let existing = existing.unwrap_or(&empty);

    let mut parents = Vec::new();
    for outcome in outcomes {
        let Some(parent_ref) = parent_refs.get(outcome.parent_index) else {
            continue;
        };
        let prior = existing.own_conditions(&parent_ref.name);
        parents.push(RouteParentReport {
            parent_ref: parent_ref.clone(),
            conditions: status::merge_conditions(
                &prior,
                vec![
                    Condition::new(
                        status::TYPE_ACCEPTED,
                        outcome.accepted,
                        outcome.accepted_reason,
                        outcome.accepted_message.clone(),
                        generation,
                        now,
                    ),
                    Condition::new(
                        status::TYPE_RESOLVED_REFS,
                        outcome.resolved_refs,
                        outcome.refs_reason,
                        outcome.refs_message.clone(),
                        generation,
                        now,
                    ),
                ],
            ),
        });
    }

    Some(RouteReport {
        kind,
        namespace: namespace.to_string(),
        name: name.to_string(),
        parents,
        foreign_parents: existing.foreign_parents(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn class(name: &str, controller: &str) -> GatewayClass {
        serde_json::from_value(json!({
            "metadata": { "name": name, "generation": 1 },
            "spec": { "controllerName": controller }
        }))
        .expect("GatewayClass fixture")
    }

    fn gateway(name: &str, class_name: &str) -> Gateway {
        serde_json::from_value(json!({
            "metadata": { "name": name, "namespace": "default", "generation": 4 },
            "spec": {
                "gatewayClassName": class_name,
                "listeners": [{ "name": "http", "port": 8080, "protocol": "HTTP" }]
            }
        }))
        .expect("Gateway fixture")
    }

    fn route(name: &str, parent: &str, host: &str) -> HTTPRoute {
        serde_json::from_value(json!({
            "metadata": { "name": name, "namespace": "default", "generation": 7 },
            "spec": {
                "parentRefs": [{ "name": parent }],
                "hostnames": [host],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        }))
        .expect("HTTPRoute fixture")
    }

    fn reconciler(dir: &TempDir) -> Reconciler {
        Reconciler::new(ReconcilerConfig {
            output_path: dir.path().join("sb.yml"),
            gateway_class: None,
            writer: WriterOptions::default(),
            write_gate: crate::leader::WriteGate::always(),
        })
    }

    fn condition<'a>(conditions: &'a [Condition], type_: &str) -> &'a Condition {
        conditions
            .iter()
            .find(|c| c.type_ == type_)
            .unwrap_or_else(|| panic!("no {type_} condition in {conditions:?}"))
    }

    #[test]
    fn a_gateway_whose_class_we_do_not_own_is_ignored_entirely() {
        let dir = TempDir::new().expect("temp dir");
        let mut r = reconciler(&dir);
        r.set_gateway_classes(vec![class("nginx", "k8s.io/nginx-gateway-controller")]);
        r.set_gateways(vec![gateway("nginx-gw", "nginx")]);
        r.set_http_routes(vec![route("api", "nginx-gw", "api.example.com")]);

        let outcome = r.reconcile().expect("reconcile writes");
        assert_eq!(outcome.origins, 0);
        assert_eq!(outcome.gateways_owned, 0);
        assert!(outcome.gateway_classes.is_empty());
        assert!(outcome.gateways.is_empty());
        assert!(
            outcome.routes.is_empty(),
            "a route attached to somebody else's Gateway must not get our status"
        );
    }

    #[test]
    fn a_gateway_on_a_claimed_class_is_served_and_gets_status() {
        let dir = TempDir::new().expect("temp dir");
        let mut r = reconciler(&dir);
        r.set_gateway_classes(vec![class("sbproxy", crate::CONTROLLER_NAME)]);
        r.set_gateways(vec![gateway("sbproxy-gw", "sbproxy")]);
        r.set_http_routes(vec![route("api", "sbproxy-gw", "api.example.com")]);

        let outcome = r.reconcile().expect("reconcile writes");
        assert_eq!(outcome.origins, 1);
        assert_eq!(outcome.gateways_owned, 1);

        assert_eq!(outcome.gateway_classes.len(), 1);
        let class_accepted = condition(&outcome.gateway_classes[0].conditions, "Accepted");
        assert_eq!(class_accepted.status, "True");
        assert_eq!(class_accepted.observed_generation, Some(1));

        assert_eq!(outcome.gateways.len(), 1);
        let gw = &outcome.gateways[0];
        assert_eq!(condition(&gw.conditions, "Accepted").status, "True");
        assert_eq!(condition(&gw.conditions, "Programmed").status, "True");
        assert_eq!(
            condition(&gw.conditions, "Programmed").observed_generation,
            Some(4)
        );
        assert_eq!(gw.listeners.len(), 1);
        assert_eq!(gw.listeners[0].attached_routes, 1);
        assert_eq!(
            condition(&gw.listeners[0].conditions, "ResolvedRefs").status,
            "True"
        );

        assert_eq!(outcome.routes.len(), 1);
        let parent = &outcome.routes[0].parents[0];
        assert_eq!(condition(&parent.conditions, "Accepted").status, "True");
        assert_eq!(
            condition(&parent.conditions, "Accepted").observed_generation,
            Some(7),
            "observedGeneration comes from the route, not the Gateway"
        );
        assert_eq!(outcome.routes[0].kind, RouteKind::Http);
    }

    #[test]
    fn no_gateway_class_means_no_gateway_is_owned() {
        // Ownership flows from the class. Until one exists that names our
        // controllerName, a Gateway pointing at "sbproxy" is somebody
        // else's or nobody's.
        let dir = TempDir::new().expect("temp dir");
        let mut r = reconciler(&dir);
        r.set_gateways(vec![gateway("sbproxy-gw", "sbproxy")]);
        r.set_http_routes(vec![route("api", "sbproxy-gw", "api.example.com")]);

        let outcome = r.reconcile().expect("reconcile writes");
        assert_eq!(outcome.origins, 0);
        assert!(outcome.gateways.is_empty());
    }

    #[test]
    fn the_gateway_class_flag_narrows_ownership_further() {
        let dir = TempDir::new().expect("temp dir");
        let mut r = Reconciler::new(ReconcilerConfig {
            output_path: dir.path().join("sb.yml"),
            gateway_class: Some("edge".to_string()),
            writer: WriterOptions::default(),
            write_gate: crate::leader::WriteGate::always(),
        });
        r.set_gateway_classes(vec![
            class("edge", crate::CONTROLLER_NAME),
            class("internal", crate::CONTROLLER_NAME),
        ]);
        r.set_gateways(vec![
            gateway("edge-gw", "edge"),
            gateway("internal-gw", "internal"),
        ]);
        r.set_http_routes(vec![
            route("a", "edge-gw", "a.example.com"),
            route("b", "internal-gw", "b.example.com"),
        ]);

        let outcome = r.reconcile().expect("reconcile writes");
        let owned: Vec<String> = r.owned_classes().into_iter().collect();
        assert_eq!(owned, vec!["edge".to_string()]);
        assert_eq!(outcome.gateways_owned, 1);
        assert_eq!(outcome.origins, 1);
        assert_eq!(
            outcome.gateway_classes.len(),
            1,
            "an out-of-scope class gets no status write, so two replicas do not fight"
        );
    }

    #[test]
    fn an_unprogrammable_listener_reports_accepted_but_not_programmed() {
        let dir = TempDir::new().expect("temp dir");
        let mut r = reconciler(&dir);
        r.set_gateway_classes(vec![class("sbproxy", crate::CONTROLLER_NAME)]);
        let a = gateway("a-gw", "sbproxy");
        let b: Gateway = serde_json::from_value(json!({
            "metadata": { "name": "b-gw", "namespace": "default", "generation": 2 },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{ "name": "http", "port": 9090, "protocol": "HTTP" }]
            }
        }))
        .expect("Gateway fixture");
        r.set_gateways(vec![a, b]);

        let outcome = r.reconcile().expect("reconcile writes");
        let loser = outcome
            .gateways
            .iter()
            .find(|g| g.name == "b-gw")
            .expect("b-gw reported");
        assert_eq!(condition(&loser.conditions, "Programmed").status, "False");
        assert_eq!(
            condition(&loser.listeners[0].conditions, "Accepted").status,
            "True"
        );
        assert_eq!(
            condition(&loser.listeners[0].conditions, "Programmed").status,
            "False"
        );
    }

    #[test]
    fn an_unreachable_output_path_is_an_error_not_a_panic() {
        let dir = TempDir::new().expect("temp dir");
        let r = Reconciler::new(ReconcilerConfig {
            output_path: dir.path().join("missing").join("sb.yml"),
            gateway_class: None,
            writer: WriterOptions::default(),
            write_gate: crate::leader::WriteGate::always(),
        });
        let error = r
            .reconcile()
            .expect_err("writing into a nonexistent directory fails");
        assert!(!format!("{error:#}").is_empty());
    }

    #[test]
    fn a_closed_leadership_gate_fences_the_config_write() {
        // WOR-2614: losing the Lease has to stop the very next write, not
        // the next process. Before the fix nothing between leadership and
        // the file existed at all, so a deposed leader kept writing.
        let dir = TempDir::new().expect("temp dir");
        let out = dir.path().join("sb.yml");
        let gate = crate::leader::WriteGate::for_election();
        let mut r = Reconciler::new(ReconcilerConfig {
            output_path: out.clone(),
            gateway_class: None,
            writer: WriterOptions::default(),
            write_gate: gate.clone(),
        });
        r.set_gateway_classes(vec![class("sbproxy", crate::CONTROLLER_NAME)]);

        let error = r.reconcile().expect_err("a non-leader must not write");
        assert!(
            format!("{error:#}").contains("not the leader"),
            "the refusal names its reason: {error:#}"
        );
        assert!(
            !out.exists(),
            "a fenced reconcile must not have touched the output file"
        );

        // The same reconciler writes once leadership opens the gate; the
        // fence is leadership, not a broken pass.
        gate.open();
        r.reconcile().expect("the leader writes");
        assert!(out.exists(), "an open gate lets the document land");

        // And loss fences the very next pass again.
        gate.close();
        r.reconcile()
            .expect_err("a deposed leader must stop writing immediately");
    }

    #[test]
    fn an_existing_transition_time_survives_a_reconcile_that_changed_nothing() {
        let dir = TempDir::new().expect("temp dir");
        let mut r = reconciler(&dir);
        r.set_gateway_classes(vec![class("sbproxy", crate::CONTROLLER_NAME)]);
        let gw: Gateway = serde_json::from_value(json!({
            "metadata": { "name": "gw", "namespace": "default", "generation": 4 },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{ "name": "http", "port": 8080, "protocol": "HTTP" }]
            },
            "status": {
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "observedGeneration": 3,
                    "lastTransitionTime": "2020-01-01T00:00:00Z",
                    "reason": "Accepted",
                    "message": "older pass"
                }],
                "listeners": []
            }
        }))
        .expect("Gateway fixture");
        r.set_gateways(vec![gw]);

        let outcome = r.reconcile().expect("reconcile writes");
        let accepted = condition(&outcome.gateways[0].conditions, "Accepted");
        assert_eq!(
            accepted.last_transition_time, "2020-01-01T00:00:00Z",
            "the answer did not change, so the timestamp must not move"
        );
        assert_eq!(
            accepted.observed_generation,
            Some(4),
            "observedGeneration still catches up to the current spec"
        );
    }

    #[test]
    fn a_foreign_controllers_route_status_is_carried_through() {
        let dir = TempDir::new().expect("temp dir");
        let mut r = reconciler(&dir);
        r.set_gateway_classes(vec![class("sbproxy", crate::CONTROLLER_NAME)]);
        r.set_gateways(vec![gateway("sbproxy-gw", "sbproxy")]);
        let route: HTTPRoute = serde_json::from_value(json!({
            "metadata": { "name": "shared", "namespace": "default", "generation": 2 },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }, { "name": "nginx-gw" }],
                "hostnames": ["shared.example.com"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            },
            "status": {
                "parents": [{
                    "parentRef": { "name": "nginx-gw" },
                    "controllerName": "k8s.io/nginx-gateway-controller",
                    "conditions": []
                }]
            }
        }))
        .expect("HTTPRoute fixture");
        r.set_http_routes(vec![route]);

        let outcome = r.reconcile().expect("reconcile writes");
        let patch = outcome.routes[0].to_patch();
        let parents = patch["status"]["parents"]
            .as_array()
            .expect("parents array");
        assert_eq!(
            parents.len(),
            2,
            "the foreign entry plus the one parentRef we own"
        );
        assert_eq!(
            parents[0]["controllerName"],
            "k8s.io/nginx-gateway-controller"
        );
        // This route names two Gateways and we own exactly one of them. We
        // report on that one and leave `nginx-gw` alone, because the entry
        // for it belongs to whoever owns that Gateway. nginx's own entry is
        // already in the list and survives untouched, which is the property
        // this test exists to pin: a shared route must not lose another
        // controller's status when we patch ours in.
        let ours: Vec<&serde_json::Value> = parents
            .iter()
            .filter(|p| p["controllerName"] == crate::CONTROLLER_NAME)
            .collect();
        assert_eq!(ours.len(), 1);
        assert_eq!(ours[0]["parentRef"]["name"], "sbproxy-gw");
        assert_eq!(ours[0]["conditions"][0]["status"], "True");
    }

    #[test]
    fn the_document_is_written_to_the_configured_path() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let mut r = reconciler(&dir);
        r.set_gateway_classes(vec![class("sbproxy", crate::CONTROLLER_NAME)]);
        r.set_gateways(vec![gateway("sbproxy-gw", "sbproxy")]);
        r.set_http_routes(vec![route("api", "sbproxy-gw", "api.example.com")]);
        r.reconcile().expect("reconcile writes");

        let body = std::fs::read_to_string(&path).expect("read back");
        assert!(body.contains("api.example.com"));
        if let Err(e) = sbproxy_config::compile_config(&body) {
            panic!("the file the data plane reads was rejected: {e:#}\n---\n{body}");
        }
    }

    #[test]
    fn a_later_reconcile_overwrites_the_previous_document() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let mut r = reconciler(&dir);
        r.set_gateway_classes(vec![class("sbproxy", crate::CONTROLLER_NAME)]);
        r.set_gateways(vec![gateway("sbproxy-gw", "sbproxy")]);
        r.set_http_routes(vec![route("api", "sbproxy-gw", "first.example.com")]);
        r.reconcile().expect("reconcile writes");

        r.set_http_routes(vec![route("api", "sbproxy-gw", "second.example.com")]);
        r.reconcile().expect("reconcile writes");

        let body = std::fs::read_to_string(&path).expect("read back");
        assert!(body.contains("second.example.com"));
        assert!(!body.contains("first.example.com"));
    }
}
