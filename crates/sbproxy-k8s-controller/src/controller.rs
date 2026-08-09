// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Watch streams, the reconcile queue, and the status writes.
//!
//! Four `kube::runtime::watcher` streams feed one in-memory snapshot per
//! kind: `GatewayClass` (cluster scoped), plus `Gateway`, `HTTPRoute`,
//! and `GRPCRoute`. Every event enqueues a kind label on a small channel;
//! one worker drains it, coalescing a burst so `kubectl apply -f dir/`
//! triggers one reconcile rather than one per file.
//!
//! A reconcile does two things: write the rendered document, then patch
//! `Accepted`, `Programmed`, and `ResolvedRefs` back onto every resource
//! the pass looked at. Status writes are best effort. A cluster whose
//! RBAC is missing the `/status` subresources still routes traffic
//! correctly; it just cannot tell its operator anything, which is a
//! degraded controller rather than a broken one. The failure shows up on
//! `sbproxy_gateway_status_writes_total{result="error"}` and in the log.
//!
//! Reconcile errors are caught and logged, never propagated. One
//! malformed resource must not take the loop down.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::watcher::{self, Event};
use kube::Client;
use tokio::sync::{mpsc, Mutex};

use crate::gateway_api::{GRPCRoute, Gateway, GatewayClass, HTTPRoute};
use crate::health;
use crate::metrics;
use crate::reconciler::{ReconcileOutcome, Reconciler, ReconcilerConfig};
use crate::shutdown::ShutdownSignal;
use crate::status::RouteKind;

/// Metrics and log label for the `GatewayClass` kind.
pub const KIND_GATEWAY_CLASS: &str = "GatewayClass";
/// Metrics and log label for the `Gateway` kind.
pub const KIND_GATEWAY: &str = "Gateway";
/// Metrics and log label for the `HTTPRoute` kind.
pub const KIND_HTTP_ROUTE: &str = "HTTPRoute";
/// Metrics and log label for the `GRPCRoute` kind.
pub const KIND_GRPC_ROUTE: &str = "GRPCRoute";
/// Metrics and log label for the timer-driven full resync.
pub const KIND_PERIODIC: &str = "periodic";

/// Owns the snapshots, the reconciler, and the reconcile queue.
pub struct ControllerHandle {
    reconciler: Mutex<Reconciler>,
    classes: Arc<Mutex<Vec<GatewayClass>>>,
    gateways: Arc<Mutex<Vec<Gateway>>>,
    http_routes: Arc<Mutex<Vec<HTTPRoute>>>,
    grpc_routes: Arc<Mutex<Vec<GRPCRoute>>>,
    schedule_tx: mpsc::Sender<&'static str>,
    schedule_rx: Mutex<mpsc::Receiver<&'static str>>,
    /// Per-instance readiness. Tests read this rather than the
    /// process-global flag in [`crate::health`], so the suite can run in
    /// parallel without one test flipping another's readiness.
    ready: AtomicBool,
    /// Present only in the binary. Its absence is what lets the whole
    /// reconcile path be tested without a cluster.
    client: Option<Client>,
}

impl ControllerHandle {
    /// Build a handle with no Kubernetes client.
    ///
    /// It renders and writes the document but publishes no status and
    /// does not touch process-global readiness.
    pub fn new(reconciler_cfg: ReconcilerConfig) -> Self {
        let (tx, rx) = mpsc::channel::<&'static str>(64);
        Self {
            reconciler: Mutex::new(Reconciler::new(reconciler_cfg)),
            classes: Arc::new(Mutex::new(Vec::new())),
            gateways: Arc::new(Mutex::new(Vec::new())),
            http_routes: Arc::new(Mutex::new(Vec::new())),
            grpc_routes: Arc::new(Mutex::new(Vec::new())),
            schedule_tx: tx,
            schedule_rx: Mutex::new(rx),
            ready: AtomicBool::new(false),
            client: None,
        }
    }

    /// Build the handle the binary uses: publishes status through
    /// `client` and flips the `/readyz` probe after the first successful
    /// pass.
    pub fn with_client(reconciler_cfg: ReconcilerConfig, client: Client) -> Self {
        Self {
            client: Some(client),
            ..Self::new(reconciler_cfg)
        }
    }

    /// Whether this handle has completed a successful reconcile.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// A sender for enqueueing extra reconciles, such as the periodic
    /// full resync.
    pub fn scheduler(&self) -> mpsc::Sender<&'static str> {
        self.schedule_tx.clone()
    }

    /// Pull the snapshots into the reconciler, run one pass, publish
    /// status, and record metrics.
    pub async fn reconcile_once(&self, kind: &'static str) -> anyhow::Result<ReconcileOutcome> {
        let started = Instant::now();

        let classes = self.classes.lock().await.clone();
        let gateways = self.gateways.lock().await.clone();
        let http_routes = self.http_routes.lock().await.clone();
        let grpc_routes = self.grpc_routes.lock().await.clone();

        let result = {
            let mut r = self.reconciler.lock().await;
            r.set_gateway_classes(classes);
            r.set_gateways(gateways);
            r.set_http_routes(http_routes);
            r.set_grpc_routes(grpc_routes);
            r.reconcile()
        };

        let elapsed = started.elapsed().as_secs_f64();
        match result {
            Ok(outcome) => {
                metrics::record_reconcile(kind, metrics::RESULT_SUCCESS, elapsed);
                tracing::info!(
                    target: "k8s_audit",
                    kind,
                    origins = outcome.origins,
                    gateways = outcome.gateways_owned,
                    "rendered Gateway API resources into an sbproxy config"
                );
                if let Some(client) = &self.client {
                    publish_status(client, &outcome).await;
                }
                self.mark_ready();
                Ok(outcome)
            }
            Err(e) => {
                metrics::record_reconcile(kind, metrics::RESULT_ERROR, elapsed);
                tracing::error!(target: "k8s_audit", kind, error = %e, "reconcile failed");
                Err(e)
            }
        }
    }

    fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
        if self.client.is_some() {
            health::set_ready(true);
        }
    }

    #[cfg(test)]
    async fn replace_gateway_classes(&self, items: Vec<GatewayClass>) {
        *self.classes.lock().await = items;
    }

    #[cfg(test)]
    async fn replace_gateways(&self, items: Vec<Gateway>) {
        *self.gateways.lock().await = items;
    }

    #[cfg(test)]
    async fn replace_http_routes(&self, items: Vec<HTTPRoute>) {
        *self.http_routes.lock().await = items;
    }

    #[cfg(test)]
    async fn replace_grpc_routes(&self, items: Vec<GRPCRoute>) {
        *self.grpc_routes.lock().await = items;
    }
}

/// Start the watchers and the reconcile worker. Returns once the shutdown
/// signal has fired and every task has exited.
pub async fn run(
    client: Client,
    handle: Arc<ControllerHandle>,
    namespace: Option<&str>,
    shutdown: ShutdownSignal,
) -> anyhow::Result<()> {
    // GatewayClass is cluster scoped, so it is never namespace filtered.
    // Narrowing it would make the controller unable to see the class that
    // grants it ownership in the first place.
    let class_api: Api<GatewayClass> = Api::all(client.clone());
    let gateway_api: Api<Gateway> = namespaced_or_all(&client, namespace);
    let http_api: Api<HTTPRoute> = namespaced_or_all(&client, namespace);
    let grpc_api: Api<GRPCRoute> = namespaced_or_all(&client, namespace);

    let class_task = tokio::spawn(watch_kind(
        class_api,
        KIND_GATEWAY_CLASS,
        handle.classes.clone(),
        handle.schedule_tx.clone(),
        shutdown.clone(),
    ));
    let gateway_task = tokio::spawn(watch_kind(
        gateway_api,
        KIND_GATEWAY,
        handle.gateways.clone(),
        handle.schedule_tx.clone(),
        shutdown.clone(),
    ));
    let http_task = tokio::spawn(watch_kind(
        http_api,
        KIND_HTTP_ROUTE,
        handle.http_routes.clone(),
        handle.schedule_tx.clone(),
        shutdown.clone(),
    ));
    let grpc_task = tokio::spawn(watch_kind(
        grpc_api,
        KIND_GRPC_ROUTE,
        handle.grpc_routes.clone(),
        handle.schedule_tx.clone(),
        shutdown.clone(),
    ));

    let worker = tokio::spawn(reconcile_worker(handle.clone(), shutdown.clone()));

    shutdown.wait().await;
    tracing::info!(target: "k8s_audit", "shutdown requested, draining watchers and reconcile worker");

    let _ = class_task.await;
    let _ = gateway_task.await;
    let _ = http_task.await;
    let _ = grpc_task.await;
    let _ = worker.await;

    tracing::info!(target: "k8s_audit", "controller exited cleanly");
    Ok(())
}

fn namespaced_or_all<K>(client: &Client, namespace: Option<&str>) -> Api<K>
where
    K: kube::Resource<Scope = kube::core::NamespaceResourceScope>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    <K as kube::Resource>::DynamicType: Default,
{
    match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    }
}

/// Drive one watch stream into `store`, scheduling a reconcile per event.
async fn watch_kind<K>(
    api: Api<K>,
    kind: &'static str,
    store: Arc<Mutex<Vec<K>>>,
    schedule: mpsc::Sender<&'static str>,
    shutdown: ShutdownSignal,
) where
    K: kube::Resource<DynamicType = ()>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + Send
        + 'static,
{
    let mut stream = std::pin::pin!(watcher::watcher(api, watcher::Config::default()).boxed());
    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                tracing::debug!(target: "k8s_audit", kind, "watcher stopping");
                return;
            }
            event = stream.next() => {
                let Some(event) = event else { return };
                match event {
                    Ok(Event::Apply(obj)) | Ok(Event::InitApply(obj)) => {
                        upsert_by_uid(&mut *store.lock().await, obj);
                        let _ = schedule.try_send(kind);
                    }
                    Ok(Event::Delete(obj)) => {
                        remove_by_uid(&mut *store.lock().await, &obj);
                        let _ = schedule.try_send(kind);
                    }
                    Ok(Event::Init) => {
                        // A fresh list-watch. Clear so the InitApply
                        // events that follow rebuild a clean snapshot
                        // rather than merging into a stale one.
                        store.lock().await.clear();
                    }
                    Ok(Event::InitDone) => {
                        let _ = schedule.try_send(kind);
                    }
                    Err(e) => {
                        metrics::record_watch_error(kind);
                        tracing::warn!(
                            target: "k8s_audit",
                            kind,
                            error = %e,
                            "watch error; kube-rs will retry with backoff"
                        );
                    }
                }
            }
        }
    }
}

async fn reconcile_worker(handle: Arc<ControllerHandle>, shutdown: ShutdownSignal) {
    loop {
        let next = {
            let mut rx = handle.schedule_rx.lock().await;
            tokio::select! {
                _ = shutdown.wait() => {
                    tracing::debug!(target: "k8s_audit", "reconcile worker stopping");
                    return;
                }
                v = rx.recv() => v,
            }
        };
        let Some(kind) = next else { return };

        // Coalesce: drain whatever else is already queued so one burst of
        // events is one reconcile.
        {
            let mut rx = handle.schedule_rx.lock().await;
            while rx.try_recv().is_ok() {}
        }

        if let Err(e) = handle.reconcile_once(kind).await {
            // Already logged and counted inside reconcile_once. Keep
            // looping so the next event still gets a pass.
            tracing::debug!(target: "k8s_audit", error = %e, "reconcile_once returned an error");
        }
    }
}

// --- Status publication ------------------------------------------------

async fn publish_status(client: &Client, outcome: &ReconcileOutcome) {
    for report in &outcome.gateway_classes {
        let api: Api<GatewayClass> = Api::all(client.clone());
        patch_status(&api, &report.name, KIND_GATEWAY_CLASS, report.to_patch()).await;
    }
    for report in &outcome.gateways {
        let api: Api<Gateway> = Api::namespaced(client.clone(), &report.namespace);
        patch_status(&api, &report.name, KIND_GATEWAY, report.to_patch()).await;
    }
    for report in &outcome.routes {
        match report.kind {
            RouteKind::Http => {
                let api: Api<HTTPRoute> = Api::namespaced(client.clone(), &report.namespace);
                patch_status(&api, &report.name, KIND_HTTP_ROUTE, report.to_patch()).await;
            }
            RouteKind::Grpc => {
                let api: Api<GRPCRoute> = Api::namespaced(client.clone(), &report.namespace);
                patch_status(&api, &report.name, KIND_GRPC_ROUTE, report.to_patch()).await;
            }
        }
    }
}

async fn patch_status<K>(api: &Api<K>, name: &str, kind: &'static str, body: serde_json::Value)
where
    K: serde::de::DeserializeOwned,
{
    match api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&body))
        .await
    {
        Ok(_) => metrics::record_status_write(kind, metrics::RESULT_SUCCESS),
        Err(e) => {
            metrics::record_status_write(kind, metrics::RESULT_ERROR);
            tracing::warn!(
                target: "k8s_audit",
                kind,
                name,
                error = %e,
                "status patch failed; the ClusterRole needs the /status subresource for this kind"
            );
        }
    }
}

// --- Snapshot helpers ---------------------------------------------------

/// Identity for snapshot bookkeeping.
///
/// `uid` is the real one. The namespace/name fallback exists because a
/// hand-built object in a test has no `uid`, and using the empty string
/// for all of them would collapse the snapshot to one entry.
fn obj_uid<T: kube::Resource<DynamicType = ()>>(obj: &T) -> String {
    obj.meta().uid.clone().unwrap_or_else(|| {
        format!(
            "{}/{}",
            obj.meta().namespace.clone().unwrap_or_default(),
            obj.meta().name.clone().unwrap_or_default()
        )
    })
}

fn upsert_by_uid<T: kube::Resource<DynamicType = ()>>(items: &mut Vec<T>, obj: T) {
    let uid = obj_uid(&obj);
    match items.iter().position(|existing| obj_uid(existing) == uid) {
        Some(pos) => items[pos] = obj,
        None => items.push(obj),
    }
}

fn remove_by_uid<T: kube::Resource<DynamicType = ()>>(items: &mut Vec<T>, obj: &T) {
    let uid = obj_uid(obj);
    items.retain(|existing| obj_uid(existing) != uid);
}

/// Check that every kind this controller watches is registered and
/// watchable before the watchers start.
///
/// Without this the controller starts, every watch fails with a 404, and
/// the only symptom is a silent `sb.yml` that never gains an origin. The
/// scope is checked too: `GatewayClass` is cluster scoped and the three
/// route kinds are namespaced, so a CRD installed at the wrong scope is
/// caught here rather than at the first list call.
pub async fn verify_crds_installed(client: &Client) -> anyhow::Result<()> {
    use kube::discovery::{verbs, Discovery, Scope};

    let discovery = Discovery::new(client.clone())
        .run()
        .await
        .context("kubernetes API discovery")?;

    let group_name = crate::gateway_api::GROUP;
    let group = discovery.get(group_name).ok_or_else(|| {
        anyhow::anyhow!(
            "API group {group_name} is not registered; install the Gateway API CRDs first"
        )
    })?;

    let want = [
        (KIND_GATEWAY_CLASS, Scope::Cluster),
        (KIND_GATEWAY, Scope::Namespaced),
        (KIND_HTTP_ROUTE, Scope::Namespaced),
        (KIND_GRPC_ROUTE, Scope::Namespaced),
    ];
    for (kind, scope) in want {
        let found = group.recommended_resources().into_iter().any(|(ar, caps)| {
            ar.kind == kind && caps.scope == scope && caps.supports_operation(verbs::WATCH)
        });
        if !found {
            anyhow::bail!(
                "{kind} in group {group_name} is not discoverable, not watchable, or not at the \
                 expected scope"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_writer::WriterOptions;
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::TempDir;

    fn handle_for(out: PathBuf) -> Arc<ControllerHandle> {
        Arc::new(ControllerHandle::new(ReconcilerConfig {
            output_path: out,
            gateway_class: None,
            writer: WriterOptions::default(),
        }))
    }

    fn class() -> GatewayClass {
        serde_json::from_value(json!({
            "metadata": { "name": "sbproxy", "uid": "c1" },
            "spec": { "controllerName": crate::CONTROLLER_NAME }
        }))
        .expect("GatewayClass fixture")
    }

    fn gateway(uid: &str, port: u16) -> Gateway {
        serde_json::from_value(json!({
            "metadata": { "name": "gw", "namespace": "default", "uid": uid },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{ "name": "http", "port": port, "protocol": "HTTP" }]
            }
        }))
        .expect("Gateway fixture")
    }

    fn http_route(uid: &str, host: &str, backend: &str) -> HTTPRoute {
        serde_json::from_value(json!({
            "metadata": { "name": uid, "namespace": "default", "uid": uid },
            "spec": {
                "parentRefs": [{ "name": "gw" }],
                "hostnames": [host],
                "rules": [{ "backendRefs": [{ "name": backend, "port": 80 }] }]
            }
        }))
        .expect("HTTPRoute fixture")
    }

    fn grpc_route(uid: &str, host: &str) -> GRPCRoute {
        serde_json::from_value(json!({
            "metadata": { "name": uid, "namespace": "default", "uid": uid },
            "spec": {
                "parentRefs": [{ "name": "gw" }],
                "hostnames": [host],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 50051 }] }]
            }
        }))
        .expect("GRPCRoute fixture")
    }

    #[tokio::test]
    async fn a_reconcile_writes_the_document() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let h = handle_for(path.clone());

        h.replace_gateway_classes(vec![class()]).await;
        h.replace_gateways(vec![gateway("u1", 9090)]).await;
        h.replace_http_routes(vec![http_route("r1", "api.example.com", "api-svc")])
            .await;

        let outcome = h.reconcile_once(KIND_GATEWAY).await.expect("reconcile");
        assert_eq!(outcome.origins, 1);
        let body = std::fs::read_to_string(&path).expect("read back");
        assert!(body.contains("api.example.com"));
        assert!(body.contains("9090"));
    }

    #[tokio::test]
    async fn a_grpc_route_reaches_the_document() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let h = handle_for(path.clone());
        h.replace_gateway_classes(vec![class()]).await;
        h.replace_gateways(vec![gateway("u1", 8080)]).await;
        h.replace_grpc_routes(vec![grpc_route("g1", "grpc.example.com")])
            .await;

        h.reconcile_once(KIND_GRPC_ROUTE).await.expect("reconcile");
        let body = std::fs::read_to_string(&path).expect("read back");
        assert!(body.contains("grpc.example.com"));
    }

    #[tokio::test]
    async fn an_update_then_a_delete_are_both_reflected() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let h = handle_for(path.clone());
        h.replace_gateway_classes(vec![class()]).await;
        h.replace_gateways(vec![gateway("u1", 8080)]).await;
        h.replace_http_routes(vec![http_route("r1", "a.example.com", "a")])
            .await;
        h.reconcile_once(KIND_GATEWAY).await.expect("reconcile");
        assert!(std::fs::read_to_string(&path)
            .expect("read back")
            .contains("8080"));

        h.replace_gateways(vec![gateway("u1", 7070)]).await;
        h.reconcile_once(KIND_GATEWAY).await.expect("reconcile");
        let body = std::fs::read_to_string(&path).expect("read back");
        assert!(body.contains("7070"));
        assert!(!body.contains("8080"));

        h.replace_gateways(vec![]).await;
        let outcome = h.reconcile_once(KIND_GATEWAY).await.expect("reconcile");
        assert_eq!(
            outcome.origins, 0,
            "deleting the Gateway takes its routes out of the document"
        );
    }

    #[tokio::test]
    async fn readiness_flips_only_after_a_successful_pass() {
        let dir = TempDir::new().expect("temp dir");
        let h = handle_for(dir.path().join("sb.yml"));
        assert!(!h.is_ready());
        h.reconcile_once(KIND_GATEWAY).await.expect("reconcile");
        assert!(h.is_ready());
    }

    #[tokio::test]
    async fn a_failed_reconcile_leaves_the_handle_unready() {
        let dir = TempDir::new().expect("temp dir");
        let h = handle_for(dir.path().join("missing-subdir").join("sb.yml"));
        let error = h
            .reconcile_once(KIND_GATEWAY)
            .await
            .expect_err("writing into a nonexistent directory fails");
        assert!(!format!("{error:#}").is_empty());
        assert!(
            !h.is_ready(),
            "a controller that has never written a document is not ready"
        );
    }

    #[tokio::test]
    async fn a_handle_with_no_client_leaves_global_readiness_alone() {
        // The binary bridges to the process-global probe; a test handle
        // must not, or parallel tests would flip each other's answer.
        health::set_ready(false);
        let dir = TempDir::new().expect("temp dir");
        let h = handle_for(dir.path().join("sb.yml"));
        h.reconcile_once(KIND_GATEWAY).await.expect("reconcile");
        assert!(h.is_ready());
        assert!(!health::is_ready());
    }

    #[tokio::test]
    async fn the_worker_stops_when_shutdown_fires() {
        let dir = TempDir::new().expect("temp dir");
        let h = handle_for(dir.path().join("sb.yml"));
        let (sig, trig) = crate::shutdown::channel();
        let worker = tokio::spawn(reconcile_worker(h.clone(), sig));

        let _ = h.scheduler().try_send(KIND_GATEWAY);
        tokio::time::sleep(Duration::from_millis(50)).await;

        trig.trigger();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), worker)
                .await
                .is_ok(),
            "the worker did not exit within the timeout"
        );
    }

    #[tokio::test]
    async fn the_worker_drains_a_burst_into_one_pass() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let h = handle_for(path.clone());
        h.replace_gateway_classes(vec![class()]).await;
        h.replace_gateways(vec![gateway("u1", 8080)]).await;

        let (sig, trig) = crate::shutdown::channel();
        let worker = tokio::spawn(reconcile_worker(h.clone(), sig));
        let tx = h.scheduler();
        for _ in 0..10 {
            let _ = tx.try_send(KIND_HTTP_ROUTE);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        trig.trigger();
        let _ = tokio::time::timeout(Duration::from_secs(2), worker).await;

        assert!(path.exists(), "the burst produced at least one document");
    }

    #[test]
    fn upsert_replaces_the_entry_with_the_same_uid() {
        let mut items = vec![http_route("u1", "a.example.com", "old")];
        let mut replacement = http_route("u1", "a.example.com", "new");
        replacement.metadata.name = Some("u1".to_string());
        upsert_by_uid(&mut items, replacement);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].spec.rules[0].backend_refs[0].name, "new");
    }

    #[test]
    fn upsert_appends_a_different_uid() {
        let mut items = vec![http_route("u1", "a.example.com", "a")];
        upsert_by_uid(&mut items, http_route("u2", "b.example.com", "b"));
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn remove_drops_only_the_matching_uid() {
        let mut items = vec![
            http_route("u1", "a.example.com", "a"),
            http_route("u2", "b.example.com", "b"),
        ];
        let target = http_route("u1", "a.example.com", "a");
        remove_by_uid(&mut items, &target);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].spec.hostnames[0], "b.example.com");
    }

    #[test]
    fn an_object_with_no_uid_falls_back_to_namespace_and_name() {
        let a: HTTPRoute = serde_json::from_value(json!({
            "metadata": { "name": "a", "namespace": "default" },
            "spec": {}
        }))
        .expect("fixture");
        let b: HTTPRoute = serde_json::from_value(json!({
            "metadata": { "name": "b", "namespace": "default" },
            "spec": {}
        }))
        .expect("fixture");
        assert_ne!(obj_uid(&a), obj_uid(&b));
        assert_eq!(obj_uid(&a), "default/a");
    }

    #[tokio::test]
    async fn a_class_we_do_not_own_produces_no_origins() {
        let dir = TempDir::new().expect("temp dir");
        let h = handle_for(dir.path().join("sb.yml"));
        let foreign: GatewayClass = serde_json::from_value(json!({
            "metadata": { "name": "sbproxy", "uid": "c1" },
            "spec": { "controllerName": "k8s.io/some-other-controller" }
        }))
        .expect("GatewayClass fixture");
        h.replace_gateway_classes(vec![foreign]).await;
        h.replace_gateways(vec![gateway("u1", 8080)]).await;
        h.replace_http_routes(vec![http_route("r1", "api.example.com", "svc")])
            .await;

        let outcome = h
            .reconcile_once(KIND_GATEWAY_CLASS)
            .await
            .expect("reconcile");
        assert_eq!(outcome.origins, 0);
        assert!(outcome.gateways.is_empty());
    }

    #[test]
    fn the_kind_labels_are_the_upstream_spellings() {
        // These land in metric labels and in status; a rename would break
        // dashboards and would stop matching the CRD kinds.
        assert_eq!(KIND_GATEWAY_CLASS, "GatewayClass");
        assert_eq!(KIND_GATEWAY, "Gateway");
        assert_eq!(KIND_HTTP_ROUTE, "HTTPRoute");
        assert_eq!(KIND_GRPC_ROUTE, "GRPCRoute");
        assert_eq!(KIND_PERIODIC, "periodic");
    }
}
