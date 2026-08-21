// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Translate Gateway API resources into an sbproxy configuration document.
//!
//! This is a pure function. Nothing here touches the network or the
//! clock, and only [`write_config`] touches the filesystem, so the whole
//! translation is exercised by unit tests that build resources from their
//! JSON wire shape.
//!
//! # The shape it emits, and why that matters
//!
//! `sbproxy-config` parses this document with `#[serde(deny_unknown_fields)]`
//! on every nested container. One misspelled key does not degrade a
//! single route, it fails the whole document, and the data plane keeps
//! serving its last good config while the controller logs success. A
//! forward rule is `{rules: [...], origin: {...}}`; a top-level `path`
//! key instead is rejected outright.
//!
//! Two things guard against that. The document is built from typed
//! structs in this module rather than hand-assembled JSON, so each key is
//! spelled exactly once. And the tests in this file feed generated
//! documents through the real `sbproxy_config::compile_config`, so a
//! shape the data plane would reject fails here rather than in a pod that
//! will not start.
//!
//! # The translation
//!
//! One origin per resolved hostname. Every Gateway API match becomes one
//! forward rule carrying exactly one matcher, and the forward rules are
//! sorted by Gateway API match precedence: exact path, then longest
//! prefix, then a method predicate, then header count, then query count.
//! The origin's own `action` is always a 404, which is what Gateway API
//! asks for when no rule matches.
//!
//! `docs/gateway-api.md` lists what is not translated.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::gateway_api::{
    BackendRef, GRPCRoute, GRPCRouteRule, Gateway, HTTPRoute, HTTPRouteRule, HeaderMatch, Listener,
    ParentReference, QueryParamMatch, RouteFilter,
};
use crate::status;

/// Default directory the Gateway TLS Secrets are expected to be mounted
/// under, one subdirectory per Secret name.
pub const DEFAULT_TLS_MOUNT_DIR: &str = "/etc/sbproxy/tls";

/// Default Kubernetes cluster DNS domain.
pub const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";

/// Knobs the rendered document depends on that no Gateway API resource
/// carries.
#[derive(Debug, Clone)]
pub struct WriterOptions {
    /// Directory the Gateway's TLS Secrets are mounted under. A
    /// `certificateRef` to Secret `api-cert` renders as
    /// `<dir>/api-cert/tls.crt` and `<dir>/api-cert/tls.key`, the two
    /// keys a `kubernetes.io/tls` Secret always carries. The controller
    /// never reads the Secret; whatever mounts it into the data plane pod
    /// has to use this layout.
    pub tls_mount_dir: String,
    /// Cluster DNS domain used to build Service addresses.
    pub cluster_domain: String,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            tls_mount_dir: DEFAULT_TLS_MOUNT_DIR.to_string(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
        }
    }
}

// --- The emitted document --------------------------------------------

/// A rendered sbproxy configuration document.
///
/// Fields are private on purpose. The serialized key names are the
/// contract with `sbproxy-config`, and letting a caller assemble one
/// field at a time is how a document drifts out of that contract.
#[derive(Debug, Default, Serialize)]
pub struct GeneratedConfig {
    proxy: ProxyBlock,
    origins: BTreeMap<String, OriginBlock>,
}

impl GeneratedConfig {
    /// Number of origins in the document.
    pub fn origin_count(&self) -> usize {
        self.origins.len()
    }

    /// Serialize to YAML.
    pub fn to_yaml(&self) -> anyhow::Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }
}

#[derive(Debug, Default, Serialize)]
struct ProxyBlock {
    http_bind_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    https_bind_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_cert_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_key_file: Option<String>,
}

#[derive(Debug, Serialize)]
struct OriginBlock {
    action: serde_json::Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    forward_rules: Vec<ForwardRule>,
}

#[derive(Debug, Serialize)]
struct ForwardRule {
    rules: Vec<RuleMatcher>,
    origin: ChildOrigin,
}

#[derive(Debug, Default, Serialize)]
struct RuleMatcher {
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<PathSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<NameValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<NameValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct PathSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    regex: Option<String>,
}

#[derive(Debug, Serialize)]
struct NameValue {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct ChildOrigin {
    action: serde_json::Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_modifiers: Vec<RequestModifier>,
}

#[derive(Debug, Clone, Serialize)]
struct RequestModifier {
    headers: HeaderOps,
}

#[derive(Debug, Clone, Default, Serialize)]
struct HeaderOps {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    set: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    add: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    remove: Vec<String>,
}

// --- Per-resource outcomes -------------------------------------------

/// What happened to one Gateway listener during a render.
///
/// The reconciler turns these into `Gateway.status.listeners[]`
/// conditions. Nothing else reads them.
#[derive(Debug, Clone)]
pub struct ListenerOutcome {
    /// Namespace of the owning Gateway.
    pub gateway_namespace: String,
    /// Name of the owning Gateway.
    pub gateway_name: String,
    /// Listener name within that Gateway.
    pub listener_name: String,
    /// Whether the listener's own configuration is one this controller
    /// can serve. A listener can be acceptable and still unprogrammed:
    /// losing the single HTTP port to an earlier Gateway is not a defect
    /// in the listener.
    pub accepted: bool,
    /// Whether the listener made it into the document.
    pub programmed: bool,
    /// One of the `status::REASON_*` constants.
    pub reason: &'static str,
    /// Human-readable detail for `kubectl describe`.
    pub message: String,
    /// Whether every reference the listener makes resolved.
    pub resolved_refs: bool,
    /// One of the `status::REASON_*` constants.
    pub refs_reason: &'static str,
    /// Human-readable detail for `kubectl describe`.
    pub refs_message: String,
    /// Routes that bound to this listener on this pass.
    pub attached_routes: i32,
}

/// What happened to one `parentRef` on one route during a render.
#[derive(Debug, Clone)]
pub struct RouteOutcome {
    /// Route namespace.
    pub namespace: String,
    /// Route name.
    pub name: String,
    /// Index into the route's own `parentRefs`, so the reconciler can
    /// echo the reference back into status verbatim.
    pub parent_index: usize,
    /// Whether the parent accepted the route.
    pub accepted: bool,
    /// One of the `status::REASON_*` constants.
    pub accepted_reason: &'static str,
    /// Human-readable detail for `kubectl describe`.
    pub accepted_message: String,
    /// Whether every backend and filter the route names was understood.
    pub resolved_refs: bool,
    /// One of the `status::REASON_*` constants.
    pub refs_reason: &'static str,
    /// Human-readable detail for `kubectl describe`.
    pub refs_message: String,
}

/// Everything one render pass produced.
#[derive(Debug)]
pub struct Render {
    /// The document to write.
    pub config: GeneratedConfig,
    /// One entry per listener on every Gateway passed in.
    pub listeners: Vec<ListenerOutcome>,
    /// One entry per Gateway-targeting `parentRef` on every route passed
    /// in. A `parentRef` naming some other kind is skipped rather than
    /// rejected: another implementation owns it.
    pub routes: Vec<RouteOutcome>,
}

// --- Entry point ------------------------------------------------------

/// Render Gateways and routes into a single configuration document.
///
/// `gateways` must already be filtered to the classes this controller
/// owns; this function never looks at `gatewayClassName`.
pub fn render(
    gateways: &[Gateway],
    http_routes: &[HTTPRoute],
    grpc_routes: &[GRPCRoute],
    options: &WriterOptions,
) -> Render {
    let mut plans = plan_listeners(gateways, options);
    let mut origins: BTreeMap<String, OriginAccumulator> = BTreeMap::new();
    let mut route_outcomes = Vec::new();

    // Routes are visited in a stable order so two reconciles over the
    // same cluster state produce byte-identical YAML. Without it the
    // watcher's arrival order leaks into the document and the data plane
    // reloads on every resync.
    let mut http_sorted: Vec<&HTTPRoute> = http_routes.iter().collect();
    http_sorted.sort_by_key(|r| (namespace_of(&r.metadata), name_of(&r.metadata)));
    let mut grpc_sorted: Vec<&GRPCRoute> = grpc_routes.iter().collect();
    grpc_sorted.sort_by_key(|r| (namespace_of(&r.metadata), name_of(&r.metadata)));

    for route in http_sorted {
        let ns = namespace_of(&route.metadata);
        let name = name_of(&route.metadata);
        let (hostnames, mut outcomes) = bind_route(
            &ns,
            &name,
            &route.spec.parent_refs,
            &route.spec.hostnames,
            &mut plans,
        );
        let mut problems = Vec::new();
        for host in &hostnames {
            let entry = origins.entry(host.clone()).or_default();
            apply_http_route(entry, route, &ns, &name, options, &mut problems);
        }
        record_ref_problems(&mut outcomes, &problems);
        route_outcomes.extend(outcomes);
    }

    for route in grpc_sorted {
        let ns = namespace_of(&route.metadata);
        let name = name_of(&route.metadata);
        let (hostnames, mut outcomes) = bind_route(
            &ns,
            &name,
            &route.spec.parent_refs,
            &route.spec.hostnames,
            &mut plans,
        );
        let mut problems = Vec::new();
        for host in &hostnames {
            let entry = origins.entry(host.clone()).or_default();
            apply_grpc_route(entry, route, &ns, &name, options, &mut problems);
        }
        record_ref_problems(&mut outcomes, &problems);
        route_outcomes.extend(outcomes);
    }

    let proxy = proxy_block(&plans);
    let origins: BTreeMap<String, OriginBlock> = origins
        .into_iter()
        .map(|(host, acc)| (host, acc.finish()))
        .collect();

    Render {
        config: GeneratedConfig { proxy, origins },
        listeners: plans.into_iter().map(|p| p.outcome).collect(),
        routes: route_outcomes,
    }
}

/// Write a rendered document to `path`, whole or not at all.
///
/// The data plane reads this file from a shared volume and re-reads it
/// on every change, so a partially written document is not a transient
/// state it rides out: `std::fs::write` truncates first, and a
/// controller killed between the truncate and the write leaves an empty
/// or half-written `sb.yml` on disk permanently. The proxy that restarts
/// after that cannot boot on it.
///
/// So the document goes to a temporary file in the same directory, is
/// flushed to the platter, and is moved into place with a rename.
///
/// # What is guaranteed, and what is not
///
/// `rename(2)` within one directory is atomic, so a reader either opens
/// the previous complete document or the new complete one. Never a
/// prefix of either. `sync_all` on the temporary before the rename is
/// what makes the new contents durable rather than the rename merely
/// pointing at unwritten pages, and the `fsync` of the directory
/// afterwards is what makes the rename itself survive power loss. On
/// crash-consistency terms: after this returns `Ok`, the new document is
/// on stable storage; if it returns `Err`, the previous file is
/// untouched and no temporary is left behind.
///
/// Two caveats worth stating rather than implying. The temporary is
/// created in `path`'s own directory because a rename is atomic only
/// within a filesystem, and `/tmp` frequently is not the same one. And
/// on a network filesystem, an NFS-backed `PersistentVolume` among them,
/// rename atomicity and `fsync` durability are the server's promise, not
/// the kernel's; this is as good as the volume underneath it.
///
/// The temporary carries the pid and a nanosecond stamp because the
/// deployment shares one volume between replicas. Two containers can
/// both be pid 1, so the pid alone does not separate them.
pub fn write_config(config: &GeneratedConfig, path: &Path) -> anyhow::Result<()> {
    let yaml = config.to_yaml()?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sb.yml");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let temporary = parent.join(format!(".{file_name}.{}.{nanos}.tmp", std::process::id()));

    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        // A rename swaps the inode, so the mode an operator set on the
        // published file would otherwise be reset to the umask default
        // on every reconcile. Carry it across; a first publish keeps the
        // default it has always had.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(existing) = std::fs::metadata(path) {
                let mode = existing.permissions().mode() & 0o777;
                file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            }
        }
        file.write_all(yaml.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        // Durability of the directory entry itself. Windows has no
        // handle to a directory to sync, and no controller image ships
        // for it.
        #[cfg(unix)]
        {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();

    if result.is_err() {
        // Best effort: the publish already failed, and a leftover
        // dotfile in the mount is the smaller problem.
        let _ = std::fs::remove_file(&temporary);
    }
    Ok(result?)
}

// --- Listener planning ------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Bind {
    Http(u16),
    Https {
        port: u16,
        cert_file: String,
        key_file: String,
    },
    None,
}

struct ListenerPlan {
    hostname: Option<String>,
    bind: Bind,
    outcome: ListenerOutcome,
}

struct PlannedListener {
    bind: Bind,
    accepted: bool,
    programmed: bool,
    reason: &'static str,
    message: String,
    resolved_refs: bool,
    refs_reason: &'static str,
    refs_message: String,
}

impl PlannedListener {
    /// The listener's own configuration is something this controller
    /// cannot serve, so it is neither accepted nor programmed.
    fn rejected(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            bind: Bind::None,
            accepted: false,
            programmed: false,
            reason,
            message: message.into(),
            resolved_refs: true,
            refs_reason: status::REASON_RESOLVED_REFS,
            refs_message: "no references to resolve".to_string(),
        }
    }

    fn bad_certificate(message: impl Into<String>, refs_message: impl Into<String>) -> Self {
        Self {
            bind: Bind::None,
            accepted: false,
            programmed: false,
            reason: status::REASON_INVALID,
            message: message.into(),
            resolved_refs: false,
            refs_reason: status::REASON_INVALID_CERTIFICATE_REF,
            refs_message: refs_message.into(),
        }
    }
}

fn plan_listeners(gateways: &[Gateway], options: &WriterOptions) -> Vec<ListenerPlan> {
    let mut sorted: Vec<&Gateway> = gateways.iter().collect();
    sorted.sort_by_key(|g| (namespace_of(&g.metadata), name_of(&g.metadata)));

    let mut plans: Vec<ListenerPlan> = Vec::new();
    // sbproxy binds exactly one HTTP port and one HTTPS port for the
    // whole process. The first listener of each kind, in the stable order
    // above, wins. A later one asking for a different port cannot be
    // honored and says so on its own status rather than silently
    // rebinding the first one out from under it.
    let mut chosen_http: Option<u16> = None;
    let mut chosen_https: Option<u16> = None;

    for gw in sorted {
        let gw_ns = namespace_of(&gw.metadata);
        let gw_name = name_of(&gw.metadata);
        for listener in &gw.spec.listeners {
            let planned = plan_one(
                listener,
                &gw_ns,
                options,
                &mut chosen_http,
                &mut chosen_https,
            );
            plans.push(ListenerPlan {
                hostname: listener.hostname.clone(),
                bind: planned.bind,
                outcome: ListenerOutcome {
                    gateway_namespace: gw_ns.clone(),
                    gateway_name: gw_name.clone(),
                    listener_name: listener.name.clone(),
                    accepted: planned.accepted,
                    programmed: planned.programmed,
                    reason: planned.reason,
                    message: planned.message,
                    resolved_refs: planned.resolved_refs,
                    refs_reason: planned.refs_reason,
                    refs_message: planned.refs_message,
                    attached_routes: 0,
                },
            });
        }
    }
    plans
}

fn plan_one(
    listener: &Listener,
    gateway_namespace: &str,
    options: &WriterOptions,
    chosen_http: &mut Option<u16>,
    chosen_https: &mut Option<u16>,
) -> PlannedListener {
    match listener.protocol.as_str() {
        "HTTP" => plan_http(listener, chosen_http),
        "HTTPS" => plan_https(listener, gateway_namespace, options, chosen_https),
        other => PlannedListener::rejected(
            status::REASON_UNSUPPORTED_PROTOCOL,
            format!("protocol {other} is not implemented; this controller serves HTTP and HTTPS"),
        ),
    }
}

fn plan_http(listener: &Listener, chosen: &mut Option<u16>) -> PlannedListener {
    match *chosen {
        Some(port) if port != listener.port => {
            return PlannedListener {
                bind: Bind::None,
                // The listener itself is fine. It lost the single HTTP
                // port to an earlier Gateway, which is a cluster-level
                // conflict, not a defect in this manifest.
                accepted: true,
                programmed: false,
                reason: status::REASON_INVALID,
                message: format!(
                    "sbproxy binds one HTTP port per process and port {port} was already claimed \
                     by an earlier listener; this one asked for {}",
                    listener.port
                ),
                resolved_refs: true,
                refs_reason: status::REASON_RESOLVED_REFS,
                refs_message: "no references to resolve".to_string(),
            };
        }
        Some(_) => {}
        None => *chosen = Some(listener.port),
    }
    PlannedListener {
        bind: Bind::Http(listener.port),
        accepted: true,
        programmed: true,
        reason: status::REASON_PROGRAMMED,
        message: format!("listening on HTTP port {}", listener.port),
        resolved_refs: true,
        refs_reason: status::REASON_RESOLVED_REFS,
        refs_message: "no references to resolve".to_string(),
    }
}

fn plan_https(
    listener: &Listener,
    gateway_namespace: &str,
    options: &WriterOptions,
    chosen: &mut Option<u16>,
) -> PlannedListener {
    let Some(tls) = &listener.tls else {
        return PlannedListener::bad_certificate(
            "an HTTPS listener needs a tls block",
            "no tls block, so there is no certificate to resolve",
        );
    };
    let mode = tls.mode.as_deref().unwrap_or("Terminate");
    if mode != "Terminate" {
        return PlannedListener::rejected(
            status::REASON_UNSUPPORTED_PROTOCOL,
            format!("tls mode {mode} is not implemented; only Terminate is"),
        );
    }
    let Some(cert) = tls.certificate_refs.first() else {
        return PlannedListener::bad_certificate(
            "an HTTPS listener needs at least one certificateRef; binding the port without one \
             would leave the data plane unable to start",
            "certificateRefs is empty",
        );
    };
    if let Some(ns) = cert
        .namespace
        .as_deref()
        .filter(|ns| *ns != gateway_namespace)
    {
        return PlannedListener::bad_certificate(
            format!("certificateRef points at namespace {ns}"),
            "a cross-namespace certificateRef needs a ReferenceGrant, which this controller does \
             not read",
        );
    }

    let extra = tls.certificate_refs.len().saturating_sub(1);
    let refs_message = if extra > 0 {
        format!(
            "using certificateRef {}; sbproxy serves one certificate per listener, so {extra} \
             further ref(s) were ignored",
            cert.name
        )
    } else {
        format!("using certificateRef {}", cert.name)
    };

    match *chosen {
        Some(port) if port != listener.port => {
            return PlannedListener {
                bind: Bind::None,
                accepted: true,
                programmed: false,
                reason: status::REASON_INVALID,
                message: format!(
                    "sbproxy binds one HTTPS port per process and port {port} was already claimed \
                     by an earlier listener; this one asked for {}",
                    listener.port
                ),
                resolved_refs: true,
                refs_reason: status::REASON_RESOLVED_REFS,
                refs_message,
            };
        }
        Some(_) => {}
        None => *chosen = Some(listener.port),
    }

    let dir = options.tls_mount_dir.trim_end_matches('/');
    PlannedListener {
        bind: Bind::Https {
            port: listener.port,
            cert_file: format!("{dir}/{}/tls.crt", cert.name),
            key_file: format!("{dir}/{}/tls.key", cert.name),
        },
        accepted: true,
        programmed: true,
        reason: status::REASON_PROGRAMMED,
        message: format!("terminating TLS on port {}", listener.port),
        resolved_refs: true,
        refs_reason: status::REASON_RESOLVED_REFS,
        refs_message,
    }
}

fn proxy_block(plans: &[ListenerPlan]) -> ProxyBlock {
    let mut block = ProxyBlock {
        http_bind_port: 8080,
        ..ProxyBlock::default()
    };
    for plan in plans {
        match &plan.bind {
            Bind::Http(port) => block.http_bind_port = *port,
            Bind::Https {
                port,
                cert_file,
                key_file,
            } => {
                block.https_bind_port = Some(*port);
                block.tls_cert_file = Some(cert_file.clone());
                block.tls_key_file = Some(key_file.clone());
            }
            Bind::None => {}
        }
    }
    block
}

// --- Route binding ----------------------------------------------------

/// Resolve a route's `parentRefs` against the planned listeners.
///
/// Returns the hostnames the route serves, deduplicated across every
/// listener it attached to, plus one outcome per Gateway-targeting
/// `parentRef`.
fn bind_route(
    namespace: &str,
    name: &str,
    parent_refs: &[ParentReference],
    route_hostnames: &[String],
    plans: &mut [ListenerPlan],
) -> (BTreeSet<String>, Vec<RouteOutcome>) {
    let mut hostnames: BTreeSet<String> = BTreeSet::new();
    let mut outcomes = Vec::new();

    for (index, parent) in parent_refs.iter().enumerate() {
        if !parent.targets_a_gateway() {
            // Another implementation owns this reference. Say nothing
            // rather than publishing a rejection on its behalf.
            continue;
        }
        let parent_ns = parent.namespace.as_deref().unwrap_or(namespace);

        let mut matched_gateway = false;
        let mut matched_listener = false;
        let mut bound: BTreeSet<String> = BTreeSet::new();

        for plan in plans.iter_mut() {
            if plan.outcome.gateway_namespace != parent_ns
                || plan.outcome.gateway_name != parent.name
            {
                continue;
            }
            matched_gateway = true;
            if parent
                .section_name
                .as_deref()
                .is_some_and(|section| section != plan.outcome.listener_name.as_str())
            {
                continue;
            }
            if plan.bind == Bind::None {
                continue;
            }
            matched_listener = true;
            let hosts = intersect_hostnames(plan.hostname.as_deref(), route_hostnames);
            if hosts.is_empty() {
                continue;
            }
            plan.outcome.attached_routes += 1;
            bound.extend(hosts);
        }

        if !matched_gateway {
            // `plans` is built only from Gateways on a GatewayClass this
            // controller claims, so failing to match one means the parentRef
            // names somebody else's Gateway or none at all. Same rule as
            // `targets_a_gateway` above: say nothing. Gateway API is explicit
            // that an implementation adds a `parents` entry only for a
            // parentRef it manages, and publishing Accepted=False here would
            // stamp our controller name onto a route whose status another
            // controller owns.
            continue;
        }
        let (accepted, reason, message) = if !matched_listener {
            (
                false,
                status::REASON_NO_MATCHING_PARENT,
                match &parent.section_name {
                    Some(s) => {
                        format!(
                            "listener {s} is not programmed on {parent_ns}/{}",
                            parent.name
                        )
                    }
                    None => format!("no listener on {parent_ns}/{} is programmed", parent.name),
                },
            )
        } else if bound.is_empty() {
            (
                false,
                status::REASON_NO_MATCHING_LISTENER_HOSTNAME,
                "the route hostnames do not intersect any listener hostname".to_string(),
            )
        } else {
            let names: Vec<&str> = bound.iter().map(String::as_str).collect();
            (
                true,
                status::REASON_ACCEPTED,
                format!("serving {}", names.join(", ")),
            )
        };

        hostnames.extend(bound);
        outcomes.push(RouteOutcome {
            namespace: namespace.to_string(),
            name: name.to_string(),
            parent_index: index,
            accepted,
            accepted_reason: reason,
            accepted_message: message,
            resolved_refs: true,
            refs_reason: status::REASON_RESOLVED_REFS,
            refs_message: "all backendRefs and filters resolved".to_string(),
        });
    }

    (hostnames, outcomes)
}

/// Gateway API hostname intersection.
///
/// When one side covers the other the more specific side wins. An empty
/// result means the route serves nothing through that listener.
fn intersect_hostnames(listener: Option<&str>, route: &[String]) -> Vec<String> {
    // A listener with no hostname accepts whatever the route names. When
    // the route names nothing either there is no key to hang an origin
    // off: sbproxy routes by Host and has no catch-all origin key.
    let Some(listener) = listener else {
        return route.to_vec();
    };
    if route.is_empty() {
        return vec![listener.to_string()];
    }
    route
        .iter()
        .filter_map(|r| {
            if covers(listener, r) {
                Some(r.clone())
            } else if covers(r, listener) {
                Some(listener.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Whether `pattern` matches `name`, where either may carry a leading
/// `*.` wildcard label.
///
/// `*.example.com` covers `api.example.com` and `*.a.example.com` but not
/// `example.com`: a wildcard label stands for at least one real label.
/// That is both the Gateway API rule and the sbproxy origin-key rule,
/// which is why hostnames pass through to `origins:` untouched.
fn covers(pattern: &str, name: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return pattern == name;
    };
    if suffix.is_empty() {
        return false;
    }
    match name.strip_prefix("*.") {
        Some(target) => target == suffix || target.ends_with(&format!(".{suffix}")),
        None => name.ends_with(&format!(".{suffix}")),
    }
}

// --- Origin accumulation ----------------------------------------------

/// Gateway API match precedence within one match, most specific first.
///
/// Field order is comparison order, so the derived `Ord` is the
/// precedence rule: exact path, then longest prefix, then a method
/// predicate, then header count, then query count.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MatchRank {
    /// 0 exact, 1 regex, 2 prefix.
    path_kind: u8,
    /// Negated path length, so a longer path sorts first.
    path_len_desc: i32,
    /// 0 when a method predicate is present.
    method_rank: u8,
    /// Negated header predicate count.
    header_count_desc: i32,
    /// Negated query predicate count.
    query_count_desc: i32,
}

/// A whole-document ordering key.
///
/// Upstream breaks the final tie on `creationTimestamp`, which this
/// controller does not read; namespace and name stand in, so the order is
/// stable but can differ from a conformance implementation when two
/// routes collide on the same match.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Precedence {
    rank: MatchRank,
    route_namespace: String,
    route_name: String,
    rule_index: usize,
    match_index: usize,
}

struct MatchPlan {
    rank: MatchRank,
    matcher: RuleMatcher,
}

/// The `/` prefix that stands in for "every request to this hostname".
/// Spelled explicitly rather than as an empty matcher so the intent
/// survives someone reading the generated file.
fn catch_all_match() -> MatchPlan {
    MatchPlan {
        rank: MatchRank {
            path_kind: 2,
            path_len_desc: 0,
            method_rank: 1,
            header_count_desc: 0,
            query_count_desc: 0,
        },
        matcher: RuleMatcher {
            path: Some(PathSpec {
                prefix: Some("/".to_string()),
                ..PathSpec::default()
            }),
            ..RuleMatcher::default()
        },
    }
}

#[derive(Default)]
struct OriginAccumulator {
    forward: Vec<(Precedence, ForwardRule)>,
}

impl OriginAccumulator {
    fn finish(mut self) -> OriginBlock {
        self.forward.sort_by(|a, b| a.0.cmp(&b.0));
        OriginBlock {
            // Gateway API answers 404 when no rule matches. sbproxy walks
            // `forward_rules` first and falls back to the origin's own
            // action, so the fallback is exactly that 404.
            action: serde_json::json!({
                "type": "static",
                "status": 404,
                "content_type": "text/plain; charset=utf-8",
                "body": "no matching route\n",
            }),
            forward_rules: self.forward.into_iter().map(|(_, rule)| rule).collect(),
        }
    }
}

/// A translation gap found while rendering one route.
struct Problem {
    reason: &'static str,
    message: String,
}

fn record_ref_problems(outcomes: &mut [RouteOutcome], problems: &[Problem]) {
    let Some(first) = problems.first() else {
        return;
    };
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut messages: Vec<&str> = Vec::new();
    for p in problems {
        if seen.insert(p.message.as_str()) {
            messages.push(p.message.as_str());
        }
    }
    let joined = messages.join("; ");
    for outcome in outcomes.iter_mut() {
        outcome.resolved_refs = false;
        outcome.refs_reason = first.reason;
        outcome.refs_message.clone_from(&joined);
    }
}

fn apply_http_route(
    acc: &mut OriginAccumulator,
    route: &HTTPRoute,
    namespace: &str,
    name: &str,
    options: &WriterOptions,
    problems: &mut Vec<Problem>,
) {
    for (rule_index, rule) in route.spec.rules.iter().enumerate() {
        let action = http_backend_action(&rule.backend_refs, namespace, options, problems);
        let modifiers = filters_to_modifiers(&rule.filters, problems);
        for (match_index, plan) in http_matchers(rule, problems).into_iter().enumerate() {
            acc.forward.push((
                Precedence {
                    rank: plan.rank,
                    route_namespace: namespace.to_string(),
                    route_name: name.to_string(),
                    rule_index,
                    match_index,
                },
                ForwardRule {
                    rules: vec![plan.matcher],
                    origin: ChildOrigin {
                        action: action.clone(),
                        request_modifiers: modifiers.clone(),
                    },
                },
            ));
        }
    }
}

fn apply_grpc_route(
    acc: &mut OriginAccumulator,
    route: &GRPCRoute,
    namespace: &str,
    name: &str,
    options: &WriterOptions,
    problems: &mut Vec<Problem>,
) {
    for (rule_index, rule) in route.spec.rules.iter().enumerate() {
        let action = grpc_backend_action(&rule.backend_refs, namespace, options, problems);
        let modifiers = filters_to_modifiers(&rule.filters, problems);
        for (match_index, plan) in grpc_matchers(rule, problems).into_iter().enumerate() {
            acc.forward.push((
                Precedence {
                    rank: plan.rank,
                    route_namespace: namespace.to_string(),
                    route_name: name.to_string(),
                    rule_index,
                    match_index,
                },
                ForwardRule {
                    rules: vec![plan.matcher],
                    origin: ChildOrigin {
                        action: action.clone(),
                        request_modifiers: modifiers.clone(),
                    },
                },
            ));
        }
    }
}

fn http_matchers(rule: &HTTPRouteRule, problems: &mut Vec<Problem>) -> Vec<MatchPlan> {
    if rule.matches.is_empty() {
        return vec![catch_all_match()];
    }

    let mut out = Vec::new();
    for m in &rule.matches {
        let (path, path_kind, path_len_desc) = match &m.path {
            None => (
                PathSpec {
                    prefix: Some("/".to_string()),
                    ..PathSpec::default()
                },
                2u8,
                0i32,
            ),
            Some(p) => {
                let len = -(p.value.len() as i32);
                match p.match_type.as_str() {
                    "Exact" => (
                        PathSpec {
                            exact: Some(p.value.clone()),
                            ..PathSpec::default()
                        },
                        0,
                        len,
                    ),
                    "RegularExpression" => (
                        PathSpec {
                            regex: Some(p.value.clone()),
                            ..PathSpec::default()
                        },
                        1,
                        len,
                    ),
                    "PathPrefix" => (
                        PathSpec {
                            prefix: Some(p.value.clone()),
                            ..PathSpec::default()
                        },
                        2,
                        len,
                    ),
                    other => {
                        problems.push(Problem {
                            reason: status::REASON_UNSUPPORTED_VALUE,
                            message: format!("path match type {other} is not implemented"),
                        });
                        continue;
                    }
                }
            }
        };

        out.push(MatchPlan {
            rank: MatchRank {
                path_kind,
                path_len_desc,
                method_rank: if m.method.is_some() { 0 } else { 1 },
                header_count_desc: -(m.headers.len() as i32),
                query_count_desc: -(m.query_params.len() as i32),
            },
            matcher: RuleMatcher {
                path: Some(path),
                header: first_header_match(&m.headers, problems),
                query: first_query_match(&m.query_params, problems),
                method: m.method.clone(),
            },
        });
    }
    out
}

fn grpc_matchers(rule: &GRPCRouteRule, problems: &mut Vec<Problem>) -> Vec<MatchPlan> {
    if rule.matches.is_empty() {
        return vec![catch_all_match()];
    }

    let mut out = Vec::new();
    for m in &rule.matches {
        // A gRPC call is an HTTP/2 POST to /<service>/<method>, so a
        // service-and-method predicate is a path predicate.
        let (path, path_kind, path_len_desc) = match &m.method {
            None => (
                PathSpec {
                    prefix: Some("/".to_string()),
                    ..PathSpec::default()
                },
                2u8,
                0i32,
            ),
            Some(mm) => {
                if mm.match_type != "Exact" {
                    problems.push(Problem {
                        reason: status::REASON_UNSUPPORTED_VALUE,
                        message: format!(
                            "gRPC method match type {} is not implemented",
                            mm.match_type
                        ),
                    });
                    continue;
                }
                match (mm.service.as_deref(), mm.method.as_deref()) {
                    (Some(service), Some(method)) => {
                        let p = format!("/{service}/{method}");
                        let len = -(p.len() as i32);
                        (
                            PathSpec {
                                exact: Some(p),
                                ..PathSpec::default()
                            },
                            0,
                            len,
                        )
                    }
                    (Some(service), None) => {
                        let p = format!("/{service}/");
                        let len = -(p.len() as i32);
                        (
                            PathSpec {
                                prefix: Some(p),
                                ..PathSpec::default()
                            },
                            2,
                            len,
                        )
                    }
                    (None, Some(_)) => {
                        problems.push(Problem {
                            reason: status::REASON_UNSUPPORTED_VALUE,
                            message: "a gRPC method match with no service is not implemented; the \
                                      request path carries the service first"
                                .to_string(),
                        });
                        continue;
                    }
                    (None, None) => (
                        PathSpec {
                            prefix: Some("/".to_string()),
                            ..PathSpec::default()
                        },
                        2,
                        0,
                    ),
                }
            }
        };

        out.push(MatchPlan {
            rank: MatchRank {
                path_kind,
                path_len_desc,
                method_rank: 1,
                header_count_desc: -(m.headers.len() as i32),
                query_count_desc: 0,
            },
            matcher: RuleMatcher {
                path: Some(path),
                header: first_header_match(&m.headers, problems),
                query: None,
                method: None,
            },
        });
    }
    out
}

fn first_header_match(headers: &[HeaderMatch], problems: &mut Vec<Problem>) -> Option<NameValue> {
    let mut usable: Vec<&HeaderMatch> = Vec::new();
    for h in headers {
        if h.match_type == "Exact" {
            usable.push(h);
        } else {
            problems.push(Problem {
                reason: status::REASON_UNSUPPORTED_VALUE,
                message: format!(
                    "header match type {} is not implemented on header {}",
                    h.match_type, h.name
                ),
            });
        }
    }
    let first = *usable.first()?;
    if usable.len() > 1 {
        problems.push(Problem {
            reason: status::REASON_UNSUPPORTED_VALUE,
            message: format!(
                "an sbproxy forward rule carries one header predicate, so {} header match(es) \
                 after {} were dropped",
                usable.len() - 1,
                first.name
            ),
        });
    }
    Some(NameValue {
        name: first.name.clone(),
        value: first.value.clone(),
    })
}

fn first_query_match(params: &[QueryParamMatch], problems: &mut Vec<Problem>) -> Option<NameValue> {
    let mut usable: Vec<&QueryParamMatch> = Vec::new();
    for q in params {
        if q.match_type == "Exact" {
            usable.push(q);
        } else {
            problems.push(Problem {
                reason: status::REASON_UNSUPPORTED_VALUE,
                message: format!(
                    "query match type {} is not implemented on parameter {}",
                    q.match_type, q.name
                ),
            });
        }
    }
    let first = *usable.first()?;
    if usable.len() > 1 {
        problems.push(Problem {
            reason: status::REASON_UNSUPPORTED_VALUE,
            message: format!(
                "an sbproxy forward rule carries one query predicate, so {} queryParam match(es) \
                 after {} were dropped",
                usable.len() - 1,
                first.name
            ),
        });
    }
    Some(NameValue {
        name: first.name.clone(),
        value: first.value.clone(),
    })
}

fn filters_to_modifiers(
    filters: &[RouteFilter],
    problems: &mut Vec<Problem>,
) -> Vec<RequestModifier> {
    let mut out = Vec::new();
    for filter in filters {
        if filter.filter_type != "RequestHeaderModifier" {
            problems.push(Problem {
                reason: status::REASON_UNSUPPORTED_VALUE,
                message: format!("the {} filter is not implemented", filter.filter_type),
            });
            continue;
        }
        let Some(hm) = &filter.request_header_modifier else {
            problems.push(Problem {
                reason: status::REASON_UNSUPPORTED_VALUE,
                message: "a RequestHeaderModifier filter carried no body".to_string(),
            });
            continue;
        };
        let mut ops = HeaderOps::default();
        for h in &hm.set {
            ops.set.insert(h.name.clone(), h.value.clone());
        }
        for h in &hm.add {
            ops.add.insert(h.name.clone(), h.value.clone());
        }
        ops.remove.extend(hm.remove.iter().cloned());
        ops.remove.sort();
        if ops.set.is_empty() && ops.add.is_empty() && ops.remove.is_empty() {
            continue;
        }
        out.push(RequestModifier { headers: ops });
    }
    out
}

// --- Backends ---------------------------------------------------------

fn service_url(
    backend: &BackendRef,
    route_namespace: &str,
    default_port: u16,
    options: &WriterOptions,
) -> String {
    let ns = backend.namespace.as_deref().unwrap_or(route_namespace);
    let port = backend.port.unwrap_or(default_port);
    format!(
        "http://{}.{ns}.svc.{}:{port}",
        backend.name, options.cluster_domain
    )
}

/// Backends that should receive traffic. Gateway API treats weight 0 as
/// "send this backend nothing", which is distinct from an absent weight,
/// which defaults to 1.
fn eligible(backends: &[BackendRef]) -> Vec<&BackendRef> {
    backends.iter().filter(|b| b.weight != Some(0)).collect()
}

fn unresolvable_action(status_code: u16, body: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "static",
        "status": status_code,
        "content_type": "text/plain; charset=utf-8",
        "body": body,
    })
}

fn note_cross_namespace(live: &[&BackendRef], route_namespace: &str, problems: &mut Vec<Problem>) {
    let cross: Vec<&str> = live
        .iter()
        .filter(|b| {
            b.namespace
                .as_deref()
                .is_some_and(|ns| ns != route_namespace)
        })
        .map(|b| b.name.as_str())
        .collect();
    if !cross.is_empty() {
        problems.push(Problem {
            reason: status::REASON_BACKEND_NOT_FOUND,
            message: format!(
                "cross-namespace backendRef(s) {} need a ReferenceGrant, which this controller \
                 does not read; the Service address is rendered anyway",
                cross.join(", ")
            ),
        });
    }
}

fn http_backend_action(
    backends: &[BackendRef],
    route_namespace: &str,
    options: &WriterOptions,
    problems: &mut Vec<Problem>,
) -> serde_json::Value {
    if backends.is_empty() {
        return unresolvable_action(404, "no backend\n");
    }
    let live = eligible(backends);
    if live.is_empty() {
        // Every weight is zero. Gateway API asks for 503 rather than 404:
        // the route exists, it just has nowhere to send anything.
        return unresolvable_action(503, "no backend has a non-zero weight\n");
    }
    note_cross_namespace(&live, route_namespace, problems);
    if live.len() == 1 {
        return serde_json::json!({
            "type": "proxy",
            "url": service_url(live[0], route_namespace, 80, options),
        });
    }
    let targets: Vec<serde_json::Value> = live
        .iter()
        .map(|b| {
            serde_json::json!({
                "url": service_url(b, route_namespace, 80, options),
                "weight": b.weight.unwrap_or(1),
            })
        })
        .collect();
    serde_json::json!({
        "type": "load_balancer",
        "algorithm": "weighted_random",
        "targets": targets,
    })
}

fn grpc_backend_action(
    backends: &[BackendRef],
    route_namespace: &str,
    options: &WriterOptions,
    problems: &mut Vec<Problem>,
) -> serde_json::Value {
    if backends.is_empty() {
        return unresolvable_action(404, "no backend\n");
    }
    let live = eligible(backends);
    if live.is_empty() {
        return unresolvable_action(503, "no backend has a non-zero weight\n");
    }
    note_cross_namespace(&live, route_namespace, problems);
    if live.len() > 1 {
        problems.push(Problem {
            reason: status::REASON_UNSUPPORTED_VALUE,
            message: format!(
                "GRPCRoute traffic splitting is not implemented; of {} backendRefs only {} is used",
                live.len(),
                live[0].name
            ),
        });
    }
    serde_json::json!({
        "type": "grpc",
        "url": service_url(live[0], route_namespace, 50051, options),
    })
}

// --- Metadata helpers -------------------------------------------------

fn namespace_of(meta: &kube::api::ObjectMeta) -> String {
    meta.namespace.clone().unwrap_or_default()
}

fn name_of(meta: &kube::api::ObjectMeta) -> String {
    meta.name.clone().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Fixtures are built from the JSON wire shape rather than from Rust
    // struct literals. That exercises the serde attributes on the way in,
    // so a `camelCase` rename that stopped matching the CRD fails a test
    // here instead of silently reading as a default in a live cluster.

    fn gateway(value: serde_json::Value) -> Gateway {
        serde_json::from_value(value).expect("Gateway fixture deserializes")
    }

    fn http_route(value: serde_json::Value) -> HTTPRoute {
        serde_json::from_value(value).expect("HTTPRoute fixture deserializes")
    }

    fn grpc_route(value: serde_json::Value) -> GRPCRoute {
        serde_json::from_value(value).expect("GRPCRoute fixture deserializes")
    }

    fn simple_gateway() -> Gateway {
        gateway(json!({
            "metadata": { "name": "sbproxy-gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{ "name": "http", "port": 8080, "protocol": "HTTP" }]
            }
        }))
    }

    fn render_default(gateways: &[Gateway], http: &[HTTPRoute], grpc: &[GRPCRoute]) -> Render {
        render(gateways, http, grpc, &WriterOptions::default())
    }

    /// Render, serialize, and hand the document to the real config
    /// compiler. Returns the YAML so a caller can assert on it too.
    ///
    /// `compile_config` returns `Result<CompiledConfig, anyhow::Error>`
    /// and `CompiledConfig` does not implement `Debug`, so the success
    /// path uses `expect` (which needs the error to be `Debug`, and
    /// `anyhow::Error` is) while every failure path in this module has to
    /// use `.err().expect(..)`.
    fn compile(rendered: &Render) -> String {
        let yaml = rendered
            .config
            .to_yaml()
            .expect("document serializes to YAML");
        if let Err(e) = sbproxy_config::compile_config(&yaml) {
            panic!("generated config was rejected by compile_config: {e:#}\n---\n{yaml}");
        }
        yaml
    }

    // --- The regression this whole file exists for --------------------

    #[test]
    fn a_forward_rule_nests_its_matcher_under_rules() {
        // The shape bug: emitting `{"path": ..., "origin": ...}` puts a
        // key on RawForwardRule that deny_unknown_fields refuses, which
        // fails the entire document rather than one route.
        let route = http_route(json!({
            "metadata": { "name": "api", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{ "path": { "type": "PathPrefix", "value": "/api" } }],
                    "backendRefs": [{ "name": "api-svc", "port": 8080 }]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("document serializes to JSON");
        let rule = &value["origins"]["api.example.com"]["forward_rules"][0];

        assert!(
            rule.get("path").is_none(),
            "a top-level `path` key is exactly what deny_unknown_fields rejects: {rule}"
        );
        assert_eq!(rule["rules"][0]["path"]["prefix"], "/api");
        assert_eq!(rule["origin"]["action"]["type"], "proxy");
        assert_eq!(
            rule["origin"]["action"]["url"],
            "http://api-svc.default.svc.cluster.local:8080"
        );

        compile(&rendered);
    }

    #[test]
    fn the_pre_fix_forward_rule_shape_is_rejected_by_the_compiler() {
        // Pins the defect itself. If a future schema change made the old
        // shape legal again this test fails and the regression test above
        // stops meaning anything.
        let broken = r#"
proxy:
  http_bind_port: 8080
origins:
  api.example.com:
    action:
      type: static
      status: 404
    forward_rules:
      - path: /api
        origin:
          action:
            type: proxy
            url: http://api-svc.default.svc.cluster.local:8080
"#;
        // `.err().expect(..)` and not `expect_err`: the latter needs the Ok
        // type to be `Debug` and `CompiledConfig` is not. See `compile`.
        let error = sbproxy_config::compile_config(broken)
            .err()
            .expect("a top-level `path` on a forward rule must fail the whole document");
        let message = format!("{error:#}");
        assert!(
            message.contains("unknown field") && message.contains("path"),
            "expected an unknown-field error naming `path`, got: {message}"
        );
    }

    // --- Golden compiles ----------------------------------------------

    #[test]
    fn a_document_using_every_wired_feature_compiles() {
        let gw = gateway(json!({
            "metadata": { "name": "sbproxy-gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [
                    { "name": "http", "port": 8080, "protocol": "HTTP" },
                    {
                        "name": "https",
                        "port": 8443,
                        "protocol": "HTTPS",
                        "tls": {
                            "mode": "Terminate",
                            "certificateRefs": [{ "name": "api-cert" }]
                        }
                    }
                ]
            }
        }));
        let api = http_route(json!({
            "metadata": { "name": "api", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["api.example.com", "*.tenants.example.com"],
                "rules": [
                    {
                        "matches": [
                            { "path": { "type": "Exact", "value": "/healthz" } },
                            {
                                "path": { "type": "PathPrefix", "value": "/v2" },
                                "method": "POST",
                                "headers": [{ "name": "X-Canary", "value": "on" }],
                                "queryParams": [{ "name": "beta", "value": "1" }]
                            }
                        ],
                        "filters": [{
                            "type": "RequestHeaderModifier",
                            "requestHeaderModifier": {
                                "set": [{ "name": "X-Gateway", "value": "sbproxy" }],
                                "add": [{ "name": "X-Trace", "value": "on" }],
                                "remove": ["X-Internal", "X-Debug"]
                            }
                        }],
                        "backendRefs": [
                            { "name": "api-blue", "port": 8080, "weight": 90 },
                            { "name": "api-green", "port": 8080, "weight": 10 }
                        ]
                    },
                    {
                        "backendRefs": [{ "name": "api-default", "port": 80 }]
                    }
                ]
            }
        }));
        let chat = grpc_route(json!({
            "metadata": { "name": "chat", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["grpc.example.com"],
                "rules": [{
                    "matches": [
                        { "method": { "service": "chat.v1.Chat", "method": "Send" } },
                        { "method": { "service": "chat.v1.Chat" } }
                    ],
                    "backendRefs": [{ "name": "chat-svc", "port": 50051 }]
                }]
            }
        }));

        let rendered = render_default(&[gw], &[api], &[chat]);
        let yaml = compile(&rendered);

        // The compiler accepted it; confirm it also routes.
        let compiled = sbproxy_config::compile_config(&yaml).expect("document compiles");
        assert!(compiled.resolve_origin("api.example.com").is_some());
        assert!(compiled.resolve_origin("grpc.example.com").is_some());
        assert!(
            compiled
                .resolve_origin("acme.tenants.example.com")
                .is_some(),
            "a `*.` origin key must still resolve a real subdomain"
        );
        assert!(
            compiled.resolve_origin("tenants.example.com").is_none(),
            "a wildcard label stands for at least one real label"
        );
        assert_eq!(rendered.config.origin_count(), 3);
    }

    #[test]
    fn the_semantic_lint_finds_nothing_but_the_known_cluster_local_false_positive() {
        // `compile_config` is the gate the data plane applies.
        // `sbproxy_config::validate` is the softer semantic linter, and
        // the operator runs it as preview validation before rolling out
        // an SBProxyConfig, refusing anything with an error-severity
        // finding. It reports exactly one thing on every document this
        // controller writes: `orphan-forward-rule-target`, because a
        // forward rule's action URL names a host that is not itself an
        // origin key. For a Kubernetes Service address it never will be.
        //
        // Pinning it here does two things. It asserts that no *other*
        // error-severity rule fires, which is how an unknown action type
        // or a bad secret reference would surface. And it fails loudly if
        // the linter ever learns about cluster-local names, so the
        // caveat in docs/gateway-api.md gets deleted at the same time.
        let route = http_route(json!({
            "metadata": { "name": "api", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["api.example.com"],
                "rules": [
                    {
                        "matches": [{ "path": { "type": "PathPrefix", "value": "/api" } }],
                        "backendRefs": [
                            { "name": "blue", "port": 80, "weight": 1 },
                            { "name": "green", "port": 80, "weight": 1 }
                        ]
                    },
                    { "backendRefs": [{ "name": "api-svc", "port": 8080 }] }
                ]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let yaml = compile(&rendered);

        let file: sbproxy_config::ConfigFile =
            serde_yaml::from_str(&yaml).expect("document parses as a ConfigFile");
        let findings =
            sbproxy_config::validate(&file, &sbproxy_config::ValidationOptions::default());

        let errors: Vec<&sbproxy_config::PlanFinding> = findings
            .iter()
            .filter(|f| f.severity == sbproxy_config::Severity::Error)
            .collect();
        assert!(
            errors
                .iter()
                .any(|f| f.rule_id == "orphan-forward-rule-target"),
            "the known false positive disappeared; delete the caveat from the docs: {errors:?}"
        );
        let unexpected: Vec<&&sbproxy_config::PlanFinding> = errors
            .iter()
            .filter(|f| f.rule_id != "orphan-forward-rule-target")
            .collect();
        assert!(
            unexpected.is_empty(),
            "the generated document tripped a lint rule we did not expect: {unexpected:?}"
        );
    }

    #[test]
    fn an_empty_cluster_still_compiles() {
        let rendered = render_default(&[], &[], &[]);
        let yaml = compile(&rendered);
        assert!(yaml.contains("http_bind_port: 8080"));
        assert_eq!(rendered.config.origin_count(), 0);
    }

    #[test]
    fn a_route_with_no_rules_compiles_to_a_404_only_origin() {
        let route = http_route(json!({
            "metadata": { "name": "bare", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["bare.example.com"],
                "rules": []
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        assert_eq!(
            value["origins"]["bare.example.com"]["action"]["status"],
            404
        );
        assert!(value["origins"]["bare.example.com"]
            .get("forward_rules")
            .is_none());
        compile(&rendered);
    }

    #[test]
    fn rendering_twice_produces_byte_identical_yaml() {
        let routes: Vec<HTTPRoute> = ["zulu", "alpha", "mike"]
            .iter()
            .map(|n| {
                http_route(json!({
                    "metadata": { "name": n, "namespace": "default" },
                    "spec": {
                        "parentRefs": [{ "name": "sbproxy-gw" }],
                        "hostnames": [format!("{n}.example.com")],
                        "rules": [{ "backendRefs": [{ "name": format!("{n}-svc"), "port": 80 }] }]
                    }
                }))
            })
            .collect();
        let first = render_default(&[simple_gateway()], &routes, &[]);
        let mut shuffled = routes;
        shuffled.reverse();
        let second = render_default(&[simple_gateway()], &shuffled, &[]);
        assert_eq!(
            first.config.to_yaml().expect("yaml"),
            second.config.to_yaml().expect("yaml"),
            "arrival order must not leak into the document"
        );
    }

    // --- Matches -------------------------------------------------------

    #[test]
    fn matches_are_ordered_by_gateway_api_precedence() {
        let route = http_route(json!({
            "metadata": { "name": "api", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [
                        { "path": { "type": "PathPrefix", "value": "/" } },
                        { "path": { "type": "PathPrefix", "value": "/a" } },
                        { "path": { "type": "PathPrefix", "value": "/a/b/c" } },
                        { "path": { "type": "Exact", "value": "/z" } }
                    ],
                    "backendRefs": [{ "name": "svc", "port": 80 }]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let rules = value["origins"]["api.example.com"]["forward_rules"]
            .as_array()
            .expect("forward rules");
        let seen: Vec<String> = rules
            .iter()
            .map(|r| {
                let p = &r["rules"][0]["path"];
                match (p.get("exact"), p.get("prefix")) {
                    (Some(e), _) => format!("exact:{}", e.as_str().unwrap_or_default()),
                    (_, Some(p)) => format!("prefix:{}", p.as_str().unwrap_or_default()),
                    _ => "?".to_string(),
                }
            })
            .collect();
        assert_eq!(
            seen,
            vec!["exact:/z", "prefix:/a/b/c", "prefix:/a", "prefix:/"],
            "exact beats prefix, then longest prefix first"
        );
        compile(&rendered);
    }

    #[test]
    fn a_method_predicate_outranks_the_same_path_without_one() {
        let route = http_route(json!({
            "metadata": { "name": "api", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [
                        { "path": { "type": "PathPrefix", "value": "/v1" } },
                        { "path": { "type": "PathPrefix", "value": "/v1" }, "method": "DELETE" }
                    ],
                    "backendRefs": [{ "name": "svc", "port": 80 }]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let rules = &value["origins"]["api.example.com"]["forward_rules"];
        assert_eq!(rules[0]["rules"][0]["method"], "DELETE");
        assert!(rules[1]["rules"][0].get("method").is_none());
        compile(&rendered);
    }

    #[test]
    fn header_and_query_predicates_survive_the_translation() {
        let route = http_route(json!({
            "metadata": { "name": "api", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{
                        "headers": [{ "name": "X-Tenant", "value": "acme" }],
                        "queryParams": [{ "name": "mode", "value": "fast" }]
                    }],
                    "backendRefs": [{ "name": "svc", "port": 80 }]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let matcher = &value["origins"]["api.example.com"]["forward_rules"][0]["rules"][0];
        assert_eq!(matcher["header"]["name"], "X-Tenant");
        assert_eq!(matcher["header"]["value"], "acme");
        assert_eq!(matcher["query"]["name"], "mode");
        assert_eq!(matcher["query"]["value"], "fast");
        compile(&rendered);
    }

    #[test]
    fn a_second_header_predicate_is_dropped_and_reported() {
        let route = http_route(json!({
            "metadata": { "name": "api", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{
                        "headers": [
                            { "name": "X-One", "value": "1" },
                            { "name": "X-Two", "value": "2" }
                        ]
                    }],
                    "backendRefs": [{ "name": "svc", "port": 80 }]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let outcome = &rendered.routes[0];
        assert!(
            !outcome.resolved_refs,
            "a dropped predicate must not be reported as fully resolved"
        );
        assert_eq!(outcome.refs_reason, status::REASON_UNSUPPORTED_VALUE);
        assert!(
            outcome.refs_message.contains("X-One"),
            "{}",
            outcome.refs_message
        );
        compile(&rendered);
    }

    #[test]
    fn a_regular_expression_header_match_is_refused_rather_than_guessed() {
        let route = http_route(json!({
            "metadata": { "name": "api", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{
                        "headers": [{ "type": "RegularExpression", "name": "X-Any", "value": "a.*" }]
                    }],
                    "backendRefs": [{ "name": "svc", "port": 80 }]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let matcher = &value["origins"]["api.example.com"]["forward_rules"][0]["rules"][0];
        assert!(
            matcher.get("header").is_none(),
            "an unsupported header match must be dropped, not silently made exact"
        );
        assert!(!rendered.routes[0].resolved_refs);
        compile(&rendered);
    }

    // --- Backends ------------------------------------------------------

    #[test]
    fn weighted_backends_become_a_weighted_random_load_balancer() {
        let route = http_route(json!({
            "metadata": { "name": "split", "namespace": "prod" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw", "namespace": "default" }],
                "hostnames": ["split.example.com"],
                "rules": [{
                    "backendRefs": [
                        { "name": "blue", "port": 80, "weight": 90 },
                        { "name": "green", "port": 80, "weight": 10 }
                    ]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let action = &value["origins"]["split.example.com"]["forward_rules"][0]["origin"]["action"];
        assert_eq!(action["type"], "load_balancer");
        assert_eq!(action["algorithm"], "weighted_random");
        assert_eq!(action["targets"][0]["weight"], 90);
        assert_eq!(
            action["targets"][0]["url"], "http://blue.prod.svc.cluster.local:80",
            "a backend with no namespace resolves in the route's namespace, not the Gateway's"
        );
        assert_eq!(action["targets"][1]["weight"], 10);
        compile(&rendered);
    }

    #[test]
    fn a_backend_weighted_zero_is_removed_from_the_pool() {
        let route = http_route(json!({
            "metadata": { "name": "drain", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["drain.example.com"],
                "rules": [{
                    "backendRefs": [
                        { "name": "live", "port": 80, "weight": 1 },
                        { "name": "drained", "port": 80, "weight": 0 }
                    ]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let action = &value["origins"]["drain.example.com"]["forward_rules"][0]["origin"]["action"];
        assert_eq!(
            action["type"], "proxy",
            "one live backend is a plain proxy, not a one-target load balancer"
        );
        assert!(action["url"].as_str().unwrap_or_default().contains("live"));
        compile(&rendered);
    }

    #[test]
    fn every_backend_weighted_zero_answers_503() {
        let route = http_route(json!({
            "metadata": { "name": "off", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["off.example.com"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80, "weight": 0 }] }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let action = &value["origins"]["off.example.com"]["forward_rules"][0]["origin"]["action"];
        assert_eq!(action["status"], 503);
        compile(&rendered);
    }

    #[test]
    fn a_grpc_method_match_becomes_an_exact_path() {
        let route = grpc_route(json!({
            "metadata": { "name": "chat", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["grpc.example.com"],
                "rules": [{
                    "matches": [{ "method": { "service": "chat.v1.Chat", "method": "Send" } }],
                    "backendRefs": [{ "name": "chat-svc" }]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[], &[route]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let rule = &value["origins"]["grpc.example.com"]["forward_rules"][0];
        assert_eq!(rule["rules"][0]["path"]["exact"], "/chat.v1.Chat/Send");
        assert_eq!(rule["origin"]["action"]["type"], "grpc");
        assert_eq!(
            rule["origin"]["action"]["url"], "http://chat-svc.default.svc.cluster.local:50051",
            "an omitted gRPC port defaults to 50051"
        );
        compile(&rendered);
    }

    // --- Filters -------------------------------------------------------

    #[test]
    fn a_request_header_modifier_becomes_a_request_modifier() {
        let route = http_route(json!({
            "metadata": { "name": "hdr", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["hdr.example.com"],
                "rules": [{
                    "filters": [{
                        "type": "RequestHeaderModifier",
                        "requestHeaderModifier": {
                            "set": [{ "name": "X-Set", "value": "1" }],
                            "add": [{ "name": "X-Add", "value": "2" }],
                            "remove": ["X-Gone"]
                        }
                    }],
                    "backendRefs": [{ "name": "svc", "port": 80 }]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let modifiers =
            &value["origins"]["hdr.example.com"]["forward_rules"][0]["origin"]["request_modifiers"];
        assert_eq!(modifiers[0]["headers"]["set"]["X-Set"], "1");
        assert_eq!(modifiers[0]["headers"]["add"]["X-Add"], "2");
        assert_eq!(modifiers[0]["headers"]["remove"][0], "X-Gone");
        assert!(rendered.routes[0].resolved_refs);
        compile(&rendered);
    }

    #[test]
    fn an_unimplemented_filter_is_reported_not_ignored() {
        let route = http_route(json!({
            "metadata": { "name": "redir", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["redir.example.com"],
                "rules": [{
                    "filters": [{
                        "type": "RequestRedirect",
                        "requestRedirect": { "scheme": "https", "statusCode": 301 }
                    }],
                    "backendRefs": [{ "name": "svc", "port": 80 }]
                }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        assert!(!rendered.routes[0].resolved_refs);
        assert_eq!(
            rendered.routes[0].refs_reason,
            status::REASON_UNSUPPORTED_VALUE
        );
        assert!(
            rendered.routes[0].refs_message.contains("RequestRedirect"),
            "{}",
            rendered.routes[0].refs_message
        );
        compile(&rendered);
    }

    // --- Listeners and TLS ---------------------------------------------

    #[test]
    fn an_https_listener_emits_the_mounted_secret_paths() {
        let gw = gateway(json!({
            "metadata": { "name": "tls-gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": { "mode": "Terminate", "certificateRefs": [{ "name": "api-cert" }] }
                }]
            }
        }));
        let rendered = render_default(&[gw], &[], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        assert_eq!(value["proxy"]["https_bind_port"], 443);
        assert_eq!(
            value["proxy"]["tls_cert_file"],
            "/etc/sbproxy/tls/api-cert/tls.crt"
        );
        assert_eq!(
            value["proxy"]["tls_key_file"],
            "/etc/sbproxy/tls/api-cert/tls.key"
        );
        assert!(rendered.listeners[0].programmed);
        compile(&rendered);
    }

    #[test]
    fn an_https_listener_with_no_certificate_does_not_bind_the_port() {
        // Emitting https_bind_port with no cert compiles fine and then
        // stops the data plane from starting at all, which is a far worse
        // failure than one unprogrammed listener.
        let gw = gateway(json!({
            "metadata": { "name": "tls-gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": { "mode": "Terminate", "certificateRefs": [] }
                }]
            }
        }));
        let rendered = render_default(&[gw], &[], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        assert!(value["proxy"].get("https_bind_port").is_none());
        assert!(!rendered.listeners[0].programmed);
        assert!(!rendered.listeners[0].resolved_refs);
        assert_eq!(
            rendered.listeners[0].refs_reason,
            status::REASON_INVALID_CERTIFICATE_REF
        );
        compile(&rendered);
    }

    #[test]
    fn a_passthrough_listener_is_refused_by_protocol() {
        let gw = gateway(json!({
            "metadata": { "name": "tls-gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [
                    {
                        "name": "passthrough",
                        "port": 443,
                        "protocol": "HTTPS",
                        "tls": { "mode": "Passthrough", "certificateRefs": [] }
                    },
                    { "name": "tcp", "port": 9000, "protocol": "TCP" }
                ]
            }
        }));
        let rendered = render_default(&[gw], &[], &[]);
        assert!(!rendered.listeners[0].programmed);
        assert_eq!(
            rendered.listeners[0].reason,
            status::REASON_UNSUPPORTED_PROTOCOL
        );
        assert!(!rendered.listeners[1].programmed);
        assert_eq!(
            rendered.listeners[1].reason,
            status::REASON_UNSUPPORTED_PROTOCOL
        );
    }

    #[test]
    fn a_second_http_port_loses_and_says_why() {
        let a = gateway(json!({
            "metadata": { "name": "a-gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{ "name": "http", "port": 8080, "protocol": "HTTP" }]
            }
        }));
        let b = gateway(json!({
            "metadata": { "name": "b-gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{ "name": "http", "port": 9090, "protocol": "HTTP" }]
            }
        }));
        let rendered = render_default(&[b, a], &[], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        assert_eq!(
            value["proxy"]["http_bind_port"], 8080,
            "a-gw sorts first, so it wins regardless of argument order"
        );
        let loser = rendered
            .listeners
            .iter()
            .find(|l| l.gateway_name == "b-gw")
            .expect("b-gw listener reported");
        assert!(!loser.programmed);
        assert!(
            loser.accepted,
            "losing a port race is a cluster conflict, not a defect in this listener"
        );
        assert_eq!(loser.reason, status::REASON_INVALID);
        assert!(loser.message.contains("8080"), "{}", loser.message);
    }

    #[test]
    fn two_listeners_on_the_same_port_are_both_programmed() {
        let gw = gateway(json!({
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [
                    { "name": "a", "port": 8080, "protocol": "HTTP", "hostname": "a.example.com" },
                    { "name": "b", "port": 8080, "protocol": "HTTP", "hostname": "b.example.com" }
                ]
            }
        }));
        let rendered = render_default(&[gw], &[], &[]);
        assert!(rendered.listeners.iter().all(|l| l.programmed));
    }

    // --- parentRefs binding ---------------------------------------------

    #[test]
    fn a_route_naming_an_unknown_gateway_gets_no_status_entry() {
        // Serves nothing, and says nothing. Gateway API is explicit that the
        // `parents` list carries entries only for parentRefs the
        // implementation is responsible for, and no implementation is
        // responsible for a Gateway that does not exist. Writing
        // Accepted=False here would stamp our controller name onto a route we
        // have no claim to, and if every controller in the cluster did it the
        // route's status would fill with rejections from implementations that
        // were never asked.
        //
        // The cost is real and accepted: an operator who typos a parentRef
        // gets silence rather than a diagnosis. The Gateway's own status and
        // an unattached route are where that surfaces instead.
        let route = http_route(json!({
            "metadata": { "name": "orphan", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "nope" }],
                "hostnames": ["orphan.example.com"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        assert_eq!(rendered.config.origin_count(), 0);
        assert!(
            rendered.routes.is_empty(),
            "a parentRef we do not manage must produce no outcome, got {:?}",
            rendered.routes
        );
    }

    #[test]
    fn a_route_with_no_parent_refs_binds_to_nothing() {
        // The pre-move controller matched routes to a Gateway by listener
        // port and ignored parentRefs entirely, so this route would have
        // been served. Gateway API attaches through parentRefs only.
        let route = http_route(json!({
            "metadata": { "name": "floating", "namespace": "default" },
            "spec": {
                "hostnames": ["floating.example.com"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        assert_eq!(rendered.config.origin_count(), 0);
        assert!(
            rendered.routes.is_empty(),
            "no parentRef, nothing to report"
        );
    }

    #[test]
    fn section_name_selects_one_listener() {
        let gw = gateway(json!({
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [
                    { "name": "public", "port": 8080, "protocol": "HTTP", "hostname": "public.example.com" },
                    { "name": "internal", "port": 8080, "protocol": "HTTP", "hostname": "internal.example.com" }
                ]
            }
        }));
        let route = http_route(json!({
            "metadata": { "name": "pinned", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "gw", "sectionName": "internal" }],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        }));
        let rendered = render_default(&[gw], &[route], &[]);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        assert!(value["origins"].get("internal.example.com").is_some());
        assert!(
            value["origins"].get("public.example.com").is_none(),
            "sectionName pins the route to one listener"
        );
        let public = rendered
            .listeners
            .iter()
            .find(|l| l.listener_name == "public")
            .expect("public listener reported");
        assert_eq!(public.attached_routes, 0);
        let internal = rendered
            .listeners
            .iter()
            .find(|l| l.listener_name == "internal")
            .expect("internal listener reported");
        assert_eq!(internal.attached_routes, 1);
        compile(&rendered);
    }

    #[test]
    fn a_parent_ref_to_another_kind_is_left_alone() {
        let route = http_route(json!({
            "metadata": { "name": "mesh", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "kind": "Service", "name": "some-svc" }],
                "hostnames": ["mesh.example.com"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        }));
        let rendered = render_default(&[simple_gateway()], &[route], &[]);
        assert!(
            rendered.routes.is_empty(),
            "publishing a rejection for a reference another implementation owns would be wrong"
        );
    }

    #[test]
    fn a_route_whose_hostnames_miss_the_listener_is_reported() {
        let gw = gateway(json!({
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{
                    "name": "http", "port": 8080, "protocol": "HTTP",
                    "hostname": "*.example.com"
                }]
            }
        }));
        let route = http_route(json!({
            "metadata": { "name": "elsewhere", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "gw" }],
                "hostnames": ["api.other.test"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        }));
        let rendered = render_default(&[gw], &[route], &[]);
        assert_eq!(rendered.config.origin_count(), 0);
        assert!(!rendered.routes[0].accepted);
        assert_eq!(
            rendered.routes[0].accepted_reason,
            status::REASON_NO_MATCHING_LISTENER_HOSTNAME
        );
    }

    #[test]
    fn two_routes_on_one_hostname_merge_into_one_origin() {
        let gw = simple_gateway();
        let a = http_route(json!({
            "metadata": { "name": "a-route", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["shared.example.com"],
                "rules": [{
                    "matches": [{ "path": { "type": "PathPrefix", "value": "/a" } }],
                    "backendRefs": [{ "name": "a-svc", "port": 80 }]
                }]
            }
        }));
        let b = http_route(json!({
            "metadata": { "name": "b-route", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "sbproxy-gw" }],
                "hostnames": ["shared.example.com"],
                "rules": [{
                    "matches": [{ "path": { "type": "PathPrefix", "value": "/b" } }],
                    "backendRefs": [{ "name": "b-svc", "port": 80 }]
                }]
            }
        }));
        let rendered = render_default(&[gw], &[a, b], &[]);
        assert_eq!(rendered.config.origin_count(), 1);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        let rules = value["origins"]["shared.example.com"]["forward_rules"]
            .as_array()
            .expect("forward rules");
        assert_eq!(rules.len(), 2);
        compile(&rendered);
    }

    // --- Hostname intersection ------------------------------------------

    #[test]
    fn hostname_intersection_takes_the_more_specific_side() {
        let route = vec!["api.example.com".to_string()];
        assert_eq!(
            intersect_hostnames(Some("*.example.com"), &route),
            vec!["api.example.com".to_string()]
        );
        assert_eq!(
            intersect_hostnames(Some("api.example.com"), &["*.example.com".to_string()]),
            vec!["api.example.com".to_string()]
        );
        assert_eq!(
            intersect_hostnames(Some("*.example.com"), &["*.a.example.com".to_string()]),
            vec!["*.a.example.com".to_string()]
        );
        assert!(
            intersect_hostnames(Some("a.example.com"), &["b.example.com".to_string()]).is_empty()
        );
    }

    #[test]
    fn a_listener_without_a_hostname_takes_the_routes_hostnames() {
        assert_eq!(
            intersect_hostnames(None, &["a.test".to_string(), "b.test".to_string()]),
            vec!["a.test".to_string(), "b.test".to_string()]
        );
        assert!(
            intersect_hostnames(None, &[]).is_empty(),
            "no hostname on either side leaves no origin key to use"
        );
    }

    #[test]
    fn a_route_without_hostnames_inherits_the_listener_hostname() {
        assert_eq!(
            intersect_hostnames(Some("edge.example.com"), &[]),
            vec!["edge.example.com".to_string()]
        );
    }

    #[test]
    fn a_wildcard_label_stands_for_at_least_one_real_label() {
        assert!(covers("*.example.com", "api.example.com"));
        assert!(covers("*.example.com", "a.b.example.com"));
        assert!(covers("*.example.com", "*.example.com"));
        assert!(covers("*.example.com", "*.tenant.example.com"));
        assert!(!covers("*.example.com", "example.com"));
        assert!(!covers("*.example.com", "notexample.com"));
        assert!(!covers("*.", "anything"));
        assert!(covers("api.example.com", "api.example.com"));
        assert!(!covers("api.example.com", "other.example.com"));
    }

    // --- Filesystem ------------------------------------------------------

    #[test]
    fn write_config_creates_the_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let rendered = render_default(&[simple_gateway()], &[], &[]);
        write_config(&rendered.config, &path).expect("write succeeds");
        let body = std::fs::read_to_string(&path).expect("read back");
        assert!(body.contains("http_bind_port: 8080"));
    }

    /// The durability half of the publish. A crash between the truncate
    /// and the write cannot be staged in-process, but every failure of
    /// the publish takes the same branch, and the guarantee is the same
    /// one: the document already on disk is still whole afterwards.
    ///
    /// Dropping the directory's write bit is what stages it. Note that
    /// it does not stop the old `std::fs::write` at all: truncating an
    /// existing file needs write permission on the file, not on its
    /// directory, so the pre-fix writer succeeds here and rewrites the
    /// document. It is creating the temporary that needs the directory.
    #[cfg(unix)]
    #[test]
    fn write_config_leaves_the_previous_document_intact_when_publication_fails() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let published = render_default(&[simple_gateway()], &[], &[]);
        write_config(&published.config, &path).expect("the first publish succeeds");
        let last_good = std::fs::read_to_string(&path).expect("read back");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("drop the directory write bit");

        // Root ignores the write bit, so on a privileged runner this
        // injection cannot fire and the assertions below would be
        // vacuous. Restore and leave rather than pretend. Every lane
        // that gates this workspace runs unprivileged.
        let probe = dir.path().join(".privilege-probe");
        if std::fs::File::create(&probe).is_ok() {
            let _ = std::fs::remove_file(&probe);
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restore the directory");
            return;
        }

        let replacement = render_default(&[], &[], &[]);
        let error = write_config(&replacement.config, &path);

        // Restore before asserting so the temp dir can still clean up
        // when an assertion below fails.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore the directory");

        let error = error.expect_err("a publish that cannot write its temporary fails");
        assert!(!format!("{error}").is_empty());
        assert_eq!(
            std::fs::read_to_string(&path).expect("the previous document is still readable"),
            last_good,
            "a failed publish left something other than the last good document"
        );
    }

    /// A rename that fails leaves its temporary behind, and this file is
    /// written on every reconcile. One dotfile per failure fills the
    /// volume the data plane reads from.
    #[test]
    fn write_config_leaves_no_temporary_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let rendered = render_default(&[simple_gateway()], &[], &[]);
        write_config(&rendered.config, &path).expect("write succeeds");
        write_config(&rendered.config, &path).expect("republish succeeds");

        let mut entries: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read the directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        entries.sort();
        assert_eq!(entries, vec!["sb.yml".to_string()]);
    }

    /// The publish swaps the inode, so without carrying the mode across
    /// a reconcile would silently reopen a file an operator had locked
    /// down.
    #[cfg(unix)]
    #[test]
    fn republishing_keeps_the_mode_the_published_file_already_had() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("sb.yml");
        let rendered = render_default(&[simple_gateway()], &[], &[]);
        write_config(&rendered.config, &path).expect("the first publish succeeds");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("tighten the published file");

        write_config(&rendered.config, &path).expect("the republish succeeds");

        let mode = std::fs::metadata(&path)
            .expect("published file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "the republish reset the operator's mode");
    }

    #[test]
    fn write_config_reports_a_bad_path_instead_of_panicking() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("missing-subdir").join("sb.yml");
        let rendered = render_default(&[], &[], &[]);
        let error = write_config(&rendered.config, &path)
            .expect_err("writing into a nonexistent directory fails");
        assert!(!format!("{error}").is_empty());
    }

    #[test]
    fn a_custom_cluster_domain_and_mount_dir_are_honored() {
        let gw = gateway(json!({
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sbproxy",
                "listeners": [{
                    "name": "https", "port": 443, "protocol": "HTTPS",
                    "tls": { "certificateRefs": [{ "name": "c" }] }
                }]
            }
        }));
        let route = http_route(json!({
            "metadata": { "name": "r", "namespace": "default" },
            "spec": {
                "parentRefs": [{ "name": "gw" }],
                "hostnames": ["h.example.com"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        }));
        let options = WriterOptions {
            tls_mount_dir: "/mnt/certs/".to_string(),
            cluster_domain: "cluster.internal".to_string(),
        };
        let rendered = render(&[gw], &[route], &[], &options);
        let value = serde_json::to_value(&rendered.config).expect("serializes");
        assert_eq!(value["proxy"]["tls_cert_file"], "/mnt/certs/c/tls.crt");
        assert_eq!(
            value["origins"]["h.example.com"]["forward_rules"][0]["origin"]["action"]["url"],
            "http://svc.default.svc.cluster.internal:80"
        );
    }
}
