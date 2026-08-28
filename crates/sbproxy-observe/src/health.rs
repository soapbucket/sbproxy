//! `/healthz` and `/readyz` endpoints.
//!
//! Per `docs/AIGOVERNANCE-BUILD.md` § 4.2:
//!
//! - `/healthz` is liveness: returns 200 if the process is up. No
//!   dependencies are checked. Kubelet uses this to decide whether
//!   to restart the pod.
//! - `/readyz` is readiness: returns 200 only when every configured
//!   dependency reports healthy. Kubelet uses this to decide whether
//!   to route traffic. Failing dependencies are listed in the body.
//!
//! Ships hooks for the dependencies that exist today and stub
//! variants for the ones landing later (Stripe, facilitator quorum,
//! agent registry). The stubs
//! return `Healthy` so they don't break readiness in builds where
//! their backing service isn't wired yet.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

static PROCESS_STARTED_AT: OnceLock<Instant> = OnceLock::new();

/// Anchor the uptime clock at process start.
///
/// Call once, early in `main`, before serving. `handle_health` otherwise
/// initializes this lazily on the first `/health` hit, which anchors
/// uptime to the first request (so it reads ~0 on that render) rather
/// than to real process start. Idempotent: the first call wins.
pub fn mark_process_start() {
    PROCESS_STARTED_AT.get_or_init(Instant::now);
}

// --- Component status enum ---

/// Health verdict for one dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    /// Dependency is reachable and reporting nominal.
    Healthy,
    /// Dependency is reachable but degraded; readiness still passes
    /// because traffic can flow.
    Degraded,
    /// Dependency is unreachable or returned a hard failure;
    /// readiness fails so the load balancer drains us.
    Unhealthy,
    /// Dependency is not yet wired into this build (hooks for Stripe,
    /// facilitator quorum, ...). Treated as `Healthy` for readiness
    /// purposes.
    NotConfigured,
}

impl ComponentStatus {
    /// Whether this status counts as "ready" for `/readyz`.
    pub fn is_ready(self) -> bool {
        matches!(
            self,
            ComponentStatus::Healthy | ComponentStatus::Degraded | ComponentStatus::NotConfigured
        )
    }
}

/// Per-component report attached to the `/readyz` body.
#[derive(Debug, Clone, Serialize)]
pub struct ComponentReport {
    /// Pillar / component name (e.g. `"usage_ledger"`,
    /// `"bot_auth_directory"`).
    pub name: String,
    /// Verdict for the component.
    pub status: ComponentStatus,
    /// Optional human-readable detail (cause of failure, last-success
    /// timestamp, etc.). Redaction is applied denylist
    /// before emission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Body of `/readyz`. Top-level `status` is `"ok"` when every
/// component reports ready, `"unready"` otherwise.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessReport {
    /// Aggregate verdict: `"ok"` or `"unready"`.
    pub status: &'static str,
    /// Per-component reports. Order is stable (pillars first, then
    /// future-wave hooks) so dashboards can group by name.
    pub components: Vec<ComponentReport>,
}

/// Metadata included in the rich `/health` response.
#[derive(Debug, Clone, Serialize)]
pub struct HealthMetadata {
    /// Crate version of the running binary.
    pub version: String,
    /// Git revision embedded at build time.
    pub build_hash: String,
    /// Current server-side timestamp.
    pub timestamp: String,
    /// Seconds since process start (see `mark_process_start`).
    pub uptime_seconds: u64,
}

/// Rich `/health` response for humans and monitoring systems.
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    /// Aggregate status. Mirrors readiness: `ok` or `unready`.
    pub status: &'static str,
    /// Version/build/time metadata.
    #[serde(flatten)]
    pub metadata: HealthMetadata,
    /// Per-component readiness checks.
    pub checks: Vec<ComponentReport>,
}

// --- Probe trait ---

/// One health probe returning `(status, optional detail)`.
///
/// Implementations are expected to be cheap (`< 1 ms`) because
/// `/readyz` is hit by load balancer health checks at high frequency.
/// Probes that need to make a network call SHOULD cache the last
/// verdict in a `Recency`-style accessor (see [`Recency`]) and
/// re-probe in the background.
pub trait Probe: Send + Sync + 'static {
    /// Identifier reported in the response body.
    fn name(&self) -> &str;
    /// Compute the current status. Must not block.
    fn check(&self) -> (ComponentStatus, Option<String>);
}

// --- Recency: a thread-safe last-success timestamp ---

/// Helper for probes that record "last successful contact at T" and
/// translate that into a status based on a staleness threshold.
///
/// Used by the bot-auth directory probe (`directory not stale beyond
/// stale-while-fail grace`), whose backing service refreshes on a timer.
///
/// A timer is what makes recency readable. Apply this only to a dependency
/// something contacts on a schedule, never to one contacted only when
/// traffic asks for it: for those, "no success recently" is what a healthy
/// idle deployment looks like, and [`RecencyProbe`] reports never-marked as
/// `Unhealthy`. That is why the AI-crawl redeem ledger has no recency probe
/// (WOR-2324), and why the `usage_ledger` component reads an append outcome
/// instead of a clock.
#[derive(Debug, Clone)]
pub struct Recency {
    inner: Arc<RwLock<Option<Instant>>>,
    fresh_for: Duration,
}

impl Recency {
    /// Create a new tracker with the given freshness window.
    pub fn new(fresh_for: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
            fresh_for,
        }
    }

    /// Mark "now" as the most recent successful contact.
    pub fn mark_success(&self) {
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *g = Some(Instant::now());
    }

    /// Whether the last success is still within the freshness window.
    pub fn is_fresh(&self) -> bool {
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match *g {
            Some(t) => t.elapsed() <= self.fresh_for,
            None => false,
        }
    }

    /// Last success timestamp, or `None` if never marked.
    pub fn last_success(&self) -> Option<Instant> {
        *self.inner.read().unwrap_or_else(|e| e.into_inner())
    }
}

// --- Built-in probes ---

/// Probe backed by a [`Recency`] tracker plus a name. The probe
/// reports `Healthy` when fresh and `Unhealthy` when stale.
pub struct RecencyProbe {
    name: String,
    recency: Recency,
}

impl RecencyProbe {
    /// Build a probe under `name` backed by `recency`.
    pub fn new(name: impl Into<String>, recency: Recency) -> Self {
        Self {
            name: name.into(),
            recency,
        }
    }
}

impl Probe for RecencyProbe {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> (ComponentStatus, Option<String>) {
        if self.recency.is_fresh() {
            (ComponentStatus::Healthy, None)
        } else {
            let detail = match self.recency.last_success() {
                Some(t) => format!("last success {} secs ago", t.elapsed().as_secs()),
                None => "no successful probe yet".to_string(),
            };
            (ComponentStatus::Unhealthy, Some(detail))
        }
    }
}

/// Stub probe for dependencies that ship later (Stripe, facilitator
/// quorum). Reports `NotConfigured` which counts as ready, so the
/// binary stays usable while the downstream integration is unfinished.
pub struct NotConfiguredProbe {
    name: String,
}

impl NotConfiguredProbe {
    /// Build a placeholder probe under `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// In-process synthetic readiness probe.
///
/// This is intentionally generic: callers register a closure that
/// exercises the code path they care about and returns the same
/// component-status shape as any other probe.
pub struct SyntheticProbe {
    name: String,
    check_fn: Arc<dyn Fn() -> (ComponentStatus, Option<String>) + Send + Sync>,
}

impl SyntheticProbe {
    /// Build a synthetic probe under `name`.
    pub fn new(
        name: impl Into<String>,
        check_fn: impl Fn() -> (ComponentStatus, Option<String>) + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            check_fn: Arc::new(check_fn),
        }
    }
}

impl Probe for SyntheticProbe {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> (ComponentStatus, Option<String>) {
        (self.check_fn)()
    }
}

impl Probe for NotConfiguredProbe {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self) -> (ComponentStatus, Option<String>) {
        (
            ComponentStatus::NotConfigured,
            Some("not yet wired in this wave".to_string()),
        )
    }
}

// --- Registry ---

/// Process-wide collection of probes that `/readyz` walks. The
/// registry is `Send + Sync` so it can be shared across the admin
/// listener and the per-pillar wiring sites.
#[derive(Default, Clone)]
pub struct HealthRegistry {
    probes: Arc<RwLock<BTreeMap<String, Arc<dyn Probe>>>>,
}

impl HealthRegistry {
    /// Build an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace a probe by name. The most recent
    /// registration wins so the wiring code can swap a
    /// `NotConfigured` stub for a real probe at startup without
    /// teardown.
    pub fn register(&self, probe: Arc<dyn Probe>) {
        let name = probe.name().to_string();
        let mut g = self.probes.write().unwrap_or_else(|e| e.into_inner());
        g.insert(name, probe);
    }

    /// Walk every registered probe and return the readiness report.
    pub fn evaluate(&self) -> ReadinessReport {
        let g = self.probes.read().unwrap_or_else(|e| e.into_inner());
        let mut components: Vec<ComponentReport> = g
            .values()
            .map(|p| {
                let (status, detail) = p.check();
                ComponentReport {
                    name: p.name().to_string(),
                    status,
                    detail,
                }
            })
            .collect();
        // Stable ordering: BTreeMap iterates in key order, so
        // dashboards see a deterministic list.
        components.sort_by(|a, b| a.name.cmp(&b.name));
        let all_ready = components.iter().all(|c| c.status.is_ready());
        ReadinessReport {
            status: if all_ready { "ok" } else { "unready" },
            components,
        }
    }
}

// --- Default registry helper ---

/// Build a registry seeded with the standard probe set:
///
/// - `usage_ledger`: backed by the supplied `Recency`.
/// - `bot_auth_directory`: backed by the supplied `Recency`.
/// - `agent_registry`: `NotConfigured` stub.
/// - `mesh_quorum`: `NotConfigured` stub.
///
/// The `agent_registry` and `mesh_quorum` real probes are registered at
/// startup (see `sbproxy-core`'s lifecycle) by calling
/// `registry.register(...)`, which overrides the seeded stub by name.
///
/// # `usage_ledger` is the chain this proxy writes, not the one it calls
///
/// The component was called `ledger` and covered neither of the two things
/// an operator read into that name (WOR-2324). What it reports is the
/// verifiable usage chain this process appends to: the AI gateway's spend
/// record and the meter's receipt chain, both of which write the same
/// process-wide append outcome. The AI-crawl redeem ledger is a separate
/// HTTP dependency with no probe at all, and a completely dead one leaves
/// readiness green.
///
/// That gap is deliberate for now rather than merely unfixed. Redeem
/// recency cannot close it: redeems only happen when a paying crawler hits
/// a priced route, so "no successful redeem in the last N seconds" is what
/// a healthy idle deployment looks like as well as a dead ledger, and a
/// [`RecencyProbe`] reports never-marked as `Unhealthy`. Wiring one would
/// pull idle-but-working pods out of rotation, which is a worse failure
/// than the reporting gap it closes. The signal that would work is the
/// redeem client's circuit breaker, which is traffic-independent in the
/// right direction: never used reads closed, and open means the dependency
/// has failed its threshold in a row.
pub fn default_registry(
    usage_ledger_recency: Recency,
    bot_auth_recency: Recency,
) -> HealthRegistry {
    default_registry_optional(Some(usage_ledger_recency), Some(bot_auth_recency))
}

/// Build the standard registry, treating absent optional services as
/// `NotConfigured` so `/readyz` remains 200 when a feature is not wired.
///
/// This is the form the proxy uses, with both arguments `None`: the real
/// `usage_ledger` and `bot_auth_directory` probes are registered by name at
/// startup and replace these seeds.
pub fn default_registry_optional(
    usage_ledger_recency: Option<Recency>,
    bot_auth_recency: Option<Recency>,
) -> HealthRegistry {
    let registry = HealthRegistry::new();
    match usage_ledger_recency {
        Some(recency) => registry.register(Arc::new(RecencyProbe::new("usage_ledger", recency))),
        None => registry.register(Arc::new(NotConfiguredProbe::new("usage_ledger"))),
    }
    match bot_auth_recency {
        Some(recency) => {
            registry.register(Arc::new(RecencyProbe::new("bot_auth_directory", recency)))
        }
        None => registry.register(Arc::new(NotConfiguredProbe::new("bot_auth_directory"))),
    }
    registry.register(Arc::new(NotConfiguredProbe::new("agent_registry")));
    registry.register(Arc::new(NotConfiguredProbe::new("mesh_quorum")));
    // WOR-1102: a poisoned sink dispatcher silently stops all telemetry
    // export while the pod keeps serving. Gate readiness on it so the
    // load balancer drains a telemetry-blind instance. A healthy or
    // not-yet-installed dispatcher (no sinks configured) stays ready.
    registry.register(Arc::new(SyntheticProbe::new("telemetry_sink", || {
        if crate::sink_dispatcher::sink_dispatcher_healthy() {
            (ComponentStatus::Healthy, None)
        } else {
            (
                ComponentStatus::Unhealthy,
                Some("sink dispatcher lock poisoned; telemetry export is down".to_string()),
            )
        }
    })));
    // WOR-2626: what this build can enforce on the files its durable
    // sinks write, exposed where an operator looks rather than only in
    // a startup log line they have to have kept.
    //
    // Posture only, and no paths. A sink path can carry a tenant name,
    // and `/health` is unauthenticated on purpose so a load balancer
    // can reach it; the modes are compile-time constants that the
    // published documentation already states, so naming them here
    // discloses nothing the docs do not.
    //
    // A platform without permission bits reports `Degraded` rather
    // than `Unhealthy`. The gap is real and worth surfacing, and it is
    // not a reason to have a load balancer drain the instance: traffic
    // flows perfectly well, the files are just inheriting an ACL.
    registry.register(Arc::new(SyntheticProbe::new("durable_file_modes", || {
        match sbproxy_util::secure_fs::enforcement() {
            sbproxy_util::secure_fs::ModeEnforcement::Posix {
                file_mode,
                dir_mode,
            } => (
                ComponentStatus::Healthy,
                Some(format!(
                    "sink files {file_mode:04o}, directories this process creates {dir_mode:04o}"
                )),
            ),
            sbproxy_util::secure_fs::ModeEnforcement::InheritedAcl => (
                ComponentStatus::Degraded,
                Some(
                    "this platform has no POSIX permission bits; sink files inherit \
                     their directory's ACL and no mode is applied"
                        .to_string(),
                ),
            ),
        }
    })));
    registry
}

// --- HTTP handlers ---

/// Render the `/healthz` response body. Liveness only: the process is
/// up if this code is running.
///
/// Returns `(status, content_type, body)`.
pub fn handle_healthz() -> (u16, &'static str, String) {
    (200, "application/json", r#"{"status":"ok"}"#.to_string())
}

/// Render the `/livez` response body. Pure liveness: returns 200 as
/// long as the binary is running, regardless of registry state. K8s
/// uses `/livez` to decide whether to restart the pod; we never
/// return 503 here so a transient readiness failure doesn't trigger
/// a restart loop. (Use `/readyz` for "should I send traffic?".)
pub fn handle_livez() -> (u16, &'static str, String) {
    (200, "application/json", r#"{"alive":true}"#.to_string())
}

/// Render the rich `/health` response body by walking the registry and
/// adding build metadata. Unlike `/healthz`, this endpoint is meant for
/// humans, dashboards, and SIEM ingestion rather than load-balancer
/// liveness checks.
pub fn handle_health(
    registry: &HealthRegistry,
    version: &str,
    build_hash: &str,
) -> (u16, &'static str, String) {
    let report = registry.evaluate();
    let status = if report.status == "ok" { 200 } else { 503 };
    let started = PROCESS_STARTED_AT.get_or_init(Instant::now);
    let body = serde_json::to_string(&HealthReport {
        status: report.status,
        metadata: HealthMetadata {
            version: version.to_string(),
            build_hash: build_hash.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            uptime_seconds: started.elapsed().as_secs(),
        },
        checks: report.components,
    })
    .unwrap_or_else(|_| r#"{"status":"unready","error":"serialize"}"#.to_string());
    (status, "application/json", body)
}

/// Render the `/readyz` response body by walking the registry. Returns
/// `200` when every component is ready and `503` otherwise; the body
/// is the JSON-serialised [`ReadinessReport`] in either case so
/// dashboards can render the per-component breakdown.
pub fn handle_readyz(registry: &HealthRegistry) -> (u16, &'static str, String) {
    let report = registry.evaluate();
    let status = if report.status == "ok" { 200 } else { 503 };
    let body = serde_json::to_string(&report).unwrap_or_else(|_| {
        // serde_json should not fail on this struct, but we'd rather
        // serve 503 with a minimal body than panic on the load
        // balancer's health check.
        r#"{"status":"unready","error":"serialize"}"#.to_string()
    });
    (status, "application/json", body)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthz_is_always_200() {
        let (status, ct, body) = handle_healthz();
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        assert!(body.contains("ok"));
    }

    #[test]
    fn livez_is_always_200() {
        let (status, ct, body) = handle_livez();
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["alive"], true);
    }

    #[test]
    fn health_includes_build_metadata_and_checks() {
        let recency = Recency::new(Duration::from_secs(60));
        recency.mark_success();
        let registry = HealthRegistry::new();
        registry.register(Arc::new(RecencyProbe::new("usage_ledger", recency)));

        let (status, ct, body) = handle_health(&registry, "1.2.3", "abc123");

        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["version"], "1.2.3");
        assert_eq!(v["build_hash"], "abc123");
        assert!(v["timestamp"].as_str().unwrap().contains('T'));
        assert!(v["uptime_seconds"].as_u64().is_some());
        assert_eq!(v["checks"][0]["name"], "usage_ledger");
        assert_eq!(v["checks"][0]["status"], "healthy");
    }

    #[test]
    fn empty_registry_is_ready() {
        let registry = HealthRegistry::new();
        let (status, _ct, body) = handle_readyz(&registry);
        assert_eq!(status, 200);
        let report: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(report["status"], "ok");
    }

    #[test]
    fn fresh_recency_probe_passes_readyz() {
        let recency = Recency::new(Duration::from_secs(60));
        recency.mark_success();
        let registry = HealthRegistry::new();
        registry.register(Arc::new(RecencyProbe::new("usage_ledger", recency.clone())));
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 200);
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains("\"name\":\"usage_ledger\""));
    }

    #[test]
    fn never_marked_recency_probe_fails_readyz() {
        let recency = Recency::new(Duration::from_secs(60));
        let registry = HealthRegistry::new();
        registry.register(Arc::new(RecencyProbe::new("usage_ledger", recency)));
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 503);
        assert!(body.contains("\"status\":\"unready\""));
        assert!(body.contains("\"usage_ledger\""));
    }

    #[test]
    fn stale_recency_probe_fails_readyz() {
        let recency = Recency::new(Duration::from_millis(10));
        recency.mark_success();
        std::thread::sleep(Duration::from_millis(50));
        let registry = HealthRegistry::new();
        registry.register(Arc::new(RecencyProbe::new("usage_ledger", recency)));
        let (status, _, _) = handle_readyz(&registry);
        assert_eq!(status, 503);
    }

    #[test]
    fn not_configured_probe_passes_readyz() {
        let registry = HealthRegistry::new();
        registry.register(Arc::new(NotConfiguredProbe::new("mesh_quorum")));
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 200);
        assert!(body.contains("not_configured"));
    }

    #[test]
    fn default_registry_optional_marks_absent_services_not_configured() {
        let registry = default_registry_optional(None, None);
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(
            status, 200,
            "absent optional services should be ready: {body}"
        );
        assert!(body.contains("\"name\":\"usage_ledger\""));
        assert!(body.contains("\"name\":\"bot_auth_directory\""));
        assert!(body.contains("\"status\":\"not_configured\""));
    }

    #[test]
    fn no_component_is_named_for_a_ledger_this_process_does_not_probe() {
        // The component reports the usage chain this process appends to.
        // It was called `ledger`, which an operator reasonably read as
        // covering the AI-crawl redeem ledger as well, and it never did
        // (WOR-2324). The bare name is not to come back under any probe:
        // whatever covers the redeem client has to say so in its own name.
        let registry = default_registry_optional(None, None);
        let report = registry.evaluate();
        let names: Vec<&str> = report
            .components
            .iter()
            .map(|component| component.name.as_str())
            .collect();
        assert!(
            names.contains(&"usage_ledger"),
            "the usage chain keeps a component: {names:?}"
        );
        assert!(
            !names.contains(&"ledger"),
            "a bare `ledger` component claims coverage of a dependency nothing probes: {names:?}"
        );
    }

    #[test]
    fn synthetic_probe_participates_in_readyz() {
        let registry = HealthRegistry::new();
        registry.register(Arc::new(SyntheticProbe::new("synthetic_pipeline", || {
            (ComponentStatus::Healthy, Some("ok".to_string()))
        })));
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 200);
        assert!(body.contains("synthetic_pipeline"));
        assert!(body.contains("\"status\":\"healthy\""));
    }

    #[test]
    fn default_registry_is_ready_when_recencies_are_fresh() {
        let l = Recency::new(Duration::from_secs(60));
        l.mark_success();
        let b = Recency::new(Duration::from_secs(60));
        b.mark_success();
        let registry = default_registry(l, b);
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 200, "body: {}", body);
        // The seeded components show up.
        assert!(body.contains("\"name\":\"usage_ledger\""));
        assert!(body.contains("bot_auth_directory"));
        assert!(body.contains("agent_registry"));
        assert!(body.contains("mesh_quorum"));
    }

    #[test]
    fn default_registry_is_unready_when_usage_ledger_stale() {
        let l = Recency::new(Duration::from_secs(60));
        // Don't mark - the ledger was never reached.
        let b = Recency::new(Duration::from_secs(60));
        b.mark_success();
        let registry = default_registry(l, b);
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 503);
        assert!(body.contains("\"name\":\"usage_ledger\""));
        assert!(body.contains("\"status\":\"unhealthy\""));
    }

    #[test]
    fn registry_re_registration_replaces_previous_probe() {
        let registry = HealthRegistry::new();
        registry.register(Arc::new(NotConfiguredProbe::new("mesh_quorum")));
        let recency = Recency::new(Duration::from_secs(60));
        recency.mark_success();
        registry.register(Arc::new(RecencyProbe::new("mesh_quorum", recency)));
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 200);
        // The replacement probe is healthy, not not_configured.
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let comps = v["components"].as_array().unwrap();
        let probe = comps.iter().find(|c| c["name"] == "mesh_quorum").unwrap();
        assert_eq!(probe["status"], "healthy");
    }

    /// WOR-2626: the durable-sink mode posture is reported where an
    /// operator looks, not only in a startup log line they had to have
    /// kept. The brief asked for a health surface and the first pass
    /// shipped only the log.
    ///
    /// Posture, never paths: `/health` is unauthenticated so a load
    /// balancer can reach it, and a sink path can carry a tenant name.
    /// The modes themselves are compile-time constants the published
    /// docs already state.
    #[test]
    fn health_reports_the_durable_file_mode_posture_without_a_path() {
        let registry = default_registry_optional(None, None);
        let report = registry.evaluate();
        let component = report
            .components
            .iter()
            .find(|c| c.name == "durable_file_modes")
            .expect("the durable-file-mode posture must be a health component");

        assert!(
            component.status.is_ready(),
            "the posture is informational; it must not drain the instance"
        );
        let detail = component
            .detail
            .as_deref()
            .expect("the posture must say what it is, not only that it exists");

        match sbproxy_util::secure_fs::enforcement() {
            sbproxy_util::secure_fs::ModeEnforcement::Posix { .. } => {
                assert!(
                    detail.contains("0600") && detail.contains("0700"),
                    "the modes must be named: {detail}"
                );
            }
            sbproxy_util::secure_fs::ModeEnforcement::InheritedAcl => {
                assert!(
                    detail.contains("ACL"),
                    "the gap must be named rather than implied: {detail}"
                );
            }
        }
        assert!(
            !detail.contains('/'),
            "a sink path can carry a tenant name and must not reach an \
             unauthenticated endpoint: {detail}"
        );
    }
}
