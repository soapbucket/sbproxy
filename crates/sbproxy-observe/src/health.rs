//! `/healthz` and `/readyz` endpoints (Wave 1 / R1.3).
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
//! Wave 1 ships hooks for the dependencies that exist today and stub
//! variants for the ones landing in later waves (Stripe in Wave 2,
//! facilitator quorum in Wave 3, agent registry in Wave 2). The stubs
//! return `Healthy` so they don't break readiness in builds where
//! their backing service isn't wired yet.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

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
    /// Dependency is not yet wired into this build (Wave 2 hooks for
    /// Stripe, Wave 3 hooks for facilitator quorum, ...). Treated as
    /// `Healthy` for readiness purposes.
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
    /// Pillar / component name (e.g. `"ledger"`, `"bot_auth_directory"`).
    pub name: String,
    /// Verdict for the component.
    pub status: ComponentStatus,
    /// Optional human-readable detail (cause of failure, last-success
    /// timestamp, etc.). Redaction is applied per the A1.5 denylist
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
/// Used by:
///
/// - The ledger probe (`last redeem succeeded within N seconds`).
/// - The bot-auth directory probe (`directory not stale beyond
///   stale-while-fail grace`).
///
/// Both backing services already track success/failure internally; the
/// probe just reads the cached value through this type.
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

/// Stub probe for dependencies that ship in a later wave (Stripe in
/// Wave 2, facilitator quorum in Wave 3). Reports `NotConfigured`
/// which counts as ready, so the binary stays usable while the
/// downstream integration is unfinished.
pub struct NotConfiguredProbe {
    name: String,
}

impl NotConfiguredProbe {
    /// Build a placeholder probe under `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
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

/// Build a registry seeded with the Wave 1 standard probe set:
///
/// - `ledger`: backed by the supplied `Recency`.
/// - `bot_auth_directory`: backed by the supplied `Recency`.
/// - `agent_registry` (Wave 2): `NotConfigured` stub.
/// - `stripe` (Wave 2): `NotConfigured` stub.
/// - `facilitator_quorum` (Wave 3): `NotConfigured` stub.
///
/// Operators wire the real `agent_registry`, `stripe`, and
/// `facilitator_quorum` probes by calling `registry.register(...)`
/// in their respective wave's startup hook.
pub fn default_registry(ledger_recency: Recency, bot_auth_recency: Recency) -> HealthRegistry {
    let registry = HealthRegistry::new();
    registry.register(Arc::new(RecencyProbe::new("ledger", ledger_recency)));
    registry.register(Arc::new(RecencyProbe::new(
        "bot_auth_directory",
        bot_auth_recency,
    )));
    registry.register(Arc::new(NotConfiguredProbe::new("agent_registry")));
    registry.register(Arc::new(NotConfiguredProbe::new("stripe")));
    registry.register(Arc::new(NotConfiguredProbe::new("facilitator_quorum")));
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
        registry.register(Arc::new(RecencyProbe::new("ledger", recency.clone())));
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 200);
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains("\"name\":\"ledger\""));
    }

    #[test]
    fn never_marked_recency_probe_fails_readyz() {
        let recency = Recency::new(Duration::from_secs(60));
        let registry = HealthRegistry::new();
        registry.register(Arc::new(RecencyProbe::new("ledger", recency)));
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 503);
        assert!(body.contains("\"status\":\"unready\""));
        assert!(body.contains("\"ledger\""));
    }

    #[test]
    fn stale_recency_probe_fails_readyz() {
        let recency = Recency::new(Duration::from_millis(10));
        recency.mark_success();
        std::thread::sleep(Duration::from_millis(50));
        let registry = HealthRegistry::new();
        registry.register(Arc::new(RecencyProbe::new("ledger", recency)));
        let (status, _, _) = handle_readyz(&registry);
        assert_eq!(status, 503);
    }

    #[test]
    fn not_configured_probe_passes_readyz() {
        let registry = HealthRegistry::new();
        registry.register(Arc::new(NotConfiguredProbe::new("stripe")));
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 200);
        assert!(body.contains("not_configured"));
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
        // All five Wave 1 components show up.
        assert!(body.contains("ledger"));
        assert!(body.contains("bot_auth_directory"));
        assert!(body.contains("agent_registry"));
        assert!(body.contains("stripe"));
        assert!(body.contains("facilitator_quorum"));
    }

    #[test]
    fn default_registry_is_unready_when_ledger_stale() {
        let l = Recency::new(Duration::from_secs(60));
        // Don't mark - ledger never reached.
        let b = Recency::new(Duration::from_secs(60));
        b.mark_success();
        let registry = default_registry(l, b);
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 503);
        assert!(body.contains("\"name\":\"ledger\""));
        assert!(body.contains("\"status\":\"unhealthy\""));
    }

    #[test]
    fn registry_re_registration_replaces_previous_probe() {
        let registry = HealthRegistry::new();
        registry.register(Arc::new(NotConfiguredProbe::new("stripe")));
        let recency = Recency::new(Duration::from_secs(60));
        recency.mark_success();
        registry.register(Arc::new(RecencyProbe::new("stripe", recency)));
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 200);
        // The replacement probe is healthy, not_configured.
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let comps = v["components"].as_array().unwrap();
        let stripe = comps.iter().find(|c| c["name"] == "stripe").unwrap();
        assert_eq!(stripe["status"], "healthy");
    }
}
