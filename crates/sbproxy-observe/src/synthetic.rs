//! Synthetic transaction probe state for `/readyz`.
//!
//! Holds the cached verdict of the most recent in-process synthetic
//! request. The driver task in `sbproxy-core` fires a request through
//! the compiled handler chain on a fixed cadence and feeds the outcome
//! back here through [`SyntheticProbeState::record_success`] or
//! [`SyntheticProbeState::record_failure`]. The `/readyz` handler reads
//! the cached verdict cheaply, never blocking on the pipeline.
//!
//! The probe is opt-in. When the synthetic origin is not enabled in
//! config, the registry should not register a [`SyntheticProbe`] backed
//! by this state at all, so `/readyz` is unaffected.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::health::{ComponentStatus, Probe};

/// Default cadence between synthetic probe runs when not overridden.
pub const DEFAULT_SYNTHETIC_INTERVAL_SECS: u64 = 30;

/// Default per-run timeout budget for the synthetic request.
pub const DEFAULT_SYNTHETIC_TIMEOUT_MS: u64 = 1000;

/// Default sentinel hostname routed to the in-process synthetic origin.
///
/// `__synthetic.local` is reserved: operators must not configure a
/// real upstream under this name, and the synthetic origin compiler
/// short-circuits any request that arrives with this `Host` header so
/// nothing reaches the network.
pub const DEFAULT_SYNTHETIC_HOSTNAME: &str = "__synthetic.local";

/// Sentinel path that the driver fires the synthetic request against.
pub const DEFAULT_SYNTHETIC_PATH: &str = "/readyz/synthetic";

#[derive(Debug, Clone)]
struct ProbeOutcome {
    status: ComponentStatus,
    detail: String,
    observed_at: Instant,
}

/// Shared cache of the synthetic probe's most recent verdict.
///
/// `Clone` is cheap (`Arc`); the driver task holds one handle and the
/// registered [`crate::health::SyntheticProbe`] holds another.
#[derive(Debug, Clone, Default)]
pub struct SyntheticProbeState {
    inner: Arc<RwLock<Option<ProbeOutcome>>>,
}

impl SyntheticProbeState {
    /// Build an empty state. The first `/readyz` evaluation that runs
    /// before the driver has produced an outcome reports `Unhealthy`
    /// so the load balancer drains us until the first synthetic round
    /// trip succeeds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful synthetic round trip and the latency it
    /// observed. Stamped with [`Instant::now`] so a subsequent
    /// staleness check can fire if the driver task has died.
    pub fn record_success(&self, latency: Duration) {
        let outcome = ProbeOutcome {
            status: ComponentStatus::Healthy,
            detail: format!("latency_ms={}", latency.as_millis()),
            observed_at: Instant::now(),
        };
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *g = Some(outcome);
    }

    /// Record a synthetic failure. `reason` is included in the
    /// `/readyz` body so an operator can see why the probe failed
    /// without grepping logs.
    pub fn record_failure(&self, reason: impl Into<String>) {
        let outcome = ProbeOutcome {
            status: ComponentStatus::Unhealthy,
            detail: reason.into(),
            observed_at: Instant::now(),
        };
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *g = Some(outcome);
    }

    /// Snapshot of the most recent outcome, if any. Used by the probe
    /// to render a `(status, detail)` pair.
    pub fn current(&self, stale_after: Duration) -> (ComponentStatus, Option<String>) {
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match g.as_ref() {
            None => (
                ComponentStatus::Unhealthy,
                Some("synthetic_probe_no_outcome_yet".to_string()),
            ),
            Some(o) if o.observed_at.elapsed() > stale_after => (
                ComponentStatus::Unhealthy,
                Some(format!(
                    "synthetic_probe_stale: last_outcome_age_secs={}",
                    o.observed_at.elapsed().as_secs()
                )),
            ),
            Some(o) => (o.status, Some(o.detail.clone())),
        }
    }
}

/// Configuration for the synthetic probe registration.
#[derive(Debug, Clone)]
pub struct SyntheticProbeRegistration {
    /// Probe name reported on `/readyz`.
    pub name: String,
    /// Backing state cache.
    pub state: SyntheticProbeState,
    /// Maximum age a cached outcome can have before the probe reports
    /// `Unhealthy`. Set this to roughly 3x the driver cadence.
    pub stale_after: Duration,
}

impl SyntheticProbeRegistration {
    /// Build a probe handle suitable for registration into the
    /// readiness registry. The returned probe shares the same
    /// underlying state cache as `self`, so the driver task continues
    /// to update both.
    pub fn into_probe(self) -> Arc<dyn Probe> {
        let state = self.state.clone();
        let stale_after = self.stale_after;
        Arc::new(crate::health::SyntheticProbe::new(self.name, move || {
            state.current(stale_after)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_reports_unhealthy() {
        let state = SyntheticProbeState::new();
        let (status, detail) = state.current(Duration::from_secs(60));
        assert_eq!(status, ComponentStatus::Unhealthy);
        assert!(detail.unwrap().contains("no_outcome_yet"));
    }

    #[test]
    fn success_makes_state_healthy() {
        let state = SyntheticProbeState::new();
        state.record_success(Duration::from_millis(7));
        let (status, detail) = state.current(Duration::from_secs(60));
        assert_eq!(status, ComponentStatus::Healthy);
        assert!(detail.unwrap().contains("latency_ms=7"));
    }

    #[test]
    fn failure_makes_state_unhealthy_with_reason() {
        let state = SyntheticProbeState::new();
        state.record_failure("upstream_502");
        let (status, detail) = state.current(Duration::from_secs(60));
        assert_eq!(status, ComponentStatus::Unhealthy);
        assert_eq!(detail.unwrap(), "upstream_502");
    }

    #[test]
    fn stale_outcome_is_unhealthy_even_if_last_was_healthy() {
        let state = SyntheticProbeState::new();
        state.record_success(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(15));
        let (status, detail) = state.current(Duration::from_millis(5));
        assert_eq!(status, ComponentStatus::Unhealthy);
        assert!(detail.unwrap().contains("stale"));
    }

    #[test]
    fn registration_into_probe_drives_status_from_state() {
        let state = SyntheticProbeState::new();
        let reg = SyntheticProbeRegistration {
            name: "synthetic_pipeline".to_string(),
            state: state.clone(),
            stale_after: Duration::from_secs(60),
        };
        let probe = reg.into_probe();

        let (s, _) = probe.check();
        assert_eq!(s, ComponentStatus::Unhealthy, "no outcome yet");

        state.record_success(Duration::from_millis(2));
        let (s, _) = probe.check();
        assert_eq!(s, ComponentStatus::Healthy);

        state.record_failure("timeout");
        let (s, d) = probe.check();
        assert_eq!(s, ComponentStatus::Unhealthy);
        assert_eq!(d.unwrap(), "timeout");
    }
}
