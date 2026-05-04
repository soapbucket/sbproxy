//! Admin-action audit emitter trait surface.
//!
//! Defines the seam between the request path and an out-of-tree audit
//! sink. The default build registers a no-op emitter; downstream
//! builds register an implementation that wraps the typed payload
//! into a richer audit envelope and persists it.
//!
//! Projection regeneration is the first consumer: every refresh emits
//! a [`ProjectionRefreshEvent`] per `(hostname, projection_kind,
//! config_version)` tuple.
//!
//! The trait deliberately exchanges a small typed payload rather than
//! a full audit envelope so this crate stays free of any cross-crate
//! type dependency.

use std::sync::{Arc, OnceLock};

/// Typed payload emitted on every projection regeneration.
///
/// One [`ProjectionRefreshEvent`] is emitted per `(hostname,
/// projection_kind, config_version)` tuple per reload. The `doc_hash`
/// is the SHA-256 of the canonical document body and `byte_len` is the
/// body length in bytes; both are recorded so external auditors can
/// verify that the served document matches what was recorded at
/// reload time.
#[derive(Debug, Clone)]
pub struct ProjectionRefreshEvent {
    /// Origin hostname the projection applies to.
    pub hostname: String,
    /// Projection kind: one of `robots`, `llms`, `llms-full`,
    /// `licenses`, or `tdmrep`. Free-form here so downstream sinks
    /// validate the value before persisting.
    pub projection_kind: String,
    /// Config version hash the projection was generated from. Carried
    /// verbatim into the audit target id so verifiers can dedupe
    /// against config history.
    pub config_version: u64,
    /// SHA-256 of the canonical document body, lowercase hex (64
    /// chars).
    pub doc_hash: String,
    /// Length of the canonical document body in bytes.
    pub byte_len: usize,
}

/// Trait for sinks that consume audit events emitted by the request
/// path.
///
/// Implementations are responsible for persisting the typed payloads.
/// `record_projection_refresh` must never block, must not panic, must
/// not propagate errors back to the caller, and should log on enqueue
/// failure so the operator notices.
pub trait AdminAuditEmitter: Send + Sync + 'static {
    /// Record one projection-refresh event.
    fn record_projection_refresh(&self, event: ProjectionRefreshEvent);
}

/// No-op emitter used when no real sink is registered.
///
/// Every method is empty; the request path keeps fail-quiet behaviour.
pub struct NoOpAdminAuditEmitter;

impl AdminAuditEmitter for NoOpAdminAuditEmitter {
    fn record_projection_refresh(&self, _event: ProjectionRefreshEvent) {
        // Default no-op. Builds that need persistence install a real
        // emitter via `install_admin_audit_emitter`.
    }
}

// --- Process-wide install slot ---

static EMITTER: OnceLock<Arc<dyn AdminAuditEmitter>> = OnceLock::new();

/// Install the process-wide admin-audit emitter.
///
/// Idempotent: a second call after the first wins is silently
/// ignored. Boot code calls this once during startup; builds that
/// leave it unset get the no-op fallback from
/// [`current_admin_audit_emitter`].
pub fn install_admin_audit_emitter(emitter: Arc<dyn AdminAuditEmitter>) {
    let _ = EMITTER.set(emitter);
}

/// Borrow the process-wide admin-audit emitter, falling back to the
/// no-op implementation when none is registered.
///
/// Returns an `Arc` so callers can clone cheaply and hold the emitter
/// across `await` points. The no-op fallback is constructed on each
/// call rather than cached so a later real registration takes effect.
pub fn current_admin_audit_emitter() -> Arc<dyn AdminAuditEmitter> {
    if let Some(e) = EMITTER.get() {
        return e.clone();
    }
    Arc::new(NoOpAdminAuditEmitter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Capture {
        events: Mutex<Vec<ProjectionRefreshEvent>>,
    }

    impl AdminAuditEmitter for Capture {
        fn record_projection_refresh(&self, event: ProjectionRefreshEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn noop_emitter_swallows_events() {
        let e = NoOpAdminAuditEmitter;
        e.record_projection_refresh(ProjectionRefreshEvent {
            hostname: "x".into(),
            projection_kind: "robots".into(),
            config_version: 7,
            doc_hash: "abc".into(),
            byte_len: 1,
        });
        // No assertion needed; no panic is the contract.
    }

    #[test]
    fn fallback_returns_noop_when_unregistered() {
        // We cannot reset the global slot between tests so this test
        // only validates the fallback contract: returns *some*
        // emitter, never panics. Subsequent tests that install a
        // real emitter would observe their events.
        let e = current_admin_audit_emitter();
        e.record_projection_refresh(ProjectionRefreshEvent {
            hostname: "y".into(),
            projection_kind: "llms".into(),
            config_version: 0,
            doc_hash: String::new(),
            byte_len: 0,
        });
    }

    #[test]
    fn capture_emitter_observes_event_payload() {
        let cap = Arc::new(Capture {
            events: Mutex::new(Vec::new()),
        });
        cap.record_projection_refresh(ProjectionRefreshEvent {
            hostname: "z.example.com".into(),
            projection_kind: "licenses".into(),
            config_version: 42,
            doc_hash: "deadbeef".into(),
            byte_len: 128,
        });
        let events = cap.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].hostname, "z.example.com");
        assert_eq!(events[0].projection_kind, "licenses");
        assert_eq!(events[0].config_version, 42);
    }
}
