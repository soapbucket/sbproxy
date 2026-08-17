//! MCP session store for the streamable HTTP transport (WOR-1642).
//!
//! The 2025-06-18 revision lets a server assign a session id during
//! `initialize` via the `Mcp-Session-Id` header; the client must then
//! carry the id on every later request, `DELETE` ends the session,
//! and an unknown or expired id gets 404 so the client knows to
//! re-initialize.
//!
//! The store is in-memory with a sliding idle TTL: sessions are a
//! transport-affinity concept, not durable state, and a proxy restart
//! invalidating them is exactly the 404-then-reinitialize flow the
//! spec prescribes. Expired entries are pruned opportunistically on
//! access, so the map never grows past the live-session set plus the
//! not-yet-touched expired tail.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Session-level risk signals used by guardrails that need memory
/// across multiple MCP requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionRisk {
    /// The session has invoked at least one tool.
    pub tool_access: bool,
    /// The session has invoked a tool classified as private-data
    /// access.
    pub private_data: bool,
    /// The session has invoked a tool classified as external
    /// communication.
    pub external_comm: bool,
}

impl SessionRisk {
    /// The "lethal trifecta": tool access plus private data plus
    /// external communication in one active session.
    pub fn is_lethal_trifecta(self) -> bool {
        self.tool_access && self.private_data && self.external_comm
    }

    fn merge(&mut self, other: SessionRisk) {
        self.tool_access |= other.tool_access;
        self.private_data |= other.private_data;
        self.external_comm |= other.external_comm;
    }
}

/// Session-level data-provenance integrity for deterministic session
/// flow enforcement (WOR-2384, MCP06). One of the two flow-label axes;
/// see [`FlowLabels`].
///
/// Sticky and monotonic: a session starts `Trusted` and moves to
/// `Tainted` the first time it reads a `tools/call` result from a
/// server not on the configured `trusted_servers` list (unlabeled
/// upstream = untrusted, the fail-closed default). It never reverts to
/// `Trusted` within the session's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionIntegrity {
    /// Every tool result the session has read so far came from a
    /// trusted server.
    Trusted,
    /// At least one tool result came from a server not on the
    /// configured trusted list.
    Tainted,
}

impl SessionIntegrity {
    /// Operator/CEL-facing label: `"trusted"` or `"tainted"`. Exposed
    /// on the `mcp` CEL/Rego namespace as `mcp.session.integrity`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Tainted => "tainted",
        }
    }
}

impl Default for SessionIntegrity {
    fn default() -> Self {
        Self::Trusted
    }
}

/// Session-level flow-control labels (WOR-2384, MCP06; fix round 1:
/// Meta's Rule of Two proper, FIDES-style integrity AND confidentiality
/// axes, per the epic's settled decision). Two independent leg signals,
/// most-restrictive-wins, monotonic within a session's lifetime: once
/// set, a label never moves back.
///
/// - `integrity`: see [`SessionIntegrity`]. Leg 1 ("touched untrusted
///   input"). Absent server configuration is fail-closed: an
///   unlabeled/unlisted server taints.
/// - `sensitive_touched`: leg 2 ("touched sensitive data"). Starts
///   `false`; flips to `true`, sticky, the first time the session reads
///   from a server or tool declared `sensitive` in config. Absent
///   sensitivity configuration reads default-open (`false` forever),
///   unlike `integrity` -- naming what is sensitive is an explicit
///   operator opt-in, not a fail-closed default.
///
/// Leg 3 ("externally-visible or state-changing action") is not stored
/// session state: it is evaluated at the moment of a `tools/call`
/// against `outbound_tools`, so it has no "touched" history to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowLabels {
    /// Data-provenance integrity of everything the session has read.
    pub integrity: SessionIntegrity,
    /// Whether the session has read from a server or tool declared
    /// `sensitive`. Sticky: never reverts to `false`.
    pub sensitive_touched: bool,
}

impl Default for FlowLabels {
    fn default() -> Self {
        Self {
            integrity: SessionIntegrity::Trusted,
            sensitive_touched: false,
        }
    }
}

/// Result of a flow-label sticky-set operation ([`SessionStore::taint`],
/// [`SessionStore::mark_sensitive_touched`]): the session's flow labels
/// after the call, and whether this specific call is the one that
/// caused the transition (as opposed to a session where that label was
/// already set). Callers use `transitioned` to decide whether to emit a
/// governance evidence event for this leg -- only the transition itself
/// is newsworthy, not every subsequent read that finds the label
/// already set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowLabelTransition {
    /// The session's flow labels after this call.
    pub labels: FlowLabels,
    /// True only on the call that caused this label's transition.
    pub transitioned: bool,
}

#[derive(Debug, Clone)]
struct SessionEntry {
    expires_at: Instant,
    risk: SessionRisk,
    /// Deterministic session-flow labels (WOR-2384, MCP06). See
    /// [`FlowLabels`].
    flow: FlowLabels,
    /// Version requirements declared at `initialize` via
    /// `_meta.tool_requirements` (the rollout plane's session rung).
    /// `Arc` so reads hand back a cheap clone under the lock.
    tool_requirements: Option<std::sync::Arc<HashMap<String, String>>>,
}

/// In-memory session table with a sliding idle TTL.
pub struct SessionStore {
    ttl: Duration,
    inner: Mutex<HashMap<String, SessionEntry>>,
}

impl SessionStore {
    /// Create a store whose sessions expire after `ttl` of inactivity.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new session and return its id (UUID v4, which
    /// satisfies the spec's visible-ASCII requirement and is not
    /// guessable).
    pub fn create(&self) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::prune(&mut map);
        map.insert(
            id.clone(),
            SessionEntry {
                expires_at: Instant::now() + self.ttl,
                risk: SessionRisk::default(),
                flow: FlowLabels::default(),
                tool_requirements: None,
            },
        );
        id
    }

    /// Attach the rollout plane's per-session version requirements
    /// (`{tool: semver range}`) to a live session. True on success;
    /// false when the session is unknown or expired. Renews the
    /// sliding TTL like every other successful access.
    pub fn set_tool_requirements(&self, id: &str, reqs: HashMap<String, String>) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                entry.tool_requirements = Some(std::sync::Arc::new(reqs));
                true
            }
            Some(_) => {
                map.remove(id);
                false
            }
            None => false,
        }
    }

    /// Version requirements declared on a live session, when any.
    /// Renews the sliding TTL.
    pub fn tool_requirements(&self, id: &str) -> Option<std::sync::Arc<HashMap<String, String>>> {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                entry.tool_requirements.clone()
            }
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
        }
    }

    /// True when the id names a live session. A successful check
    /// renews the sliding TTL.
    pub fn validate(&self, id: &str) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                true
            }
            Some(_) => {
                map.remove(id);
                false
            }
            None => false,
        }
    }

    /// End a session. True when the id named a live session.
    pub fn end(&self, id: &str) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.remove(id) {
            Some(entry) => entry.expires_at > Instant::now(),
            None => false,
        }
    }

    /// Merge risk signals into a live session and return its new
    /// aggregate state. `None` means the session is unknown or expired.
    pub fn record_risk(&self, id: &str, risk: SessionRisk) -> Option<SessionRisk> {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                entry.risk.merge(risk);
                Some(entry.risk)
            }
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
        }
    }

    /// Current flow labels for a live session (WOR-2384, MCP06). `None`
    /// for an unknown or expired session (pruned on this call, like
    /// every other lookup here). A successful lookup renews the
    /// sliding TTL like every other successful access.
    pub fn flow_labels(&self, id: &str) -> Option<FlowLabels> {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                Some(entry.flow)
            }
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
        }
    }

    /// Taint a live session's `integrity` label (WOR-2384, MCP06):
    /// moves to [`SessionIntegrity::Tainted`], sticky -- calling this
    /// again on an already-tainted session is a no-op beyond refreshing
    /// the TTL and reports `transitioned: false`. `None` for an unknown
    /// or expired session. Renews the sliding TTL.
    pub fn taint(&self, id: &str) -> Option<FlowLabelTransition> {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                let transitioned = entry.flow.integrity == SessionIntegrity::Trusted;
                entry.flow.integrity = SessionIntegrity::Tainted;
                Some(FlowLabelTransition {
                    labels: entry.flow,
                    transitioned,
                })
            }
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
        }
    }

    /// Mark a live session's `sensitive_touched` label `true` (WOR-2384,
    /// MCP06 fix round 1): sticky -- calling this again on a session
    /// that has already touched sensitive data is a no-op beyond
    /// refreshing the TTL and reports `transitioned: false`. `None` for
    /// an unknown or expired session. Renews the sliding TTL. Uses the
    /// same lock and the same per-session entry `taint` does, so the two
    /// labels can never observe a torn intermediate state.
    pub fn mark_sensitive_touched(&self, id: &str) -> Option<FlowLabelTransition> {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                let transitioned = !entry.flow.sensitive_touched;
                entry.flow.sensitive_touched = true;
                Some(FlowLabelTransition {
                    labels: entry.flow,
                    transitioned,
                })
            }
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
        }
    }

    /// Live-session count (post-prune), for tests and introspection.
    pub fn len(&self) -> usize {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::prune(&mut map);
        map.len()
    }

    /// True when no live sessions exist.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn prune(map: &mut HashMap<String, SessionEntry>) {
        let now = Instant::now();
        map.retain(|_, entry| entry.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_validate_then_end() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        assert!(store.validate(&id));
        assert!(store.end(&id));
        assert!(!store.validate(&id), "ended session must not validate");
        assert!(!store.end(&id), "double end is a miss");
    }

    #[test]
    fn unknown_id_is_invalid() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(!store.validate("nope"));
        assert!(!store.end("nope"));
    }

    #[test]
    fn expired_session_is_invalid_and_pruned() {
        let store = SessionStore::new(Duration::from_millis(10));
        let id = store.create();
        std::thread::sleep(Duration::from_millis(30));
        assert!(!store.validate(&id));
        assert!(store.is_empty(), "expired entries must be pruned");
    }

    #[test]
    fn validate_renews_the_sliding_ttl() {
        let store = SessionStore::new(Duration::from_millis(80));
        let id = store.create();
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(40));
            assert!(store.validate(&id), "touches inside the ttl must renew");
        }
    }

    #[test]
    fn ids_are_unique_and_ascii() {
        let store = SessionStore::new(Duration::from_secs(60));
        let a = store.create();
        let b = store.create();
        assert_ne!(a, b);
        assert!(a.is_ascii());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn risk_accumulates_within_one_live_session() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        let first = store
            .record_risk(
                &id,
                SessionRisk {
                    tool_access: true,
                    private_data: true,
                    external_comm: false,
                },
            )
            .expect("live session");
        assert!(!first.is_lethal_trifecta());

        let second = store
            .record_risk(
                &id,
                SessionRisk {
                    tool_access: true,
                    private_data: false,
                    external_comm: true,
                },
            )
            .expect("live session");
        assert!(second.is_lethal_trifecta());
    }

    #[test]
    fn tool_requirements_roundtrip() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        assert!(store.tool_requirements(&id).is_none());
        let reqs = std::collections::HashMap::from([("search".to_string(), "^1".to_string())]);
        assert!(store.set_tool_requirements(&id, reqs.clone()));
        let got = store.tool_requirements(&id).expect("live session");
        assert_eq!(got.as_ref(), &reqs);
    }

    #[test]
    fn tool_requirements_unknown_session_is_rejected() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(!store.set_tool_requirements(
            "nope",
            std::collections::HashMap::from([("a".to_string(), "^1".to_string())])
        ));
        assert!(store.tool_requirements("nope").is_none());
    }

    // --- Session flow labels (WOR-2384, MCP06; fix round 1: Rule of
    // Two's confidentiality axis) ---

    #[test]
    fn flow_labels_default_to_trusted_and_not_sensitive_touched() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        let labels = store.flow_labels(&id).expect("live session");
        assert_eq!(labels.integrity, SessionIntegrity::Trusted);
        assert!(!labels.sensitive_touched);
    }

    #[test]
    fn taint_flips_integrity_and_reports_the_transition() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();

        let first = store.taint(&id).expect("live session");
        assert_eq!(first.labels.integrity, SessionIntegrity::Tainted);
        assert!(
            first.transitioned,
            "the first taint call must report the transition"
        );

        let second = store.taint(&id).expect("live session");
        assert_eq!(second.labels.integrity, SessionIntegrity::Tainted);
        assert!(
            !second.transitioned,
            "a session already tainted must not report a transition again"
        );
    }

    #[test]
    fn mark_sensitive_touched_flips_the_label_and_reports_the_transition() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();

        let first = store.mark_sensitive_touched(&id).expect("live session");
        assert!(first.labels.sensitive_touched);
        assert!(
            first.transitioned,
            "the first mark call must report the transition"
        );
        // Marking sensitivity must never taint integrity; the two axes
        // are independent.
        assert_eq!(first.labels.integrity, SessionIntegrity::Trusted);

        let second = store.mark_sensitive_touched(&id).expect("live session");
        assert!(second.labels.sensitive_touched);
        assert!(
            !second.transitioned,
            "a session that already touched sensitive data must not report a transition again"
        );
    }

    #[test]
    fn taint_is_sticky_across_later_reads() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        store.taint(&id).expect("live session");

        // Reading the labels several more times must never observe a
        // reversion back to Trusted; nothing in this module ever
        // un-taints a session.
        for _ in 0..3 {
            let labels = store.flow_labels(&id).expect("live session");
            assert_eq!(labels.integrity, SessionIntegrity::Tainted);
        }
    }

    #[test]
    fn sensitive_touched_is_sticky_across_later_reads() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        store.mark_sensitive_touched(&id).expect("live session");

        for _ in 0..3 {
            let labels = store.flow_labels(&id).expect("live session");
            assert!(labels.sensitive_touched);
        }
    }

    #[test]
    fn the_two_axes_accumulate_independently() {
        // Neither label's sticky-set can regress or interfere with the
        // other: a session that touches sensitive data first, then is
        // tainted, ends up with both flipped, not just the last one
        // applied.
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        store.mark_sensitive_touched(&id).expect("live session");
        store.taint(&id).expect("live session");

        let labels = store.flow_labels(&id).expect("live session");
        assert_eq!(labels.integrity, SessionIntegrity::Tainted);
        assert!(labels.sensitive_touched);
    }

    #[test]
    fn taint_on_unknown_or_expired_session_is_a_miss() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(store.taint("nope").is_none());

        let short = SessionStore::new(Duration::from_millis(10));
        let id = short.create();
        std::thread::sleep(Duration::from_millis(30));
        assert!(short.taint(&id).is_none());
    }

    #[test]
    fn mark_sensitive_touched_on_unknown_or_expired_session_is_a_miss() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(store.mark_sensitive_touched("nope").is_none());

        let short = SessionStore::new(Duration::from_millis(10));
        let id = short.create();
        std::thread::sleep(Duration::from_millis(30));
        assert!(short.mark_sensitive_touched(&id).is_none());
    }

    #[test]
    fn two_sessions_taint_and_touch_independently() {
        // Stands in for the per-tenant isolation guarantee: nothing in
        // this store keys on tenant, only on session id, so two
        // sessions (however owned) never observe each other's flow
        // state, on either axis.
        let store = SessionStore::new(Duration::from_secs(60));
        let tenant_a_session = store.create();
        let tenant_b_session = store.create();

        store.taint(&tenant_a_session).expect("live session");
        store
            .mark_sensitive_touched(&tenant_a_session)
            .expect("live session");

        let a_labels = store.flow_labels(&tenant_a_session).expect("live session");
        assert_eq!(a_labels.integrity, SessionIntegrity::Tainted);
        assert!(a_labels.sensitive_touched);

        let b_labels = store.flow_labels(&tenant_b_session).expect("live session");
        assert_eq!(
            b_labels.integrity,
            SessionIntegrity::Trusted,
            "tainting one session must never taint another"
        );
        assert!(
            !b_labels.sensitive_touched,
            "marking one session sensitive-touched must never mark another"
        );
    }
}
