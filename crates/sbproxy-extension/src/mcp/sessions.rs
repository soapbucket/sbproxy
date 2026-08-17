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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Ceiling on the number of concurrently-live sessions one
/// [`SessionStore`] tracks with independently-mutable state (WOR-2384,
/// I3 fix round). Mirrors `crate::mcp::peer_profile::MAX_TRACKED_PEERS`'s
/// order of magnitude and reasoning: a session id is minted by this
/// server, not caller-supplied, but minting itself is driven by
/// inbound `initialize` requests, so an unbounded map is still a
/// memory-exhaustion knob for a caller who can afford enough
/// concurrent connections to keep flooding it.
pub const MAX_TRACKED_SESSIONS: usize = 4096;

/// The single session every mint past [`MAX_TRACKED_SESSIONS`] shares
/// (WOR-2384, I3 fix round). A NUL-prefixed sentinel keeps it out of
/// the UUID-v4 id space [`SessionStore::create`] otherwise returns, so
/// it can never collide with a real minted id.
const OVERFLOW_SESSION_ID: &str = "\u{0}sbproxy-mcp-session-overflow";

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
    /// The tenant a session was minted for (WOR-2384, MCP10). Stamped
    /// once at [`SessionStore::create`] and never mutated; checked by
    /// [`SessionStore::validate`] so a session id guessed or replayed
    /// by a different tenant is invalid, not merely undocumented.
    tenant_id: String,
}

/// Outcome of [`SessionStore::validate`] (WOR-2384, MCP10).
///
/// A three-way result rather than a plain bool so the caller can tell
/// "no such session" apart from "this session exists, but not for the
/// tenant that presented it" -- the latter is a security-relevant
/// event worth its own audit line, even though both cases return the
/// same generic 404 to the wire (a validating server must not reveal
/// that a differently-owned session id happens to exist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionValidation {
    /// The id names a live session minted for the presenting tenant.
    /// The sliding TTL was renewed.
    Valid,
    /// The id names no live session (never minted, ended, or expired).
    /// Indistinguishable on the wire from [`Self::TenantMismatch`] by
    /// design.
    Unknown,
    /// The id names a live session, but it was minted for a different
    /// tenant than the one presenting it now. The TTL is *not*
    /// renewed and the entry is *not* removed -- the session stays
    /// live for its rightful tenant.
    TenantMismatch,
}

impl SessionValidation {
    /// True only for [`Self::Valid`]. Convenience for call sites that
    /// only need the old bool shape (e.g. deciding whether to accept
    /// the id for the rest of the request) without caring which
    /// refusal reason applied.
    pub fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// In-memory session table with a sliding idle TTL, bounded at
/// [`MAX_TRACKED_SESSIONS`] (WOR-2384, I3 fix round).
pub struct SessionStore {
    ttl: Duration,
    inner: Mutex<HashMap<String, SessionEntry>>,
    /// Latches true the first time this store routes a mint to the
    /// shared overflow session, so the saturation warning logs once
    /// per store rather than once per flooding call. Per-instance
    /// (not a process-wide `static`, unlike
    /// `crate::mcp::peer_profile`'s registry): a hot reload compiles a
    /// fresh `SessionStore`, and an operator running several `mcp`
    /// origins has one store per origin, so a process-wide latch would
    /// silence the warning for every store after the first one to
    /// saturate.
    saturated: AtomicBool,
}

impl SessionStore {
    /// Create a store whose sessions expire after `ttl` of inactivity.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
            saturated: AtomicBool::new(false),
        }
    }

    /// Create a new session bound to `tenant_id` and return its id
    /// (UUID v4, which satisfies the spec's visible-ASCII requirement
    /// and is not guessable) -- or, once the store holds
    /// [`MAX_TRACKED_SESSIONS`] entries, the shared overflow session id
    /// every mint past the cap returns instead. See
    /// [`Self::create_capped`] for the overflow behavior.
    ///
    /// WOR-2384 (MCP10): `tenant_id` is stamped once at mint time and
    /// checked by every later [`Self::validate`] call for this id. It
    /// must come from the request's route-derived tenant, the same
    /// source every other per-tenant gate in this codebase uses, never
    /// from a caller-mutable header or body field.
    pub fn create(&self, tenant_id: &str) -> String {
        self.create_capped(tenant_id, MAX_TRACKED_SESSIONS)
    }

    /// The actual mint-or-overflow logic, parameterized on the cap
    /// rather than reaching for [`MAX_TRACKED_SESSIONS`] directly.
    ///
    /// Split out for the same reason
    /// `crate::mcp::peer_profile::observe_and_record_capped` is:
    /// exercising the overflow branch against the real
    /// [`MAX_TRACKED_SESSIONS`] (4096) would take thousands of real
    /// mints to reach inside a test.
    ///
    /// Below the cap, mints a normal, independently-tracked session
    /// with the usual trusted/untouched defaults. At the cap, every
    /// further mint (regardless of tenant) shares one
    /// [`OVERFLOW_SESSION_ID`] session instead of growing the map
    /// further. Unlike `peer_profile`'s shared overflow profile (an
    /// aggregate downgrade-detection signal, safe to merge across
    /// unrelated callers by construction), an MCP session legitimately
    /// carries per-client state, so sharing one here is a deliberate
    /// degradation, not a free one:
    ///
    /// - The shared session's flow labels start at their
    ///   most-restrictive values (`SessionIntegrity::Tainted` +
    ///   `sensitive_touched: true`) instead of the normal
    ///   trusted/untouched defaults -- fail closed on the Rule-of-Two
    ///   guardrail for a session this store can no longer track with
    ///   dedicated state.
    /// - Only the tenant that first claims the shared slot can ever
    ///   [`Self::validate`] it again: every other tenant's mint gets
    ///   back the *same* session id, but `tenant_id` was already
    ///   stamped by whichever mint claimed the slot first, so every
    ///   later tenant's very next request fails the tenant check --
    ///   the fail-closed direction, since a caller flooding
    ///   `initialize` to exhaust the registry gets a session that
    ///   locks it out rather than one that silently under-enforces the
    ///   flow guardrail or leaks state to an unrelated tenant.
    fn create_capped(&self, tenant_id: &str, cap: usize) -> String {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::prune(&mut map);

        if map.len() < cap {
            let id = uuid::Uuid::new_v4().to_string();
            map.insert(
                id.clone(),
                SessionEntry {
                    expires_at: Instant::now() + self.ttl,
                    risk: SessionRisk::default(),
                    flow: FlowLabels::default(),
                    tool_requirements: None,
                    tenant_id: tenant_id.to_string(),
                },
            );
            return id;
        }

        let first_time_this_episode = !map.contains_key(OVERFLOW_SESSION_ID);
        if first_time_this_episode && !self.saturated.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "sbproxy::mcp::sessions",
                max_sessions = cap,
                "mcp session registry is full; new sessions share a fallback session"
            );
        }
        sbproxy_observe::metrics::record_mcp_session_registry_saturated();
        let entry = map
            .entry(OVERFLOW_SESSION_ID.to_string())
            .or_insert_with(|| SessionEntry {
                expires_at: Instant::now() + self.ttl,
                risk: SessionRisk::default(),
                flow: FlowLabels {
                    integrity: SessionIntegrity::Tainted,
                    sensitive_touched: true,
                },
                tool_requirements: None,
                tenant_id: tenant_id.to_string(),
            });
        entry.expires_at = Instant::now() + self.ttl;
        OVERFLOW_SESSION_ID.to_string()
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

    /// Validate a live session id against the tenant presenting it
    /// (WOR-2384, MCP10). A successful [`SessionValidation::Valid`]
    /// renews the sliding TTL; [`SessionValidation::TenantMismatch`]
    /// does neither -- the mismatched caller gets no side effect on
    /// the session at all, and the entry stays live for its rightful
    /// tenant.
    ///
    /// This is an isolation invariant, not a policy: it is always
    /// enforced, with no warn mode, because a session id was already
    /// an opaque per-deployment UUID before this method existed --
    /// binding it to the tenant that minted it cannot break an
    /// existing legitimate config.
    pub fn validate(&self, id: &str, tenant_id: &str) -> SessionValidation {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                if entry.tenant_id != tenant_id {
                    return SessionValidation::TenantMismatch;
                }
                entry.expires_at = Instant::now() + self.ttl;
                SessionValidation::Valid
            }
            Some(_) => {
                map.remove(id);
                SessionValidation::Unknown
            }
            None => SessionValidation::Unknown,
        }
    }

    /// End a live session, scoped to the tenant that minted it
    /// (WOR-2384, MCP10). Returns the same three-way
    /// [`SessionValidation`] [`Self::validate`] does: `Valid` when the
    /// id named a live session for `tenant_id` (now removed);
    /// `TenantMismatch` when it named a live session for a *different*
    /// tenant, left completely untouched -- not removed, TTL not
    /// renewed, flow labels intact; `Unknown` when it named no live
    /// session at all.
    ///
    /// `TenantMismatch` and `Unknown` are deliberately
    /// indistinguishable to a caller that only checks `is_valid()`,
    /// the same existence-oracle guard `validate()` enforces: a
    /// cross-tenant `DELETE` must not (a) confirm that someone else's
    /// session id happens to exist by returning a different wire
    /// response than an unknown id would, (b) terminate that session,
    /// or (c) reset the Rule-of-Two flow labels it carries -- ending
    /// and re-minting a session is itself a guardrail reset a
    /// non-owning tenant must not be able to trigger.
    pub fn end(&self, id: &str, tenant_id: &str) -> SessionValidation {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                let tenant_matches = entry.tenant_id == tenant_id;
                if tenant_matches {
                    map.remove(id);
                    SessionValidation::Valid
                } else {
                    SessionValidation::TenantMismatch
                }
            }
            Some(_) => {
                map.remove(id);
                SessionValidation::Unknown
            }
            None => SessionValidation::Unknown,
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
        let id = store.create("acme");
        assert!(store.validate(&id, "acme").is_valid());
        assert!(store.end(&id, "acme").is_valid());
        assert!(
            !store.validate(&id, "acme").is_valid(),
            "ended session must not validate"
        );
        assert!(!store.end(&id, "acme").is_valid(), "double end is a miss");
    }

    #[test]
    fn unknown_id_is_invalid() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(!store.validate("nope", "acme").is_valid());
        assert!(!store.end("nope", "acme").is_valid());
    }

    #[test]
    fn expired_session_is_invalid_and_pruned() {
        let store = SessionStore::new(Duration::from_millis(10));
        let id = store.create("acme");
        std::thread::sleep(Duration::from_millis(30));
        assert!(!store.validate(&id, "acme").is_valid());
        assert!(store.is_empty(), "expired entries must be pruned");
    }

    #[test]
    fn validate_renews_the_sliding_ttl() {
        let store = SessionStore::new(Duration::from_millis(80));
        let id = store.create("acme");
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(40));
            assert!(
                store.validate(&id, "acme").is_valid(),
                "touches inside the ttl must renew"
            );
        }
    }

    #[test]
    fn ids_are_unique_and_ascii() {
        let store = SessionStore::new(Duration::from_secs(60));
        let a = store.create("acme");
        let b = store.create("acme");
        assert_ne!(a, b);
        assert!(a.is_ascii());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn risk_accumulates_within_one_live_session() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("acme");
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
        let id = store.create("acme");
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
        let id = store.create("acme");
        let labels = store.flow_labels(&id).expect("live session");
        assert_eq!(labels.integrity, SessionIntegrity::Trusted);
        assert!(!labels.sensitive_touched);
    }

    #[test]
    fn taint_flips_integrity_and_reports_the_transition() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("acme");

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
        let id = store.create("acme");

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
        let id = store.create("acme");
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
        let id = store.create("acme");
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
        let id = store.create("acme");
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
        let id = short.create("acme");
        std::thread::sleep(Duration::from_millis(30));
        assert!(short.taint(&id).is_none());
    }

    #[test]
    fn mark_sensitive_touched_on_unknown_or_expired_session_is_a_miss() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(store.mark_sensitive_touched("nope").is_none());

        let short = SessionStore::new(Duration::from_millis(10));
        let id = short.create("acme");
        std::thread::sleep(Duration::from_millis(30));
        assert!(short.mark_sensitive_touched(&id).is_none());
    }

    #[test]
    fn two_sessions_taint_and_touch_independently() {
        // Flow-label isolation is keyed on session id, not tenant: two
        // sessions, even two owned by the very same tenant, never
        // observe each other's flow state on either axis. Tenant
        // isolation of *who may present which session id at all* is
        // covered separately by the `validate` tenant-binding tests
        // below.
        let store = SessionStore::new(Duration::from_secs(60));
        let tenant_a_session = store.create("acme");
        let tenant_b_session = store.create("acme");

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

    // --- Tenant-bound sessions (WOR-2384, MCP10) ---

    #[test]
    fn a_session_validates_only_for_the_tenant_it_was_minted_for() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("tenant-a");
        assert_eq!(store.validate(&id, "tenant-a"), SessionValidation::Valid);
    }

    #[test]
    fn a_session_presented_by_a_different_tenant_is_rejected() {
        // This is the adversarial case the mint-time binding exists to
        // close: tenant B guesses or replays tenant A's session id.
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("tenant-a");
        assert_eq!(
            store.validate(&id, "tenant-b"),
            SessionValidation::TenantMismatch,
            "a session minted for tenant-a must be invalid when presented by tenant-b"
        );
    }

    #[test]
    fn tenant_mismatch_and_unknown_id_are_indistinguishable_on_is_valid() {
        // The wire-visible refusal must not leak "this session exists,
        // just not for you" versus "this session never existed" --
        // both collapse to `is_valid() == false` for a caller that only
        // wants the pass/fail bit (the generic 404 both cases map to
        // at the HTTP boundary).
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("tenant-a");
        assert!(!store.validate(&id, "tenant-b").is_valid());
        assert!(!store.validate("does-not-exist", "tenant-b").is_valid());
    }

    #[test]
    fn a_tenant_mismatch_does_not_renew_the_ttl_or_evict_the_session() {
        // A wrong-tenant probe must be a pure no-op against the entry:
        // it neither extends the session's life (which would let an
        // attacker keep someone else's session alive by polling it)
        // nor deletes it (which would let an attacker end another
        // tenant's session by guessing its id).
        let store = SessionStore::new(Duration::from_millis(60));
        let id = store.create("tenant-a");
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(
            store.validate(&id, "tenant-b"),
            SessionValidation::TenantMismatch
        );
        // Still valid for the rightful tenant well past the original
        // TTL window, because the mismatch attempt above did not renew
        // it -- but it also must not have evicted the entry outright.
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(store.validate(&id, "tenant-a"), SessionValidation::Valid);
    }

    #[test]
    fn an_unknown_id_stays_unknown_regardless_of_tenant() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert_eq!(
            store.validate("nope", "any-tenant"),
            SessionValidation::Unknown
        );
    }

    #[test]
    fn two_tenants_each_validate_only_their_own_session() {
        let store = SessionStore::new(Duration::from_secs(60));
        let a = store.create("tenant-a");
        let b = store.create("tenant-b");
        assert_eq!(store.validate(&a, "tenant-a"), SessionValidation::Valid);
        assert_eq!(
            store.validate(&a, "tenant-b"),
            SessionValidation::TenantMismatch
        );
        assert_eq!(store.validate(&b, "tenant-b"), SessionValidation::Valid);
        assert_eq!(
            store.validate(&b, "tenant-a"),
            SessionValidation::TenantMismatch
        );
    }

    // --- Tenant-bound end() (WOR-2384, C2 fix round) ---

    #[test]
    fn a_foreign_delete_leaves_the_session_alive() {
        // The C2 finding: end() used to take a bare id, so a
        // cross-tenant DELETE could terminate a session it did not
        // mint. A mismatched end() must be a pure no-op against the
        // entry -- the rightful tenant must still be able to validate
        // it afterward.
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("tenant-a");
        assert_eq!(
            store.end(&id, "tenant-b"),
            SessionValidation::TenantMismatch
        );
        assert_eq!(store.validate(&id, "tenant-a"), SessionValidation::Valid);
    }

    #[test]
    fn a_foreign_delete_does_not_reset_the_flow_labels() {
        // Ending and re-minting a session would silently reset its
        // Rule-of-Two flow labels -- a remote guardrail reset a
        // non-owning tenant must not be able to trigger by guessing an
        // id and calling DELETE.
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("tenant-a");
        store.taint(&id).expect("live session");
        store.mark_sensitive_touched(&id).expect("live session");

        assert_eq!(
            store.end(&id, "tenant-b"),
            SessionValidation::TenantMismatch
        );

        let labels = store.flow_labels(&id).expect("session must still exist");
        assert_eq!(labels.integrity, SessionIntegrity::Tainted);
        assert!(labels.sensitive_touched);
    }

    #[test]
    fn a_foreign_delete_is_indistinguishable_from_an_unknown_id() {
        // No existence oracle: a DELETE from the wrong tenant and a
        // DELETE for an id that never existed must collapse to the
        // same `is_valid() == false` a caller checking only the bool
        // shape would see.
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("tenant-a");
        assert!(!store.end(&id, "tenant-b").is_valid());
        assert!(!store.end("does-not-exist", "tenant-b").is_valid());
    }

    #[test]
    fn the_rightful_tenant_can_still_end_their_own_session() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("tenant-a");
        assert_eq!(store.end(&id, "tenant-a"), SessionValidation::Valid);
        assert_eq!(
            store.validate(&id, "tenant-a"),
            SessionValidation::Unknown,
            "a successfully ended session must no longer validate"
        );
    }

    // --- Bounded session registry (WOR-2384, I3 fix round) ---

    #[test]
    fn mints_past_the_cap_share_the_overflow_session_instead_of_growing_unbounded() {
        // Mirrors `peer_profile`'s and `evidence_seq`'s own overflow
        // tests: exercises `create_capped` directly against a small
        // throwaway cap rather than filling the real 4096-entry store.
        let store = SessionStore::new(Duration::from_secs(60));
        let cap = 2;

        let a = store.create_capped("tenant-a", cap);
        let b = store.create_capped("tenant-a", cap);
        assert_ne!(a, b, "both mints below the cap must get independent ids");

        // The store is now at the cap. A third mint shares the
        // overflow session rather than getting a third independent id.
        let c = store.create_capped("tenant-a", cap);
        assert_eq!(c, "\u{0}sbproxy-mcp-session-overflow");
        assert_ne!(c, a);
        assert_ne!(c, b);

        // A fourth mint, even for the same tenant, shares the exact
        // same overflow session -- the map must not keep growing.
        let d = store.create_capped("tenant-a", cap);
        assert_eq!(d, c);
    }

    #[test]
    fn the_overflow_session_starts_at_the_flow_guardrails_most_restrictive_labels() {
        let store = SessionStore::new(Duration::from_secs(60));
        let cap = 1;
        store.create_capped("tenant-a", cap); // fills the one real slot
        let overflow_id = store.create_capped("tenant-a", cap);

        let labels = store
            .flow_labels(&overflow_id)
            .expect("overflow session is itself a live session");
        assert_eq!(
            labels.integrity,
            SessionIntegrity::Tainted,
            "an overflow session must fail closed on the integrity leg"
        );
        assert!(
            labels.sensitive_touched,
            "an overflow session must fail closed on the sensitivity leg"
        );
    }

    #[test]
    fn only_the_first_tenant_to_claim_the_overflow_session_can_validate_it_again() {
        // Fail-closed direction: cardinality pressure must not let a
        // second tenant validate a session id it was handed but that
        // was actually claimed by whichever tenant minted it first.
        let store = SessionStore::new(Duration::from_secs(60));
        let cap = 1;
        store.create_capped("tenant-a", cap); // fills the one real slot
        let overflow_id = store.create_capped("tenant-a", cap);
        // A different tenant's mint returns the same id (nothing else
        // to hand out), but does not reassign the entry's tenant.
        let same_overflow_id = store.create_capped("tenant-b", cap);
        assert_eq!(overflow_id, same_overflow_id);

        assert_eq!(
            store.validate(&overflow_id, "tenant-a"),
            SessionValidation::Valid,
            "the tenant that first claimed the overflow slot must still be able to use it"
        );
        assert_eq!(
            store.validate(&overflow_id, "tenant-b"),
            SessionValidation::TenantMismatch,
            "a later tenant sharing the overflow slot must not be able to validate it"
        );
    }

    #[test]
    fn a_flood_of_mints_never_grows_the_map_past_the_cap_plus_the_overflow_slot() {
        let store = SessionStore::new(Duration::from_secs(60));
        let cap = 8;
        for i in 0..cap * 10 {
            store.create_capped(&format!("tenant-{i}"), cap);
        }
        assert_eq!(
            store.len(),
            cap + 1,
            "cap real sessions plus exactly one shared overflow session, regardless of flood size"
        );
    }
}
