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
/// [`SessionStore`] tracks (WOR-2384, I3 fix round; fail-closed per the
/// I3 fix round 2 ruling). Mirrors
/// `crate::mcp::peer_profile::MAX_TRACKED_PEERS`'s order of magnitude
/// and reasoning: a session id is minted by this server, not
/// caller-supplied, but minting itself is driven by inbound
/// `initialize` requests, so an unbounded map is still a
/// memory-exhaustion knob for a caller who can afford enough
/// concurrent connections to keep flooding it. Acts as a backstop
/// behind [`MAX_TRACKED_SESSIONS_PER_TENANT`]: a single tenant can
/// never reach this ceiling on its own (it would hit its own sub-cap
/// first), so this bounds the number of *distinct tenants* with live
/// sessions at once, not a single tenant's flood. `4096 /
/// MAX_TRACKED_SESSIONS_PER_TENANT` (16 tenants at full sub-cap) is a
/// deployment-sizing fact -- how many tenants this process can hold
/// sessions for at once -- not a per-tenant isolation guarantee; the
/// sub-cap is what isolates one tenant's flood from every other's.
pub const MAX_TRACKED_SESSIONS: usize = 4096;

/// Ceiling on the number of concurrently-live sessions one tenant may
/// hold in one [`SessionStore`] (WOR-2384, I3 fix round 2). A tenant at
/// its own sub-cap is refused a new session while every other tenant,
/// and every one of this tenant's own already-live sessions, is
/// unaffected -- one tenant flooding `initialize` cannot exhaust the
/// registry for anyone else, the gap the fix round 1 shared-overflow
/// design (removed; see git history) failed to close.
pub const MAX_TRACKED_SESSIONS_PER_TENANT: usize = 256;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionIntegrity {
    /// Every tool result the session has read so far came from a
    /// trusted server.
    #[default]
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

/// Outcome of [`SessionStore::create`] (WOR-2384, I3 fix round 2).
///
/// A session id is minted by this server, never caller-supplied, so
/// there is no tenant-mismatch case here the way [`SessionValidation`]
/// has one -- the only failure mode is the registry being too full to
/// hand out a new, independently-tracked session at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionMint {
    /// A new session was minted and is live under `tenant_id`.
    Minted(String),
    /// The store is saturated -- either the global
    /// [`MAX_TRACKED_SESSIONS`] cap or the presenting tenant's own
    /// [`MAX_TRACKED_SESSIONS_PER_TENANT`] sub-cap -- and refused to
    /// mint a new session. Every existing session, for this tenant and
    /// every other, is unaffected: no session was ended, no label was
    /// reset, and no entry was shared with anyone.
    Saturated,
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

impl SessionMint {
    /// The minted id, when this call succeeded; `None` for
    /// [`Self::Saturated`]. Convenience for a caller that only needs
    /// the `Option<String>` shape.
    pub fn minted(self) -> Option<String> {
        match self {
            Self::Minted(id) => Some(id),
            Self::Saturated => None,
        }
    }
}

/// In-memory session table with a sliding idle TTL, bounded at
/// [`MAX_TRACKED_SESSIONS`] globally and [`MAX_TRACKED_SESSIONS_PER_TENANT`]
/// per tenant (WOR-2384, I3 fix round; fail-closed per the I3 fix round
/// 2 ruling -- a mint past either cap is refused outright, never
/// shared with another caller).
pub struct SessionStore {
    ttl: Duration,
    inner: Mutex<HashMap<String, SessionEntry>>,
    /// Latches true the first time this store refuses a mint for
    /// saturation, so the warning logs once per store rather than once
    /// per flooding call. Per-instance (not a process-wide `static`,
    /// unlike `crate::mcp::peer_profile`'s registry): a hot reload
    /// compiles a fresh `SessionStore`, and an operator running
    /// several `mcp` origins has one store per origin, so a
    /// process-wide latch would silence the warning for every store
    /// after the first one to saturate.
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
    /// and is not guessable) as [`SessionMint::Minted`] -- or
    /// [`SessionMint::Saturated`] when the store cannot mint one
    /// (WOR-2384, I3 fix round 2). See [`Self::create_capped`] for the
    /// exact caps.
    ///
    /// WOR-2384 (MCP10): `tenant_id` is stamped once at mint time and
    /// checked by every later [`Self::validate`] call for this id. It
    /// must come from the request's route-derived tenant, the same
    /// source every other per-tenant gate in this codebase uses, never
    /// from a caller-mutable header or body field.
    pub fn create(&self, tenant_id: &str) -> SessionMint {
        self.create_capped(
            tenant_id,
            MAX_TRACKED_SESSIONS,
            MAX_TRACKED_SESSIONS_PER_TENANT,
        )
    }

    /// The actual mint-or-refuse logic, parameterized on both caps
    /// rather than reaching for [`MAX_TRACKED_SESSIONS`] /
    /// [`MAX_TRACKED_SESSIONS_PER_TENANT`] directly.
    ///
    /// Split out for the same reason
    /// `crate::mcp::peer_profile::observe_and_record_capped` is:
    /// exercising either cap against the real constants (4096 / 256)
    /// would take that many real mints to reach inside a test.
    ///
    /// Below both caps, mints a normal, independently-tracked session
    /// with the usual trusted/untouched defaults. At either cap, the
    /// mint is refused outright (WOR-2384, I3 fix round 2 -- this
    /// replaces fix round 1's shared-overflow-session design, which a
    /// review found let a saturated store silently issue a 200 with no
    /// `Mcp-Session-Id` header, since the shared id's leading NUL byte
    /// is rejected by the HTTP header encoder, and let
    /// `set_tool_requirements` write onto that shared entry across
    /// tenants because it took no tenant parameter -- both real bugs
    /// a shared mutable session can produce that an outright refusal
    /// cannot). No entry is inserted, no existing session (this
    /// tenant's or any other's) is touched, and the caller is
    /// responsible for surfacing the refusal to the client -- this
    /// method only decides whether to mint, it never talks to the
    /// wire itself.
    fn create_capped(&self, tenant_id: &str, cap: usize, tenant_cap: usize) -> SessionMint {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::prune(&mut map);

        // Per-tenant sub-cap first (whole-branch review, item 5):
        // checking the global cap first would let a 17th tenant be
        // refused outright the moment the registry as a whole is
        // full, even though that tenant itself holds no sessions yet
        // -- an honest refusal names the reason the caller actually
        // hit. "Your own tenant is at its sub-cap" is the more common,
        // more actionable one to report first; the global cap still
        // exists to bound how many *distinct* tenants this process
        // tracks sessions for at all, 16 at a time at full sub-cap
        // (`MAX_TRACKED_SESSIONS / MAX_TRACKED_SESSIONS_PER_TENANT`),
        // a deployment-sizing fact, not a per-tenant isolation
        // guarantee.
        let tenant_live = map.values().filter(|e| e.tenant_id == tenant_id).count();
        if tenant_live >= tenant_cap {
            self.report_saturation(tenant_cap, "tenant");
            return SessionMint::Saturated;
        }
        if map.len() >= cap {
            self.report_saturation(cap, "global");
            return SessionMint::Saturated;
        }

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
        SessionMint::Minted(id)
    }

    /// Log (once per store) and record the saturation metric for a
    /// refused mint. `scope` is `"global"` or `"tenant"`, naming which
    /// cap refused it, for the one log line only -- the metric and the
    /// wire-visible refusal both stay a single closed reason
    /// (`session_registry_saturated`) regardless of which cap tripped,
    /// since the caller-visible behavior (refused, try again later) is
    /// identical either way.
    fn report_saturation(&self, cap: usize, scope: &'static str) {
        if !self.saturated.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "sbproxy::mcp::sessions",
                scope,
                cap,
                "mcp session registry is full; refusing to mint a new session"
            );
        }
        sbproxy_observe::metrics::record_mcp_session_registry_saturated();
    }

    /// Attach the rollout plane's per-session version requirements
    /// (`{tool: semver range}`) to a live session bound to `tenant_id`.
    /// True on success; false when the session is unknown, expired, or
    /// minted for a different tenant (WOR-2384, I3 fix round 2: tenant
    /// checked here too, matching every other per-session write, even
    /// though the one production call site only ever presents the
    /// tenant's own just-minted id). Renews the sliding TTL like every
    /// other successful access; a tenant mismatch renews nothing,
    /// matching [`Self::validate`]'s no-side-effect-on-mismatch rule.
    pub fn set_tool_requirements(
        &self,
        id: &str,
        tenant_id: &str,
        reqs: HashMap<String, String>,
    ) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                if entry.tenant_id != tenant_id {
                    // No side effect on a mismatch, matching
                    // `validate()`: the entry is not removed and its
                    // TTL is not renewed, it just is not this caller's
                    // to write.
                    return false;
                }
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
        let id = store.create("acme").minted().expect("mint below the cap");
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
        let id = store.create("acme").minted().expect("mint below the cap");
        std::thread::sleep(Duration::from_millis(30));
        assert!(!store.validate(&id, "acme").is_valid());
        assert!(store.is_empty(), "expired entries must be pruned");
    }

    #[test]
    fn validate_renews_the_sliding_ttl() {
        let store = SessionStore::new(Duration::from_millis(80));
        let id = store.create("acme").minted().expect("mint below the cap");
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
        let a = store.create("acme").minted().expect("mint below the cap");
        let b = store.create("acme").minted().expect("mint below the cap");
        assert_ne!(a, b);
        assert!(a.is_ascii());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn risk_accumulates_within_one_live_session() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("acme").minted().expect("mint below the cap");
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
        let id = store.create("acme").minted().expect("mint below the cap");
        assert!(store.tool_requirements(&id).is_none());
        let reqs = std::collections::HashMap::from([("search".to_string(), "^1".to_string())]);
        assert!(store.set_tool_requirements(&id, "acme", reqs.clone()));
        let got = store.tool_requirements(&id).expect("live session");
        assert_eq!(got.as_ref(), &reqs);
    }

    #[test]
    fn tool_requirements_unknown_session_is_rejected() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(!store.set_tool_requirements(
            "nope",
            "acme",
            std::collections::HashMap::from([("a".to_string(), "^1".to_string())])
        ));
        assert!(store.tool_requirements("nope").is_none());
    }

    // --- Session flow labels (WOR-2384, MCP06; fix round 1: Rule of
    // Two's confidentiality axis) ---

    #[test]
    fn flow_labels_default_to_trusted_and_not_sensitive_touched() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("acme").minted().expect("mint below the cap");
        let labels = store.flow_labels(&id).expect("live session");
        assert_eq!(labels.integrity, SessionIntegrity::Trusted);
        assert!(!labels.sensitive_touched);
    }

    #[test]
    fn taint_flips_integrity_and_reports_the_transition() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create("acme").minted().expect("mint below the cap");

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
        let id = store.create("acme").minted().expect("mint below the cap");

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
        let id = store.create("acme").minted().expect("mint below the cap");
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
        let id = store.create("acme").minted().expect("mint below the cap");
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
        let id = store.create("acme").minted().expect("mint below the cap");
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
        let id = short.create("acme").minted().expect("mint below the cap");
        std::thread::sleep(Duration::from_millis(30));
        assert!(short.taint(&id).is_none());
    }

    #[test]
    fn mark_sensitive_touched_on_unknown_or_expired_session_is_a_miss() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(store.mark_sensitive_touched("nope").is_none());

        let short = SessionStore::new(Duration::from_millis(10));
        let id = short.create("acme").minted().expect("mint below the cap");
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
        let tenant_a_session = store.create("acme").minted().expect("mint below the cap");
        let tenant_b_session = store.create("acme").minted().expect("mint below the cap");

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
        let id = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
        assert_eq!(store.validate(&id, "tenant-a"), SessionValidation::Valid);
    }

    #[test]
    fn a_session_presented_by_a_different_tenant_is_rejected() {
        // This is the adversarial case the mint-time binding exists to
        // close: tenant B guesses or replays tenant A's session id.
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
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
        let id = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
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
        let id = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
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
        let a = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
        let b = store
            .create("tenant-b")
            .minted()
            .expect("mint below the cap");
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
        let id = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
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
        let id = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
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
        let id = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
        assert!(!store.end(&id, "tenant-b").is_valid());
        assert!(!store.end("does-not-exist", "tenant-b").is_valid());
    }

    #[test]
    fn the_rightful_tenant_can_still_end_their_own_session() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
        assert_eq!(store.end(&id, "tenant-a"), SessionValidation::Valid);
        assert_eq!(
            store.validate(&id, "tenant-a"),
            SessionValidation::Unknown,
            "a successfully ended session must no longer validate"
        );
    }

    // --- Bounded session registry (WOR-2384, I3 fix round 2: fail
    // closed, no shared overflow session) ---

    #[test]
    fn mints_below_both_caps_succeed_independently() {
        let store = SessionStore::new(Duration::from_secs(60));
        let (cap, tenant_cap) = (8, 8);
        let a = store
            .create_capped("tenant-a", cap, tenant_cap)
            .minted()
            .expect("below both caps");
        let b = store
            .create_capped("tenant-a", cap, tenant_cap)
            .minted()
            .expect("below both caps");
        assert_ne!(a, b);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn a_mint_past_the_global_cap_is_refused_and_mints_nothing() {
        // Mirrors `peer_profile`'s and `evidence_seq`'s own capped
        // tests: exercises `create_capped` directly against a small
        // throwaway cap rather than filling the real 4096-entry store.
        let store = SessionStore::new(Duration::from_secs(60));
        let (cap, tenant_cap) = (2, 100);
        store.create_capped("tenant-a", cap, tenant_cap);
        store.create_capped("tenant-b", cap, tenant_cap);

        assert_eq!(
            store.create_capped("tenant-c", cap, tenant_cap),
            SessionMint::Saturated,
            "a third tenant must be refused once the global cap is hit"
        );
        assert_eq!(
            store.len(),
            2,
            "a refused mint must not insert anything, shared or otherwise"
        );
    }

    #[test]
    fn a_mint_past_the_tenant_sub_cap_is_refused_while_other_tenants_are_unaffected() {
        let store = SessionStore::new(Duration::from_secs(60));
        let (cap, tenant_cap) = (100, 2);
        store.create_capped("tenant-a", cap, tenant_cap);
        store.create_capped("tenant-a", cap, tenant_cap);

        assert_eq!(
            store.create_capped("tenant-a", cap, tenant_cap),
            SessionMint::Saturated,
            "tenant-a is at its own sub-cap"
        );
        assert!(
            matches!(
                store.create_capped("tenant-b", cap, tenant_cap),
                SessionMint::Minted(_)
            ),
            "a different tenant, unaffected by tenant-a's sub-cap, must still mint"
        );
    }

    #[test]
    fn the_tenant_sub_cap_is_checked_before_the_global_cap() {
        // Whole-branch review, item 5: checking the global cap first
        // would refuse a brand-new tenant that has minted nothing
        // itself, once the registry as a whole happens to be full --
        // an honest refusal names the reason the *caller* actually
        // hit. Set the global cap equal to the tenant cap so both are
        // simultaneously true, and confirm the sub-cap is what a
        // caller sees first: the third mint for the same tenant is
        // refused with the registry still one slot under the global
        // cap, proving the tenant check ran, and won, before the
        // global one could.
        let store = SessionStore::new(Duration::from_secs(60));
        let (cap, tenant_cap) = (3, 2);
        store.create_capped("tenant-a", cap, tenant_cap);
        store.create_capped("tenant-a", cap, tenant_cap);
        assert_eq!(store.len(), 2, "one slot under the global cap of 3");
        assert_eq!(
            store.create_capped("tenant-a", cap, tenant_cap),
            SessionMint::Saturated,
            "tenant-a's own sub-cap refuses this before the global cap ever would"
        );
    }

    #[test]
    fn existing_sessions_keep_working_when_the_store_is_saturated() {
        let store = SessionStore::new(Duration::from_secs(60));
        let (cap, tenant_cap) = (1, 100);
        let pre_existing = store
            .create_capped("tenant-a", cap, tenant_cap)
            .minted()
            .expect("fills the one global slot");

        assert_eq!(
            store.create_capped("tenant-b", cap, tenant_cap),
            SessionMint::Saturated
        );

        // The pre-existing session is untouched: still validates, still
        // renews its TTL, still carries its own flow labels -- nothing
        // about refusing a *new* mint reaches back into what already
        // exists.
        assert_eq!(
            store.validate(&pre_existing, "tenant-a"),
            SessionValidation::Valid
        );
        let transition = store.taint(&pre_existing).expect("still live");
        assert!(transition.transitioned);
    }

    #[test]
    fn a_flood_of_mints_never_grows_the_map_past_the_cap() {
        let store = SessionStore::new(Duration::from_secs(60));
        let (cap, tenant_cap) = (8, 100);
        for i in 0..cap * 10 {
            store.create_capped(&format!("tenant-{i}"), cap, tenant_cap);
        }
        assert_eq!(
            store.len(),
            cap,
            "exactly the cap's worth of sessions survive a flood of distinct-tenant mints, \
             none shared, none silently dropped past the cap"
        );
    }

    #[test]
    fn set_tool_requirements_is_tenant_checked() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store
            .create("tenant-a")
            .minted()
            .expect("mint below the cap");
        assert!(!store.set_tool_requirements(
            &id,
            "tenant-b",
            HashMap::from([("search".to_string(), "^1".to_string())])
        ));
        assert!(
            store.tool_requirements(&id).is_none(),
            "a cross-tenant write must not land"
        );
        assert!(store.set_tool_requirements(
            &id,
            "tenant-a",
            HashMap::from([("search".to_string(), "^1".to_string())])
        ));
        assert!(store.tool_requirements(&id).is_some());
    }
}
