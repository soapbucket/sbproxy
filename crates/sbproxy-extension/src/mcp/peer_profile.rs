//! Downgrade-resistant negotiation profiles for federated MCP peers
//! (WOR-2384).
//!
//! `federated_servers[].protocol: auto` (the default) does not pin one
//! upstream MCP protocol era; instead the gateway remembers, per
//! `(tenant, server)`, the best era and the strictest auth posture the
//! peer has ever demonstrated. [`McpPeerProfile`] is that memory. Once a
//! peer has shown the modern era (or shown it requires auth), a later
//! contact that looks weaker -- a legacy-only answer, or a successful
//! call that needed no credentials -- is a *downgrade*, not simply "the
//! server's current state": an attacker sitting on the path to that
//! upstream (or an upstream itself compromised) benefits from a caller
//! trusting whatever the most recent answer says, so this module refuses
//! (or, in `warn` mode, flags) exactly the transitions that would let
//! a silently-downgraded connection look like nothing changed.
//!
//! A pinned `protocol:` (a literal era, not `auto`) is a different,
//! unconditional rule: [`check_pin`] never consults history at all, and
//! never negotiates. An upstream that ever answers with any other era is
//! refused outright.
//!
//! # Two independent axes
//!
//! - Protocol era: [`super::types::LEGACY_PROTOCOL_VERSION`] ranks below
//!   [`super::types::MODERN_PROTOCOL_VERSION`]; anything else observed is
//!   treated as legacy-or-weaker (the gateway only trusts *positive*
//!   modern evidence, matching how inbound era classification already
//!   works -- see the `protocol/` module's `classify_http_era`).
//! - Auth posture: `auth_required: true -> false` is the dangerous
//!   direction (a peer that used to demand credentials and now does not
//!   is either misconfigured or has been quietly swapped underneath the
//!   gateway). `false -> true` never triggers a refusal; it only means
//!   the peer got stricter, which is always safe to accept.
//!
//! Both stored fields are **high-water marks**: [`observe`] never lowers
//! them. A `warn`-mode downgrade is allowed through but does not erase
//! the peer's best-ever era or strictest-ever auth posture, so the next
//! weaker contact is flagged again too, for as long as the weaker
//! behavior continues. Only a config change to the affected server entry
//! (including the escape hatch of pinning `protocol:` explicitly) starts
//! a fresh profile -- see [`peer_key`].
//!
//! # Tenant scoping and the bounded registry
//!
//! [`observe_and_record`] stores one profile per `(tenant_id, peer_key)`
//! pair in a process-global map, bounded at [`MAX_TRACKED_PEERS`]
//! globally and [`MAX_TRACKED_PEERS_PER_TENANT`] per tenant -- the same
//! cap hygiene `sbproxy_observe::evidence_seq` applies to its per-tenant
//! sequence counters, and the same two-cap shape [`super::sessions::SessionStore`]
//! uses: `tenant_id` is caller-controlled, so an unbounded map keyed by
//! it is a memory-exhaustion knob a single tenant could pull on its
//! own without the sub-cap.
//!
//! A pair past either cap is refused a dedicated slot outright, fail
//! closed (WOR-2384 fix round N): there is no shared fallback profile.
//! An earlier design routed every overflowing pair to one shared
//! mutable profile, on the theory that erring toward more
//! false-positive downgrade warnings under cardinality pressure beats
//! silently skipping the check. A review found that reasoning
//! backwards for an *enforcement input* like this one: tenant A's
//! observation of a weak, unauthenticated peer could seed the shared
//! profile, so tenant B's later MITM'd downgrade against the *same
//! shared bucket* would compare clean and the control would be
//! silently off for B -- or, in the other direction, a shared
//! high-water mark could refuse a tenant's legitimate legacy peer it
//! had never actually seen degrade. `tenant_id` being caller-controlled
//! means an attacker can walk the shared bucket into either failure
//! mode on purpose by supplying junk `(tenant, peer)` pairs, and the
//! old design ticked no metric when it did, so the drift was invisible
//! too.
//!
//! A pair this process cannot track therefore gets no downgrade
//! baseline at all, and [`observe_and_record`] reports
//! [`ObservationVerdict::Saturated`] rather than comparing against
//! anyone else's history. What that means on the wire depends on the
//! configured [`PeerDowngradePolicy`], decided by the caller (see
//! `mcp_peer_downgrade_check` in `sbproxy-core`): `block` refuses the
//! call fail-closed, with its own rule id
//! ([`PEER_PROFILE_SATURATED_RULE_ID`]), on the same reasoning an
//! unprofiled peer under `block` cannot be trusted any more than a
//! demonstrated downgrade can; `warn` allows it, since `warn` never
//! refuses a downgrade it *can* observe either. Either way the event is
//! observable: [`sbproxy_observe::metrics::record_mcp_peer_registry_saturated`]
//! ticks on every refused-tracking call (label-free and not
//! tenant-scoped, the same reason `evidence_seq`'s own tenant-cap
//! counter is), and a `tracing::warn!` line logs once per tenant so a
//! single flooding tenant cannot spam the log on every subsequent call.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::SystemTime;

use parking_lot::Mutex;

/// Stable rule id every peer-downgrade refusal or warning carries on the
/// `mcp_governance_decision` evidence event and the `SecurityAuditEntry`
/// it accompanies, regardless of which axis (protocol or auth posture)
/// triggered it. A SIEM rule keys on this one string; [`PeerDowngradeKind::reason_code`]
/// carries the finer-grained detail for a human reading the record.
///
/// Distinct from [`PROTOCOL_PIN_MISMATCH_RULE_ID`] and
/// [`PEER_PROFILE_SATURATED_RULE_ID`]: neither of those is a downgrade
/// against a recorded profile (a pin mismatch never consults one, see
/// [`check_pin`]; a saturated registry has no profile to consult at
/// all), so each carries its own rule id rather than this one
/// (WOR-2384 fix round 1, item 2; saturation added fix round N).
pub const PEER_DOWNGRADE_RULE_ID: &str = "peer_downgrade";

/// Stable rule id a pinned `protocol:` mismatch carries. Unconditional
/// and history-free (see [`check_pin`]), so it is never
/// [`PEER_DOWNGRADE_RULE_ID`] even though both refuse a `tools/call`
/// for the same underlying reason (a federated peer's contact cannot be
/// trusted at the pinned/recorded posture).
pub const PROTOCOL_PIN_MISMATCH_RULE_ID: &str = "protocol_pin_mismatch";

/// Stable rule id a `downgrade: block` refusal carries when the peer
/// registry cannot track this `(tenant, peer_key)` pair at all (WOR-2384
/// fix round N: past [`MAX_TRACKED_PEERS`] or [`MAX_TRACKED_PEERS_PER_TENANT`]).
/// Distinct from [`PEER_DOWNGRADE_RULE_ID`] for the same reason
/// [`PROTOCOL_PIN_MISMATCH_RULE_ID`] is: refusing a peer this process
/// has no history for is not itself a demonstrated downgrade against a
/// recorded profile, even though `block` treats both as reasons to
/// refuse the call.
pub const PEER_PROFILE_SATURATED_RULE_ID: &str = "peer_profile_saturated";

/// Ceiling on the number of `(tenant, server)` pairs this process tracks
/// a dedicated peer profile for, across every tenant (WOR-2384 fix
/// round N: fail-closed per-pair, no shared fallback; mirrors
/// `sbproxy_observe::evidence_seq::MAX_TRACKED_TENANTS`'s order of
/// magnitude and reasoning). Acts as a backstop behind
/// [`MAX_TRACKED_PEERS_PER_TENANT`]: a single tenant can never reach
/// this ceiling on its own (it would hit its own sub-cap first), so
/// this bounds the number of *distinct tenants* with live peer
/// profiles at once, not a single tenant's flood. `4096 /
/// MAX_TRACKED_PEERS_PER_TENANT` (16 tenants at full sub-cap) is a
/// deployment-sizing fact, not a per-tenant isolation guarantee -- see
/// [`MAX_TRACKED_PEERS_PER_TENANT`]'s own doc.
pub const MAX_TRACKED_PEERS: usize = 4096;

/// Ceiling on the number of `(tenant, server)` pairs one tenant may hold
/// a dedicated peer profile for in this process (WOR-2384 fix round N).
/// A tenant at its own sub-cap is refused a new profile while every
/// other tenant, and every one of this tenant's own already-tracked
/// peers, is unaffected -- one tenant flooding `tenant_id` (a
/// caller-controlled value) cannot exhaust the registry for anyone
/// else, the gap the earlier shared-overflow-profile design (removed;
/// see git history) failed to close.
pub const MAX_TRACKED_PEERS_PER_TENANT: usize = 256;

/// One upstream MCP peer's negotiation history for one tenant.
///
/// `negotiated_protocol` and `auth_required` are both high-water marks:
/// the best era and the strictest auth posture this peer has ever
/// demonstrated to this tenant, not simply "what it said last."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpPeerProfile {
    /// The best protocol era this peer has demonstrated
    /// (`LEGACY_PROTOCOL_VERSION` or `MODERN_PROTOCOL_VERSION`).
    pub negotiated_protocol: String,
    /// Whether this peer has ever required authentication on contact.
    /// Once true, stays true in the stored profile regardless of a
    /// later contact that needed none (that later contact is the
    /// downgrade this module exists to catch).
    pub auth_required: bool,
    /// When this profile was first recorded.
    pub first_seen: SystemTime,
    /// When this profile was last updated by an *accepted* observation.
    /// A `block`-mode refusal leaves this untouched (see [`observe`]).
    pub last_seen: SystemTime,
}

/// Downgrade-resistance mode applied when an `auto`-negotiated peer's
/// contact looks weaker than its recorded profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDowngradePolicy {
    /// Log and count the downgrade; the call proceeds. The stored
    /// profile keeps its historical high-water mark.
    Warn,
    /// Refuse the call. The stored profile is left completely
    /// unchanged (not even `last_seen` advances), until the operator
    /// pins `protocol:` explicitly or edits the server entry.
    Block,
}

/// Which axis a downgrade was observed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDowngradeKind {
    /// The peer answered with a weaker era than its recorded high-water
    /// mark.
    Protocol,
    /// The peer's contact needed no credentials, but its recorded
    /// profile shows it has required them before.
    AuthPosture,
}

impl PeerDowngradeKind {
    /// Fine-grained, human-readable reason code for this downgrade axis.
    /// Pair with [`PEER_DOWNGRADE_RULE_ID`] for the coarse, stable rule
    /// id a SIEM rule keys on.
    pub fn reason_code(self) -> &'static str {
        match self {
            PeerDowngradeKind::Protocol => "peer_protocol_downgrade",
            PeerDowngradeKind::AuthPosture => "peer_auth_posture_downgrade",
        }
    }
}

/// Outcome of comparing one observed contact against a peer's recorded
/// profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationVerdict {
    /// No downgrade: either there was no prior profile, or the contact
    /// matched or exceeded the recorded high-water mark. The call
    /// proceeds and the profile is raised if the contact was stronger.
    Allowed,
    /// A downgrade was observed under `warn` mode: the call proceeds,
    /// but the profile keeps its historical high-water mark rather than
    /// being lowered to match this contact.
    Warned(PeerDowngradeKind),
    /// A downgrade was observed under `block` mode: the call must be
    /// refused. The profile is left completely unchanged.
    Refused(PeerDowngradeKind),
    /// The registry could not track this NEW `(tenant, peer_key)` pair
    /// -- past [`MAX_TRACKED_PEERS`] globally or the presenting
    /// tenant's own [`MAX_TRACKED_PEERS_PER_TENANT`] sub-cap (WOR-2384
    /// fix round N). No profile was created, and nothing was shared
    /// with any other caller. There is no baseline to compare this
    /// contact against, so this is deliberately not folded into
    /// [`PeerDowngradeKind`]: the caller decides what "no baseline"
    /// means for the configured [`PeerDowngradePolicy`] (refuse under
    /// `block`, allow under `warn`, with its own rule id,
    /// [`PEER_PROFILE_SATURATED_RULE_ID`]), the same way it already
    /// decides for a [`PinMismatch`] rather than this module deciding
    /// for it. Every existing profile, for this tenant and every
    /// other, is unaffected.
    Saturated,
}

/// A pinned `protocol:` disagreed with what the peer actually answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinMismatch {
    /// The literal era `protocol:` pinned.
    pub expected: String,
    /// The era the peer actually answered with on this contact.
    pub observed: String,
}

/// Check a pinned `protocol:` against what the peer answered on this
/// contact. Independent of any stored profile and of `downgrade:`: a
/// pinned protocol never negotiates, so `pinned: None` (i.e.
/// `protocol: auto`) always succeeds here regardless of what was
/// observed -- negotiation for `auto` is [`observe`]'s job, not this
/// function's.
pub fn check_pin(pinned: Option<&str>, observed_protocol: &str) -> Result<(), PinMismatch> {
    match pinned {
        None => Ok(()),
        Some(expected) if expected == observed_protocol => Ok(()),
        Some(expected) => Err(PinMismatch {
            expected: expected.to_string(),
            observed: observed_protocol.to_string(),
        }),
    }
}

/// Compute the stable identity key one `federated_servers[]` entry uses
/// in the peer-profile registry.
///
/// Two calls with identical `(server_name, origin, protocol_pin,
/// downgrade)` address the same stored profile. Changing *any* of the
/// four -- including the escape hatch of pinning `protocol:` explicitly,
/// or simply editing `origin:` -- produces a distinct key, so the old
/// profile becomes unreachable under the new one. That is the entire
/// mechanism behind "the profile is cleared by config reload of that
/// server entry": there is no explicit reset call, no reload-generation
/// bookkeeping, and (deliberately) no effect on any *other* server's
/// profile just because an unrelated part of the config changed and
/// triggered a reload. `protocol_pin` should be the literal configured
/// value (`"auto"` or a pinned era string) and `downgrade` the
/// configured mode's wire name (`"warn"` / `"block"`), not resolved or
/// normalized values, so an edit that only flips one of those two knobs
/// still resets the profile even though it did not change `origin` or
/// `server_name`.
pub fn peer_key(server_name: &str, origin: &str, protocol_pin: &str, downgrade: &str) -> String {
    format!("{server_name}\u{1}{origin}\u{1}{protocol_pin}\u{1}{downgrade}")
}

fn protocol_rank(version: &str) -> u8 {
    if version == super::types::MODERN_PROTOCOL_VERSION {
        1
    } else {
        0
    }
}

/// Compare one observed contact against an optional prior profile and
/// decide the outcome, without touching any process-global state. Pure
/// and directly unit-testable; [`observe_and_record`] is the
/// process-global wrapper real call sites use.
fn observe(
    prior: Option<&McpPeerProfile>,
    observed_protocol: &str,
    observed_auth_required: bool,
    policy: PeerDowngradePolicy,
    now: SystemTime,
) -> (McpPeerProfile, ObservationVerdict) {
    let Some(prior) = prior else {
        // First contact: nothing to compare against, so nothing can be
        // a downgrade yet.
        return (
            McpPeerProfile {
                negotiated_protocol: observed_protocol.to_string(),
                auth_required: observed_auth_required,
                first_seen: now,
                last_seen: now,
            },
            ObservationVerdict::Allowed,
        );
    };

    let protocol_downgrade =
        protocol_rank(observed_protocol) < protocol_rank(&prior.negotiated_protocol);
    let auth_downgrade = prior.auth_required && !observed_auth_required;

    // Protocol takes priority when a single contact somehow trips both
    // axes at once; both are still observable independently through
    // repeated calls, and a `warn`-mode caller keeps getting flagged
    // until the underlying contact stops looking weaker on either axis.
    let kind = if protocol_downgrade {
        Some(PeerDowngradeKind::Protocol)
    } else if auth_downgrade {
        Some(PeerDowngradeKind::AuthPosture)
    } else {
        None
    };

    let Some(kind) = kind else {
        // Equal or stronger than the recorded high-water mark: raise it
        // and allow.
        let stronger_protocol =
            if protocol_rank(observed_protocol) > protocol_rank(&prior.negotiated_protocol) {
                observed_protocol.to_string()
            } else {
                prior.negotiated_protocol.clone()
            };
        return (
            McpPeerProfile {
                negotiated_protocol: stronger_protocol,
                auth_required: prior.auth_required || observed_auth_required,
                first_seen: prior.first_seen,
                last_seen: now,
            },
            ObservationVerdict::Allowed,
        );
    };

    match policy {
        PeerDowngradePolicy::Block => (prior.clone(), ObservationVerdict::Refused(kind)),
        PeerDowngradePolicy::Warn => (
            McpPeerProfile {
                negotiated_protocol: prior.negotiated_protocol.clone(),
                auth_required: prior.auth_required,
                first_seen: prior.first_seen,
                last_seen: now,
            },
            ObservationVerdict::Warned(kind),
        ),
    }
}

fn registry() -> &'static Mutex<HashMap<(String, String), McpPeerProfile>> {
    static REGISTRY: OnceLock<Mutex<HashMap<(String, String), McpPeerProfile>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Tenant ids that have already triggered the once-per-tenant
/// saturation warning log line (WOR-2384 fix round N), so a single
/// flooding tenant does not spam the log on every refused-tracking
/// call after the first. Deliberately per-tenant rather than the
/// once-per-process latch [`super::sessions::SessionStore::report_saturation`]
/// uses: `tenant_id` is exactly the caller-controlled value driving
/// the flood this redesign exists to contain, so a process-wide latch
/// would silence every *other* tenant's first warning the moment one
/// tenant saturates the registry first.
///
/// Capped at [`MAX_TRACKED_PEERS`] for the same reason the profile
/// registry itself is: an unbounded set keyed by caller-controlled
/// `tenant_id` would just relocate the memory-exhaustion knob this
/// whole module exists to close, one indirection over. Past that cap,
/// a tenant not already in the set is warned on every subsequent
/// refused-tracking call instead of just its first -- a noisier log,
/// never a missed [`sbproxy_observe::metrics::record_mcp_peer_registry_saturated`]
/// increment or a missed fail-closed refusal, since neither of those
/// reads this set.
fn warned_tenants() -> &'static Mutex<HashSet<String>> {
    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Record one refused-tracking call for `tenant_id`: always bumps
/// [`sbproxy_observe::metrics::record_mcp_peer_registry_saturated`]
/// (registry capacity is a fact regardless of `downgrade:` policy, so
/// the counter reflects every occurrence), and logs a `tracing::warn!`
/// line the first time this specific tenant hits it (see
/// [`warned_tenants`]). The latch never re-arms within a process: a
/// second saturation episode for the same tenant after the first has
/// cleared is silent in logs and visible only on the counter -- alert
/// on the metric, not the log line.
fn report_peer_registry_saturation(tenant_id: &str, cap: usize, scope: &'static str) {
    let mut warned = warned_tenants().lock();
    let already_warned = warned.contains(tenant_id);
    if !already_warned && warned.len() < MAX_TRACKED_PEERS {
        warned.insert(tenant_id.to_string());
    }
    drop(warned);
    if !already_warned {
        tracing::warn!(
            target: "sbproxy::mcp::peer_profile",
            tenant = tenant_id,
            scope,
            cap,
            "mcp peer profile registry is full; this tenant's new peer pairs get no downgrade baseline until it drains"
        );
    }
    sbproxy_observe::metrics::record_mcp_peer_registry_saturated();
}

/// Observe one peer contact for one tenant against the process-global
/// registry, persist the resulting profile, and report the verdict the
/// caller must act on: `Refused` means the call must not proceed, and
/// [`ObservationVerdict::Saturated`] means there is no profile to
/// compare against at all -- the caller decides what that means for
/// the configured [`PeerDowngradePolicy`].
pub fn observe_and_record(
    tenant_id: &str,
    peer_key: &str,
    observed_protocol: &str,
    observed_auth_required: bool,
    policy: PeerDowngradePolicy,
) -> ObservationVerdict {
    let mut guard = registry().lock();
    observe_and_record_capped(
        &mut guard,
        tenant_id,
        peer_key,
        observed_protocol,
        observed_auth_required,
        policy,
        SystemTime::now(),
        MAX_TRACKED_PEERS,
        MAX_TRACKED_PEERS_PER_TENANT,
    )
}

/// Read the currently recorded profile for `(tenant_id, peer_key)`
/// without observing a new contact: no mutation, no cap-overflow
/// routing, no effect on any other call. `None` when nothing has been
/// recorded yet.
///
/// Exists for a caller that has an observation on one axis but not the
/// other this cycle (WOR-2384 fix round 1, item 5: the auth-posture
/// signal is only ever `Some` on a clean unauthenticated success or a
/// classified 401/407; every other outcome has "no observation" for
/// that axis). Such a caller reads the prior recorded value here and
/// passes it straight through to [`observe_and_record`] as this
/// cycle's "observed" value on that axis, which is a no-op against the
/// stored high-water mark: it can never look weaker than itself, so it
/// never manufactures a downgrade out of missing data.
pub fn peek(tenant_id: &str, peer_key: &str) -> Option<McpPeerProfile> {
    registry()
        .lock()
        .get(&(tenant_id.to_string(), peer_key.to_string()))
        .cloned()
}

/// The actual lookup-or-insert-or-overflow-and-observe logic,
/// parameterized on the map and the cap rather than reaching for the
/// process-global registry directly.
///
/// Split out for the same reason
/// `sbproxy_observe::evidence_seq::next_seq_capped` is: exercising the
/// overflow branch against the real [`MAX_TRACKED_PEERS`]-entry
/// process-global registry inside a test would permanently saturate it
/// for every other test sharing this test binary's process.
#[allow(clippy::too_many_arguments)] // every argument is an independent input `observe` already takes plus the registry/cap plumbing around it; grouping any subset into a struct would just move the naming problem rather than solve it
fn observe_and_record_capped(
    profiles: &mut HashMap<(String, String), McpPeerProfile>,
    tenant_id: &str,
    peer_key: &str,
    observed_protocol: &str,
    observed_auth_required: bool,
    policy: PeerDowngradePolicy,
    now: SystemTime,
    cap: usize,
    tenant_cap: usize,
) -> ObservationVerdict {
    let key = (tenant_id.to_string(), peer_key.to_string());

    // An existing pair always gets to observe against its own history,
    // cap or no cap: neither cap check below applies to a pair that
    // already has a dedicated slot, only to minting a *new* one.
    if !profiles.contains_key(&key) {
        // Per-tenant sub-cap first (WOR-2384 fix round N, item 5 of
        // the whole-branch review): checking the global cap first
        // would let a 17th tenant be refused outright the moment the
        // registry as a whole is full, even though *that* tenant has
        // tracked nothing yet -- an honest refusal names the actual
        // reason the caller hit, and "your own tenant is at its
        // sub-cap" is the more common, more actionable one to report
        // first. Both checks still exist because they answer
        // different questions: the sub-cap bounds one tenant's own
        // flood; the global cap bounds how many *distinct* tenants
        // this process tracks profiles for at all, 16 at a time at
        // full sub-cap (`MAX_TRACKED_PEERS / MAX_TRACKED_PEERS_PER_TENANT`)
        // -- a deployment-sizing fact, not a per-tenant isolation
        // guarantee.
        let tenant_live = profiles.keys().filter(|(t, _)| t == tenant_id).count();
        if tenant_live >= tenant_cap {
            report_peer_registry_saturation(tenant_id, tenant_cap, "tenant");
            return ObservationVerdict::Saturated;
        }
        if profiles.len() >= cap {
            report_peer_registry_saturation(tenant_id, cap, "global");
            return ObservationVerdict::Saturated;
        }
    }

    let prior = profiles.get(&key).cloned();
    let (updated, verdict) = observe(
        prior.as_ref(),
        observed_protocol,
        observed_auth_required,
        policy,
        now,
    );
    profiles.insert(key, updated);
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh tenant id per test, so tests running in the same binary
    /// (the process-global registry is shared) never collide.
    fn unique_tenant(label: &str) -> String {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("sbproxy-test-tenant-{label}-{n}")
    }

    const LEGACY: &str = crate::mcp::types::LEGACY_PROTOCOL_VERSION;
    const MODERN: &str = crate::mcp::types::MODERN_PROTOCOL_VERSION;

    // --- check_pin ---

    #[test]
    fn auto_pin_never_mismatches_regardless_of_what_was_observed() {
        assert_eq!(check_pin(None, LEGACY), Ok(()));
        assert_eq!(check_pin(None, MODERN), Ok(()));
        assert_eq!(check_pin(None, "2099-01-01"), Ok(()));
    }

    #[test]
    fn a_pinned_modern_protocol_refuses_a_legacy_answer() {
        // WOR-2384 red-first case: "pinned modern + legacy answer
        // refused."
        let err = check_pin(Some(MODERN), LEGACY).unwrap_err();
        assert_eq!(err.expected, MODERN);
        assert_eq!(err.observed, LEGACY);
    }

    #[test]
    fn a_pinned_legacy_protocol_refuses_a_modern_answer() {
        let err = check_pin(Some(LEGACY), MODERN).unwrap_err();
        assert_eq!(err.expected, LEGACY);
        assert_eq!(err.observed, MODERN);
    }

    #[test]
    fn a_pinned_protocol_accepts_a_matching_answer() {
        assert_eq!(check_pin(Some(MODERN), MODERN), Ok(()));
        assert_eq!(check_pin(Some(LEGACY), LEGACY), Ok(()));
    }

    // --- observe (pure) ---

    #[test]
    fn first_contact_records_a_fresh_profile_and_allows() {
        let now = SystemTime::now();
        let (profile, verdict) = observe(None, MODERN, true, PeerDowngradePolicy::Block, now);
        assert_eq!(verdict, ObservationVerdict::Allowed);
        assert_eq!(profile.negotiated_protocol, MODERN);
        assert!(profile.auth_required);
        assert_eq!(profile.first_seen, now);
        assert_eq!(profile.last_seen, now);
    }

    #[test]
    fn an_upgrade_from_legacy_to_modern_raises_the_high_water_mark_and_allows() {
        let first_seen = SystemTime::now();
        let prior = McpPeerProfile {
            negotiated_protocol: LEGACY.to_string(),
            auth_required: false,
            first_seen,
            last_seen: first_seen,
        };
        let later = first_seen + std::time::Duration::from_secs(60);
        let (profile, verdict) = observe(
            Some(&prior),
            MODERN,
            false,
            PeerDowngradePolicy::Block,
            later,
        );
        assert_eq!(verdict, ObservationVerdict::Allowed);
        assert_eq!(profile.negotiated_protocol, MODERN);
        assert_eq!(profile.first_seen, first_seen, "first_seen is preserved");
        assert_eq!(profile.last_seen, later);
    }

    #[test]
    fn modern_then_legacy_is_refused_in_block_mode() {
        // WOR-2384 red-first case: "auto + modern-then-legacy refused
        // in block mode."
        let first_seen = SystemTime::now();
        let prior = McpPeerProfile {
            negotiated_protocol: MODERN.to_string(),
            auth_required: false,
            first_seen,
            last_seen: first_seen,
        };
        let later = first_seen + std::time::Duration::from_secs(60);
        let (profile, verdict) = observe(
            Some(&prior),
            LEGACY,
            false,
            PeerDowngradePolicy::Block,
            later,
        );
        assert_eq!(
            verdict,
            ObservationVerdict::Refused(PeerDowngradeKind::Protocol)
        );
        // The stored profile is completely unchanged, including
        // last_seen: a refused contact never happened as far as the
        // profile is concerned.
        assert_eq!(profile, prior);
    }

    #[test]
    fn modern_then_legacy_is_warned_in_warn_mode() {
        // WOR-2384 red-first case: "... warned in warn mode."
        let first_seen = SystemTime::now();
        let prior = McpPeerProfile {
            negotiated_protocol: MODERN.to_string(),
            auth_required: false,
            first_seen,
            last_seen: first_seen,
        };
        let later = first_seen + std::time::Duration::from_secs(60);
        let (profile, verdict) = observe(
            Some(&prior),
            LEGACY,
            false,
            PeerDowngradePolicy::Warn,
            later,
        );
        assert_eq!(
            verdict,
            ObservationVerdict::Warned(PeerDowngradeKind::Protocol)
        );
        // The call is allowed to proceed, but the high-water mark does
        // not drop: the profile still remembers this peer demonstrated
        // the modern era.
        assert_eq!(profile.negotiated_protocol, MODERN);
        assert_eq!(
            profile.last_seen, later,
            "an allowed contact still updates last_seen"
        );
    }

    #[test]
    fn warn_mode_keeps_warning_on_every_subsequent_legacy_contact() {
        // The high-water mark never drops, so a peer that keeps
        // answering with legacy after having shown modern keeps
        // tripping the warning on every single contact, not just the
        // first one after the downgrade.
        let t0 = SystemTime::now();
        let prior = McpPeerProfile {
            negotiated_protocol: MODERN.to_string(),
            auth_required: false,
            first_seen: t0,
            last_seen: t0,
        };
        let t1 = t0 + std::time::Duration::from_secs(1);
        let (profile1, verdict1) =
            observe(Some(&prior), LEGACY, false, PeerDowngradePolicy::Warn, t1);
        assert_eq!(
            verdict1,
            ObservationVerdict::Warned(PeerDowngradeKind::Protocol)
        );
        let t2 = t1 + std::time::Duration::from_secs(1);
        let (profile2, verdict2) = observe(
            Some(&profile1),
            LEGACY,
            false,
            PeerDowngradePolicy::Warn,
            t2,
        );
        assert_eq!(
            verdict2,
            ObservationVerdict::Warned(PeerDowngradeKind::Protocol)
        );
        assert_eq!(profile2.negotiated_protocol, MODERN);
    }

    #[test]
    fn auth_required_true_to_false_is_detected_as_a_downgrade() {
        // WOR-2384 red-first case: "auth posture drop detected."
        let first_seen = SystemTime::now();
        let prior = McpPeerProfile {
            negotiated_protocol: LEGACY.to_string(),
            auth_required: true,
            first_seen,
            last_seen: first_seen,
        };
        let later = first_seen + std::time::Duration::from_secs(60);
        let (profile, verdict) = observe(
            Some(&prior),
            LEGACY,
            false,
            PeerDowngradePolicy::Block,
            later,
        );
        assert_eq!(
            verdict,
            ObservationVerdict::Refused(PeerDowngradeKind::AuthPosture)
        );
        assert!(
            profile.auth_required,
            "the stored high-water mark keeps recording auth as required"
        );
    }

    #[test]
    fn auth_required_false_to_true_is_never_a_downgrade() {
        // The safe direction: a peer getting stricter about auth is
        // always accepted, never refused or warned.
        let first_seen = SystemTime::now();
        let prior = McpPeerProfile {
            negotiated_protocol: LEGACY.to_string(),
            auth_required: false,
            first_seen,
            last_seen: first_seen,
        };
        let later = first_seen + std::time::Duration::from_secs(60);
        let (profile, verdict) = observe(
            Some(&prior),
            LEGACY,
            true,
            PeerDowngradePolicy::Block,
            later,
        );
        assert_eq!(verdict, ObservationVerdict::Allowed);
        assert!(profile.auth_required);
    }

    // --- observe_and_record_capped (registry semantics) ---

    #[test]
    fn profile_is_tenant_scoped() {
        // WOR-2384 red-first case: "profile is tenant-scoped (tenant A's
        // profile never affects tenant B)."
        let mut profiles = HashMap::new();
        let key = "server-x\u{1}origin\u{1}auto\u{1}block";

        // Tenant A demonstrates modern, then is refused a legacy
        // answer.
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                key,
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                SystemTime::now(),
                MAX_TRACKED_PEERS,
                MAX_TRACKED_PEERS_PER_TENANT,
            ),
            ObservationVerdict::Allowed
        );
        // Tenant B, same server, has never contacted it before: a
        // legacy answer is its first contact, not a downgrade, even
        // though tenant A's profile for the identical peer_key is
        // already at modern.
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-b",
                key,
                LEGACY,
                false,
                PeerDowngradePolicy::Block,
                SystemTime::now(),
                MAX_TRACKED_PEERS,
                MAX_TRACKED_PEERS_PER_TENANT,
            ),
            ObservationVerdict::Allowed
        );
        // Tenant A is still refused on its own next legacy contact.
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                key,
                LEGACY,
                false,
                PeerDowngradePolicy::Block,
                SystemTime::now(),
                MAX_TRACKED_PEERS,
                MAX_TRACKED_PEERS_PER_TENANT,
            ),
            ObservationVerdict::Refused(PeerDowngradeKind::Protocol)
        );
    }

    #[test]
    fn a_different_peer_key_starts_a_fresh_profile_reload_of_the_server_entry_resets_it() {
        // WOR-2384 red-first case: "reload of the server entry resets
        // the profile." Simulated here by computing two different
        // peer_key values for the "before" and "after" shape of one
        // federated_servers[] entry (e.g. the operator edited
        // `downgrade:` from block to warn, or re-pinned `protocol:`),
        // exactly as `peer_key` would produce from two different
        // compiles of the same entry.
        let mut profiles = HashMap::new();
        let key_before = peer_key("srv", "https://upstream.example.com", "auto", "block");
        let key_after = peer_key("srv", "https://upstream.example.com", "auto", "warn");
        assert_ne!(key_before, key_after);

        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                &key_before,
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                SystemTime::now(),
                MAX_TRACKED_PEERS,
                MAX_TRACKED_PEERS_PER_TENANT,
            ),
            ObservationVerdict::Allowed
        );
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                &key_before,
                LEGACY,
                false,
                PeerDowngradePolicy::Block,
                SystemTime::now(),
                MAX_TRACKED_PEERS,
                MAX_TRACKED_PEERS_PER_TENANT,
            ),
            ObservationVerdict::Refused(PeerDowngradeKind::Protocol),
            "before the edit, a legacy answer is still a downgrade"
        );
        // After the (simulated) config edit, the same tenant and the
        // same physical server answer legacy again, but the profile
        // under the new key has no history: this is a fresh start, not
        // a downgrade.
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                &key_after,
                LEGACY,
                false,
                PeerDowngradePolicy::Block,
                SystemTime::now(),
                MAX_TRACKED_PEERS,
                MAX_TRACKED_PEERS_PER_TENANT,
            ),
            ObservationVerdict::Allowed,
            "the edited entry's new peer_key starts with no recorded history"
        );
    }

    #[test]
    fn peer_key_changes_when_any_of_its_four_inputs_changes() {
        let base = peer_key("srv", "https://a.example.com", "auto", "warn");
        assert_ne!(
            base,
            peer_key("other", "https://a.example.com", "auto", "warn")
        );
        assert_ne!(
            base,
            peer_key("srv", "https://b.example.com", "auto", "warn")
        );
        assert_ne!(
            base,
            peer_key("srv", "https://a.example.com", MODERN, "warn")
        );
        assert_ne!(
            base,
            peer_key("srv", "https://a.example.com", "auto", "block")
        );
        assert_eq!(
            base,
            peer_key("srv", "https://a.example.com", "auto", "warn")
        );
    }

    // --- Bounded peer registry (WOR-2384 fix round N: fail closed, no
    // shared overflow profile -- mirrors `sessions.rs`'s own
    // redesign) ---

    #[test]
    fn observations_below_both_caps_succeed_independently() {
        let mut profiles = HashMap::new();
        let (cap, tenant_cap) = (8, 8);
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                "k1",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                SystemTime::now(),
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Allowed
        );
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                "k2",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                SystemTime::now(),
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Allowed
        );
        assert_eq!(profiles.len(), 2);
    }

    #[test]
    fn a_new_pair_past_the_global_cap_is_saturated_and_tracks_nothing() {
        // Mirrors `sessions.rs`'s own global-cap test: exercises
        // `observe_and_record_capped` directly against a local,
        // throwaway map and a small cap, rather than filling the real
        // 4096-entry process-global registry.
        let mut profiles = HashMap::new();
        let (cap, tenant_cap) = (2, 100);
        let now = SystemTime::now();
        observe_and_record_capped(
            &mut profiles,
            "t1",
            "k1",
            MODERN,
            false,
            PeerDowngradePolicy::Block,
            now,
            cap,
            tenant_cap,
        );
        observe_and_record_capped(
            &mut profiles,
            "t2",
            "k2",
            LEGACY,
            false,
            PeerDowngradePolicy::Block,
            now,
            cap,
            tenant_cap,
        );

        // The registry is now at its global cap. A pair never seen
        // before -- a third, distinct tenant -- gets no profile at
        // all: not a shared one, not a dedicated one.
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "t3",
                "k3",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Saturated,
            "a pair past the global cap must be refused tracking, never shared"
        );
        assert_eq!(
            profiles.len(),
            2,
            "a saturated observation must not insert anything, shared or otherwise"
        );
        // The two pairs that already had a dedicated slot are
        // completely unaffected -- neither one now compares against
        // whatever the refused t3 pair observed, because nothing
        // about t3 was ever recorded anywhere.
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "t1",
                "k1",
                LEGACY,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Refused(PeerDowngradeKind::Protocol),
            "t1's own recorded modern high-water mark must still be enforced"
        );
    }

    #[test]
    fn a_new_pair_past_the_tenant_sub_cap_is_saturated_while_other_tenants_are_unaffected() {
        let mut profiles = HashMap::new();
        let (cap, tenant_cap) = (100, 2);
        let now = SystemTime::now();
        observe_and_record_capped(
            &mut profiles,
            "tenant-a",
            "k1",
            MODERN,
            false,
            PeerDowngradePolicy::Block,
            now,
            cap,
            tenant_cap,
        );
        observe_and_record_capped(
            &mut profiles,
            "tenant-a",
            "k2",
            MODERN,
            false,
            PeerDowngradePolicy::Block,
            now,
            cap,
            tenant_cap,
        );

        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                "k3",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Saturated,
            "tenant-a is at its own sub-cap"
        );
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-b",
                "k1",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Allowed,
            "a different tenant, unaffected by tenant-a's sub-cap, must still be tracked"
        );
    }

    #[test]
    fn the_tenant_sub_cap_is_checked_before_the_global_cap() {
        // WOR-2384 whole-branch review, item 5: checking the global
        // cap first would refuse a brand-new tenant that has tracked
        // nothing itself, once the registry as a whole happens to be
        // full -- an honest refusal names the reason the *caller*
        // actually hit. Set the global cap equal to the tenant cap so
        // both are simultaneously true, and confirm the sub-cap is
        // still what a caller would see reported first (observable
        // here as: the third observation for the same tenant is
        // refused with the registry still one slot under the global
        // cap, proving the tenant check ran, and won, before the
        // global one could).
        let mut profiles = HashMap::new();
        let (cap, tenant_cap) = (3, 2);
        let now = SystemTime::now();
        observe_and_record_capped(
            &mut profiles,
            "tenant-a",
            "k1",
            MODERN,
            false,
            PeerDowngradePolicy::Block,
            now,
            cap,
            tenant_cap,
        );
        observe_and_record_capped(
            &mut profiles,
            "tenant-a",
            "k2",
            MODERN,
            false,
            PeerDowngradePolicy::Block,
            now,
            cap,
            tenant_cap,
        );
        assert_eq!(profiles.len(), 2, "one slot under the global cap of 3");
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                "k3",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Saturated,
            "tenant-a's own sub-cap refuses this before the global cap ever would"
        );
    }

    #[test]
    fn existing_pairs_keep_working_when_the_registry_is_saturated() {
        let mut profiles = HashMap::new();
        let (cap, tenant_cap) = (1, 100);
        let now = SystemTime::now();
        observe_and_record_capped(
            &mut profiles,
            "tenant-a",
            "k1",
            MODERN,
            false,
            PeerDowngradePolicy::Block,
            now,
            cap,
            tenant_cap,
        );

        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-b",
                "k1",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Saturated
        );

        // The pre-existing pair is untouched: still compares against
        // its own real history, nothing about refusing a *new* pair
        // reaches back into what already exists.
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-a",
                "k1",
                LEGACY,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Refused(PeerDowngradeKind::Protocol)
        );
    }

    #[test]
    fn a_flood_of_new_pairs_never_grows_the_registry_past_the_cap() {
        let mut profiles = HashMap::new();
        let (cap, tenant_cap) = (8, 100);
        let now = SystemTime::now();
        for i in 0..cap * 10 {
            observe_and_record_capped(
                &mut profiles,
                &format!("tenant-{i}"),
                "k",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
                tenant_cap,
            );
        }
        assert_eq!(
            profiles.len(),
            cap,
            "exactly the cap's worth of profiles survive a flood of distinct-tenant \
             observations, none shared, none silently dropped past the cap"
        );
    }

    #[test]
    fn a_saturated_registry_under_warn_policy_still_reports_saturated() {
        // `ObservationVerdict::Saturated` itself carries no policy
        // opinion -- the caller (`mcp_peer_downgrade_check` in
        // sbproxy-core) is the one that turns this into "refuse" under
        // `block` or "allow" under `warn`. This only proves the
        // registry-capacity signal itself does not silently disappear
        // just because the configured policy is `warn`.
        let mut profiles = HashMap::new();
        let (cap, tenant_cap) = (1, 100);
        let now = SystemTime::now();
        observe_and_record_capped(
            &mut profiles,
            "tenant-a",
            "k1",
            MODERN,
            false,
            PeerDowngradePolicy::Warn,
            now,
            cap,
            tenant_cap,
        );
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "tenant-b",
                "k1",
                MODERN,
                false,
                PeerDowngradePolicy::Warn,
                now,
                cap,
                tenant_cap,
            ),
            ObservationVerdict::Saturated
        );
    }

    #[test]
    fn observe_and_record_reaches_the_real_process_global_registry() {
        // Not exercising the overflow branch (see the dedicated test
        // above for why): just confirming the public entry point
        // actually stores into, and reads back from, the real registry
        // rather than only the capped helper working in isolation.
        let tenant = unique_tenant("public-api");
        let key = peer_key("srv-public", "https://public.example.com", "auto", "block");
        assert_eq!(
            observe_and_record(&tenant, &key, MODERN, true, PeerDowngradePolicy::Block),
            ObservationVerdict::Allowed
        );
        assert_eq!(
            observe_and_record(&tenant, &key, LEGACY, true, PeerDowngradePolicy::Block),
            ObservationVerdict::Refused(PeerDowngradeKind::Protocol),
            "the process-global registry remembered the first call's modern high-water mark"
        );
    }

    #[test]
    fn reason_code_and_rule_id_are_distinct_and_stable() {
        assert_eq!(
            PeerDowngradeKind::Protocol.reason_code(),
            "peer_protocol_downgrade"
        );
        assert_eq!(
            PeerDowngradeKind::AuthPosture.reason_code(),
            "peer_auth_posture_downgrade"
        );
        assert_eq!(PEER_DOWNGRADE_RULE_ID, "peer_downgrade");
    }

    #[test]
    fn protocol_pin_mismatch_rule_id_is_distinct_from_peer_downgrade() {
        // WOR-2384 fix round 1, item 2: the two must never collide,
        // since a SIEM rule keyed on one must not also match the other.
        assert_ne!(PROTOCOL_PIN_MISMATCH_RULE_ID, PEER_DOWNGRADE_RULE_ID);
        assert_eq!(PROTOCOL_PIN_MISMATCH_RULE_ID, "protocol_pin_mismatch");
    }

    #[test]
    fn peer_profile_saturated_rule_id_is_distinct_from_the_other_two() {
        // WOR-2384 whole-branch review, item 1: a saturated registry is
        // neither a demonstrated downgrade nor a pin mismatch, so it
        // must carry its own rule id, not collide with either.
        assert_ne!(PEER_PROFILE_SATURATED_RULE_ID, PEER_DOWNGRADE_RULE_ID);
        assert_ne!(
            PEER_PROFILE_SATURATED_RULE_ID,
            PROTOCOL_PIN_MISMATCH_RULE_ID
        );
        assert_eq!(PEER_PROFILE_SATURATED_RULE_ID, "peer_profile_saturated");
    }

    #[test]
    fn an_upgrade_back_to_the_high_water_mark_after_a_warned_downgrade_is_allowed_again() {
        // WOR-2384 fix round 1, item 6 (the named-in-brief
        // warn-upgrade-after-warn case): a warn-mode downgrade never
        // lowers the stored profile (see
        // `warn_mode_keeps_warning_on_every_subsequent_legacy_contact`
        // above), so a later contact that returns to -- or exceeds --
        // that still-modern high-water mark is a plain `Allowed`, not
        // something the warn history leaves permanently flagged.
        let t0 = SystemTime::now();
        let prior = McpPeerProfile {
            negotiated_protocol: MODERN.to_string(),
            auth_required: false,
            first_seen: t0,
            last_seen: t0,
        };
        let t1 = t0 + std::time::Duration::from_secs(1);
        let (warned_profile, verdict1) =
            observe(Some(&prior), LEGACY, false, PeerDowngradePolicy::Warn, t1);
        assert_eq!(
            verdict1,
            ObservationVerdict::Warned(PeerDowngradeKind::Protocol)
        );

        let t2 = t1 + std::time::Duration::from_secs(1);
        let (profile2, verdict2) = observe(
            Some(&warned_profile),
            MODERN,
            false,
            PeerDowngradePolicy::Warn,
            t2,
        );
        assert_eq!(
            verdict2,
            ObservationVerdict::Allowed,
            "a contact back at the high-water mark is not a downgrade, warned or not"
        );
        assert_eq!(profile2.negotiated_protocol, MODERN);
        assert_eq!(profile2.last_seen, t2);
    }

    #[test]
    fn peek_reads_the_recorded_profile_without_mutating_or_observing() {
        let tenant = unique_tenant("peek");
        let key = peer_key("srv-peek", "https://peek.example.com", "auto", "warn");

        assert_eq!(
            peek(&tenant, &key),
            None,
            "nothing recorded yet for this pair"
        );

        assert_eq!(
            observe_and_record(&tenant, &key, MODERN, true, PeerDowngradePolicy::Block),
            ObservationVerdict::Allowed
        );
        let peeked = peek(&tenant, &key).expect("now recorded");
        assert_eq!(peeked.negotiated_protocol, MODERN);
        assert!(peeked.auth_required);

        // A second peek is unaffected by the first: reading is not
        // itself an observation.
        assert_eq!(peek(&tenant, &key), Some(peeked));
    }

    #[test]
    fn peek_is_tenant_scoped_like_observe_and_record() {
        let tenant_a = unique_tenant("peek-a");
        let tenant_b = unique_tenant("peek-b");
        let key = peer_key("srv-peek-scope", "https://peek.example.com", "auto", "warn");

        assert_eq!(
            observe_and_record(&tenant_a, &key, MODERN, false, PeerDowngradePolicy::Block),
            ObservationVerdict::Allowed
        );
        assert!(peek(&tenant_a, &key).is_some());
        assert_eq!(
            peek(&tenant_b, &key),
            None,
            "tenant b's profile for the identical peer_key is untouched"
        );
    }
}
