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
//! pair in a process-global, [`MAX_TRACKED_PEERS`]-bounded map, the same
//! cap hygiene `sbproxy_observe::evidence_seq` applies to its per-tenant
//! sequence counters: `tenant_id` is caller-controlled, so an unbounded
//! map keyed by it is a memory-exhaustion knob. A pair past the cap
//! shares one overflow profile with every other overflowing pair rather
//! than being refused a slot outright -- the same reasoning as
//! `evidence_seq`'s overflow bucket, except here erring toward *more*
//! false-positive downgrade warnings under extreme cardinality pressure
//! is the safe direction for a security control, where erring toward
//! *silently* skipping the check would not be.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

use parking_lot::Mutex;

/// Stable rule id every peer-downgrade refusal or warning carries on the
/// `mcp_governance_decision` evidence event and the `SecurityAuditEntry`
/// it accompanies, regardless of which axis (protocol or auth posture)
/// triggered it. A SIEM rule keys on this one string; [`PeerDowngradeKind::reason_code`]
/// carries the finer-grained detail for a human reading the record.
pub const PEER_DOWNGRADE_RULE_ID: &str = "peer_downgrade";

/// Ceiling on the number of `(tenant, server)` pairs this process tracks
/// a dedicated peer profile for. Mirrors
/// `sbproxy_observe::evidence_seq::MAX_TRACKED_TENANTS`'s order of
/// magnitude and reasoning.
pub const MAX_TRACKED_PEERS: usize = 4096;

/// The bucket every `(tenant, peer_key)` pair past [`MAX_TRACKED_PEERS`]
/// shares. A NUL prefix keeps both halves out of the space of real
/// tenant ids and peer keys, so neither can collide with it by chance.
const OVERFLOW_TENANT: &str = "\u{0}sbproxy-mcp-peer-overflow-tenant";
const OVERFLOW_PEER: &str = "\u{0}sbproxy-mcp-peer-overflow-peer";

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

/// Latches true the first time the registry routes a new `(tenant,
/// peer_key)` pair to the overflow bucket, so the saturation warning
/// logs once per process rather than once per overflowing call.
fn registry_saturated() -> &'static AtomicBool {
    static SATURATED: OnceLock<AtomicBool> = OnceLock::new();
    SATURATED.get_or_init(|| AtomicBool::new(false))
}

/// Observe one peer contact for one tenant against the process-global
/// registry, persist the resulting profile, and report the verdict the
/// caller must act on: `Refused` means the call must not proceed.
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
    )
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
) -> ObservationVerdict {
    let key = (tenant_id.to_string(), peer_key.to_string());
    let effective_key = if profiles.contains_key(&key) || profiles.len() < cap {
        key
    } else {
        if !registry_saturated().swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "sbproxy::mcp::peer_profile",
                max_peers = cap,
                "mcp peer profile registry is full; new tenant/server pairs share a fallback profile"
            );
        }
        (OVERFLOW_TENANT.to_string(), OVERFLOW_PEER.to_string())
    };

    let prior = profiles.get(&effective_key).cloned();
    let (updated, verdict) = observe(
        prior.as_ref(),
        observed_protocol,
        observed_auth_required,
        policy,
        now,
    );
    profiles.insert(effective_key, updated);
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh tenant id per test, so tests running in the same binary
    /// (the process-global registry is shared) never collide.
    fn unique_tenant(label: &str) -> String {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
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

    #[test]
    fn pairs_past_the_cap_share_the_overflow_profile_instead_of_losing_downgrade_detection() {
        // Mirrors evidence_seq's overflow test: exercises
        // `observe_and_record_capped` directly against a local,
        // throwaway map and a cap of 2, rather than filling the real
        // 4096-entry process-global registry.
        let mut profiles = HashMap::new();
        let cap = 2;
        let now = SystemTime::now();

        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "t1",
                "k1",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
            ),
            ObservationVerdict::Allowed
        );
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "t2",
                "k2",
                LEGACY,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
            ),
            ObservationVerdict::Allowed
        );
        // The map is now at the cap. A pair never seen before shares
        // the overflow bucket, which was seeded modern by nobody yet,
        // so this first overflow contact still just records.
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
            ),
            ObservationVerdict::Allowed
        );
        // A second, distinct overflow pair now collides with the first
        // overflow pair's recorded modern high-water mark: a legacy
        // contact from an entirely different (tenant, server) is
        // flagged, because cardinality pressure forced them to share
        // one bucket. This is the documented, safe-direction tradeoff:
        // false positives under saturation, never a silent bypass.
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "t4",
                "k4",
                LEGACY,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
            ),
            ObservationVerdict::Refused(PeerDowngradeKind::Protocol)
        );
        // A pair that already had a dedicated slot before the cap was
        // hit is unaffected.
        assert_eq!(
            observe_and_record_capped(
                &mut profiles,
                "t2",
                "k2",
                MODERN,
                false,
                PeerDowngradePolicy::Block,
                now,
                cap,
            ),
            ObservationVerdict::Allowed
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
}
