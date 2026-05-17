//! Trust-tier combiner (WOR-504).
//!
//! The detection and verification surface has grown to where a single
//! request can pick up evidence from several independent sources: JA4
//! TLS signals, named-agent rule packs (the `sbproxy-agent-detect`
//! `AgentDetection` type), Web Bot Auth signature verification, KYA,
//! TAP tags, CAP tokens, and the ACP / AP2 / x402 mandate verifiers.
//! Each component currently exposes its result on the request context
//! as its own typed field. That works for the components themselves
//! but pushes a fan-out decision onto every downstream policy: a rate
//! limiter that wants to be looser for signed agents has to inspect
//! WBA + KYA + TAP independently; an audit tag that wants to record
//! "this was a trusted, named call" has to replicate the same logic.
//!
//! This module collapses that fan-out into a single [`TrustTier`]
//! enum: downstream code asks one question instead of N. The combiner
//! is deliberately conservative. The mapping is:
//!
//! * [`TrustTier::Suspicious`] when any verifier or rule actively
//!   denied the request (signature mismatch, named-agent rule that
//!   matched but in a deny stance, low `AgentDetection` score with a
//!   deny signal). This is the "operator should look at this" tier.
//! * [`TrustTier::Strong`] when any verifier confirmed a cryptographic
//!   signature: WBA, KYA, TAP, or a similar signed-mandate verifier.
//! * [`TrustTier::Named`] when an unsigned rule pack matched a named
//!   agent and the scorer agreed (`agent_score >= 50`). This tier
//!   covers "we recognise this user-agent / fingerprint pattern but
//!   nothing here is cryptographically bound".
//! * [`TrustTier::Anonymous`] as the catch-all default: no signature,
//!   no rule-pack hit (or a hit with too low a confidence score), no
//!   active deny signal.
//!
//! ## Ordering
//!
//! Suspicious wins over Strong wins over Named wins over Anonymous.
//! The deny check is intentionally first so that a request with both a
//! valid signature **and** a deny signal (a misconfigured client whose
//! signature verifies but whose CAP token is expired) still surfaces
//! as `Suspicious`: the operator wants to see the deny, not the
//! contradicting valid signature.
//!
//! ## Out of scope here
//!
//! Wiring `TrustTier` into `sbproxy_core::server::RequestContext` and
//! exposing it on the CEL / Lua / JS / WASM scripting surfaces lives
//! in follow-up tickets. This module ships the type and the function;
//! the integration touches a wide enough call-site surface that it
//! deserves its own review.

use serde::{Deserialize, Serialize};

/// Aggregated evidence from every detection or verification source
/// that runs on a request. Each field is optional in the sense that
/// callers populate only what they have; missing evidence reads as
/// neutral (`false` / `None` / `0`).
///
/// The struct is deliberately small and `Copy`-friendly so the
/// combiner stays on the hot path without forcing allocations. The
/// `named_agent` field carries the rule-pack identifier (e.g.
/// `"claude-code"`) as a borrowed string slice so callers can pass a
/// reference into an existing `sbproxy-agent-detect` `AgentDetection`
/// without cloning.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrustSignals<'a> {
    /// At least one cryptographic verifier confirmed a signature on
    /// this request: Web Bot Auth, KYA, TAP, or a similar
    /// signed-mandate verifier (ACP / AP2 / x402).
    pub signed: bool,
    /// Named-agent rule pack matched. The value is the `agent_id`
    /// populated by the `sbproxy-agent-detect` rule-pack evaluator.
    /// `None` when no rule matched.
    pub named_agent: Option<&'a str>,
    /// Scorer-reported probability the traffic is agent-origin, on
    /// the 0-100 scale used by `sbproxy-agent-detect::AgentDetection`.
    pub agent_score: u8,
    /// Any active deny signal: a verifier returned a denial, a rule
    /// pack matched in a deny stance, or the scorer reported a
    /// suspicious-low confidence on traffic that nonetheless wants
    /// elevated trust. Wins over every positive signal.
    pub deny_observed: bool,
}

impl<'a> TrustSignals<'a> {
    /// Build an empty signal bag. Equivalent to `Default::default()`
    /// but reads more clearly at call sites that explicitly want the
    /// neutral starting point.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Score threshold above which a named-agent rule-pack hit promotes to
/// [`TrustTier::Named`]. Below this the request stays at
/// [`TrustTier::Anonymous`]: a rule that matched only by user-agent
/// alone, without any reinforcing TLS or HTTP signal, is not enough.
///
/// The threshold lives as a constant here (not a tunable) because the
/// downstream contract treats `Named` as "the proxy is confident
/// enough to attach a label to this traffic". Operators who need a
/// lower bar should look at the rule-pack scoring instead of moving
/// the combiner threshold.
pub const NAMED_AGENT_SCORE_THRESHOLD: u8 = 50;

/// Trust tier the combiner emits for downstream policy consumption.
///
/// The serde representation uses kebab-case so the same string is
/// usable for log fields, metric labels, and YAML round-trips without
/// a separate mapping table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// At least one verifier or rule actively denied this request.
    /// Operators treat this as the "needs attention" tier.
    Suspicious,
    /// Cryptographic signature verified. Web Bot Auth, KYA, TAP, or a
    /// signed-mandate verifier confirmed identity.
    Strong,
    /// Named-agent rule pack matched with a sufficient confidence
    /// score. Identity is recognised but not cryptographically bound.
    Named,
    /// Default: no signature, no rule match, no deny signal. The
    /// catch-all bucket for unrecognised traffic.
    Anonymous,
}

impl TrustTier {
    /// Stable string identifier for metric labels, log fields, and
    /// scripting exposure. Matches the kebab-case serde discriminant
    /// so the same literal is usable across the audit pipeline.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suspicious => "suspicious",
            Self::Strong => "strong",
            Self::Named => "named",
            Self::Anonymous => "anonymous",
        }
    }
}

/// Collapse the per-source evidence in `signals` into a single
/// [`TrustTier`].
///
/// See the module docstring for the full rule set. The function is
/// pure: no allocation, no locks, no I/O. Safe to call on every
/// request from the hot path.
pub fn compute_trust_tier(signals: &TrustSignals<'_>) -> TrustTier {
    // Deny wins. A request with a valid signature and a deny signal
    // is still suspicious: the operator wants to see the deny.
    if signals.deny_observed {
        return TrustTier::Suspicious;
    }

    // Cryptographic signature beats every positive signal below.
    if signals.signed {
        return TrustTier::Strong;
    }

    // Named-agent rule pack matched and the scorer agreed.
    if signals.named_agent.is_some() && signals.agent_score >= NAMED_AGENT_SCORE_THRESHOLD {
        return TrustTier::Named;
    }

    TrustTier::Anonymous
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Single-branch coverage --------------------------------------------

    #[test]
    fn anonymous_when_no_signals() {
        let signals = TrustSignals::new();
        assert_eq!(compute_trust_tier(&signals), TrustTier::Anonymous);
    }

    #[test]
    fn anonymous_when_named_below_threshold() {
        let signals = TrustSignals {
            named_agent: Some("claude-code"),
            agent_score: NAMED_AGENT_SCORE_THRESHOLD - 1,
            ..TrustSignals::new()
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Anonymous);
    }

    #[test]
    fn anonymous_when_named_id_missing_even_if_score_high() {
        // Score alone without a rule-pack match must not promote to
        // Named. The combiner requires both, otherwise generic
        // "looks agenty" heuristics would mislabel anonymous traffic.
        let signals = TrustSignals {
            named_agent: None,
            agent_score: 90,
            ..TrustSignals::new()
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Anonymous);
    }

    #[test]
    fn named_when_rule_pack_hits_and_score_at_threshold() {
        let signals = TrustSignals {
            named_agent: Some("claude-code"),
            agent_score: NAMED_AGENT_SCORE_THRESHOLD,
            ..TrustSignals::new()
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Named);
    }

    #[test]
    fn named_when_rule_pack_hits_and_score_well_above_threshold() {
        let signals = TrustSignals {
            named_agent: Some("cursor"),
            agent_score: 95,
            ..TrustSignals::new()
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Named);
    }

    #[test]
    fn strong_when_signed() {
        let signals = TrustSignals {
            signed: true,
            ..TrustSignals::new()
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Strong);
    }

    #[test]
    fn suspicious_when_deny_observed() {
        let signals = TrustSignals {
            deny_observed: true,
            ..TrustSignals::new()
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Suspicious);
    }

    // --- Tie-break ordering -----------------------------------------------

    #[test]
    fn suspicious_wins_over_signed() {
        // A request whose WBA signature validates but whose CAP token
        // is expired (a deny from a separate verifier) must surface
        // as Suspicious so the operator sees the contradiction.
        let signals = TrustSignals {
            signed: true,
            deny_observed: true,
            ..TrustSignals::new()
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Suspicious);
    }

    #[test]
    fn suspicious_wins_over_named() {
        let signals = TrustSignals {
            named_agent: Some("claude-code"),
            agent_score: 80,
            deny_observed: true,
            ..TrustSignals::new()
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Suspicious);
    }

    #[test]
    fn suspicious_wins_over_all_positive_signals() {
        let signals = TrustSignals {
            signed: true,
            named_agent: Some("cursor"),
            agent_score: 100,
            deny_observed: true,
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Suspicious);
    }

    #[test]
    fn signed_wins_over_named() {
        // A signed request that also matches a named-agent rule pack
        // is Strong, not Named. The cryptographic binding is the
        // stronger evidence and downstream policy should branch on it.
        let signals = TrustSignals {
            signed: true,
            named_agent: Some("claude-code"),
            agent_score: 80,
            ..TrustSignals::new()
        };
        assert_eq!(compute_trust_tier(&signals), TrustTier::Strong);
    }

    #[test]
    fn named_wins_over_anonymous() {
        // Sanity check that a rule-pack hit at the threshold beats
        // the empty-signal default.
        let with_named = TrustSignals {
            named_agent: Some("claude-code"),
            agent_score: NAMED_AGENT_SCORE_THRESHOLD,
            ..TrustSignals::new()
        };
        let empty = TrustSignals::new();
        assert_ne!(compute_trust_tier(&with_named), compute_trust_tier(&empty));
        assert_eq!(compute_trust_tier(&with_named), TrustTier::Named);
        assert_eq!(compute_trust_tier(&empty), TrustTier::Anonymous);
    }

    // --- Stable label surface ---------------------------------------------

    #[test]
    fn as_str_is_kebab_case() {
        assert_eq!(TrustTier::Suspicious.as_str(), "suspicious");
        assert_eq!(TrustTier::Strong.as_str(), "strong");
        assert_eq!(TrustTier::Named.as_str(), "named");
        assert_eq!(TrustTier::Anonymous.as_str(), "anonymous");
    }

    #[test]
    fn as_str_matches_serde_discriminant() {
        // Audit + metrics + YAML round-trips all assume the label
        // string equals the serde discriminant. If this ever drifts,
        // those consumers silently misclassify, so pin it.
        for tier in [
            TrustTier::Suspicious,
            TrustTier::Strong,
            TrustTier::Named,
            TrustTier::Anonymous,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            // serde_json wraps the value in quotes.
            assert_eq!(json, format!("\"{}\"", tier.as_str()));
        }
    }

    // --- Serde round-trip --------------------------------------------------

    #[test]
    fn serde_roundtrip_kebab_case() {
        for tier in [
            TrustTier::Suspicious,
            TrustTier::Strong,
            TrustTier::Named,
            TrustTier::Anonymous,
        ] {
            let s = serde_json::to_string(&tier).expect("serialize");
            let back: TrustTier = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(tier, back);
        }
    }

    #[test]
    fn serde_deserialize_rejects_unknown_label() {
        // Forward-compat guard: an unknown tier label is rejected
        // rather than silently mapping to a default. Downstream
        // consumers want to fail loudly if the wire format drifts.
        let parsed: Result<TrustTier, _> = serde_json::from_str("\"trusted\"");
        assert!(parsed.is_err(), "unknown label must not deserialize");
    }

    #[test]
    fn serde_deserialize_rejects_pascal_case() {
        // The discriminant is kebab-case. Reject Pascal-case so
        // downstream consumers cannot accidentally rely on a second
        // valid spelling and lock the schema into supporting both.
        let parsed: Result<TrustTier, _> = serde_json::from_str("\"Suspicious\"");
        assert!(parsed.is_err(), "pascal-case label must not deserialize");
    }

    // --- Signal helpers ----------------------------------------------------

    #[test]
    fn trust_signals_default_is_neutral() {
        let signals = TrustSignals::default();
        assert!(!signals.signed);
        assert!(signals.named_agent.is_none());
        assert_eq!(signals.agent_score, 0);
        assert!(!signals.deny_observed);
        assert_eq!(compute_trust_tier(&signals), TrustTier::Anonymous);
    }
}
