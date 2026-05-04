//! Per-agent metric labels (Wave 1 / G1.6).
//!
//! Defines [`AgentLabels`], the typed bundle that carries `agent_id`,
//! `agent_class`, `agent_vendor`, `payment_rail`, and `content_shape`
//! into the metric helpers. The set is fixed by
//! `docs/adr-metric-cardinality.md` (A1.1) and the value space comes
//! from `docs/adr-agent-class-taxonomy.md` (G1.1).
//!
//! Three sentinels stand in when the resolver has no concrete entry:
//!
//! - `human` for non-agent traffic.
//! - `anonymous` for an authenticated-but-unidentified Web Bot Auth
//!   request (`draft-rescorla-anonymous-webbotauth-00`).
//! - `unknown` for traffic that looks automated but does not match the
//!   catalog.
//!
//! Empty agent context (e.g. legacy call sites that have not yet been
//! plumbed with the resolver) maps to the empty-string sentinel
//! `UNSET`. Empty-string is the correct choice for "absent" rather
//! than `unknown`, because `unknown` is a positive identity claim
//! ("this looked like a bot but I could not place it") and we should
//! not attribute it to traffic the resolver never saw.

/// Sentinel used when the request has not been classified yet (legacy
/// metric-update sites, human traffic that has not been explicitly
/// marked, etc.). Rendered as the empty string so dashboards can tell
/// "no agent context attached" apart from a positive `human` /
/// `unknown` / `anonymous` decision.
pub const UNSET: &str = "";

/// Reserved `agent_id` / `agent_class` / `agent_vendor` value for
/// non-agent (human) traffic. Stable across releases.
pub const HUMAN: &str = "human";

/// Reserved value for traffic that authenticated via anonymous Web Bot
/// Auth without a resolved keyid. Stable across releases.
pub const ANONYMOUS: &str = "anonymous";

/// Reserved value for traffic that looks automated but does not match
/// any catalog entry. Stable across releases.
pub const UNKNOWN: &str = "unknown";

/// Per-request label bundle attached to per-agent metric updates.
///
/// All fields are `&str` so callers can pass borrowed sentinels or
/// catalog-derived strings without allocation. Values are not
/// validated here; the metric helpers run them through the cardinality
/// budget before applying them to a Prometheus collector.
#[derive(Debug, Clone, Copy)]
pub struct AgentLabels<'a> {
    /// Stable `agent_id` from the agent-class catalog, or one of the
    /// reserved sentinels (`human`, `anonymous`, `unknown`). Empty
    /// string means "no resolution attempted".
    pub agent_id: &'a str,
    /// `agent_class` from the catalog, or matching sentinel.
    pub agent_class: &'a str,
    /// `agent_vendor` from the catalog, or matching sentinel.
    pub agent_vendor: &'a str,
    /// Closed enum: `none`, `x402`, `mpp_card`, `mpp_stablecoin`,
    /// `stripe_fiat`, `lightning`. Empty string when no payment rail
    /// applies.
    pub payment_rail: &'a str,
    /// Closed enum: `html`, `markdown`, `json`, `pdf`, `other`. Empty
    /// string when the response shape has not been resolved (e.g.
    /// pre-response metric path).
    pub content_shape: &'a str,
}

impl<'a> AgentLabels<'a> {
    /// All-empty placeholder used by call sites that have no agent
    /// context yet. Equivalent to `Default::default()` but `const`
    /// so it can sit in a static.
    pub const fn unset() -> Self {
        Self {
            agent_id: UNSET,
            agent_class: UNSET,
            agent_vendor: UNSET,
            payment_rail: UNSET,
            content_shape: UNSET,
        }
    }

    /// Build a label bundle for a non-agent request. All identity
    /// fields stamp `human`; the rail/shape stay empty unless the
    /// caller overrides them.
    pub const fn human() -> Self {
        Self {
            agent_id: HUMAN,
            agent_class: HUMAN,
            agent_vendor: HUMAN,
            payment_rail: UNSET,
            content_shape: UNSET,
        }
    }

    /// Build a label bundle for an anonymous Web Bot Auth request
    /// (draft-rescorla). All identity fields stamp `anonymous`.
    pub const fn anonymous() -> Self {
        Self {
            agent_id: ANONYMOUS,
            agent_class: ANONYMOUS,
            agent_vendor: ANONYMOUS,
            payment_rail: UNSET,
            content_shape: UNSET,
        }
    }

    /// Build a label bundle for traffic that looks automated but does
    /// not match the catalog.
    pub const fn unknown() -> Self {
        Self {
            agent_id: UNKNOWN,
            agent_class: UNKNOWN,
            agent_vendor: UNKNOWN,
            payment_rail: UNSET,
            content_shape: UNSET,
        }
    }
}

impl<'a> Default for AgentLabels<'a> {
    fn default() -> Self {
        Self::unset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_is_all_empty() {
        let l = AgentLabels::unset();
        assert_eq!(l.agent_id, "");
        assert_eq!(l.agent_class, "");
        assert_eq!(l.agent_vendor, "");
        assert_eq!(l.payment_rail, "");
        assert_eq!(l.content_shape, "");
    }

    #[test]
    fn human_marks_identity_fields() {
        let l = AgentLabels::human();
        assert_eq!(l.agent_id, "human");
        assert_eq!(l.agent_class, "human");
        assert_eq!(l.agent_vendor, "human");
        // Rail / shape stay empty unless explicitly set.
        assert_eq!(l.payment_rail, "");
        assert_eq!(l.content_shape, "");
    }

    #[test]
    fn anonymous_and_unknown_distinct_values() {
        let a = AgentLabels::anonymous();
        let u = AgentLabels::unknown();
        assert_ne!(a.agent_id, u.agent_id);
        assert_eq!(a.agent_id, "anonymous");
        assert_eq!(u.agent_id, "unknown");
    }

    #[test]
    fn default_is_unset() {
        let d: AgentLabels = Default::default();
        let u = AgentLabels::unset();
        assert_eq!(d.agent_id, u.agent_id);
        assert_eq!(d.payment_rail, u.payment_rail);
    }
}
