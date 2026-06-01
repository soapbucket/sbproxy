//! WOR-812: typed A2A AgentCard model + capability / modality
//! negotiation helpers.
//!
//! The [`crate::action::a2a::A2aAction`] surface ships a raw
//! `agent_card: Option<serde_json::Value>` so an operator can paste an
//! agent's published card verbatim. That works for proxying but does
//! not let the gateway answer "is this caller compatible with this
//! agent?" before the upstream call. This module ships the typed
//! version: an [`AgentCard`] mirror of the A2A 0.x protocol fields the
//! gateway actually needs, plus
//! [`Negotiation`](struct.Negotiation.html)-shaped helpers that pair a
//! caller's `Accept` / `Content-Type` against the agent's advertised
//! `defaultInputModes` and `defaultOutputModes`.
//!
//! # What the gateway uses it for
//!
//! * **Capability discovery**. The action can be configured to serve
//!   the card itself at `/.well-known/agent.json` so an A2A client can
//!   probe SBproxy and get back the agent it would route to. The
//!   serving handler is the natural place to advertise federated
//!   capabilities; that wire lands as a follow-up.
//! * **Modality negotiation**. Before forwarding the request the
//!   gateway runs [`AgentCard::negotiate_input`] over the caller's
//!   `Content-Type` and [`AgentCard::negotiate_output`] over the
//!   caller's `Accept`. A mismatch returns 406 with a typed error so
//!   the caller knows which dimension failed.
//! * **Capability gating**. CEL policies can branch on
//!   `card.supports_streaming` / `card.supports_push_notifications`
//!   once the negotiation result is on the request context.
//!
//! The card model is intentionally permissive on the deserialisation
//! side: unknown fields are preserved on `AgentCard::extensions` so
//! the operator's full card round-trips through the proxy without
//! loss. Only the fields SBproxy actually reads are typed; everything
//! else stays as `serde_json::Value`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A2A AgentCard, typed for the fields SBproxy reads. Mirrors the
/// fields the published agentgateway 0.x card uses; the rest of the
/// card body round-trips through [`AgentCard::extensions`] so the
/// surface SBproxy emits matches what the operator authored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentCard {
    /// Operator-facing agent name.
    #[serde(default)]
    pub name: String,
    /// Human-readable description shown by client UIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Version stamp the agent advertises.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Public URL the agent serves on. Optional because the gateway
    /// can emit a card for an agent it represents at a different URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Capability flags the agent advertises.
    #[serde(default)]
    pub capabilities: AgentCapabilities,
    /// MIME types the agent accepts on the input side. Empty list
    /// means "no declared restriction"; the negotiator passes
    /// everything when the list is empty.
    #[serde(default, alias = "defaultInputModes")]
    pub default_input_modes: Vec<String>,
    /// MIME types the agent emits on the output side. Empty list
    /// means "no declared restriction"; the negotiator passes any
    /// caller `Accept` value when the list is empty.
    #[serde(default, alias = "defaultOutputModes")]
    pub default_output_modes: Vec<String>,
    /// Optional list of skills the agent advertises. Opaque to the
    /// gateway today; preserved for surface-level passthrough.
    #[serde(default)]
    pub skills: Vec<serde_json::Value>,
    /// Any fields the card carries that SBproxy does not type. Lets
    /// an operator paste a full card and have it round-trip without
    /// loss.
    #[serde(default, flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// Capability flags the agent advertises. The shape matches the A2A
/// 0.x protocol; later flags slot in here as `Option<bool>` so an
/// unset flag round-trips as `null` rather than `false`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct AgentCapabilities {
    /// Whether the agent supports streaming task updates.
    #[serde(default)]
    pub streaming: bool,
    /// Whether the agent supports push notifications back to the
    /// caller for long-running tasks.
    #[serde(default, alias = "pushNotifications")]
    pub push_notifications: bool,
    /// Whether the agent records task state transitions so a
    /// follow-up call can resume the conversation.
    #[serde(default, alias = "stateTransitionHistory")]
    pub state_transition_history: bool,
}

/// Negotiation outcome for a single side (input or output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationOutcome {
    /// The caller's preferred mode is supported by the agent. Carries
    /// the matched mode so downstream code can stamp the chosen
    /// modality on the upstream request.
    Matched(String),
    /// The caller did not declare a preference (no `Accept` header
    /// on the output side, no `Content-Type` on the input side). The
    /// gateway falls back to the agent's first declared mode, which
    /// the negotiator returns here so the caller can echo it.
    NoCallerPreference(String),
    /// The agent's declared modes do not include any value the
    /// caller offered. Returns the agent's declared mode list so the
    /// caller can render a helpful error.
    Mismatch {
        /// What the caller asked for, lower-cased and trimmed.
        requested: Vec<String>,
        /// What the agent advertises.
        advertised: Vec<String>,
    },
    /// The agent did not declare a mode list, so the gateway lets the
    /// caller's preference through. The caller's preferred mode is
    /// echoed back so audit / log can record what passed.
    AgentUndeclared(String),
}

impl NegotiationOutcome {
    /// Whether the negotiation resolved to a valid mode the upstream
    /// call should proceed with.
    pub fn is_acceptable(&self) -> bool {
        !matches!(self, Self::Mismatch { .. })
    }

    /// The mode the gateway should use on the outgoing call when the
    /// negotiation succeeded. `None` on a mismatch.
    pub fn chosen_mode(&self) -> Option<&str> {
        match self {
            Self::Matched(m) | Self::NoCallerPreference(m) | Self::AgentUndeclared(m) => {
                Some(m.as_str())
            }
            Self::Mismatch { .. } => None,
        }
    }
}

impl AgentCard {
    /// Parse a card from a raw `serde_json::Value`. Permissive on
    /// unknown fields (they land on `extensions`).
    pub fn from_json(v: serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(v)
    }

    /// Whether the agent advertises support for a specific input
    /// MIME type. Comparison is case-insensitive on the canonical
    /// `type/subtype` head (any `;` parameters are ignored).
    pub fn supports_input(&self, mime: &str) -> bool {
        if self.default_input_modes.is_empty() {
            return true;
        }
        let head = canonical_head(mime);
        self.default_input_modes
            .iter()
            .any(|m| canonical_head(m) == head)
    }

    /// Whether the agent advertises support for a specific output
    /// MIME type.
    pub fn supports_output(&self, mime: &str) -> bool {
        if self.default_output_modes.is_empty() {
            return true;
        }
        let head = canonical_head(mime);
        self.default_output_modes
            .iter()
            .any(|m| canonical_head(m) == head)
    }

    /// Negotiate the input modality. `content_type` is the caller's
    /// `Content-Type` header value (may include `;` parameters).
    /// `None` means the caller sent no body or no `Content-Type`.
    pub fn negotiate_input(&self, content_type: Option<&str>) -> NegotiationOutcome {
        if self.default_input_modes.is_empty() {
            return NegotiationOutcome::AgentUndeclared(
                content_type
                    .map(canonical_head)
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
            );
        }
        match content_type {
            Some(ct) => {
                let head = canonical_head(ct);
                if self
                    .default_input_modes
                    .iter()
                    .any(|m| canonical_head(m) == head)
                {
                    NegotiationOutcome::Matched(head)
                } else {
                    NegotiationOutcome::Mismatch {
                        requested: vec![head],
                        advertised: self
                            .default_input_modes
                            .iter()
                            .map(|s| canonical_head(s))
                            .collect(),
                    }
                }
            }
            None => {
                NegotiationOutcome::NoCallerPreference(canonical_head(&self.default_input_modes[0]))
            }
        }
    }

    /// Negotiate the output modality from the caller's `Accept`
    /// header. The header is parsed as a comma-separated list; each
    /// token is compared against the agent's advertised
    /// `defaultOutputModes`. `*/*` matches the agent's first
    /// declared mode.
    pub fn negotiate_output(&self, accept: Option<&str>) -> NegotiationOutcome {
        if self.default_output_modes.is_empty() {
            return NegotiationOutcome::AgentUndeclared(
                accept
                    .and_then(parse_first_accept_token)
                    .unwrap_or_else(|| "application/json".to_string()),
            );
        }
        let requested: Vec<String> = accept
            .map(|hdr| {
                hdr.split(',')
                    .map(canonical_head)
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if requested.is_empty() {
            return NegotiationOutcome::NoCallerPreference(canonical_head(
                &self.default_output_modes[0],
            ));
        }
        for tok in &requested {
            if tok == "*/*" {
                return NegotiationOutcome::Matched(canonical_head(&self.default_output_modes[0]));
            }
            if let Some(matched) = self
                .default_output_modes
                .iter()
                .find(|m| canonical_head(m) == *tok)
            {
                return NegotiationOutcome::Matched(canonical_head(matched));
            }
        }
        NegotiationOutcome::Mismatch {
            requested,
            advertised: self
                .default_output_modes
                .iter()
                .map(|s| canonical_head(s))
                .collect(),
        }
    }
}

/// Lower-case + strip parameters from a MIME-style token.
/// `application/json; charset=utf-8` -> `application/json`.
fn canonical_head(s: &str) -> String {
    let trimmed = s.trim();
    let head = trimmed.split(';').next().unwrap_or(trimmed).trim();
    head.to_ascii_lowercase()
}

fn parse_first_accept_token(header: &str) -> Option<String> {
    header
        .split(',')
        .map(canonical_head)
        .find(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_card() -> AgentCard {
        AgentCard::from_json(json!({
            "name": "Test agent",
            "description": "Talks back",
            "version": "0.3.0",
            "url": "https://agent.example.com/",
            "capabilities": {
                "streaming": true,
                "pushNotifications": false
            },
            "defaultInputModes": ["application/json", "text/plain"],
            "defaultOutputModes": ["application/json"],
            "skills": [{"id": "echo"}]
        }))
        .expect("parse")
    }

    #[test]
    fn card_round_trips_capability_flags_via_aliases() {
        let card = sample_card();
        assert!(card.capabilities.streaming);
        assert!(!card.capabilities.push_notifications);
        assert!(!card.capabilities.state_transition_history);
        assert_eq!(card.default_input_modes.len(), 2);
        assert_eq!(card.default_output_modes, vec!["application/json"]);
    }

    #[test]
    fn unknown_card_fields_round_trip_via_extensions() {
        let card = AgentCard::from_json(json!({
            "name": "Y",
            "futureField": {"k": "v"},
            "topLevelString": "ok"
        }))
        .expect("parse");
        assert_eq!(card.extensions["futureField"]["k"], "v");
        assert_eq!(card.extensions["topLevelString"], "ok");
    }

    #[test]
    fn supports_input_ignores_parameters_and_case() {
        let card = sample_card();
        assert!(card.supports_input("application/json"));
        assert!(card.supports_input("APPLICATION/JSON; charset=utf-8"));
        assert!(card.supports_input("text/plain"));
        assert!(!card.supports_input("application/xml"));
    }

    #[test]
    fn supports_output_ignores_parameters_and_case() {
        let card = sample_card();
        assert!(card.supports_output("application/json"));
        assert!(card.supports_output("Application/JSON; charset=utf-8"));
        assert!(!card.supports_output("text/plain"));
    }

    #[test]
    fn negotiate_input_matches_supported_content_type() {
        let card = sample_card();
        let out = card.negotiate_input(Some("application/json; charset=utf-8"));
        assert_eq!(out, NegotiationOutcome::Matched("application/json".into()));
        assert!(out.is_acceptable());
        assert_eq!(out.chosen_mode(), Some("application/json"));
    }

    #[test]
    fn negotiate_input_returns_mismatch_with_full_lists() {
        let card = sample_card();
        let out = card.negotiate_input(Some("application/xml"));
        match out {
            NegotiationOutcome::Mismatch {
                requested,
                advertised,
            } => {
                assert_eq!(requested, vec!["application/xml"]);
                assert_eq!(advertised, vec!["application/json", "text/plain"]);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn negotiate_input_no_caller_preference_falls_back_to_first_mode() {
        let card = sample_card();
        let out = card.negotiate_input(None);
        assert_eq!(
            out,
            NegotiationOutcome::NoCallerPreference("application/json".into())
        );
    }

    #[test]
    fn negotiate_input_agent_undeclared_passes_caller_through() {
        let mut card = sample_card();
        card.default_input_modes.clear();
        let out = card.negotiate_input(Some("text/xml"));
        assert_eq!(out, NegotiationOutcome::AgentUndeclared("text/xml".into()));
    }

    #[test]
    fn negotiate_output_picks_first_match_from_accept_list() {
        let card = sample_card();
        let out = card.negotiate_output(Some("text/plain, application/json; q=0.5"));
        // Only application/json is in the agent list, so it wins
        // even though `text/plain` is listed first.
        assert_eq!(out, NegotiationOutcome::Matched("application/json".into()));
    }

    #[test]
    fn negotiate_output_star_matches_first_advertised() {
        let card = sample_card();
        let out = card.negotiate_output(Some("*/*"));
        assert_eq!(out, NegotiationOutcome::Matched("application/json".into()));
    }

    #[test]
    fn negotiate_output_mismatch_returns_full_lists() {
        let card = sample_card();
        let out = card.negotiate_output(Some("application/xml, text/plain"));
        match out {
            NegotiationOutcome::Mismatch {
                requested,
                advertised,
            } => {
                assert_eq!(requested, vec!["application/xml", "text/plain"]);
                assert_eq!(advertised, vec!["application/json"]);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn negotiate_output_no_accept_falls_back_to_first_mode() {
        let card = sample_card();
        let out = card.negotiate_output(None);
        assert_eq!(
            out,
            NegotiationOutcome::NoCallerPreference("application/json".into())
        );
    }
}
