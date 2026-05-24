//! Chain reducer + Plugin verdict translation.
//!
//! This module isolates the multi-policy resolution rules from
//! `docs/adr-policy-verdict-shape.md`:
//!
//! 1. Any `Deny` in the chain wins; the first `Deny` short-circuits
//!    the rest. The dispatcher in `server.rs` enforces this via
//!    early `return PolicyResult::Deny(...)` (existing behaviour;
//!    PR 1b only adds audit emission to the path).
//! 2. If no `Deny`, the first `Confirm` wins. The OSS bridge
//!    translates `Confirm` to `AllowWithHeaders` with
//!    `X-Policy-Confirm: <reason>` stamped; later `Confirm`
//!    verdicts in the chain are recorded but do not re-stamp the
//!    header. Tracked via [`crate::policy_dispatch::ConfirmReducerState`].
//! 3. `AllowWithHeaders` from any number of policies accumulate
//!    onto the response header list in chain order. The dispatcher
//!    threads these through `RequestContext::policy_response_headers`
//!    and the response_filter drains the slot on the way out.
//! 4. Otherwise the verdict is `Allow`.
//!
//! Confirm-verdict edge cases per the verdict-shape ADR:
//!
//! - `expires_at` already in the past: synthesise a 410 deny.
//! - `webhook_url` blocked by the SSRF guard: synthesise a 502
//!   deny so an obviously-bad URL never reaches the (enterprise)
//!   approver flow. Validation alone is enough; the OSS pipeline
//!   never actually calls the webhook.

use sbproxy_observe::events::VerdictTag;
use sbproxy_plugin::PolicyDecision;

/// Mutable reducer state for chain-level Confirm resolution.
///
/// Per the verdict-shape ADR's resolution rule 2: the first
/// `Confirm` in chain order is the parking source; any later
/// `Confirm` is recorded but does not re-stamp the response
/// header. Tracked here rather than as an ad-hoc bool inside
/// the dispatcher loop so the reducer state stays explicit.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmReducerState {
    /// `true` once a Confirm verdict in the current chain has
    /// stamped its `X-Policy-Confirm` header. Subsequent Confirm
    /// verdicts are still surfaced in audit but do not re-stamp.
    pub first_consumed: bool,
}

/// Outcome of a single Plugin policy decision after the OSS
/// bridge has applied the verdict-shape ADR's edge cases.
///
/// The dispatcher matches on this to either continue the chain
/// (`Continue`) or short-circuit with a Deny (`Deny`). The
/// `verdict` field always carries the raw [`VerdictTag`] for
/// audit emission, even when the bridge synthesised a Deny from
/// an originally-Confirm decision.
#[derive(Debug)]
pub struct TranslatedDecision {
    /// Audit-tag for the original verdict shape.
    pub verdict: VerdictTag,
    /// Set when the bridge produces a denial. Tuple is
    /// `(status, message, policy_type_label)`.
    pub deny: Option<(u16, String, &'static str)>,
}

/// Translate a [`PolicyDecision`] returned by a `Policy::Plugin`
/// enforcer into the dispatcher's chain-reducer state.
///
/// See the module-level docs for the rules. The function pushes
/// any header pairs onto `policy_response_headers` (chain-order
/// accumulation per rule 3) and updates `confirm_state` (rule 2).
pub fn translate_plugin_decision(
    decision: PolicyDecision,
    policy_response_headers: &mut Vec<(String, String)>,
    confirm_state: &mut ConfirmReducerState,
) -> TranslatedDecision {
    match decision {
        PolicyDecision::Allow => TranslatedDecision {
            verdict: VerdictTag::Allow,
            deny: None,
        },
        PolicyDecision::AllowWithHeaders { headers } => {
            for entry in headers {
                policy_response_headers.push(entry);
            }
            TranslatedDecision {
                verdict: VerdictTag::AllowWithHeaders,
                deny: None,
            }
        }
        PolicyDecision::Deny { status, message } => TranslatedDecision {
            verdict: VerdictTag::Deny,
            deny: Some((status, message, "plugin")),
        },
        PolicyDecision::Confirm {
            reason,
            webhook_url,
            expires_at,
            ..
        } => {
            // Edge case 1: `expires_at` already elapsed at decision
            // time. Per the verdict-shape ADR's edge-cases section,
            // synthesise a 410 deny immediately rather than route
            // through the AllowWithHeaders bridge.
            if let Some(deadline) = expires_at {
                if deadline < chrono::Utc::now() {
                    return TranslatedDecision {
                        verdict: VerdictTag::Confirm,
                        deny: Some((
                            410,
                            "policy confirmation expired".to_string(),
                            "plugin_confirm_expired",
                        )),
                    };
                }
            }
            // Edge case 2: webhook_url present. Run through the
            // SSRF guard at decision time so an obviously-bad URL
            // never reaches the (enterprise) approver flow. The
            // OSS pipeline does not actually call the webhook;
            // validation alone is enough to fail-closed on loops
            // and private-IP targets.
            if let Some(url) = webhook_url.as_ref() {
                if let Err(reason) = sbproxy_security::ssrf::validate_url(url.as_str()) {
                    tracing::warn!(
                        target: "sbproxy::policy",
                        url = %url,
                        ssrf_reason = %reason,
                        "policy Confirm webhook blocked by SSRF guard"
                    );
                    return TranslatedDecision {
                        verdict: VerdictTag::Confirm,
                        deny: Some((502, "ssrf_blocked".to_string(), "plugin_confirm_ssrf")),
                    };
                }
            }
            // OSS bridge: stamp X-Policy-Confirm via the
            // AllowWithHeaders mechanism. Per resolution rule 2 a
            // later Confirm in the chain is recorded but does not
            // re-stamp.
            if confirm_state.first_consumed {
                tracing::debug!(
                    target: "sbproxy::policy",
                    reason = %reason,
                    "additional Confirm verdict superseded by earlier chain entry"
                );
                return TranslatedDecision {
                    verdict: VerdictTag::Confirm,
                    deny: None,
                };
            }
            confirm_state.first_consumed = true;
            policy_response_headers.push(("X-Policy-Confirm".to_string(), reason));
            TranslatedDecision {
                verdict: VerdictTag::Confirm,
                deny: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_does_nothing() {
        let mut headers = Vec::new();
        let mut state = ConfirmReducerState::default();
        let out = translate_plugin_decision(PolicyDecision::Allow, &mut headers, &mut state);
        assert_eq!(out.verdict, VerdictTag::Allow);
        assert!(out.deny.is_none());
        assert!(headers.is_empty());
        assert!(!state.first_consumed);
    }

    #[test]
    fn deny_short_circuits_with_status_and_message() {
        let mut headers = Vec::new();
        let mut state = ConfirmReducerState::default();
        let out = translate_plugin_decision(
            PolicyDecision::Deny {
                status: 418,
                message: "i am a teapot".to_string(),
            },
            &mut headers,
            &mut state,
        );
        assert_eq!(out.verdict, VerdictTag::Deny);
        let (status, msg, label) = out.deny.expect("deny set");
        assert_eq!(status, 418);
        assert_eq!(msg, "i am a teapot");
        assert_eq!(label, "plugin");
    }

    #[test]
    fn allow_with_headers_accumulates() {
        let mut headers = Vec::new();
        let mut state = ConfirmReducerState::default();
        translate_plugin_decision(
            PolicyDecision::AllowWithHeaders {
                headers: vec![("X-A".into(), "1".into())],
            },
            &mut headers,
            &mut state,
        );
        translate_plugin_decision(
            PolicyDecision::AllowWithHeaders {
                headers: vec![("X-B".into(), "2".into())],
            },
            &mut headers,
            &mut state,
        );
        assert_eq!(
            headers,
            vec![
                ("X-A".to_string(), "1".to_string()),
                ("X-B".to_string(), "2".to_string()),
            ],
        );
    }

    #[test]
    fn first_confirm_stamps_header_subsequent_skipped() {
        let mut headers = Vec::new();
        let mut state = ConfirmReducerState::default();
        let out1 = translate_plugin_decision(
            PolicyDecision::confirm("first", None, None),
            &mut headers,
            &mut state,
        );
        assert_eq!(out1.verdict, VerdictTag::Confirm);
        assert!(out1.deny.is_none());
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "X-Policy-Confirm");
        assert_eq!(headers[0].1, "first");
        assert!(state.first_consumed);

        let out2 = translate_plugin_decision(
            PolicyDecision::confirm("second", None, None),
            &mut headers,
            &mut state,
        );
        assert_eq!(out2.verdict, VerdictTag::Confirm);
        assert!(out2.deny.is_none());
        // second Confirm did not push another header
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn confirm_with_past_expiry_synthesises_410() {
        let mut headers = Vec::new();
        let mut state = ConfirmReducerState::default();
        let past = chrono::Utc::now() - chrono::Duration::minutes(5);
        let out = translate_plugin_decision(
            PolicyDecision::confirm("approval", None, Some(past)),
            &mut headers,
            &mut state,
        );
        assert_eq!(out.verdict, VerdictTag::Confirm);
        let (status, msg, label) = out.deny.expect("deny synthesised");
        assert_eq!(status, 410);
        assert!(msg.contains("expired"));
        assert_eq!(label, "plugin_confirm_expired");
        // Header was not stamped because we short-circuited.
        assert!(headers.is_empty());
        assert!(!state.first_consumed);
    }

    #[test]
    fn confirm_with_ssrf_blocked_webhook_synthesises_502() {
        let mut headers = Vec::new();
        let mut state = ConfirmReducerState::default();
        // localhost is the canonical SSRF target the guard rejects.
        let webhook = url::Url::parse("http://127.0.0.1:9999/approve").expect("static url");
        let out = translate_plugin_decision(
            PolicyDecision::confirm("spend approval", Some(webhook), None),
            &mut headers,
            &mut state,
        );
        assert_eq!(out.verdict, VerdictTag::Confirm);
        let (status, msg, label) = out.deny.expect("deny synthesised");
        assert_eq!(status, 502);
        assert_eq!(msg, "ssrf_blocked");
        assert_eq!(label, "plugin_confirm_ssrf");
        assert!(headers.is_empty());
        assert!(!state.first_consumed);
    }

    #[test]
    fn confirm_with_safe_webhook_stamps_header() {
        let mut headers = Vec::new();
        let mut state = ConfirmReducerState::default();
        // example.com resolves to a public IP; the SSRF guard
        // permits public targets.
        let webhook = url::Url::parse("https://example.com/approve").expect("static url");
        let out = translate_plugin_decision(
            PolicyDecision::confirm("review", Some(webhook), None),
            &mut headers,
            &mut state,
        );
        assert_eq!(out.verdict, VerdictTag::Confirm);
        assert!(out.deny.is_none());
        assert_eq!(
            headers,
            vec![("X-Policy-Confirm".to_string(), "review".to_string())]
        );
    }
}
