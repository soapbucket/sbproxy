//! WOR-201 PR 1b: multi-policy chain reducer rules.
//!
//! Exercises the resolution rules from
//! `docs/adr-policy-verdict-shape.md` against the public
//! [`sbproxy_core::policy_dispatch`] surface. The dispatcher in
//! `server.rs` calls into the same helpers; an integration test
//! over the helpers covers the rules without booting Pingora.

use sbproxy_core::policy_dispatch::{translate_plugin_decision, ConfirmReducerState};
use sbproxy_observe::events::VerdictTag;
use sbproxy_plugin::PolicyDecision;

/// Outcome of running a chain of [`PolicyDecision`] values
/// through the dispatcher reducer. Aggregated into one struct so
/// the helper signature stays under clippy's `type_complexity`
/// threshold.
struct ChainOutcome {
    /// Per-policy audit verdict tag, in the order the dispatcher
    /// produced them. Capped at the first deny because the
    /// reducer short-circuits.
    verdicts: Vec<VerdictTag>,
    /// Header pairs accumulated onto
    /// `RequestContext::policy_response_headers` by
    /// AllowWithHeaders verdicts and the OSS Confirm bridge.
    headers: Vec<(String, String)>,
    /// Reducer state at the end of the run; `first_consumed`
    /// flips on the first Confirm.
    state: ConfirmReducerState,
    /// `Some((status, message, policy_type))` when the chain
    /// short-circuited on a deny.
    deny: Option<(u16, String, &'static str)>,
}

fn drive_chain(decisions: Vec<PolicyDecision>) -> ChainOutcome {
    let mut verdicts = Vec::new();
    let mut headers = Vec::new();
    let mut state = ConfirmReducerState::default();
    let mut deny: Option<(u16, String, &'static str)> = None;
    for decision in decisions {
        let translated = translate_plugin_decision(decision, &mut headers, &mut state);
        verdicts.push(translated.verdict);
        if let Some(d) = translated.deny {
            // Rule 1: any Deny short-circuits. Stop iterating.
            deny = Some(d);
            break;
        }
    }
    ChainOutcome {
        verdicts,
        headers,
        state,
        deny,
    }
}

/// Rule 1: any Deny in the chain wins. The first Deny encountered
/// short-circuits the rest; later Allow / AllowWithHeaders never
/// run.
#[test]
fn rule_one_deny_short_circuits_rest_of_chain() {
    let chain = vec![
        PolicyDecision::Allow,
        PolicyDecision::Deny {
            status: 403,
            message: "blocked".to_string(),
        },
        PolicyDecision::Allow,
    ];
    let outcome = drive_chain(chain);
    assert_eq!(outcome.verdicts, vec![VerdictTag::Allow, VerdictTag::Deny]);
    assert!(outcome.headers.is_empty());
    assert!(!outcome.state.first_consumed);
    let (status, msg, label) = outcome.deny.expect("deny short-circuited");
    assert_eq!(status, 403);
    assert_eq!(msg, "blocked");
    assert_eq!(label, "plugin");
}

/// Rule 2: when no Deny fires, the first Confirm in chain order
/// wins. The OSS bridge stamps `X-Policy-Confirm` once via the
/// AllowWithHeaders mechanism; later AllowWithHeaders verdicts
/// still accumulate onto the response.
#[test]
fn rule_two_first_confirm_wins_over_allow_with_headers() {
    let chain = vec![
        PolicyDecision::AllowWithHeaders {
            headers: vec![("X-Before".into(), "first".into())],
        },
        PolicyDecision::confirm("approval needed", None, None),
        PolicyDecision::AllowWithHeaders {
            headers: vec![("X-After".into(), "second".into())],
        },
    ];
    let outcome = drive_chain(chain);
    assert!(outcome.deny.is_none(), "no Deny in this chain");
    assert_eq!(
        outcome.verdicts,
        vec![
            VerdictTag::AllowWithHeaders,
            VerdictTag::Confirm,
            VerdictTag::AllowWithHeaders,
        ],
    );
    assert!(
        outcome.state.first_consumed,
        "first Confirm consumed the slot"
    );
    // Headers accumulate in chain order: pre-Confirm header,
    // X-Policy-Confirm from the bridge, then the trailing
    // AllowWithHeaders entry.
    assert_eq!(
        outcome.headers,
        vec![
            ("X-Before".to_string(), "first".to_string()),
            (
                "X-Policy-Confirm".to_string(),
                "approval needed".to_string()
            ),
            ("X-After".to_string(), "second".to_string()),
        ],
    );
}

/// Rule 3: AllowWithHeaders verdicts accumulate. Two header pairs
/// from two policies both land on the response in chain order.
#[test]
fn rule_three_allow_with_headers_accumulates_in_order() {
    let chain = vec![
        PolicyDecision::AllowWithHeaders {
            headers: vec![("X-First".into(), "a".into())],
        },
        PolicyDecision::AllowWithHeaders {
            headers: vec![("X-Second".into(), "b".into())],
        },
    ];
    let outcome = drive_chain(chain);
    assert!(outcome.deny.is_none());
    assert_eq!(
        outcome.verdicts,
        vec![VerdictTag::AllowWithHeaders, VerdictTag::AllowWithHeaders],
    );
    assert_eq!(
        outcome.headers,
        vec![
            ("X-First".to_string(), "a".to_string()),
            ("X-Second".to_string(), "b".to_string()),
        ],
    );
}

/// Rule 4: with no Deny, no Confirm, and no AllowWithHeaders, the
/// effective verdict is Allow. No headers stamped.
#[test]
fn rule_four_allow_falls_through() {
    let chain = vec![PolicyDecision::Allow, PolicyDecision::Allow];
    let outcome = drive_chain(chain);
    assert!(outcome.deny.is_none());
    assert_eq!(outcome.verdicts, vec![VerdictTag::Allow, VerdictTag::Allow]);
    assert!(outcome.headers.is_empty());
    assert!(!outcome.state.first_consumed);
}

/// Multiple Confirm in a single chain: the second one is recorded
/// as a Confirm verdict in the audit but does not re-stamp the
/// X-Policy-Confirm header. Mirrors the
/// `multi_confirm_consumed_first` rule in the verdict-shape ADR.
#[test]
fn second_confirm_in_chain_is_recorded_but_skipped() {
    let chain = vec![
        PolicyDecision::confirm("first", None, None),
        PolicyDecision::confirm("second", None, None),
    ];
    let outcome = drive_chain(chain);
    assert_eq!(
        outcome.verdicts,
        vec![VerdictTag::Confirm, VerdictTag::Confirm]
    );
    assert!(outcome.state.first_consumed);
    assert_eq!(
        outcome.headers,
        vec![("X-Policy-Confirm".to_string(), "first".to_string())],
        "only the first Confirm stamps the response header",
    );
}
