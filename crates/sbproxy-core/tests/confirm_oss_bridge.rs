//! WOR-201 PR 1b: OSS Confirm-to-AllowWithHeaders bridge.
//!
//! Per `docs/adr-policy-verdict-shape.md`, OSS routes a
//! `PolicyDecision::Confirm` through the existing AllowWithHeaders
//! mechanism with `X-Policy-Confirm: <reason>` stamped on the
//! response. The enterprise pipeline parks the request before the
//! bridge fires; OSS never parks. Edge cases:
//!
//! - `expires_at` already in the past at decision time -> 410 Deny.
//! - `webhook_url` blocked by the SSRF guard -> 502 Deny.
//! - Otherwise: AllowWithHeaders carrying X-Policy-Confirm.

use sbproxy_core::policy_dispatch::{translate_plugin_decision, ConfirmReducerState};
use sbproxy_observe::events::VerdictTag;
use sbproxy_plugin::PolicyDecision;

#[test]
fn plain_confirm_stamps_x_policy_confirm_via_allow_with_headers() {
    let mut headers = Vec::new();
    let mut state = ConfirmReducerState::default();
    let translated = translate_plugin_decision(
        PolicyDecision::confirm("manager review required", None, None),
        &mut headers,
        &mut state,
    );
    assert_eq!(translated.verdict, VerdictTag::Confirm);
    assert!(
        translated.deny.is_none(),
        "plain Confirm must not deny in OSS"
    );
    assert_eq!(
        headers,
        vec![(
            "X-Policy-Confirm".to_string(),
            "manager review required".to_string(),
        )],
        "OSS bridge stamps the reason on the response header"
    );
    assert!(state.first_consumed);
}

#[test]
fn expired_confirm_synthesises_410_deny() {
    let mut headers = Vec::new();
    let mut state = ConfirmReducerState::default();
    let past = chrono::Utc::now() - chrono::Duration::seconds(60);
    let translated = translate_plugin_decision(
        PolicyDecision::confirm("approval", None, Some(past)),
        &mut headers,
        &mut state,
    );
    assert_eq!(translated.verdict, VerdictTag::Confirm);
    let (status, msg, label) = translated.deny.expect("expired Confirm denies");
    assert_eq!(status, 410);
    assert!(msg.contains("expired"));
    assert_eq!(label, "plugin_confirm_expired");
    // Bridge did NOT stamp the header on the synthesised deny.
    assert!(headers.is_empty());
    assert!(!state.first_consumed);
}

#[test]
fn ssrf_blocked_webhook_synthesises_502_deny() {
    let mut headers = Vec::new();
    let mut state = ConfirmReducerState::default();
    // Loopback IPs are the canonical SSRF target the guard
    // refuses; confirms the OSS validation step rejects them at
    // decision time before the (enterprise) approver flow ever
    // runs.
    let loopback = url::Url::parse("http://127.0.0.1:8080/inbound").expect("static url");
    let translated = translate_plugin_decision(
        PolicyDecision::confirm("review high spend", Some(loopback), None),
        &mut headers,
        &mut state,
    );
    assert_eq!(translated.verdict, VerdictTag::Confirm);
    let (status, msg, label) = translated.deny.expect("ssrf-blocked webhook denies");
    assert_eq!(status, 502);
    assert_eq!(msg, "ssrf_blocked");
    assert_eq!(label, "plugin_confirm_ssrf");
    assert!(headers.is_empty());
    assert!(!state.first_consumed);
}

#[test]
fn future_expires_at_does_not_short_circuit() {
    let mut headers = Vec::new();
    let mut state = ConfirmReducerState::default();
    // A far-future deadline should NOT trigger the 410 path.
    let future = chrono::Utc::now() + chrono::Duration::days(7);
    let translated = translate_plugin_decision(
        PolicyDecision::confirm("review", None, Some(future)),
        &mut headers,
        &mut state,
    );
    assert_eq!(translated.verdict, VerdictTag::Confirm);
    assert!(translated.deny.is_none());
    assert_eq!(
        headers,
        vec![("X-Policy-Confirm".to_string(), "review".to_string())]
    );
}
