//! Per-request context slots that the
//! response handler keys on after the per-policy ports.
//!
//! `RequestContext::deny_policy_type` carries the same string
//! the existing `audit_deny!` macro takes, so the response
//! handler can prefer the slot once a ported enforcer wrapper
//! populates it. `RequestContext::tls_terminated` precomputes
//! the "request was TLS at the edge" signal so a wrapper
//! enforcer that only sees the request snapshot (not the live
//! Pingora session) can read it without rederiving.
//!
//! Both fields default to their empty / false state so the
//! shape stays behaviour-neutral until a downstream PR starts
//! reading the slots.

use sbproxy_core::context::RequestContext;

#[test]
fn deny_policy_type_defaults_to_none() {
    let ctx = RequestContext::default();
    assert!(ctx.deny_policy_type.is_none());
}

#[test]
fn tls_terminated_defaults_to_false() {
    let ctx = RequestContext::default();
    assert!(!ctx.tls_terminated);
}

#[test]
fn deny_policy_type_round_trip() {
    // Build with the default ctor first to avoid clippy's
    // `field-reassign-with-default` lint, then exercise the slot.
    let mut ctx = RequestContext::new();
    ctx.deny_policy_type = Some("rate_limit");
    assert_eq!(ctx.deny_policy_type, Some("rate_limit"));

    // Setting back to None mirrors the per-request reset that
    // happens when the dispatcher runs without producing a
    // deny verdict on the current request.
    ctx.deny_policy_type = None;
    assert!(ctx.deny_policy_type.is_none());
}

#[test]
fn tls_terminated_round_trip() {
    let mut ctx = RequestContext::new();
    ctx.tls_terminated = true;
    assert!(ctx.tls_terminated);
    ctx.tls_terminated = false;
    assert!(!ctx.tls_terminated);
}

/// `RequestContext::new()` and `RequestContext::default()`
/// both leave the new slots at their empty state. The default
/// path is the one `Pingora`'s `new_ctx` calls; if a future
/// refactor diverges them this test catches it.
#[test]
fn new_and_default_agree_on_new_slots() {
    let a = RequestContext::new();
    let b = RequestContext::default();
    assert_eq!(a.deny_policy_type, b.deny_policy_type);
    assert_eq!(a.tls_terminated, b.tls_terminated);
}
