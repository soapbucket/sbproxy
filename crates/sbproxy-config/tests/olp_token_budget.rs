//! Config contract for `origins.<host>.olp` (WOR-2673).
//!
//! `POST /.well-known/olp/token` is unauthenticated by design and mints
//! an Ed25519 bearer license token per call, ahead of authentication
//! and the policy chain where an origin's own rate limits live. The
//! budget in this block is the only bound on it, which is why zero is
//! refused rather than read as "unlimited".

use sbproxy_config::compile_config;

/// A complete config whose one origin carries `olp_extra` inside its
/// `olp:` block.
fn config_with_olp(olp_extra: &str) -> String {
    format!(
        "proxy:\n  http_bind_port: 8080\n\
         origins:\n  \"licensing.test\":\n    action:\n      type: static\n      \
         status_code: 200\n      content_type: text/plain\n      body: ok\n    \
         olp:\n      enabled: true\n      \
         signing_key: \"1122334455667788990011223344556677889900112233445566778899001122\"\n      \
         key_id: 2026-q3\n      issuer: https://licensing.test\n{olp_extra}"
    )
}

#[test]
fn the_token_budget_defaults_when_the_key_is_absent() {
    let compiled = compile_config(&config_with_olp("")).expect("the default shape compiles");
    let olp = compiled
        .origins
        .iter()
        .find(|origin| origin.hostname == "licensing.test")
        .and_then(|origin| origin.olp.as_ref())
        .expect("the origin carries an olp block");
    assert_eq!(
        olp.token_rate_limit_per_minute, 60,
        "an operator who writes no budget still gets one"
    );
}

#[test]
fn an_explicit_token_budget_is_carried_through() {
    let compiled = compile_config(&config_with_olp("      token_rate_limit_per_minute: 5\n"))
        .expect("an explicit budget compiles");
    let olp = compiled
        .origins
        .iter()
        .find(|origin| origin.hostname == "licensing.test")
        .and_then(|origin| origin.olp.as_ref())
        .expect("the origin carries an olp block");
    assert_eq!(olp.token_rate_limit_per_minute, 5);
}

#[test]
fn a_zero_token_budget_is_refused_rather_than_read_as_unlimited() {
    // The failure this prevents: an operator writes 0 meaning "no
    // limit", and an unauthenticated mint endpoint runs unbounded
    // because a bound one typo away from off is not a bound.
    let Err(error) = compile_config(&config_with_olp("      token_rate_limit_per_minute: 0\n"))
    else {
        panic!("a zero token budget must not compile");
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("token_rate_limit_per_minute"),
        "the refusal must name the key: {message}"
    );
    assert!(
        message.contains("unlimited"),
        "the refusal must say why zero is not the way to disable it: {message}"
    );
}
