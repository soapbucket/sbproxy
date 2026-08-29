//! Runtime seam coverage for the `abtest` action.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;
use std::path::Path;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn wait_for_access_log_entry(path: &Path, request_path: &str, origin: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        if let Some(entry) = contents
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|entry| {
                entry.get("path").and_then(serde_json::Value::as_str) == Some(request_path)
                    && entry.get("origin").and_then(serde_json::Value::as_str) == Some(origin)
            })
        {
            return entry;
        }

        assert!(
            Instant::now() < deadline,
            "access log did not contain {request_path} for {origin}: {contents}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn abtest_weighted_selection_reaches_the_selected_upstream() {
    let unselected =
        MockUpstream::start(json!({"variant": "unselected"})).expect("start zero-weight upstream");
    let selected =
        MockUpstream::start(json!({"variant": "selected"})).expect("start selected upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "abtest.localhost":
    action:
      type: abtest
      variants:
        - name: unselected
          url: "{}"
          weight: 0
        - name: selected
          url: "{}"
          weight: 1
"#,
        unselected.base_url(),
        selected.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .get("/weighted", "abtest.localhost")
        .expect("send request");

    assert_eq!(response.status, 200);
    assert_eq!(
        response.json().expect("JSON response")["variant"],
        "selected"
    );
    assert_eq!(
        selected.captured().len(),
        1,
        "selected upstream must receive request"
    );
    assert!(
        unselected.captured().is_empty(),
        "zero-weight upstream must not receive request"
    );
}

#[test]
fn abtest_existing_sticky_cookie_pins_its_variant_and_is_not_restamped() {
    let control = MockUpstream::start(json!({"variant": "control"})).expect("control upstream");
    let experiment =
        MockUpstream::start(json!({"variant": "experiment"})).expect("experiment upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "abtest.localhost":
    action:
      type: abtest
      sticky_cookie: sb_ab_variant
      variants:
        - name: control
          url: "{}"
          weight: 0
        - name: experiment
          url: "{}"
          weight: 1
"#,
        control.base_url(),
        experiment.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .get_with_headers(
            "/sticky",
            "abtest.localhost",
            &[("cookie", "sb_ab_variant=control")],
        )
        .expect("send request");

    assert_eq!(response.status, 200);
    assert_eq!(
        response.json().expect("JSON response")["variant"],
        "control"
    );
    assert_eq!(
        control.captured().len(),
        1,
        "sticky variant must receive request"
    );
    assert!(experiment.captured().is_empty());
    assert!(
        !response.headers.contains_key("set-cookie"),
        "a client that already carries the pin must not be restamped, so the \
         Max-Age window counts from its first visit rather than sliding"
    );
}

/// The wire half of the sticky pin: the `Set-Cookie` reaches the
/// client, and the value it carries is one the pinning path accepts.
///
/// `abtest_mints_a_sticky_pin_for_a_client_that_arrives_without_one` in
/// `action_dispatch.rs` proves the request phase decides to set a
/// cookie. It cannot prove the response phase emits it, because that
/// append happens in `response_filter` against a real Pingora session.
///
/// Deliberately not named "routes the next request": the weights here
/// are 0 and 1, so the second call would land on `experiment` whether
/// or not the pin were honored, and asserting that it did would be
/// vacuous. The pin-decides direction is proved by
/// `abtest_existing_sticky_cookie_pins_its_variant_and_is_not_restamped`
/// above, which pins to the *zero-weight* variant so the weighted roll
/// cannot produce the same answer by chance. What this test adds is the
/// half that one cannot reach: that the proxy issues the pin at all.
#[test]
fn abtest_first_visit_is_handed_a_pin_the_client_can_spend() {
    let control = MockUpstream::start(json!({"variant": "control"})).expect("control upstream");
    let experiment =
        MockUpstream::start(json!({"variant": "experiment"})).expect("experiment upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "abtest.localhost":
    action:
      type: abtest
      sticky_cookie: sb_ab_variant
      variants:
        - name: control
          url: "{}"
          weight: 0
        - name: experiment
          url: "{}"
          weight: 1
"#,
        control.base_url(),
        experiment.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // First visit: no cookie, so the weighted roll picks `experiment`
    // (control is weighted 0) and the response carries the pin.
    let first = proxy
        .get("/first", "abtest.localhost")
        .expect("send first request");
    assert_eq!(first.status, 200);
    assert_eq!(
        first.json().expect("JSON response")["variant"],
        "experiment"
    );
    let set_cookie = first
        .headers
        .get("set-cookie")
        .expect("a first visit must be handed a sticky pin");
    assert!(
        set_cookie.starts_with("sb_ab_variant=experiment;"),
        "the pin names the configured cookie and the selected variant: {set_cookie}"
    );
    for flag in ["Path=/", "SameSite=Lax", "HttpOnly"] {
        assert!(
            set_cookie.contains(flag),
            "pin is missing {flag}: {set_cookie}"
        );
    }

    // Second visit: send the pin back. It has to reach the same variant,
    // and it must not be restamped.
    let pin = set_cookie
        .split(';')
        .next()
        .expect("cookie name=value pair")
        .to_string();
    let second = proxy
        .get_with_headers("/second", "abtest.localhost", &[("cookie", &pin)])
        .expect("send second request");
    assert_eq!(second.status, 200);
    assert_eq!(
        second.json().expect("JSON response")["variant"],
        "experiment"
    );
    assert!(
        !second.headers.contains_key("set-cookie"),
        "the returning client already carries the pin and must not be restamped"
    );
    assert_eq!(
        experiment.captured().len(),
        2,
        "both requests reach the weighted-selected variant"
    );
    assert!(
        control.captured().is_empty(),
        "the zero-weight variant must never be reached"
    );
}

#[test]
fn abtest_invalid_selected_url_returns_502_after_its_request_callback_runs() {
    let callback = MockUpstream::start(json!({"callback": "received"})).expect("callback");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "broken-abtest.localhost":
    action:
      type: abtest
      variants:
        - name: broken
          url: "http://"
          weight: 1
    on_request:
      - url: "{}/abtest"
        method: POST
        enrich: true
        timeout: 5
"#,
        callback.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let broken = proxy
        .get("/bad", "broken-abtest.localhost")
        .expect("send invalid A/B request");

    assert_eq!(broken.status, 502);
    assert!(
        broken
            .text()
            .expect("error body")
            .contains("invalid upstream URL"),
        "unexpected invalid-url response"
    );
    let callbacks = callback.captured();
    assert_eq!(
        callbacks.len(),
        1,
        "the failing A/B request must run its own on_request callback"
    );
    assert_eq!(
        callbacks[0]
            .headers
            .get("x-sbproxy-event")
            .map(String::as_str),
        Some("on_request")
    );
    let callback_body = std::str::from_utf8(&callbacks[0].body).expect("callback JSON");
    assert!(
        callback_body.contains("\"path\":\"/bad\""),
        "callback must belong to the failed request: {callback_body}"
    );
    assert!(
        callback_body.contains("\"host\":\"broken-abtest.localhost\""),
        "callback must name the failed origin: {callback_body}"
    );
}

#[test]
fn abtest_invalid_selected_url_is_logged_after_its_same_request_fails() {
    let access_log = NamedTempFile::new().expect("create access log");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
access_log:
  enabled: true
  status_codes: [502]
  methods: [GET]
  output:
    type: file
    path: "{}"
origins:
  "broken-abtest.localhost":
    action:
      type: abtest
      variants:
        - name: broken
          url: "http://"
          weight: 1
"#,
        access_log.path().display(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .get("/bad", "broken-abtest.localhost")
        .expect("send invalid A/B request");

    assert_eq!(response.status, 502);
    assert!(
        response
            .text()
            .expect("error body")
            .contains("invalid upstream URL"),
        "unexpected invalid-url response"
    );

    let entry = wait_for_access_log_entry(access_log.path(), "/bad", "broken-abtest.localhost");
    assert_eq!(entry["status"], json!(502));
    assert_eq!(entry["method"], json!("GET"));
}

/// The sticky pin and the response cache, together.
///
/// The pin is appended in `response_filter`, and the response cache
/// captures headers later in that same function, so a stored entry can
/// carry the `Set-Cookie` the proxy just minted. If it does, and the
/// entry is replayed, a second client that sent no cookie is handed the
/// first client's pin. That is not a slow cache: it silently corrupts
/// every result the A/B split exists to produce, because two clients
/// that were never assigned the same variant now report as one cohort.
/// In shape it is a cross-client cookie leak, even though the value
/// this cookie carries today is only a variant name.
///
/// Three properties, in the order they matter:
///
/// 1. A cached hit must not replay a `Set-Cookie`.
/// 2. A second client sending no cookie gets its own pin, not the
///    first client's.
/// 3. The cache still works on this origin, so property 1 is not
///    passing because nothing was ever cached.
#[test]
fn a_cached_abtest_response_never_replays_the_first_client_pin() {
    let experiment =
        MockUpstream::start(json!({"variant": "experiment"})).expect("experiment upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "abtest-cache.localhost":
    action:
      type: abtest
      sticky_cookie: sb_ab_variant
      variants:
        - name: experiment
          url: "{}"
          weight: 1
    response_cache:
      enabled: true
      ttl: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
"#,
        experiment.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // First client, no cookie: takes the pick and is handed a pin.
    let first = proxy
        .get("/cached", "abtest-cache.localhost")
        .expect("first client request");
    assert_eq!(first.status, 200);
    let first_pin = first
        .headers
        .get("set-cookie")
        .expect("a first visit is handed a pin")
        .clone();
    assert!(first_pin.starts_with("sb_ab_variant=experiment;"));

    // Warm the cache. Poll rather than assume the store is synchronous.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut cached = None;
    while std::time::Instant::now() < deadline {
        let response = proxy
            .get("/cached", "abtest-cache.localhost")
            .expect("cache poll");
        if response
            .headers
            .get("x-sbproxy-cache")
            .is_some_and(|v| v == "HIT")
        {
            cached = Some(response);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let Some(hit) = cached else {
        // Property 3 failed: nothing cached, so properties 1 and 2 would
        // pass vacuously. Say so rather than reporting a green run.
        panic!(
            "the response cache never served a HIT on an abtest origin, so this test \
             cannot show anything about what a hit replays"
        );
    };

    // Property 1: the replayed entry carries no pin.
    assert!(
        !hit.headers.contains_key("set-cookie"),
        "a cached abtest response replayed a Set-Cookie; every client served from this \
         entry would be pinned to the first client's variant: {:?}",
        hit.headers.get("set-cookie")
    );

    // Property 2: a client arriving fresh still gets its own pin, so the
    // fix cannot be "stop minting pins on a cacheable origin".
    let second = proxy
        .get("/cached-other", "abtest-cache.localhost")
        .expect("second client request");
    assert_eq!(second.status, 200);
    let second_pin = second
        .headers
        .get("set-cookie")
        .expect("a second client with no cookie must be handed its own pin");
    assert!(
        second_pin.starts_with("sb_ab_variant=experiment;"),
        "unexpected pin for the second client: {second_pin}"
    );
}
