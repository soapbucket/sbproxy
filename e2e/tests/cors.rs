//! CORS preflight + actual-request behaviour.
//!
//! `examples/05-headers-and-cors/sb.yml` documents the shape of
//! the `cors:` block. Here we build a small static-action origin
//! with the same shape so we don't need an external upstream and
//! exercise the documented preflight contract:
//!
//! - OPTIONS from an allowed origin returns the negotiated CORS
//!   response headers.
//! - OPTIONS from an unlisted origin still gets a response, but
//!   does not echo `Access-Control-Allow-Origin`.

use sbproxy_e2e::ProxyHarness;

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "cors.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    cors:
      allow_origins: ["https://example.com"]
      allow_methods: ["GET", "POST", "OPTIONS"]
      allow_headers: ["Content-Type", "Authorization"]
      max_age_seconds: 600
"#;

#[test]
fn allowed_origin_preflight_returns_cors_headers() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let client = reqwest::blocking::Client::new();

    let resp = client
        .request(reqwest::Method::OPTIONS, format!("{}/", harness.base_url()))
        .header("host", "cors.localhost")
        .header("origin", "https://example.com")
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "content-type")
        .send()
        .expect("preflight");

    let allow_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .map(|v| v.to_str().unwrap_or("").to_string());
    assert_eq!(
        allow_origin.as_deref(),
        Some("https://example.com"),
        "expected allow-origin echo for whitelisted origin"
    );

    let allow_methods = resp
        .headers()
        .get("access-control-allow-methods")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    assert!(
        allow_methods.to_uppercase().contains("GET"),
        "expected allow-methods to include GET, got: {}",
        allow_methods
    );
}

#[test]
fn unlisted_origin_does_not_get_cors_echo() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let client = reqwest::blocking::Client::new();

    let resp = client
        .request(reqwest::Method::OPTIONS, format!("{}/", harness.base_url()))
        .header("host", "cors.localhost")
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "GET")
        .send()
        .expect("preflight");

    // The proxy may still respond, but it must not echo back the
    // attacker's origin as the allow-origin value.
    let allow_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .map(|v| v.to_str().unwrap_or("").to_string());
    assert_ne!(
        allow_origin.as_deref(),
        Some("https://evil.example"),
        "must not echo unlisted origin back in allow-origin"
    );
}
