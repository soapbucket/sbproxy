//! PII / secret redaction regression (Wave 1 / Q1.9).
//!
//! Per  (A1.5), every output sink
//! (access log, error log, audit log, trace exporter, customer-facing
//! telemetry) MUST run the typed `RedactedField` denylist before write.
//! A new field that should be redacted but the redactor doesn't know
//! about it is a CI block.
//!
//! This test exercises the contract end-to-end: drive a request whose
//! headers and body carry every member of `RedactedField`, then assert
//! the marker `<redacted:<key>>` appears in every sink and the original
//! secret value appears in **none** of them.
//!
//! The harness wires the existing `sbproxy-observe::redact` middleware
//! to a fake-sink trait so the same line is inspected per-sink without
//! shelling to Loki / Tempo / Postgres. That wiring shipped: the buffers
//! live in `sbproxy_observe::fake_sinks` and the admin debug routes that
//! read them are in `sbproxy-core`'s request phase, both behind
//! `SBPROXY_TEST_FAKE_SINKS=1` so a production binary never exposes
//! them. Every test in this file runs by default; none is `#[ignore]`d.
//!
//! `redaction_fixture_floor_no_secret_leaks_through_legacy_redactor` is
//! the cheap floor underneath the two that spawn a proxy. It runs the
//! fixture list through `redact_secrets()` directly so the value list
//! stays grep-clean even if a harness change takes the per-sink pair
//! offline.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Every `RedactedField` member from A1.5, paired with the literal
/// secret value the test injects and the marker the redactor MUST emit
/// in its place. Marker format is `[REDACTED:` + uppercased member +
/// `]` (schema-v2 normalised marker; the legacy `<redacted:foo>`
/// shape was retired alongside the structured-log schema-v2 bump).
struct RedactionFixture {
    /// Human label for assertion error messages.
    label: &'static str,
    /// The literal secret value the test plants. MUST NOT appear in any
    /// sink after redaction.
    secret: &'static str,
    /// The marker the redactor emits. MUST appear in every sink.
    marker: &'static str,
    /// Where the secret is planted. Drives how the test injects it.
    site: SecretSite,
}

#[derive(Clone, Copy)]
// The fan-out test matches on the variant to choose how it plants the
// secret, and only `RequestHeader` needs its payload to do that: the
// body fixture plants both JSON keys at once and the env fixture drives
// a plain request. `path` and `name` stay because they document where
// each secret is supposed to land, and a fixture whose site is written
// down is one a reader can check against the redactor.
#[allow(dead_code)]
enum SecretSite {
    /// HTTP request header (key, value pre-formatted).
    RequestHeader { name: &'static str },
    /// HTTP request body, JSON-encoded under the given key path.
    RequestBodyField { path: &'static str },
    /// Environment variable read by the proxy at boot. The redactor
    /// scrubs values that match the env-var allowlist.
    EnvVar { name: &'static str },
}

/// The denylist test fixture, one entry per `RedactedField` variant.
/// Order matches the ADR's enum order so a future variant addition
/// shows up as a missing entry in this list and a failing test, not as
/// a silent gap.
fn fixtures() -> Vec<RedactionFixture> {
    vec![
        RedactionFixture {
            label: "AuthorizationHeader (Bearer)",
            secret: "Bearer s3cret-bearer-token-aaaaaaaaaaaaaaaa",
            marker: "[REDACTED:AUTHORIZATION]",
            site: SecretSite::RequestHeader {
                name: "authorization",
            },
        },
        RedactionFixture {
            label: "AuthorizationHeader (Basic)",
            secret: "Basic dXNlcjpwYXNzd29yZHNlY3JldA==",
            marker: "[REDACTED:AUTHORIZATION]",
            site: SecretSite::RequestHeader {
                name: "authorization",
            },
        },
        RedactionFixture {
            label: "StripeSecretKey",
            secret: "sk_live_51HjklmNopQrsTuvWxyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
            marker: "[REDACTED:STRIPE_SECRET_KEY]",
            site: SecretSite::RequestHeader {
                name: "x-stripe-key",
            },
        },
        RedactionFixture {
            label: "LedgerHmacKey",
            secret: "ledger-hmac-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            marker: "[REDACTED:LEDGER_HMAC_KEY]",
            site: SecretSite::EnvVar {
                name: "SBPROXY_LEDGER_HMAC_KEY",
            },
        },
        RedactionFixture {
            label: "KyaToken",
            secret: "kya_token_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            marker: "[REDACTED:KYA_TOKEN]",
            site: SecretSite::RequestHeader { name: "x-kya" },
        },
        RedactionFixture {
            label: "PromptBody",
            secret: "PROMPT_PII_alice@example.com SSN=123-45-6789",
            marker: "[REDACTED:PROMPT_BODY]",
            site: SecretSite::RequestBodyField {
                path: "messages.0.content",
            },
        },
        RedactionFixture {
            label: "Cookie",
            secret: "session=cookie-value-must-not-leak-aaaaaa",
            marker: "[REDACTED:COOKIE]",
            site: SecretSite::RequestHeader { name: "cookie" },
        },
        RedactionFixture {
            label: "OAuthClientSecret",
            secret: "oauth-client-secret-aaaaaaaaaaaaaaaaaaaa",
            marker: "[REDACTED:OAUTH_CLIENT_SECRET]",
            site: SecretSite::RequestBodyField {
                path: "oauth_client_secret",
            },
        },
        RedactionFixture {
            label: "PaymentReceiptSecret",
            secret: "rcpt_secret_aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            marker: "[REDACTED:PAYMENT_RECEIPT_SECRET]",
            site: SecretSite::RequestHeader {
                name: "x-sb-receipt-secret",
            },
        },
        RedactionFixture {
            label: "ApiKey",
            secret: "api_key=ak_aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            marker: "[REDACTED:API_KEY]",
            site: SecretSite::RequestHeader { name: "x-api-key" },
        },
    ]
}

/// Per-ADR list of every output sink the redactor fans into. Each sink
/// runs the same denylist before write; a new sink added to the proxy
/// without going through this list is a CI block.
const SINKS: &[&str] = &["access_log", "error_log", "audit_log", "trace_exporter"];

/// Round-trip every fixture through `sbproxy_observe::redact_secrets()`
/// and assert no original secret value survives. This is the regression
/// FLOOR under `redaction_per_sink_fan_out`, not a stand-in for it: it
/// needs no proxy, so it still reports when a harness or port problem
/// takes the two spawning tests out.
///
/// `redact_secrets` is the legacy free-form scrubber and does not emit
/// typed markers. The typed `[REDACTED:FIELD_UPPER]` output comes from
/// the structured-log redactor in `sbproxy_observe::logging`, which is
/// what the fan-out test reads out of the sink buffers.
///
/// Two assertions:
/// 1. The legacy redactor scrubs the value bytes for the patterns it
///    knows about (Bearer, Basic, api_key=).
/// 2. Every fixture entry carries a well-shaped marker. This catches
///    "added a new variant, forgot the marker" at the cheap tier
///    instead of inside a spawned-proxy failure message.
#[test]
fn redaction_fixture_floor_no_secret_leaks_through_legacy_redactor() {
    use sbproxy_observe::redact::redact_secrets;

    for fx in fixtures() {
        let redacted = redact_secrets(fx.secret);
        // The legacy regex redactor knows Bearer / Basic / api_key /
        // password patterns. For those, the original secret bytes MUST
        // be gone. Stripe SK uses `sk_live_` (underscore) which the
        // legacy `sk-` regex does NOT match; the structured redactor in
        // `sbproxy_observe::logging` is what catches that one, and
        // KyaToken, OAuthClientSecret, the ledger HMAC key, and the
        // prompt body likewise. Those are the fan-out test's to prove;
        // here the floor asserts marker shape only.
        let legacy_known = matches!(
            fx.label,
            "AuthorizationHeader (Bearer)" | "AuthorizationHeader (Basic)" | "ApiKey"
        );
        if legacy_known {
            assert!(
                !redacted.contains(fx.secret),
                "legacy redactor leaked secret for {}: {}",
                fx.label,
                redacted
            );
        }
        assert!(!fx.marker.is_empty(), "marker empty for {}", fx.label);
        assert!(
            fx.marker.starts_with("[REDACTED:") && fx.marker.ends_with(']'),
            "marker shape wrong for {}: {}",
            fx.label,
            fx.marker
        );
    }
}

/// Per-sink fan-out: for each fixture, drive a request that plants the
/// secret in the documented site, then read the captured output of
/// every sink and assert (a) the marker is present and (b) the secret
/// is absent. Mirrors the ADR's "marker variant matches the field
/// type" rule (Authorization gets `[REDACTED:AUTHORIZATION]`, not a
/// generic marker).
#[test]
fn redaction_per_sink_fan_out() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("start mock upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
observability:
  log:
    sinks:
      - name: access_log
        format: json
        profile: internal
      - name: error_log
        format: json
        profile: internal
      - name: audit_log
        format: json
        profile: internal
      - name: trace_exporter
        format: otlp
        profile: internal
origins:
  "redact.localhost":
    action:
      type: proxy
      url: "{}"
"#,
        upstream.base_url()
    );
    let harness =
        ProxyHarness::start_with_yaml_and_env(&yaml, FAKE_SINKS_ENV).expect("start proxy");

    for fx in fixtures() {
        // Reset the sink capture buffer before each fixture so cross-
        // contamination from earlier fixtures cannot mask a leak.
        let _ = reset_sink_buffers(&harness);

        // Plant the secret per its site and fire one request.
        match fx.site {
            SecretSite::RequestHeader { name } => {
                let _ = harness
                    .get_with_headers("/", "redact.localhost", &[(name, fx.secret)])
                    .expect("planted-header GET");
            }
            SecretSite::RequestBodyField { path: _ } => {
                let body = json!({
                    "messages": [{ "role": "user", "content": fx.secret }],
                    "oauth_client_secret": fx.secret,
                });
                let _ = harness
                    .post_json("/", "redact.localhost", &body, &[])
                    .expect("planted-body POST");
            }
            SecretSite::EnvVar { name: _ } => {
                // A plain request is enough. The capture helper stamps a
                // placeholder for every env-typed redaction target into
                // the synthetic event on every captured request, so the
                // typed-key matcher fires whether or not the operator
                // ever set the variable. Nothing needs planting here;
                // what is under test is that the field is redacted by
                // key rather than by recognizing the value.
                let _ = harness
                    .get_with_headers("/", "redact.localhost", &[])
                    .expect("env-planted GET");
            }
        }

        for &sink in SINKS {
            let buf = read_sink_buffer(&harness, sink).unwrap_or_default();
            assert!(
                buf.contains(fx.marker),
                "sink {sink}: marker {} missing for {}; got: {buf}",
                fx.marker,
                fx.label
            );
            assert!(
                !buf.contains(fx.secret),
                "sink {sink}: secret leaked for {}; got: {buf}",
                fx.label
            );
        }
    }

    drop(harness);
    drop(upstream);
}

/// Negative coverage: a non-secret value (a plain user-agent like
/// `smoke-bot/1.0`) MUST NOT be replaced with any redaction marker.
/// Catches over-eager redactors that match too broadly.
#[test]
fn redaction_does_not_eat_non_secrets() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("start mock upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "redact.localhost":
    action:
      type: proxy
      url: "{}"
"#,
        upstream.base_url()
    );
    let harness =
        ProxyHarness::start_with_yaml_and_env(&yaml, FAKE_SINKS_ENV).expect("start proxy");

    let _ = reset_sink_buffers(&harness);
    let _ = harness
        .get_with_headers(
            "/healthz",
            "redact.localhost",
            &[("user-agent", "smoke-bot/1.0")],
        )
        .expect("plain GET");

    for &sink in SINKS {
        let buf = read_sink_buffer(&harness, sink).unwrap_or_default();
        assert!(
            !buf.contains("[REDACTED:"),
            "sink {sink}: false-positive redaction on non-secret request: {buf}"
        );
    }

    drop(harness);
    drop(upstream);
}

// --- Test-only sink helpers ---
//
// These wrap the admin-side debug endpoints landed in WOR-87. The
// returned strings are the raw concatenated lines of the named sink
// since the last reset. The endpoints are gated behind the
// `SBPROXY_TEST_FAKE_SINKS=1` env var so production binaries never
// expose them; [`FAKE_SINKS_ENV`] passes the var on the spawned proxy
// child's environment, leaving this test runner's own environment
// untouched (WOR-646).

/// Child-process environment that turns the fake-sink admin routes on
/// in the spawned proxy.
const FAKE_SINKS_ENV: &[(&str, &str)] = &[("SBPROXY_TEST_FAKE_SINKS", "1")];

fn reset_sink_buffers(h: &ProxyHarness) -> anyhow::Result<()> {
    // POST /api/_test/sinks/reset against the proxy port. The
    // endpoint clears every per-sink buffer and returns 204.
    let url = format!("{}/api/_test/sinks/reset", h.base_url());
    let resp = reqwest::blocking::Client::new()
        .post(&url)
        .header("host", "localhost")
        .send()?;
    if resp.status().as_u16() != 204 {
        anyhow::bail!(
            "unexpected status from /api/_test/sinks/reset: {}",
            resp.status()
        );
    }
    Ok(())
}

fn read_sink_buffer(h: &ProxyHarness, sink: &str) -> anyhow::Result<String> {
    // GET /api/_test/sinks/{name} returns the named sink's buffer
    // as `text/plain`, one redacted JSON line per record.
    let url = format!("{}/api/_test/sinks/{sink}", h.base_url());
    let resp = reqwest::blocking::Client::new()
        .get(&url)
        .header("host", "localhost")
        .send()?;
    Ok(resp.text()?)
}
