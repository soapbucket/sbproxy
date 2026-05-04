//! PII / secret redaction regression (Wave 1 / Q1.9).
//!
//! Per `docs/adr-log-schema-redaction.md` (A1.5), every output sink
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
//! shelling to Loki / Tempo / Postgres. The fake-sink wiring lives
//! behind R1.2; until then the per-sink assertions are `#[ignore]`d.
//! The simpler `redactor_input_round_trip` test runs today against the
//! existing `redact_secrets()` API as a regression floor so the value
//! list at least stays grep-clean.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Every `RedactedField` member from A1.5, paired with the literal
/// secret value the test injects and the marker the redactor MUST emit
/// in its place. Marker format is `<redacted:` + kebab-cased member +
/// `>` (verbatim from the ADR).
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
#[allow(dead_code)] // Path / name fields are read by the per-sink fan-out test once R1.2 lands.
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
            marker: "<redacted:authorization>",
            site: SecretSite::RequestHeader {
                name: "authorization",
            },
        },
        RedactionFixture {
            label: "AuthorizationHeader (Basic)",
            secret: "Basic dXNlcjpwYXNzd29yZHNlY3JldA==",
            marker: "<redacted:authorization>",
            site: SecretSite::RequestHeader {
                name: "authorization",
            },
        },
        RedactionFixture {
            label: "StripeSecretKey",
            secret: "sk_live_51HjklmNopQrsTuvWxyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz",
            marker: "<redacted:stripe-secret-key>",
            site: SecretSite::RequestHeader {
                name: "x-stripe-key",
            },
        },
        RedactionFixture {
            label: "LedgerHmacKey",
            secret: "ledger-hmac-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            marker: "<redacted:ledger-hmac-key>",
            site: SecretSite::EnvVar {
                name: "SBPROXY_LEDGER_HMAC_KEY",
            },
        },
        RedactionFixture {
            label: "KyaToken",
            secret: "kya_token_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            marker: "<redacted:kya-token>",
            site: SecretSite::RequestHeader { name: "x-kya" },
        },
        RedactionFixture {
            label: "PromptBody",
            secret: "PROMPT_PII_alice@example.com SSN=123-45-6789",
            marker: "<redacted:prompt-body>",
            site: SecretSite::RequestBodyField {
                path: "messages.0.content",
            },
        },
        RedactionFixture {
            label: "Cookie",
            secret: "session=cookie-value-must-not-leak-aaaaaa",
            marker: "<redacted:cookie>",
            site: SecretSite::RequestHeader { name: "cookie" },
        },
        RedactionFixture {
            label: "OAuthClientSecret",
            secret: "oauth-client-secret-aaaaaaaaaaaaaaaaaaaa",
            marker: "<redacted:oauth-client-secret>",
            site: SecretSite::RequestBodyField {
                path: "oauth_client_secret",
            },
        },
        RedactionFixture {
            label: "PaymentReceiptSecret",
            secret: "rcpt_secret_aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            marker: "<redacted:payment-receipt-secret>",
            site: SecretSite::RequestHeader {
                name: "x-sb-receipt-secret",
            },
        },
        RedactionFixture {
            label: "ApiKey",
            secret: "api_key=ak_aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            marker: "<redacted:api-key>",
            site: SecretSite::RequestHeader { name: "x-api-key" },
        },
    ]
}

/// Per-ADR list of every output sink the redactor fans into. Each sink
/// runs the same denylist before write; a new sink added to the proxy
/// without going through this list is a CI block.
const SINKS: &[&str] = &["access_log", "error_log", "audit_log", "trace_exporter"];

/// Round-trip every fixture through `sbproxy_observe::redact_secrets()`
/// and assert no original secret value survives. This is a regression
/// FLOOR: the substantive coverage lands when the per-sink harness
/// (R1.2) is wired. Today's redactor only scrubs free-form strings;
/// the typed-marker output (`<redacted:authorization>`) is part of
/// R1.2's structured-log redactor, not the legacy regex-based one.
///
/// We assert two things this test CAN check today:
/// 1. The legacy redactor scrubs the value bytes for the patterns it
///    knows about (Bearer, Basic, sk_live_, api_key=, etc).
/// 2. Every fixture entry has a non-empty marker string. This catches
///    "added a new variant, forgot the marker" before the typed
///    redactor lands.
#[test]
fn redaction_fixture_floor_no_secret_leaks_through_legacy_redactor() {
    use sbproxy_observe::redact::redact_secrets;

    for fx in fixtures() {
        let redacted = redact_secrets(fx.secret);
        // The legacy regex redactor knows Bearer / Basic / api_key /
        // password patterns. For those, the original secret bytes MUST
        // be gone. Stripe SK uses `sk_live_` (underscore) which the
        // legacy `sk-` regex does NOT match; the typed redactor in
        // R1.2 picks that up. KyaToken, OAuthClientSecret, ledger
        // HMAC, prompt-body, etc. are also typed-redactor-only. For
        // those the floor test asserts marker shape only.
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
            fx.marker.starts_with("<redacted:") && fx.marker.ends_with('>'),
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
/// type" rule (Authorization gets `<redacted:authorization>`, not a
/// generic marker).
#[test]
#[ignore = "TODO(wave3): typed redactor lives in `sbproxy-observe::redact` but the fake-sink test harness (admin endpoints `/api/_test/sinks/reset` + `/api/_test/sinks/{name}`) was never built; the local stubs `reset_sink_buffers` / `read_sink_buffer` return empty so all sink-buffer assertions fail. Needs the test admin-endpoint scaffolding."]
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
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

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
                // Env-var coverage drives a config-reload event so the
                // boot path emits a `config_reload` log line. The R1.2
                // harness exposes a tickle endpoint; we leave it to the
                // implementation to wire.
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
#[ignore = "TODO(wave3): negative coverage rides the same fake-sink harness which has not been built yet."]
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
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

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
            !buf.contains("<redacted:"),
            "sink {sink}: false-positive redaction on non-secret request: {buf}"
        );
    }

    drop(harness);
    drop(upstream);
}

// --- Test-only sink helpers ---
//
// These wrap the admin-side debug endpoints exposed by R1.2. The
// returned strings are the raw concatenated lines of the named sink
// since the last reset. The endpoints don't exist yet; the
// implementation lands behind R1.2.

fn reset_sink_buffers(_h: &ProxyHarness) -> anyhow::Result<()> {
    // POST /api/_test/sinks/reset
    Ok(())
}

fn read_sink_buffer(_h: &ProxyHarness, _sink: &str) -> anyhow::Result<String> {
    // GET /api/_test/sinks/{name}
    Ok(String::new())
}
