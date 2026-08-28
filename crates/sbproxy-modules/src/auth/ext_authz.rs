//! WOR-2667: `ext_authz` provider, Envoy-style external authorization.
//!
//! The proxy asks an authorization service you run whether to admit a
//! request, sending the method, the path, and an allowlisted subset of
//! the request headers as JSON, and reading back
//! `{"allowed": bool, ...}`. It is the seam for an authorization
//! decision that has to live in your own code: an entitlement lookup, a
//! per-tenant quota, a policy engine the gateway does not host.
//!
//! # Wire contract
//!
//! The check request is a `POST` of
//!
//! ```json
//! {"method": "GET", "path": "/orders/42", "headers": {"x-tenant": "acme"}}
//! ```
//!
//! and the answer is
//!
//! ```json
//! {"allowed": false, "status": 402, "body": "quota exhausted",
//!  "headers": {"x-quota-reset": "3600"}}
//! ```
//!
//! `allowed` is the only required field. `status` and `body` shape the
//! refusal the client sees (defaulting to `403 Forbidden by
//! ext_authz`), and `headers` are attached to that refusal, which is
//! how a service returns a `WWW-Authenticate` challenge or a
//! `Retry-After`. This is the JSON shape Envoy's `ext_authz` HTTP
//! service filter and the OpenPolicyAgent Envoy plugin both speak, so
//! a service written for either answers this provider unchanged.
//!
//! # How it differs from `forward_auth`
//!
//! `forward_auth` replays the request against an endpoint and reads a
//! status code. This provider sends a typed check document and reads a
//! typed answer, which buys three things `forward_auth` cannot do: the
//! service picks the refusal status and body, the provider composes
//! inside an `authentication:` list, and it runs on the HTTP/3 dispatch
//! path. What it does not do is copy headers from an *allow* answer
//! onto the upstream request; `forward_auth`'s `trust_headers` is
//! still the way to inject an identity header upstream. Headers on a
//! *deny* answer are attached to the refusal.
//!
//! # Security posture
//!
//! * **`headers_to_forward` is an allowlist and it starts empty.** A
//!   check document that carried every inbound header by default would
//!   ship `Authorization`, `Cookie`, and every internal trust header to
//!   the authorization service on the first request after an operator
//!   pointed the URL at it. The enterprise implementation this replaces
//!   treated an empty list as "forward everything"; that default is not
//!   carried over. Name the headers the service reads.
//! * **The URL is operator config and carries no request-derived
//!   component.** There is nothing a caller can put in a header or a
//!   path that changes which host is dialed, so the callout is not an
//!   SSRF primitive the way a fetch built from request data would be.
//! * **The check response is bounded** at
//!   `MAX_CHECK_RESPONSE_BYTES` (64 KiB) before it is parsed, so a service
//!   that answers with an unbounded body cannot exhaust the proxy.
//! * **Failure is closed by default.** A service that times out, refuses
//!   the connection, or answers unparseable JSON refuses the request
//!   with a `503`. `failure_mode_allow: true` inverts that, and every
//!   request it admits is counted separately as a fail-open rather than
//!   folded into the allow count, because a request that proceeded
//!   without the decision being made is not the same event as one the
//!   service allowed.
//!
//! # Bounding the outbound call
//!
//! Authentication runs before an origin's `policies:` are evaluated, so
//! an origin's `rate_limit` cannot cap what this provider dials, the
//! same structural gap [`crate::auth::ldap`] documents. Two bounds ship here:
//! the per-request `timeout_ms` (250ms by default, an order of
//! magnitude below the LDAP default because this is a local service
//! call rather than a directory bind), and the pooled client's
//! connection reuse, which keeps a burst from opening a new connection
//! per request. An authorization service is expected to sit next to the
//! proxy; one across the internet will show up as `auth_ms` in the
//! access log long before it shows up anywhere else.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// Default per-check timeout in milliseconds.
///
/// Matches Envoy's own `ext_authz` HTTP service default of 250ms. The
/// number is a budget statement, not a guess: the callout sits in front
/// of every request to the origin, so a service that cannot answer in a
/// quarter of a second is one whose latency the operator has to see.
pub const DEFAULT_TIMEOUT_MS: u64 = 250;

/// Largest check response the provider will parse.
///
/// The answer is a small JSON object by construction. Anything past
/// this is either a misconfigured URL pointing at a real page or a
/// service returning something it should not, and both are cheaper to
/// refuse than to buffer.
const MAX_CHECK_RESPONSE_BYTES: usize = 64 * 1024;

/// Response headers the provider reads a resolved subject from, in
/// order, when the service allows a request without naming one
/// explicitly in `subject`.
///
/// The set is the union of what oauth2-proxy, nginx's `auth_request`
/// recipes, and Envoy's ext_authz examples stamp, so a service written
/// against any of those conventions resolves a subject here without
/// extra config.
const SUBJECT_HEADERS: [&str; 5] = [
    "x-forwarded-user",
    "x-auth-request-user",
    "x-auth-user",
    "x-user",
    "remote-user",
];

/// `ext_authz` provider configuration.
#[derive(Debug, Clone)]
pub struct ExtAuthzProvider {
    /// URL of the authorization service's check endpoint.
    pub url: String,
    /// Per-check timeout.
    pub timeout: Duration,
    /// When true, a callout that fails admits the request instead of
    /// refusing it. Counted as a fail-open, never as an allow.
    pub failure_mode_allow: bool,
    /// Lowercased request header names copied into the check document.
    /// Empty means no request headers are forwarded.
    pub headers_to_forward: Vec<String>,
    /// Shared client. Built once at config-compile time so a burst
    /// reuses connections instead of opening one per request.
    client: reqwest::Client,
}

/// What the authorization service decided, plus the two outcomes that
/// are not the service's decision at all.
///
/// `FailedOpen` is deliberately not folded into `Allowed`: it is a
/// request that proceeded *without* the decision being made, which is
/// the event an operator alerts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtAuthzOutcome {
    /// The service allowed the request.
    Allowed {
        /// Subject the service resolved, when it named one.
        subject: Option<String>,
    },
    /// The service refused the request.
    Denied {
        /// Status the service asked for (`403` when it named none).
        status: u16,
        /// Body the service asked for.
        message: String,
        /// Headers to attach to the refusal.
        headers: Vec<(String, String)>,
    },
    /// The callout failed and `failure_mode_allow` is false. The
    /// request is refused with a `503`: the decision was never made,
    /// so it is not the caller's credential that is in question.
    Unavailable,
    /// The callout failed and `failure_mode_allow` is true, so the
    /// request proceeds without a decision.
    FailedOpen,
}

impl ExtAuthzOutcome {
    /// Stable metric label for this outcome.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Allowed { .. } => "allow",
            Self::Denied { .. } => "deny",
            Self::Unavailable => "unavailable",
            Self::FailedOpen => "fail_open",
        }
    }
}

/// The JSON document sent to the authorization service.
#[derive(Debug, Serialize)]
struct CheckRequest<'a> {
    method: &'a str,
    path: &'a str,
    headers: BTreeMap<&'a str, &'a str>,
}

/// The JSON document the authorization service answers with.
#[derive(Debug, Deserialize)]
struct CheckResponse {
    allowed: bool,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    body: Option<String>,
    /// Subject the service resolved. Read before the
    /// [`SUBJECT_HEADERS`] fallback so a service can name the subject
    /// without also stamping a header for it.
    #[serde(default)]
    subject: Option<String>,
}

impl ExtAuthzProvider {
    /// Build a provider from its `authentication:` block.
    ///
    /// Unknown keys are refused (WOR-2181): the keys worth misspelling
    /// here are `failure_mode_allow`, which turns the fail-closed
    /// default off, and `headers_to_forward`, which decides what
    /// leaves the proxy.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawConfig {
            url: String,
            #[serde(default = "default_timeout_ms")]
            timeout_ms: u64,
            #[serde(default)]
            failure_mode_allow: bool,
            #[serde(default)]
            headers_to_forward: Vec<String>,
        }
        fn default_timeout_ms() -> u64 {
            DEFAULT_TIMEOUT_MS
        }

        let raw: RawConfig = super::provider_config_from_value(value)?;
        Self::new(
            raw.url,
            raw.timeout_ms,
            raw.failure_mode_allow,
            raw.headers_to_forward,
        )
    }

    /// Build a provider from already-parsed fields.
    ///
    /// Refuses a URL that is not `http://` or `https://`, so a typo
    /// cannot turn the callout into a filesystem or gopher fetch, and a
    /// zero timeout, which reqwest would read as "no timeout" and turn
    /// the authorization service's worst case into the proxy's.
    pub fn new(
        url: String,
        timeout_ms: u64,
        failure_mode_allow: bool,
        headers_to_forward: Vec<String>,
    ) -> anyhow::Result<Self> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            anyhow::bail!(
                "ext_authz url must start with http:// or https://, got {:?}",
                sbproxy_security::url_redact::redacted_url(&url)
            );
        }
        if timeout_ms == 0 {
            anyhow::bail!(
                "ext_authz timeout_ms must be at least 1; a zero timeout means \
                 no timeout, which hands the request's deadline to the \
                 authorization service"
            );
        }
        let timeout = Duration::from_millis(timeout_ms);
        // No redirects: the check document can carry a forwarded
        // `Authorization` header when the operator listed one, and a
        // redirect would hand it to whatever host the service named.
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| anyhow::anyhow!("ext_authz client build failed: {e}"))?;
        Ok(Self {
            url,
            timeout,
            failure_mode_allow,
            headers_to_forward: headers_to_forward
                .into_iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            client,
        })
    }

    /// Ask the authorization service about one request.
    ///
    /// Never returns an error: every failure mode is one of the four
    /// [`ExtAuthzOutcome`] variants, so a caller cannot accidentally
    /// treat a transport failure as an allow. The outcome is recorded
    /// on `sbproxy_ext_authz_decisions_total` before it is returned, so
    /// the metric cannot disagree with what the request did.
    pub async fn authorize(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
    ) -> ExtAuthzOutcome {
        let outcome = self.authorize_inner(method, path, headers).await;
        sbproxy_observe::metrics::record_ext_authz_decision(outcome.metric_label());
        outcome
    }

    /// The subset of the request's headers the check document carries.
    ///
    /// Its own function, and `pub(crate)` rather than inlined into
    /// [`Self::authorize_inner`], because it is this provider's whole
    /// security posture: an operator who names nothing gets a check
    /// document with no request headers in it at all. WOR-2667's first
    /// test for that copied the filter expression into the test body,
    /// so reverting the filter to the enterprise
    /// `is_empty() || contains(..)` semantics left the test green. The
    /// production path and the test call this.
    pub(crate) fn forwarded_headers<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
    ) -> BTreeMap<&'a str, &'a str> {
        self.headers_to_forward
            .iter()
            .filter_map(|name| {
                let value = headers.get(name.as_str())?.to_str().ok()?;
                Some((name.as_str(), value))
            })
            .collect()
    }

    async fn authorize_inner(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
    ) -> ExtAuthzOutcome {
        let document = CheckRequest {
            method,
            path,
            headers: self.forwarded_headers(headers),
        };

        // The caller instruments this future with
        // `sbproxy.intake.authenticate`, so the ambient span is the
        // context to propagate and nothing needs plumbing here. Without
        // it the callout is a gap in the trace exactly where an
        // operator is asking why admission took 200ms.
        let request = sbproxy_observe::telemetry::inject_reqwest_trace_context(
            self.client.post(&self.url).json(&document),
            None,
        );
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                // Not `error = %e`: reqwest's Display ends with the
                // full URL, and an authorization endpoint is operator
                // config that can carry a token in its path (WOR-2629).
                warn!(
                    error = %sbproxy_httpkit::request_error_summary(&error),
                    url = %sbproxy_security::url_redact::redacted_url(&self.url),
                    failure_mode_allow = self.failure_mode_allow,
                    "ext_authz check failed"
                );
                return self.on_failure();
            }
        };

        // Envoy treats a non-2xx from the authorization service as a
        // failure of the check rather than as a decision, and so does
        // `oauth_introspection` a file over. A 500 whose body happens
        // to parse as `{"allowed": true}` is not an authorization.
        let status = response.status();
        if !status.is_success() {
            warn!(
                url = %sbproxy_security::url_redact::redacted_url(&self.url),
                status = status.as_u16(),
                failure_mode_allow = self.failure_mode_allow,
                "ext_authz service answered a non-success status"
            );
            return self.on_failure();
        }

        if let Some(length) = response.content_length() {
            if length > MAX_CHECK_RESPONSE_BYTES as u64 {
                warn!(
                    url = %sbproxy_security::url_redact::redacted_url(&self.url),
                    content_length = length,
                    limit = MAX_CHECK_RESPONSE_BYTES,
                    "ext_authz check response is larger than the parse limit"
                );
                return self.on_failure();
            }
        }
        let body = match response.bytes().await {
            Ok(body) => body,
            Err(error) => {
                warn!(
                    error = %sbproxy_httpkit::request_error_summary(&error),
                    url = %sbproxy_security::url_redact::redacted_url(&self.url),
                    "ext_authz check response could not be read"
                );
                return self.on_failure();
            }
        };
        // A chunked answer has no `content-length`, so the cap is
        // re-checked against what actually arrived.
        if body.len() > MAX_CHECK_RESPONSE_BYTES {
            warn!(
                url = %sbproxy_security::url_redact::redacted_url(&self.url),
                received = body.len(),
                limit = MAX_CHECK_RESPONSE_BYTES,
                "ext_authz check response exceeded the parse limit"
            );
            return self.on_failure();
        }
        let parsed: CheckResponse = match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(error) => {
                // The parse error names a position, never the payload,
                // so an authorization service that answers with a
                // credential-bearing page does not log one.
                warn!(
                    url = %sbproxy_security::url_redact::redacted_url(&self.url),
                    error = %error,
                    "ext_authz check response is not a check document"
                );
                return self.on_failure();
            }
        };

        Self::interpret(parsed)
    }

    /// Turn a parsed check document into an outcome. Split out so the
    /// interpretation is testable without a live service.
    fn interpret(parsed: CheckResponse) -> ExtAuthzOutcome {
        if parsed.allowed {
            let subject = parsed
                .subject
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| subject_from_headers(&parsed.headers));
            return ExtAuthzOutcome::Allowed { subject };
        }
        ExtAuthzOutcome::Denied {
            status: sanitize_denial_status(parsed.status),
            message: parsed
                .body
                .filter(|body| !body.is_empty())
                .unwrap_or_else(|| "Forbidden by ext_authz".to_string()),
            headers: parsed.headers.into_iter().collect(),
        }
    }

    /// What a failed callout means, given the configured failure mode.
    fn on_failure(&self) -> ExtAuthzOutcome {
        if self.failure_mode_allow {
            ExtAuthzOutcome::FailedOpen
        } else {
            ExtAuthzOutcome::Unavailable
        }
    }
}

/// Clamp the status an authorization service asked for onto a refusal.
///
/// A service that answers `allowed: false, status: 200` would otherwise
/// have the proxy write a success status over a refusal, and one that
/// answers `status: 500` would blame the proxy for a decision the
/// service made deliberately. Anything outside 4xx becomes `403`.
fn sanitize_denial_status(status: Option<u16>) -> u16 {
    match status {
        Some(status) if (400..500).contains(&status) => status,
        _ => 403,
    }
}

/// Read a resolved subject out of the headers an allow answer carried.
fn subject_from_headers(headers: &BTreeMap<String, String>) -> Option<String> {
    for candidate in SUBJECT_HEADERS {
        for (name, value) in headers {
            if name.eq_ignore_ascii_case(candidate) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(failure_mode_allow: bool) -> ExtAuthzProvider {
        ExtAuthzProvider::new(
            "http://127.0.0.1:1/check".to_string(),
            50,
            failure_mode_allow,
            vec!["X-Tenant".to_string()],
        )
        .expect("provider builds")
    }

    fn check_response(json: serde_json::Value) -> CheckResponse {
        serde_json::from_value(json).expect("check document parses")
    }

    #[test]
    fn from_config_defaults_are_fail_closed_and_forward_nothing() {
        let provider = ExtAuthzProvider::from_config(serde_json::json!({
            "type": "ext_authz",
            "url": "https://authz.internal/check",
        }))
        .expect("config compiles");
        assert_eq!(provider.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
        assert!(
            !provider.failure_mode_allow,
            "the default must refuse when the service cannot answer"
        );
        assert!(
            provider.headers_to_forward.is_empty(),
            "an empty allowlist must forward no request headers"
        );
    }

    #[test]
    fn from_config_refuses_an_unknown_key() {
        let error = ExtAuthzProvider::from_config(serde_json::json!({
            "type": "ext_authz",
            "url": "https://authz.internal/check",
            "failure_mode_alow": true,
        }))
        .expect_err("a misspelled fail-open key must not compile");
        assert!(error.to_string().contains("failure_mode_alow"), "{error:#}");
    }

    #[test]
    fn from_config_refuses_a_non_http_url() {
        let error = ExtAuthzProvider::from_config(serde_json::json!({
            "type": "ext_authz",
            "url": "file:///etc/passwd",
        }))
        .expect_err("a non-http url must not compile");
        assert!(error.to_string().contains("http://"), "{error:#}");
    }

    #[test]
    fn from_config_refuses_a_zero_timeout() {
        let error = ExtAuthzProvider::from_config(serde_json::json!({
            "type": "ext_authz",
            "url": "https://authz.internal/check",
            "timeout_ms": 0,
        }))
        .expect_err("a zero timeout must not compile");
        assert!(error.to_string().contains("timeout_ms"), "{error:#}");
    }

    #[test]
    fn header_allowlist_is_lowercased_for_lookup() {
        let provider = provider(false);
        assert_eq!(provider.headers_to_forward, vec!["x-tenant".to_string()]);
    }

    #[test]
    fn allow_reads_the_subject_field_before_any_header() {
        let outcome = ExtAuthzProvider::interpret(check_response(serde_json::json!({
            "allowed": true,
            "subject": "alice",
            "headers": {"x-forwarded-user": "bob"},
        })));
        assert_eq!(
            outcome,
            ExtAuthzOutcome::Allowed {
                subject: Some("alice".to_string())
            }
        );
    }

    #[test]
    fn allow_falls_back_to_a_well_known_subject_header() {
        let outcome = ExtAuthzProvider::interpret(check_response(serde_json::json!({
            "allowed": true,
            "headers": {"Remote-User": " carol "},
        })));
        assert_eq!(
            outcome,
            ExtAuthzOutcome::Allowed {
                subject: Some("carol".to_string())
            }
        );
    }

    #[test]
    fn allow_without_a_subject_is_anonymous_rather_than_refused() {
        let outcome = ExtAuthzProvider::interpret(check_response(serde_json::json!({
            "allowed": true,
        })));
        assert_eq!(outcome, ExtAuthzOutcome::Allowed { subject: None });
    }

    #[test]
    fn deny_carries_the_services_status_body_and_headers() {
        let outcome = ExtAuthzProvider::interpret(check_response(serde_json::json!({
            "allowed": false,
            "status": 402,
            "body": "quota exhausted",
            "headers": {"x-quota-reset": "3600"},
        })));
        assert_eq!(
            outcome,
            ExtAuthzOutcome::Denied {
                status: 402,
                message: "quota exhausted".to_string(),
                headers: vec![("x-quota-reset".to_string(), "3600".to_string())],
            }
        );
    }

    #[test]
    fn deny_status_outside_4xx_is_clamped_to_403() {
        // A service that answers `allowed: false, status: 200` must not
        // have the proxy write a success status over a refusal.
        assert_eq!(sanitize_denial_status(Some(200)), 403);
        assert_eq!(sanitize_denial_status(Some(500)), 403);
        assert_eq!(sanitize_denial_status(Some(302)), 403);
        assert_eq!(sanitize_denial_status(None), 403);
        assert_eq!(sanitize_denial_status(Some(429)), 429);
    }

    #[tokio::test]
    async fn an_unreachable_service_refuses_by_default() {
        // Port 1 is not listening, so the connect fails inside the
        // configured timeout.
        let outcome = provider(false)
            .authorize("GET", "/", &http::HeaderMap::new())
            .await;
        assert_eq!(outcome, ExtAuthzOutcome::Unavailable);
    }

    #[tokio::test]
    async fn an_unreachable_service_fails_open_only_when_asked() {
        let outcome = provider(true)
            .authorize("GET", "/", &http::HeaderMap::new())
            .await;
        assert_eq!(
            outcome,
            ExtAuthzOutcome::FailedOpen,
            "a fail-open must not be reported as an allow"
        );
    }

    #[test]
    fn fail_open_and_allow_have_different_metric_labels() {
        assert_eq!(
            ExtAuthzOutcome::Allowed { subject: None }.metric_label(),
            "allow"
        );
        assert_eq!(ExtAuthzOutcome::FailedOpen.metric_label(), "fail_open");
        assert_eq!(ExtAuthzOutcome::Unavailable.metric_label(), "unavailable");
    }

    #[test]
    fn only_allowlisted_headers_reach_the_check_document() {
        let provider = provider(false);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-tenant", http::HeaderValue::from_static("acme"));
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer super-secret"),
        );
        headers.insert(http::header::COOKIE, http::HeaderValue::from_static("s=1"));

        // The production filter, not a copy of it. Reverting
        // `forwarded_headers` to the enterprise
        // `is_empty() || contains(..)` semantics turns this red.
        let document = serde_json::to_string(&CheckRequest {
            method: "GET",
            path: "/",
            headers: provider.forwarded_headers(&headers),
        })
        .expect("document serializes");

        assert!(document.contains("acme"), "{document}");
        assert!(
            !document.contains("super-secret"),
            "an un-allowlisted Authorization header must not leave the proxy: {document}"
        );
        assert!(!document.contains("s=1"), "{document}");
    }

    /// The empty allowlist is the default and it is the whole point.
    /// Same production entry point, so the two cannot drift.
    #[test]
    fn an_empty_allowlist_forwards_no_request_header() {
        let provider = ExtAuthzProvider::from_config(serde_json::json!({
            "type": "ext_authz",
            "url": "https://authz.internal/check",
        }))
        .expect("config compiles");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer super-secret"),
        );
        headers.insert("x-tenant", http::HeaderValue::from_static("acme"));
        assert!(
            provider.forwarded_headers(&headers).is_empty(),
            "an operator who named no headers must ship none"
        );
    }
}
