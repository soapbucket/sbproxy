//! Bounded, TLS-verifying HTTP clients for outbound integrations.

use std::time::Duration;

use reqwest::redirect::Policy;

/// The maximum time allowed to establish an outbound TCP connection.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The maximum time allowed for a complete outbound request.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The idle lifetime of a pooled outbound connection.
pub const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// The maximum number of idle connections retained for one host.
pub const DEFAULT_MAX_IDLE_PER_HOST: usize = 64;
/// The maximum number of redirects for outbound requests without credentials.
pub const DEFAULT_REDIRECT_LIMIT: usize = 2;
/// The user agent sent by outbound integration clients.
pub const USER_AGENT: &str = concat!("sbproxy/", env!("CARGO_PKG_VERSION"));

/// Builds outbound clients with sbproxy's bounded defaults.
///
/// The builder intentionally has no option to disable TLS certificate
/// verification. Call [`Self::no_redirects`] for requests that carry bearer
/// credentials, so a redirect cannot forward those credentials to another
/// endpoint.
pub struct OutboundClientBuilder {
    inner: reqwest::ClientBuilder,
}

impl OutboundClientBuilder {
    /// Creates a builder configured with sbproxy's bounded defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: reqwest::Client::builder()
                .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
                .timeout(DEFAULT_REQUEST_TIMEOUT)
                .pool_idle_timeout(DEFAULT_POOL_IDLE_TIMEOUT)
                .pool_max_idle_per_host(DEFAULT_MAX_IDLE_PER_HOST)
                .redirect(Policy::limited(DEFAULT_REDIRECT_LIMIT))
                .user_agent(USER_AGENT),
        }
    }

    /// Sets the maximum time allowed to establish a connection.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.connect_timeout(timeout);
        self
    }

    /// Sets the maximum time allowed for the complete request.
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    /// Sets how long an idle pooled connection is retained.
    #[must_use]
    pub fn pool_idle_timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.pool_idle_timeout(timeout);
        self
    }

    /// Sets the maximum number of idle pooled connections retained per host.
    #[must_use]
    pub fn max_idle_per_host(mut self, maximum: usize) -> Self {
        self.inner = self.inner.pool_max_idle_per_host(maximum);
        self
    }

    /// Disables redirects, for use with bearer credentials.
    #[must_use]
    pub fn no_redirects(mut self) -> Self {
        self.inner = self.inner.redirect(Policy::none());
        self
    }

    /// Follows at most `maximum` redirects.
    #[must_use]
    pub fn limited_redirects(mut self, maximum: usize) -> Self {
        self.inner = self.inner.redirect(Policy::limited(maximum));
        self
    }

    /// Sets the HTTP user agent.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.inner = self.inner.user_agent(user_agent.into());
        self
    }

    /// Pins `domain` to the given socket addresses instead of re-resolving it.
    ///
    /// Requests keep the original URL host (so TLS verification and the
    /// `Host` header are unchanged) but dial only the pinned addresses.
    /// Callers that validated a hostname against an SSRF policy use this to
    /// close the gap between validation-time resolution and dial-time
    /// resolution (DNS rebinding).
    #[must_use]
    pub fn resolve_to_addrs(mut self, domain: &str, addrs: &[std::net::SocketAddr]) -> Self {
        self.inner = self.inner.resolve_to_addrs(domain, addrs);
        self
    }

    /// Builds the configured TLS-verifying client.
    pub fn build(self) -> Result<reqwest::Client, reqwest::Error> {
        self.inner.build()
    }

    /// Returns the underlying reqwest builder for an integration-specific setting.
    ///
    /// This transfers responsibility to the caller for preserving TLS verification
    /// and the outbound security defaults while applying further customization.
    /// Normal callers should prefer [`Self::build`].
    pub fn into_inner(self) -> reqwest::ClientBuilder {
        self.inner
    }
}

impl Default for OutboundClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the bounded client for outbound requests without bearer credentials.
#[must_use]
pub fn default_outbound() -> reqwest::Client {
    OutboundClientBuilder::new()
        .limited_redirects(DEFAULT_REDIRECT_LIMIT)
        .build()
        .expect("the fixed sbproxy outbound client configuration is valid")
}

/// Returns the bounded client for outbound requests carrying bearer credentials.
#[must_use]
pub fn token_bearing_outbound() -> reqwest::Client {
    OutboundClientBuilder::new()
        .no_redirects()
        .build()
        .expect("the fixed sbproxy outbound client configuration is valid")
}

/// Number of characters of a wrapped error's own message that are kept.
///
/// The text comes from hyper, rustls, or the resolver rather than from
/// this workspace, so it is bounded here rather than trusted to be short.
const SOURCE_DETAIL_MAX_CHARS: usize = 200;

/// Render a [`reqwest::Error`] in a form that is safe to put in a log
/// line, an error string, or an event field.
///
/// `reqwest::Error`'s own `Display` ends with `" for url ({url})"`, so
/// interpolating one directly writes the full request URL, path and query
/// included. Userinfo is stripped when the request is built, but for a
/// Slack, Teams, or PagerDuty webhook the path *is* the credential, so the
/// URL is not something a failure line can carry (WOR-2629).
///
/// This returns the failure class plus the wrapped error's own message.
/// The URL appears in neither: reqwest keeps it on the outer error only,
/// never on the source it wraps. Log the target separately, through
/// `sbproxy_security::url_redact::redacted_url`.
///
/// ```no_run
/// # async fn example(client: &reqwest::Client) {
/// use sbproxy_httpkit::request_error_summary;
/// if let Err(error) = client.get("https://example.test").send().await {
///     // Safe to log. `format!("{error}")` would carry path and query.
///     let summary = request_error_summary(&error);
///     assert!(!summary.contains("example.test"));
/// }
/// # }
/// ```
#[must_use]
pub fn request_error_summary(error: &reqwest::Error) -> String {
    let class = if error.is_timeout() {
        "request timed out".to_string()
    } else if error.is_connect() {
        "connection failed".to_string()
    } else if let Some(status) = error.status() {
        format!("http status {}", status.as_u16())
    } else if error.is_body() {
        "body transfer failed".to_string()
    } else if error.is_decode() {
        "response decode failed".to_string()
    } else if error.is_redirect() {
        "redirect policy refused the response".to_string()
    } else if error.is_builder() {
        "request could not be built".to_string()
    } else {
        "request failed".to_string()
    };

    let Some(source) = std::error::Error::source(error) else {
        return class;
    };
    let detail: String = source
        .to_string()
        .chars()
        .take(SOURCE_DETAIL_MAX_CHARS)
        .collect();
    if detail.is_empty() {
        class
    } else {
        format!("{class}: {detail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the rest of the workspace relies on: whatever shape a
    /// `reqwest::Error` arrives in, its URL does not come out the other
    /// side. Interpolating the error directly is what does.
    #[tokio::test]
    async fn a_summary_never_carries_the_request_url() {
        let client = OutboundClientBuilder::new()
            .connect_timeout(Duration::from_millis(50))
            .request_timeout(Duration::from_millis(50))
            .build()
            .expect("the bounded test client builds");
        // Loopback port 1: refused immediately, no name resolution and no
        // packet leaves the host, so this stays an offline test.
        let url = "http://127.0.0.1:1/services/T0/B0/xoxb-path-secret?token=q";
        let error = client
            .get(url)
            .send()
            .await
            .expect_err("TEST-NET-1 discards the connection");

        // The direct interpolation is the leak this function exists to
        // replace, so assert it is real before asserting the fix.
        let direct = format!("{error}");
        assert!(direct.contains("xoxb-path-secret"), "got: {direct}");

        let summary = request_error_summary(&error);
        assert!(!summary.contains("xoxb-path-secret"), "got: {summary}");
        assert!(!summary.contains("127.0.0.1"), "got: {summary}");
        assert!(!summary.contains("token=q"), "got: {summary}");
        assert!(!summary.is_empty());
    }

    /// A refusal that happens before any dial still attaches the URL to
    /// the error, so the builder class needs the same treatment.
    #[tokio::test]
    async fn a_builder_failure_is_classed_without_its_url() {
        let error = default_outbound()
            .get("ftp://aclname:topsecret@example.test/path-secret")
            .send()
            .await
            .expect_err("ftp is not a supported scheme");

        let summary = request_error_summary(&error);
        assert!(!summary.contains("topsecret"), "got: {summary}");
        assert!(!summary.contains("path-secret"), "got: {summary}");
        assert!(
            summary.starts_with("request could not be built"),
            "got: {summary}"
        );
    }
}
