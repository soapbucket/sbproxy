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

    /// Builds the configured TLS-verifying client.
    pub fn build(self) -> Result<reqwest::Client, reqwest::Error> {
        self.inner.build()
    }

    /// Returns the underlying reqwest builder for an integration-specific setting.
    #[must_use]
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
