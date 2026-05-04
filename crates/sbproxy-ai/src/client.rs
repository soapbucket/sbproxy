//! HTTP client for forwarding requests to AI providers.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::ai_metrics;
use crate::handler::AiHandlerConfig;
use crate::provider::ProviderConfig;
use crate::providers::{get_provider_info, ProviderFormat};
use crate::routing::Router;
use crate::translators;

/// Default upper bound on shadow requests in flight per `AiClient`.
/// Sized so a 1024-deep queue holding ~32 KB of request state per
/// task fits comfortably in well under 64 MB of resident memory,
/// while still absorbing burst traffic to a slow shadow provider.
pub const DEFAULT_SHADOW_MAX_INFLIGHT: usize = 1024;

/// Minimum interval between rate-limited shadow-overflow WARN log
/// lines. Bursts above this rate are coalesced into a single line.
const SHADOW_OVERFLOW_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Supervisor for shadow / side-by-side eval tasks.
///
/// Owns a bounded in-flight queue (`Semaphore`) so a slow or hung
/// shadow provider can never accumulate unbounded background tasks.
/// Each spawned task wraps `run_shadow_request` in
/// `tokio::time::timeout`; when the timeout elapses the future is
/// dropped (which aborts the in-flight reqwest connection) and the
/// `sbproxy_ai_shadow_timeout_total` counter ticks. When `try_acquire`
/// fails the supervisor logs at WARN at most once per minute and ticks
/// `sbproxy_ai_shadow_dropped_total`.
pub struct ShadowSupervisor {
    semaphore: Arc<Semaphore>,
    max_inflight: usize,
    /// Unix-epoch nanoseconds of the last overflow WARN log. `0`
    /// means "never logged"; `AtomicI64` because `Instant` is not
    /// portable to atomics and a wall-clock skew of a few seconds is
    /// fine for log-rate-limiting.
    last_warn_unix_nanos: AtomicI64,
}

impl ShadowSupervisor {
    /// Build a supervisor with the given in-flight bound.
    pub fn new(max_inflight: usize) -> Self {
        let bound = max_inflight.max(1);
        Self {
            semaphore: Arc::new(Semaphore::new(bound)),
            max_inflight: bound,
            last_warn_unix_nanos: AtomicI64::new(0),
        }
    }

    /// Maximum concurrent shadow tasks this supervisor will admit.
    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }

    /// Number of shadow slots currently free.
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Try to admit one shadow task. Returns the owned permit on
    /// success; on overflow, ticks `sbproxy_ai_shadow_dropped_total`,
    /// emits a rate-limited WARN, and returns `None`.
    fn try_admit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                ai_metrics::record_shadow_dropped();
                self.maybe_warn_overflow();
                None
            }
        }
    }

    /// Emit at most one overflow WARN per
    /// `SHADOW_OVERFLOW_WARN_INTERVAL`. Concurrent overflows are
    /// coalesced via a CAS on `last_warn_unix_nanos`.
    fn maybe_warn_overflow(&self) {
        let now_nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(i64::MAX);
        let interval_nanos = SHADOW_OVERFLOW_WARN_INTERVAL.as_nanos() as i64;
        loop {
            let last = self.last_warn_unix_nanos.load(Ordering::Relaxed);
            if last != 0 && now_nanos.saturating_sub(last) < interval_nanos {
                return;
            }
            // CAS so only one racer per window emits the WARN.
            if self
                .last_warn_unix_nanos
                .compare_exchange(last, now_nanos, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                warn!(
                    target: "sbproxy_ai_shadow",
                    max_inflight = self.max_inflight,
                    "shadow supervisor queue full; dropping shadow request (rate-limited)"
                );
                return;
            }
        }
    }
}

impl Default for ShadowSupervisor {
    fn default() -> Self {
        Self::new(DEFAULT_SHADOW_MAX_INFLIGHT)
    }
}

/// RAII guard that decrements the in-flight gauge when dropped.
struct ShadowInflightGuard;

impl ShadowInflightGuard {
    fn enter() -> Self {
        ai_metrics::inc_shadow_inflight();
        Self
    }
}

impl Drop for ShadowInflightGuard {
    fn drop(&mut self) {
        ai_metrics::dec_shadow_inflight();
    }
}

/// HTTP client that forwards AI requests to upstream providers.
pub struct AiClient {
    http: reqwest::Client,
    shadow_supervisor: Arc<ShadowSupervisor>,
}

impl AiClient {
    /// Create a new AI client with a shared reqwest::Client and a
    /// default-sized shadow supervisor (`DEFAULT_SHADOW_MAX_INFLIGHT`
    /// in-flight slots).
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            shadow_supervisor: Arc::new(ShadowSupervisor::default()),
        }
    }

    /// Create a new AI client with a custom shadow supervisor. Used
    /// by unit tests that need to drive overflow / timeout behavior
    /// at controlled queue depths.
    pub fn with_shadow_supervisor(supervisor: Arc<ShadowSupervisor>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            shadow_supervisor: supervisor,
        }
    }

    /// Borrow the shadow supervisor (test + diagnostic accessor).
    pub fn shadow_supervisor(&self) -> &Arc<ShadowSupervisor> {
        &self.shadow_supervisor
    }

    /// Forward a chat completions request to the selected provider.
    ///
    /// Selects a provider via the router, maps the model name if configured,
    /// and sends the request with the correct auth headers.
    ///
    /// When the response status is 5xx, a transport-level error
    /// occurs, or the request times out, the failure is recorded
    /// against the provider's circuit breaker and outlier detector.
    /// Up to `max_attempts` (default 1) total tries fan across
    /// different providers; subsequent attempts skip providers the
    /// resilience layer has already ejected.
    pub async fn forward_chat_request(
        &self,
        config: &AiHandlerConfig,
        router: &Router,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        // Shadow / side-by-side eval: fire a copy of the request at
        // the configured shadow provider concurrently with the
        // primary. The shadow response is logged + drained; the
        // primary response is what the client sees.
        if let Some(shadow_cfg) = config.shadow.as_ref() {
            let sampled = if shadow_cfg.sample_rate >= 1.0 {
                true
            } else if shadow_cfg.sample_rate <= 0.0 {
                false
            } else {
                rand::random::<f32>() < shadow_cfg.sample_rate
            };
            if sampled {
                if let Some(shadow_provider) = config
                    .providers
                    .iter()
                    .find(|p| p.name == shadow_cfg.provider)
                    .cloned()
                {
                    let http = self.http.clone();
                    let path_owned = path.to_string();
                    let body_owned = if let Some(model) = shadow_cfg.model.as_ref() {
                        let mut b = body.clone();
                        if let Some(obj) = b.as_object_mut() {
                            obj.insert(
                                "model".to_string(),
                                serde_json::Value::String(model.clone()),
                            );
                        }
                        b
                    } else {
                        body.clone()
                    };
                    let http_timeout_ms = shadow_cfg.timeout_ms;
                    let task_timeout_ms = shadow_cfg.task_timeout_ms;
                    let http_timeout = Duration::from_millis(http_timeout_ms);
                    let task_timeout = Duration::from_millis(task_timeout_ms);
                    // Bounded supervisor: try_admit returns None when
                    // the in-flight queue is full. On admit, we hold
                    // the OwnedSemaphorePermit + an inflight gauge
                    // guard inside the spawned task so both clean up
                    // automatically whether the future completes,
                    // times out, or is cancelled.
                    if let Some(permit) = self.shadow_supervisor.try_admit() {
                        tokio::spawn(async move {
                            let _permit = permit;
                            let _gauge = ShadowInflightGuard::enter();
                            match tokio::time::timeout(
                                task_timeout,
                                run_shadow_request(
                                    http,
                                    shadow_provider,
                                    path_owned,
                                    body_owned,
                                    http_timeout,
                                ),
                            )
                            .await
                            {
                                Ok(()) => {}
                                Err(_) => {
                                    ai_metrics::record_shadow_timeout();
                                    warn!(
                                        target: "sbproxy_ai_shadow",
                                        timeout_ms = task_timeout_ms,
                                        "shadow request exceeded supervisor timeout; dropping"
                                    );
                                }
                            }
                        });
                    }
                } else {
                    warn!(
                        provider = %shadow_cfg.provider,
                        "shadow target not found in providers list"
                    );
                }
            }
        }

        // Race strategy: fan out to every eligible provider in
        // parallel, return the first 2xx, cancel the losers. The
        // resilience layer's record_provider_* signals still apply
        // to each leg so persistently slow providers eventually get
        // ejected from the eligible set.
        if router.is_race() {
            return self.forward_race(config, router, path, body).await;
        }

        let max_attempts = config.resilience_max_attempts();
        let mut last_err: Option<anyhow::Error> = None;
        let mut attempted_indices: Vec<usize> = Vec::with_capacity(max_attempts);

        for _ in 0..max_attempts {
            let provider_idx = router.select(&config.providers).ok_or_else(|| {
                last_err
                    .as_ref()
                    .map(|e| anyhow::anyhow!("all providers failed: {e}"))
                    .unwrap_or_else(|| anyhow::anyhow!("no enabled providers available"))
            })?;

            // If the resilience layer happens to keep selecting the
            // same provider (small pool, all others ejected) bail out
            // rather than retry the same dead provider repeatedly.
            if attempted_indices.contains(&provider_idx) && !attempted_indices.is_empty() {
                break;
            }
            attempted_indices.push(provider_idx);
            let provider = &config.providers[provider_idx];

            match self.forward_request(provider, path, body).await {
                Ok(resp) if resp.status().is_server_error() => {
                    router.record_provider_failure(provider_idx, provider.name.as_str());
                    let status = resp.status();
                    last_err = Some(anyhow::anyhow!(
                        "provider {} returned {}",
                        provider.name,
                        status
                    ));
                    // Don't return the 5xx body to caller; try next provider.
                    continue;
                }
                Ok(resp) => {
                    router.record_provider_success(provider_idx, provider.name.as_str());
                    return Ok(resp);
                }
                Err(e) => {
                    router.record_provider_failure(provider_idx, provider.name.as_str());
                    last_err = Some(e);
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no providers attempted")))
    }

    /// Forward a request to a specific provider.
    ///
    /// Builds the full URL from the provider's base URL + path,
    /// sets the auth header, and sends the JSON body. When the
    /// provider speaks a non-OpenAI wire format (Anthropic Messages
    /// API today), the body and path are translated before sending.
    /// Response bodies are returned untranslated; callers route them
    /// through `translators::translate_response_bytes` after reading.
    pub async fn forward_request(
        &self,
        provider: &ProviderConfig,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        let format = provider_format(provider);
        let (translated_body, translated_path) =
            translators::translate_request(format, path, body.clone());

        let base_url_owned = provider.effective_base_url();
        let base_url = base_url_owned.trim_end_matches('/');
        let url = build_url(base_url, &translated_path);

        let (auth_header, auth_value) = provider.auth_header();

        debug!(
            url = %url,
            provider = %provider.name,
            format = ?format,
            auth_header = %auth_header,
            "forwarding AI request to provider"
        );

        let mut req = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .header(auth_header, &auth_value);

        // Anthropic requires an api-version header; default the most
        // widely deployed value when the caller didn't set one.
        if matches!(format, ProviderFormat::Anthropic) {
            req = req.header("anthropic-version", "2023-06-01");
        }

        let resp = req.json(&translated_body).send().await?;

        Ok(resp)
    }

    /// Forward a GET request to a specific provider (for /v1/models).
    pub async fn forward_get_request(
        &self,
        provider: &ProviderConfig,
        path: &str,
    ) -> Result<reqwest::Response> {
        let base_url_owned = provider.effective_base_url();
        let base_url = base_url_owned.trim_end_matches('/');
        let url = build_url(base_url, path);

        let (auth_header, auth_value) = provider.auth_header();

        debug!(
            url = %url,
            provider = %provider.name,
            "forwarding AI GET request to provider"
        );

        let resp = self
            .http
            .get(&url)
            .header(auth_header, &auth_value)
            .send()
            .await?;

        Ok(resp)
    }
}

impl AiClient {
    async fn forward_race(
        &self,
        config: &AiHandlerConfig,
        router: &Router,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response> {
        use futures::stream::{FuturesUnordered, StreamExt};

        let candidates = router.eligible_indices(&config.providers);
        if candidates.is_empty() {
            return Err(anyhow::anyhow!("no eligible providers for race"));
        }
        if candidates.len() == 1 {
            // No race needed; single provider just forwards.
            let idx = candidates[0];
            let p = &config.providers[idx];
            return match self.forward_request(p, path, body).await {
                Ok(r) if r.status().is_server_error() => {
                    router.record_provider_failure(idx, p.name.as_str());
                    Err(anyhow::anyhow!(
                        "race fallback provider {} returned {}",
                        p.name,
                        r.status()
                    ))
                }
                Ok(r) => {
                    router.record_provider_success(idx, p.name.as_str());
                    Ok(r)
                }
                Err(e) => {
                    router.record_provider_failure(idx, p.name.as_str());
                    Err(e)
                }
            };
        }

        let mut tasks = FuturesUnordered::new();
        for idx in &candidates {
            let provider = config.providers[*idx].clone();
            let path_owned = path.to_string();
            let body_owned = body.clone();
            let http = self.http.clone();
            let i = *idx;
            tasks.push(async move {
                let format = provider_format(&provider);
                let (translated_body, translated_path) =
                    translators::translate_request(format, &path_owned, body_owned);
                let base_url_owned = provider.effective_base_url();
                let base_url = base_url_owned.trim_end_matches('/');
                let url = build_url(base_url, &translated_path);
                let (auth_header, auth_value) = provider.auth_header();
                let mut req = http
                    .post(&url)
                    .header("content-type", "application/json")
                    .header(auth_header, &auth_value);
                if matches!(format, ProviderFormat::Anthropic) {
                    req = req.header("anthropic-version", "2023-06-01");
                }
                let resp = req.json(&translated_body).send().await;
                (i, provider, resp)
            });
        }

        let mut last_err: Option<anyhow::Error> = None;
        while let Some((idx, provider, result)) = tasks.next().await {
            match result {
                Ok(resp) if resp.status().is_server_error() => {
                    router.record_provider_failure(idx, provider.name.as_str());
                    last_err = Some(anyhow::anyhow!(
                        "race leg {} returned {}",
                        provider.name,
                        resp.status()
                    ));
                    continue;
                }
                Ok(resp) => {
                    router.record_provider_success(idx, provider.name.as_str());
                    debug!(
                        provider = %provider.name,
                        "race leg won; cancelling {} losers",
                        candidates.len() - 1
                    );
                    // Drop the remaining FuturesUnordered to cancel
                    // the in-flight requests. Tokio cancels the
                    // pending sends; reqwest aborts the connection.
                    drop(tasks);
                    return Ok(resp);
                }
                Err(e) => {
                    router.record_provider_failure(idx, provider.name.as_str());
                    last_err = Some(anyhow::Error::from(e));
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("race exhausted")))
    }
}

/// Fire a single shadow request at `provider`, log the metadata, and
/// drain the body so connections return to the pool.
async fn run_shadow_request(
    http: reqwest::Client,
    provider: ProviderConfig,
    path: String,
    body: serde_json::Value,
    timeout: std::time::Duration,
) {
    let format = provider_format(&provider);
    let (translated_body, translated_path) = translators::translate_request(format, &path, body);
    let base_url_owned = provider.effective_base_url();
    let base_url = base_url_owned.trim_end_matches('/');
    let url = build_url(base_url, &translated_path);
    let (auth_header, auth_value) = provider.auth_header();
    let started = std::time::Instant::now();
    let mut req = http
        .post(&url)
        .header("content-type", "application/json")
        .header(auth_header, &auth_value)
        .header("x-sbproxy-shadow", "1")
        .json(&translated_body)
        .timeout(timeout);
    if matches!(format, ProviderFormat::Anthropic) {
        req = req.header("anthropic-version", "2023-06-01");
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(provider = %provider.name, error = %e, "shadow request transport error");
            return;
        }
    };
    let status = resp.status();
    let raw_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            warn!(provider = %provider.name, error = %e, "shadow body drain failed");
            return;
        }
    };
    // Translate non-OpenAI shadow responses into OpenAI shape so the
    // metadata parsing below works uniformly across providers.
    let bytes_vec = translators::translate_response_bytes(format, &raw_bytes);
    let bytes: &[u8] = &bytes_vec;
    let elapsed = started.elapsed();
    let (prompt_tokens, completion_tokens, finish_reason) = parse_shadow_metadata(bytes);
    info!(
        target: "sbproxy_ai_shadow",
        provider = %provider.name,
        status = %status,
        latency_ms = elapsed.as_millis() as u64,
        bytes = bytes.len(),
        prompt_tokens = ?prompt_tokens,
        completion_tokens = ?completion_tokens,
        finish_reason = ?finish_reason,
        "shadow response"
    );
}

/// Best-effort extraction of token counts and finish_reason from an
/// OpenAI-shaped response body. Returns `None`s when the upstream
/// shape differs.
fn parse_shadow_metadata(body: &[u8]) -> (Option<u64>, Option<u64>, Option<String>) {
    let v: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (None, None, None),
    };
    let prompt = v
        .get("usage")
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|n| n.as_u64());
    let completion = v
        .get("usage")
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|n| n.as_u64());
    let finish = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("finish_reason"))
        .and_then(|s| s.as_str())
        .map(str::to_string);
    (prompt, completion, finish)
}

impl Default for AiClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Look up a provider's wire format. Falls back to `OpenAi` (the
/// pass-through path) for unknown / custom provider names so existing
/// configurations keep working unchanged.
pub fn provider_format(provider: &ProviderConfig) -> ProviderFormat {
    get_provider_info(&provider.name)
        .map(|info| info.format)
        .unwrap_or(ProviderFormat::OpenAi)
}

/// Build a full URL from base_url and path, handling version prefix overlap.
///
/// If the base_url already includes a version path (e.g. /v1) and the
/// request path starts with the same version prefix, we strip the
/// overlapping portion from the path to avoid duplication.
///
/// Examples:
/// ```text
/// base="http://host:18889/v1", path="/v1/chat/completions"
///   -> "http://host:18889/v1/chat/completions"
/// base="http://api.groq.com/openai/v1", path="/v1/chat/completions"
///   -> "http://api.groq.com/openai/v1/chat/completions"
/// ```
fn build_url(base_url: &str, path: &str) -> String {
    // Extract the last path segment from the base URL to check for overlap.
    // e.g. "http://host:8080/openai/v1" -> last segment is "/v1"
    if let Some(scheme_end) = base_url.find("://") {
        let after_scheme = &base_url[scheme_end + 3..];
        // Find the first slash after the host (start of path portion).
        if let Some(host_end) = after_scheme.find('/') {
            let base_path = &after_scheme[host_end..]; // e.g. "/openai/v1" or "/v1"
                                                       // Check if the request path starts with the last segment of the base path.
                                                       // e.g. base_path="/openai/v1", path="/v1/chat/completions"
                                                       // We want to find that "/v1" is at the end of base_path and start of path.
            if let Some(last_slash) = base_path.rfind('/') {
                let last_segment = &base_path[last_slash..]; // e.g. "/v1"
                if !last_segment.is_empty() && last_segment != "/" && path.starts_with(last_segment)
                {
                    // Strip the overlapping prefix from path.
                    let remainder = &path[last_segment.len()..]; // e.g. "/chat/completions"
                    return format!("{}{}", base_url, remainder);
                }
            }
        }
    }
    format!("{}{}", base_url, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_with_v1_overlap() {
        let url = build_url("http://127.0.0.1:18889/v1", "/v1/chat/completions");
        assert_eq!(url, "http://127.0.0.1:18889/v1/chat/completions");
    }

    #[test]
    fn build_url_no_overlap() {
        let url = build_url("http://127.0.0.1:18889", "/v1/chat/completions");
        assert_eq!(url, "http://127.0.0.1:18889/v1/chat/completions");
    }

    #[test]
    fn build_url_different_path_prefix() {
        let url = build_url("http://api.example.com/openai/v1", "/v1/chat/completions");
        assert_eq!(url, "http://api.example.com/openai/v1/chat/completions");
    }

    #[test]
    fn build_url_https() {
        let url = build_url("https://api.openai.com/v1", "/v1/models");
        assert_eq!(url, "https://api.openai.com/v1/models");
    }

    #[test]
    fn build_url_no_scheme() {
        // Edge case: no scheme, just concatenate
        let url = build_url("localhost:8080", "/v1/chat/completions");
        assert_eq!(url, "localhost:8080/v1/chat/completions");
    }

    // --- Shadow supervisor tests ---
    //
    // These exercise the bounded-supervisor wrapper around
    // `run_shadow_request`. Each test drives a stand-in shadow future
    // through `tokio::time::timeout` plus the `ShadowSupervisor`
    // semaphore so the production cancellation + bookkeeping paths
    // are covered without needing a live HTTP server.

    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    #[tokio::test]
    async fn shadow_supervisor_succeeds_within_timeout() {
        // Note: the shadow_dropped_total and shadow_timeout_total
        // counters are process-wide LazyLock prometheus statics, so
        // concurrent tests in this module will tick them too. We only
        // assert this test's local supervisor + inflight permit
        // bookkeeping, not the global counter values.
        let supervisor = ShadowSupervisor::new(8);
        let counter = Arc::new(AtomicU64::new(0));

        let permit = supervisor.try_admit().expect("queue has room");
        let counter_in = counter.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            let _gauge = ShadowInflightGuard::enter();
            let res = tokio::time::timeout(Duration::from_millis(500), async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                counter_in.fetch_add(1, AtomicOrdering::SeqCst);
            })
            .await;
            assert!(res.is_ok(), "fast shadow future should not time out");
        });
        task.await.unwrap();

        assert_eq!(counter.load(AtomicOrdering::SeqCst), 1);
        // Permit dropped: full queue width restored.
        assert_eq!(supervisor.available(), 8);
    }

    #[tokio::test]
    async fn shadow_supervisor_records_timeout_when_future_hangs() {
        let supervisor = ShadowSupervisor::new(4);
        let timeout_before = ai_metrics::shadow_timeout_value();

        let permit = supervisor.try_admit().expect("queue has room");
        let task = tokio::spawn(async move {
            let _permit = permit;
            let _gauge = ShadowInflightGuard::enter();
            // The supervisor timeout is 50ms; the inner future sleeps
            // for 5s. tokio::time::timeout must drop the inner future
            // and the supervisor must tick the timeout counter.
            let res = tokio::time::timeout(Duration::from_millis(50), async {
                tokio::time::sleep(Duration::from_secs(5)).await;
            })
            .await;
            if res.is_err() {
                ai_metrics::record_shadow_timeout();
            }
            assert!(res.is_err(), "slow future should time out");
        });
        task.await.unwrap();

        assert_eq!(supervisor.available(), 4);
        assert!(
            ai_metrics::shadow_timeout_value() - timeout_before >= 1.0,
            "shadow_timeout_total should have ticked"
        );
    }

    #[tokio::test]
    async fn shadow_supervisor_drops_request_when_queue_full() {
        let supervisor = ShadowSupervisor::new(2);
        let dropped_before = ai_metrics::shadow_dropped_value();

        // Fill every slot. Hold the permits across the test so the
        // semaphore stays at zero.
        let p1 = supervisor.try_admit().expect("first admit ok");
        let p2 = supervisor.try_admit().expect("second admit ok");
        assert_eq!(supervisor.available(), 0);

        // Third try must return None and tick the dropped counter.
        let denied = supervisor.try_admit();
        assert!(denied.is_none(), "queue must reject when full");
        assert!(
            ai_metrics::shadow_dropped_value() - dropped_before >= 1.0,
            "shadow_dropped_total should have ticked"
        );

        // Releasing one slot lets a new request in again.
        drop(p1);
        let p3 = supervisor.try_admit().expect("admit after release");
        drop(p2);
        drop(p3);
        assert_eq!(supervisor.available(), 2);
    }
}
