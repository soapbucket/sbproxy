//! Single-provider judge client.
//!
//! Wires up a [`reqwest::Client`], a [`super::JudgeCache`], and a
//! [`super::BudgetTracker`] behind one async entry point. The
//! configured provider is BYOK: the bearer token is read from the
//! environment variable named in [`JudgeConfig::api_key_env`].
//!
//! The judge is expected to speak an OpenAI-compatible chat
//! completions shape. We send:
//!
//! ```json
//! { "messages": [{"role": "system", "content": "<prompt>"},
//!                {"role": "user",   "content": <payload>}] }
//! ```
//!
//! and accept either:
//!
//! 1. A direct verdict body: `{"verdict": "allow" | "deny",
//!    "message": "<optional>"}`. This is the shape produced by an
//!    in-VPC classifier or a thin facilitator endpoint.
//! 2. A chat-completions body: `{"choices": [{"message":
//!    {"content": "<json with verdict>"}}], "usage": {...}}`. The
//!    `content` field is parsed as JSON and must yield the same
//!    `verdict` key. This is what a frontier model in JSON mode
//!    returns.
//!
//! Anything else surfaces as [`JudgeError::MalformedResponse`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use sbproxy_plugin::PolicyDecision;
use serde_json::Value as Json;
use tracing::{debug, warn};

use super::budget::BudgetTracker;
use super::cache::{cache_key, JudgeCache};
use super::telemetry::{
    record_budget_exhausted, record_judge_call, VERDICT_ALLOW, VERDICT_ALLOW_WITH_HEADERS,
    VERDICT_CONFIRM, VERDICT_DENY, VERDICT_ERROR,
};
use super::{JudgeConfig, JudgeError};

/// Per-call token charge applied when the upstream does not report
/// usage. A judge call never costs less than one budget unit so a
/// runaway loop cannot drain the budget for free; this is the floor.
const DEFAULT_TOKEN_COST: u64 = 1;

/// HTTP-status threshold above which we surface
/// [`JudgeError::ProviderError`] without trying to parse the body.
const PROVIDER_ERROR_THRESHOLD: u16 = 400;

/// Single-provider judge client.
///
/// Cheap to clone (`Arc`-backed cache and budget). Build one per
/// configuration block at startup; do not rebuild per request.
#[derive(Clone)]
pub struct JudgeClient {
    config: Arc<JudgeConfig>,
    http: reqwest::Client,
    cache: Arc<JudgeCache>,
    budget: Arc<BudgetTracker>,
    /// Stable provider tag attached to all metrics. Derived from
    /// the endpoint host so dashboards can filter by upstream
    /// without exposing the full URL.
    provider_label: String,
    /// Tenant identifier used on the budget-exhausted counter.
    /// Empty when the runtime is single-tenant.
    tenant_label: String,
}

impl JudgeClient {
    /// Build a new client. The `reqwest::Client` is configured with
    /// the per-call timeout from `config`; cache and budget are
    /// sized from the same config block.
    pub fn new(config: JudgeConfig) -> Self {
        Self::with_tenant(config, String::new())
    }

    /// Build a new client tagged with a tenant identifier. The
    /// tenant string is attached to the
    /// `sbproxy_judge_budget_exhausted_total{tenant}` counter so
    /// dashboards can break out budget-exhaustion alerts per
    /// tenant. Pass an empty string in single-tenant deployments.
    pub fn with_tenant(config: JudgeConfig, tenant: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(u64::from(config.timeout_ms)))
            .build()
            .unwrap_or_default();
        let provider_label = config.endpoint.host_str().unwrap_or("unknown").to_string();
        let cache = Arc::new(JudgeCache::new(config.cache_capacity));
        let budget = Arc::new(BudgetTracker::new(config.budget_tokens));
        Self {
            config: Arc::new(config),
            http,
            cache,
            budget,
            provider_label,
            tenant_label: tenant,
        }
    }

    /// Build a client around already-allocated cache and budget
    /// instances. Used by the tests, and by future enterprise wiring
    /// that swaps the cache for a Redis-backed implementation.
    pub fn with_components(
        config: JudgeConfig,
        cache: Arc<JudgeCache>,
        budget: Arc<BudgetTracker>,
        tenant: String,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(u64::from(config.timeout_ms)))
            .build()
            .unwrap_or_default();
        let provider_label = config.endpoint.host_str().unwrap_or("unknown").to_string();
        Self {
            config: Arc::new(config),
            http,
            cache,
            budget,
            provider_label,
            tenant_label: tenant,
        }
    }

    /// Borrow the underlying cache. Test + diagnostic accessor.
    pub fn cache(&self) -> &Arc<JudgeCache> {
        &self.cache
    }

    /// Borrow the underlying budget tracker. Test + diagnostic
    /// accessor.
    pub fn budget(&self) -> &Arc<BudgetTracker> {
        &self.budget
    }

    /// Evaluate `prompt` over `payload`.
    ///
    /// Behaviour:
    ///
    /// 1. Compute the cache key. On hit, return the stored verdict
    ///    and tick the calls counter with `cached="true"`. The
    ///    budget is **not** charged on a cache hit.
    /// 2. On miss, charge the budget. If the budget is empty,
    ///    return [`JudgeError::BudgetExhausted`]. The caller
    ///    converts to `PolicyDecision::Deny` per the ADR.
    /// 3. POST to the configured endpoint. Map non-success statuses
    ///    to [`JudgeError::ProviderError`] (or `BudgetExhausted` for
    ///    a 429, treated as upstream-side throttling).
    /// 4. Parse the response into a `PolicyDecision`. Cache it.
    /// 5. Record metrics and return.
    pub async fn semantic(
        &self,
        prompt: &str,
        payload: Json,
    ) -> Result<PolicyDecision, JudgeError> {
        let started = Instant::now();
        let key = cache_key(prompt, &payload);

        // --- Cache hit: shortcut everything else ---
        if let Some(cached) = self.cache.get(key) {
            let elapsed = started.elapsed().as_secs_f64();
            record_judge_call(
                &self.provider_label,
                verdict_label(&cached),
                true,
                elapsed,
                0.0,
            );
            return Ok(cached);
        }

        // --- Budget gate: hard fail before any network I/O ---
        if let Err(_e) = self.budget.charge(DEFAULT_TOKEN_COST) {
            record_budget_exhausted(&self.tenant_label);
            let elapsed = started.elapsed().as_secs_f64();
            record_judge_call(&self.provider_label, VERDICT_ERROR, false, elapsed, 0.0);
            return Err(JudgeError::BudgetExhausted);
        }

        // --- Live provider call ---
        let api_key = std::env::var(&self.config.api_key_env).unwrap_or_default();
        let body = serde_json::json!({
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": payload},
            ],
        });

        let result = self
            .http
            .post(self.config.endpoint.as_str())
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", api_key))
            .json(&body)
            .send()
            .await;

        let response = match result {
            Ok(resp) => resp,
            Err(err) if err.is_timeout() => {
                let elapsed = started.elapsed().as_secs_f64();
                record_judge_call(&self.provider_label, VERDICT_ERROR, false, elapsed, 0.0);
                warn!(
                    target: "sbproxy_judge",
                    provider = %self.provider_label,
                    "judge call timed out"
                );
                return Err(JudgeError::Timeout);
            }
            Err(err) => {
                let elapsed = started.elapsed().as_secs_f64();
                record_judge_call(&self.provider_label, VERDICT_ERROR, false, elapsed, 0.0);
                warn!(
                    target: "sbproxy_judge",
                    provider = %self.provider_label,
                    error = %err,
                    "judge call transport error"
                );
                return Err(JudgeError::ProviderError(err.to_string()));
            }
        };

        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            // Upstream-reported throttling collapses into the
            // budget-exhausted hard-fail path so the caller sees a
            // single failure mode and operators see a single
            // alert.
            record_budget_exhausted(&self.tenant_label);
            let elapsed = started.elapsed().as_secs_f64();
            record_judge_call(&self.provider_label, VERDICT_ERROR, false, elapsed, 0.0);
            return Err(JudgeError::BudgetExhausted);
        }
        if status.as_u16() >= PROVIDER_ERROR_THRESHOLD {
            let elapsed = started.elapsed().as_secs_f64();
            record_judge_call(&self.provider_label, VERDICT_ERROR, false, elapsed, 0.0);
            return Err(JudgeError::ProviderError(format!(
                "upstream returned {}",
                status
            )));
        }

        let body_text = match response.text().await {
            Ok(t) => t,
            Err(err) => {
                let elapsed = started.elapsed().as_secs_f64();
                record_judge_call(&self.provider_label, VERDICT_ERROR, false, elapsed, 0.0);
                return Err(JudgeError::ProviderError(format!(
                    "read body failed: {err}"
                )));
            }
        };

        let parsed: Json = match serde_json::from_str(&body_text) {
            Ok(v) => v,
            Err(err) => {
                let elapsed = started.elapsed().as_secs_f64();
                record_judge_call(&self.provider_label, VERDICT_ERROR, false, elapsed, 0.0);
                return Err(JudgeError::MalformedResponse(format!(
                    "non-JSON body: {err}"
                )));
            }
        };

        let (decision, cost_usd) = match parse_verdict(&parsed) {
            Ok(v) => v,
            Err(e) => {
                let elapsed = started.elapsed().as_secs_f64();
                record_judge_call(&self.provider_label, VERDICT_ERROR, false, elapsed, 0.0);
                return Err(e);
            }
        };

        self.cache.put(key, decision.clone());
        let elapsed = started.elapsed().as_secs_f64();
        record_judge_call(
            &self.provider_label,
            verdict_label(&decision),
            false,
            elapsed,
            cost_usd,
        );
        debug!(
            target: "sbproxy_judge",
            provider = %self.provider_label,
            latency_seconds = elapsed,
            cost_usd,
            "judge call resolved"
        );
        Ok(decision)
    }
}

fn verdict_label(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => VERDICT_ALLOW,
        PolicyDecision::Deny { .. } => VERDICT_DENY,
        PolicyDecision::AllowWithHeaders { .. } => VERDICT_ALLOW_WITH_HEADERS,
        PolicyDecision::Confirm { .. } => VERDICT_CONFIRM,
    }
}

/// Pull a `PolicyDecision` plus optional cost out of either the
/// direct verdict shape or a chat-completions wrapper.
fn parse_verdict(body: &Json) -> Result<(PolicyDecision, f64), JudgeError> {
    // Direct verdict shape first; that is what an in-VPC judge or a
    // bare facilitator returns.
    if let Some(direct) = body.get("verdict").and_then(|v| v.as_str()) {
        let decision = decision_from_str(direct, body)?;
        let cost = body.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
        return Ok((decision, cost));
    }

    // Chat-completions wrapper.
    if let Some(content) = body
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
    {
        let inner: Json = serde_json::from_str(content).map_err(|e| {
            JudgeError::MalformedResponse(format!("choices[0].message.content not JSON: {e}"))
        })?;
        let verdict_str = inner
            .get("verdict")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JudgeError::MalformedResponse(
                    "missing 'verdict' key in choices[0].message.content".to_string(),
                )
            })?;
        let decision = decision_from_str(verdict_str, &inner)?;
        let cost = body
            .pointer("/usage/cost_usd")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        return Ok((decision, cost));
    }

    Err(JudgeError::MalformedResponse(
        "expected either 'verdict' field or chat-completions 'choices' wrapper".to_string(),
    ))
}

fn decision_from_str(raw: &str, body: &Json) -> Result<PolicyDecision, JudgeError> {
    match raw {
        "allow" => Ok(PolicyDecision::Allow),
        "deny" => {
            let message = body
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("denied by judge")
                .to_string();
            let status = body
                .get("status")
                .and_then(|v| v.as_u64())
                .map(|n| n as u16)
                .unwrap_or(403);
            Ok(PolicyDecision::Deny { status, message })
        }
        other => Err(JudgeError::MalformedResponse(format!(
            "unknown verdict: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    /// Start a single-shot HTTP/1.1 mock that accepts one connection
    /// and returns the given response. Returns the bound address so
    /// the test can plumb it into the JudgeConfig.
    fn one_shot_mock(response: String) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                // Best-effort drain: read until reqwest's headers
                // and body land. We do not need to parse the request
                // for these tests; we only need to write back.
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(response.as_bytes());
                let _ = sock.shutdown(std::net::Shutdown::Both);
            }
        });
        addr
    }

    fn http_response(status_line: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
            status_line,
            body.len(),
            body
        )
    }

    fn build_client(endpoint: url::Url, budget: u64) -> JudgeClient {
        let cfg = JudgeConfig {
            endpoint,
            api_key_env: "SBPROXY_JUDGE_TEST_KEY".to_string(),
            timeout_ms: 1_500,
            cache_capacity: 16,
            budget_tokens: budget,
        };
        JudgeClient::new(cfg)
    }

    #[tokio::test]
    async fn provider_returns_allow_json_yields_allow_decision() {
        let body = json!({"verdict": "allow"}).to_string();
        let addr = one_shot_mock(http_response("200 OK", &body));
        let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).unwrap();
        let client = build_client(endpoint, 100);

        let decision = client
            .semantic("classify this", json!({"text": "hello"}))
            .await
            .expect("allow path returns Ok");
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn cache_hit_returns_stored_verdict_without_calling_provider() {
        // First call gets one mock response, second call would hit
        // a cache that we pre-load. To prove the second call does
        // not touch the network we point the endpoint at a closed
        // port; if the cache misses, the call would error out.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).unwrap();
        let client = build_client(endpoint, 100);

        // Pre-load the cache with the verdict the test expects.
        let prompt = "ratchet";
        let payload = json!({"u": 1});
        let key = cache_key(prompt, &payload);
        client.cache().put(
            key,
            PolicyDecision::Deny {
                status: 403,
                message: "from cache".to_string(),
            },
        );

        let decision = client.semantic(prompt, payload).await.expect("cache hit");
        assert_eq!(
            decision,
            PolicyDecision::Deny {
                status: 403,
                message: "from cache".to_string()
            }
        );
        // Budget untouched on cache hit.
        assert_eq!(client.budget().remaining(), 100);
    }

    #[tokio::test]
    async fn malformed_provider_response_yields_malformed_error() {
        let body = "this is not JSON";
        let addr = one_shot_mock(http_response("200 OK", body));
        let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).unwrap();
        let client = build_client(endpoint, 100);

        let err = client
            .semantic("p", json!({"a": 1}))
            .await
            .expect_err("malformed body must surface error");
        match err {
            JudgeError::MalformedResponse(_) => {}
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn provider_429_maps_to_budget_exhausted() {
        let body = json!({"error": "rate limited"}).to_string();
        let addr = one_shot_mock(http_response("429 Too Many Requests", &body));
        let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).unwrap();
        let client = build_client(endpoint, 100);

        let err = client
            .semantic("p", json!({"a": 1}))
            .await
            .expect_err("429 must hard-fail");
        assert!(matches!(err, JudgeError::BudgetExhausted));
    }

    #[tokio::test]
    async fn budget_exhausted_when_charge_fails_before_network() {
        // Budget of 0 forces the budget gate to fire before the
        // client even reaches reqwest. We point the endpoint at a
        // closed port to assert that no network call happens.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).unwrap();
        let cfg = JudgeConfig {
            endpoint,
            api_key_env: "SBPROXY_JUDGE_TEST_KEY".to_string(),
            timeout_ms: 1_500,
            cache_capacity: 4,
            budget_tokens: 0,
        };
        let client = JudgeClient::new(cfg);

        let err = client
            .semantic("p", json!({"a": 1}))
            .await
            .expect_err("zero budget must hard-fail");
        assert!(matches!(err, JudgeError::BudgetExhausted));
    }

    #[tokio::test]
    async fn chat_completions_wrapper_is_parsed() {
        let body = json!({
            "choices": [{
                "message": {
                    "content": "{\"verdict\": \"deny\", \"message\": \"blocked\", \"status\": 451}"
                }
            }],
            "usage": {"cost_usd": 0.005}
        })
        .to_string();
        let addr = one_shot_mock(http_response("200 OK", &body));
        let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).unwrap();
        let client = build_client(endpoint, 100);

        let decision = client
            .semantic("p", json!({"a": 1}))
            .await
            .expect("chat-completions shape parses");
        assert_eq!(
            decision,
            PolicyDecision::Deny {
                status: 451,
                message: "blocked".to_string()
            }
        );
    }

    #[test]
    fn parse_verdict_rejects_unknown_verdict_string() {
        let body = json!({"verdict": "maybe"});
        let err = parse_verdict(&body).expect_err("unknown verdict must error");
        assert!(matches!(err, JudgeError::MalformedResponse(_)));
    }

    #[tokio::test]
    async fn second_call_after_cache_warm_does_not_charge_budget() {
        let body = json!({"verdict": "allow"}).to_string();
        let addr = one_shot_mock(http_response("200 OK", &body));
        let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).unwrap();
        let cfg = JudgeConfig {
            endpoint,
            api_key_env: "SBPROXY_JUDGE_TEST_KEY".to_string(),
            timeout_ms: 1_500,
            cache_capacity: 16,
            budget_tokens: 5,
        };
        let client = Arc::new(JudgeClient::new(cfg));
        let before = client.budget().remaining();

        let _ = client
            .semantic("p", json!({"a": 1}))
            .await
            .expect("first call hits provider");
        let after_first = client.budget().remaining();
        assert!(after_first < before, "first call must charge budget");

        // Second call hits the cache; budget must not move.
        let _ = client
            .semantic("p", json!({"a": 1}))
            .await
            .expect("second call hits cache");
        let after_second = client.budget().remaining();
        assert_eq!(
            after_second, after_first,
            "cache hit must not charge budget"
        );
    }
}
