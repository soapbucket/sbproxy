//! HTTP ledger client.
//!
//! Sync (blocking) by design: the [`Ledger`] trait is sync because
//! the policy fast-path lives inside Pingora's request filter. We use
//! `reqwest::blocking` the same way the WAF rule-feed loader does at
//! config-compile. When the filter runs on a tokio worker thread,
//! `redeem` bridges through `block_in_place` so the blocking client's
//! internal runtime never drops in a blocking-forbidden context (a
//! debug-build panic since tokio 1.52).
//! For high-rps deployments the circuit breaker bounds the cost of
//! a slow ledger to one round-trip + breaker-open period.
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rand::Rng;
use sbproxy_platform::CircuitBreaker;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use super::{Ledger, LedgerError, RedeemResult};

type HmacSha256 = Hmac<Sha256>;

/// Configuration for `HttpLedger`.
#[derive(Debug, Clone)]
pub struct HttpLedgerConfig {
    /// Base URL, e.g. `https://ledger.internal`. The client appends
    /// `/v1/ledger/redeem` (and other verb paths in later waves).
    /// Plain HTTP is rejected at construction time per the ADR.
    pub endpoint: String,
    /// HMAC key id (selects which key on the ledger side validates
    /// the signature).
    pub key_id: String,
    /// HMAC key bytes. Loaded from `SBPROXY_LEDGER_HMAC_KEY_FILE`
    /// in the binary; tests pass raw bytes.
    pub key: Vec<u8>,
    /// Workspace tenant key. `default` in OSS, the customer
    /// workspace id in enterprise.
    pub workspace_id: String,
    /// Agent identifier from the agent-class taxonomy. Older
    /// callers forward `unknown` until the resolver lands; widening
    /// the call site is a follow-up.
    pub agent_id: String,
    /// Convenience copy of the taxonomy `vendor` carried so the
    /// ledger does not need to load the taxonomy.
    pub agent_vendor: String,
    /// Per-attempt deadline; the client aborts the request after
    /// this many milliseconds and counts it as a transient failure.
    pub per_attempt_timeout: Duration,
    /// Total deadline across all retries.
    pub total_timeout: Duration,
    /// Maximum retry attempts. Hard-capped at 5 by the ADR.
    pub max_attempts: u32,
    /// Consecutive failures that open the circuit breaker.
    pub breaker_failure_threshold: u32,
    /// Successes in `HalfOpen` to close the breaker again.
    pub breaker_success_threshold: u32,
    /// Duration the breaker stays open before allowing a probe.
    pub breaker_open_duration: Duration,
}

impl HttpLedgerConfig {
    /// Defaults aligned with the ADR (5 attempts, 5 s per attempt,
    /// 30 s total, breaker opens after 10 failures, 5 s open).
    pub fn with_defaults(
        endpoint: impl Into<String>,
        key_id: impl Into<String>,
        key: Vec<u8>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            key_id: key_id.into(),
            key,
            workspace_id: "default".to_string(),
            agent_id: "unknown".to_string(),
            agent_vendor: "unknown".to_string(),
            per_attempt_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            max_attempts: 5,
            breaker_failure_threshold: 10,
            breaker_success_threshold: 1,
            breaker_open_duration: Duration::from_secs(5),
        }
    }
}

/// HTTP ledger client.
///
/// # No readiness probe, and not by omission (WOR-2324)
///
/// This client carried a `with_recency` hook that stamped a readiness
/// tracker on every successful redeem. Nothing ever called it, and the
/// `/readyz` component that looked like its destination was reporting the
/// proxy's own usage chain the whole time, under a name (`ledger`) that
/// read as though it covered this.
///
/// The hook is gone rather than wired, because redeem recency cannot say
/// what a reader would take it to say. Redeems happen only when a paying
/// crawler hits a priced route, so "no successful redeem in the last N
/// seconds" describes a healthy idle deployment exactly as well as a dead
/// ledger, and `sbproxy_observe::RecencyProbe` reports a never-marked
/// tracker as `Unhealthy`. Wiring it would drop working pods out of
/// rotation for want of traffic, which is a worse failure than the
/// reporting gap it closes.
///
/// [`HttpLedger::breaker`] is the signal that would work, and is still
/// exposed for it: it is traffic-independent in the right direction, since
/// a breaker nobody has exercised reads closed and an open one means the
/// endpoint has failed its configured threshold in a row. What is missing
/// is a way to hand this client's breaker to the health registry, because
/// the client is built during config compile and lives inside a policy
/// enforcer behind a pipeline generation.
pub struct HttpLedger {
    config: HttpLedgerConfig,
    client: reqwest::blocking::Client,
    breaker: Arc<CircuitBreaker>,
}

impl std::fmt::Debug for HttpLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpLedger")
            .field("endpoint", &self.config.endpoint)
            .field("key_id", &self.config.key_id)
            .field("workspace_id", &self.config.workspace_id)
            .field("agent_id", &self.config.agent_id)
            .finish()
    }
}

impl HttpLedger {
    /// Build a new client. Returns `Err` if `endpoint` is not HTTPS.
    pub fn new(config: HttpLedgerConfig) -> anyhow::Result<Self> {
        // The ADR mandates HTTPS for the ledger endpoint. A plain
        // HTTP target is almost always a misconfiguration, so we
        // refuse to construct the client rather than fail later.
        if !config.endpoint.starts_with("https://") {
            anyhow::bail!(
                "HttpLedger endpoint must be https://; got '{}'",
                config.endpoint
            );
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(config.per_attempt_timeout)
            .build()?;
        let breaker = Arc::new(CircuitBreaker::new(
            config.breaker_failure_threshold,
            config.breaker_success_threshold,
            config.breaker_open_duration,
        ));
        Ok(Self {
            config,
            client,
            breaker,
        })
    }

    /// Inject a custom HTTP client (used by tests to point at a
    /// stub server with a relaxed TLS config).
    pub fn with_client(mut self, client: reqwest::blocking::Client) -> Self {
        self.client = client;
        self
    }

    /// Inject a custom circuit breaker, e.g. one shared across
    /// multiple verbs in a future wave.
    pub fn with_breaker(mut self, breaker: Arc<CircuitBreaker>) -> Self {
        self.breaker = breaker;
        self
    }

    /// Expose the breaker state for `/readyz` and Grafana dashboards.
    pub fn breaker(&self) -> &CircuitBreaker {
        &self.breaker
    }
}

impl Ledger for HttpLedger {
    fn redeem(
        &self,
        token: &str,
        host: &str,
        path: &str,
        expected_amount_micros: u64,
        expected_currency: &str,
    ) -> Result<RedeemResult, LedgerError> {
        // The retry loop below sleeps and drives reqwest's blocking
        // client, whose internal runtime must not be dropped on an
        // async worker thread (tokio panics on that in debug builds).
        // When called from a multi-thread runtime worker, tell tokio
        // this thread is intentionally blocking; anywhere else the
        // call is already on a plain thread and runs directly.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| {
                    self.redeem_blocking(
                        token,
                        host,
                        path,
                        expected_amount_micros,
                        expected_currency,
                    )
                })
            }
            _ => self.redeem_blocking(token, host, path, expected_amount_micros, expected_currency),
        }
    }
}

impl HttpLedger {
    fn redeem_blocking(
        &self,
        token: &str,
        host: &str,
        path: &str,
        expected_amount_micros: u64,
        expected_currency: &str,
    ) -> Result<RedeemResult, LedgerError> {
        // --- Breaker gate ---
        //
        // When open we short-circuit with a synthetic transient
        // error; the policy at the request path then emits 503.
        if !self.breaker.allow_request() {
            return Err(
                LedgerError::transient("ledger.unavailable", "circuit breaker open")
                    .with_retry_after(self.config.breaker_open_duration.as_secs().max(1) as u32),
            );
        }

        // --- Request envelope ---
        let request_id = Ulid::new().to_string();
        let idempotency_key = Ulid::new().to_string();
        let nonce = random_nonce_hex();
        let timestamp = rfc3339_millis_now();
        let envelope = RedeemEnvelope {
            v: 1,
            request_id: request_id.clone(),
            timestamp: timestamp.clone(),
            nonce: nonce.clone(),
            agent_id: self.config.agent_id.clone(),
            agent_vendor: self.config.agent_vendor.clone(),
            workspace_id: self.config.workspace_id.clone(),
            payload: RedeemPayload {
                token: token.to_string(),
                host: host.to_string(),
                path: path.to_string(),
                amount_micros: expected_amount_micros,
                currency: expected_currency.to_string(),
                content_shape: None,
            },
        };
        // Every early return between the breaker gate above and the retry
        // loop below has to hand the probe slot back. In HalfOpen the gate
        // did not just answer a question, it took the one slot the breaker
        // hands out per recovery cycle, and these two paths never reach
        // `record_success` or `record_failure` to give it up. Nothing was
        // dispatched, so the endpoint's health is exactly as unknown as it
        // was a line earlier.
        let body_bytes = serde_json::to_vec(&envelope).map_err(|e| {
            self.breaker.release_probe();
            LedgerError::hard("ledger.bad_request", format!("envelope encode: {e}"))
        })?;
        let body_hash_hex = sha256_hex(&body_bytes);

        let path_only = "/v1/ledger/redeem";
        let signing_string = canonical_signing_string(
            envelope.v,
            &request_id,
            &timestamp,
            &nonce,
            &self.config.workspace_id,
            "POST",
            path_only,
            &body_hash_hex,
        );
        let signature_hex =
            hmac_sha256_hex(&self.config.key, signing_string.as_bytes()).map_err(|e| {
                self.breaker.release_probe();
                LedgerError::hard("ledger.bad_request", format!("hmac init: {e}"))
            })?;
        let signature_header = format!("v1={signature_hex}");

        let url = format!(
            "{}{}",
            self.config.endpoint.trim_end_matches('/'),
            path_only
        );

        // --- Retry loop ---
        //
        // Schedule per ADR: 0 ms, 250 ms, 500 ms, 1 s, 2 s base
        // delay, each with `[0, base)` jitter added. Same Idempotency-Key
        // across retries so the ledger short-circuits on replay.
        let max_attempts = self.config.max_attempts.clamp(1, 5);
        let total_deadline = Instant::now() + self.config.total_timeout;
        let mut last_err: Option<LedgerError> = None;
        for attempt in 0..max_attempts {
            if attempt > 0 {
                let base_ms = match attempt {
                    1 => 250u64,
                    2 => 500,
                    3 => 1000,
                    _ => 2000,
                };
                let jitter_ms = rand::thread_rng().gen_range(0..base_ms.max(1));
                let delay = Duration::from_millis(base_ms + jitter_ms);
                if Instant::now() + delay >= total_deadline {
                    break;
                }
                std::thread::sleep(delay);
            }
            if Instant::now() >= total_deadline {
                break;
            }
            match self.send_attempt(
                &url,
                &body_bytes,
                &idempotency_key,
                &request_id,
                &signature_header,
            ) {
                Ok(result) => {
                    if let Some((from, to)) = self.breaker.record_success() {
                        sbproxy_observe::metrics::record_circuit_breaker_transition(
                            &self.config.endpoint,
                            from.as_str(),
                            to.as_str(),
                            "success_threshold_met",
                            "",
                        );
                    }
                    return Ok(result);
                }
                Err(err) => {
                    if err.retryable {
                        if let Some((from, to)) = self.breaker.record_failure() {
                            let reason = match from {
                                sbproxy_platform::CircuitState::HalfOpen => "probe_failed",
                                _ => "failure_threshold_exceeded",
                            };
                            sbproxy_observe::metrics::record_circuit_breaker_transition(
                                &self.config.endpoint,
                                from.as_str(),
                                to.as_str(),
                                reason,
                                "",
                            );
                        }
                        last_err = Some(err);
                        continue;
                    }
                    // Hard failure: do not retry, do not flap the
                    // breaker. The policy will translate to 402.
                    //
                    // The breaker still has to get its slot back. A hard
                    // error is what a perfectly healthy ledger answers
                    // with when a crawler presents a spent or badly
                    // signed token, and in HalfOpen this request is
                    // holding the single probe slot. Leaving it out would
                    // make one refused token answer every other redeem
                    // with a synthetic `ledger.unavailable` for a whole
                    // open duration, which the crawl policy turns into a
                    // fail-closed 503 for crawlers whose tokens are fine.
                    self.breaker.release_probe();
                    return Err(err);
                }
            }
        }
        if last_err.is_none() {
            // The loop fell out without ever dispatching an attempt: the
            // total deadline had already lapsed. Nothing recorded an
            // outcome, so the probe slot is still held and has to go back
            // rather than wait out the stale-slot forgiveness.
            self.breaker.release_probe();
        }
        Err(last_err.unwrap_or_else(|| {
            LedgerError::transient("ledger.unavailable", "max retries exhausted")
        }))
    }
}

impl HttpLedger {
    fn send_attempt(
        &self,
        url: &str,
        body: &[u8],
        idempotency_key: &str,
        request_id: &str,
        signature_header: &str,
    ) -> Result<RedeemResult, LedgerError> {
        let mut request = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .header("idempotency-key", idempotency_key)
            .header("x-sb-ledger-signature", signature_header)
            .header("x-sb-ledger-key-id", &self.config.key_id)
            .header("x-sb-request-id", request_id)
            .body(body.to_vec());
        // The redeem call is a hop in the request's trace, so it carries
        // the request's trace context. Taken from the ambient span rather
        // than plumbed: `Ledger::redeem` is a sync trait with no
        // `RequestContext` in its signature, and the AI-crawl enforcer
        // that calls it runs inside `sbproxy.policy.enforce`. The
        // `block_in_place` bridge above stays on the calling thread, so
        // `Span::current()` is still that span down here.
        //
        // The blocking builder is a different type from the async one, so
        // this reads the header pairs directly instead of going through
        // `inject_reqwest_trace_context`. Same source, same formatter.
        for (name, value) in sbproxy_observe::telemetry::outbound_trace_headers(None) {
            request = request.header(name, value);
        }
        let response = request.send();

        let response = match response {
            Ok(r) => r,
            Err(e) => {
                // Network errors (DNS, TCP RST, TLS, read timeout)
                // are always retryable.
                return Err(LedgerError::transient(
                    "ledger.unavailable",
                    format!("network: {e}"),
                ));
            }
        };

        let status = response.status();
        let retry_after_header = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok());
        let body_text = response.text().unwrap_or_default();

        if status.is_success() {
            let envelope: ResponseEnvelope = serde_json::from_str(&body_text).map_err(|e| {
                LedgerError::transient("ledger.internal", format!("decode response: {e}"))
            })?;
            if let Some(result) = envelope.result {
                let redeemed = result.redeemed.unwrap_or(false);
                if !redeemed {
                    return Err(LedgerError::hard(
                        "ledger.token_already_spent",
                        "ledger reported redeemed=false",
                    ));
                }
                return Ok(RedeemResult {
                    token_id: result
                        .redemption_id
                        .unwrap_or_else(|| request_id.to_string()),
                    amount_micros: result.amount_micros.unwrap_or(0),
                    currency: result.currency.unwrap_or_default(),
                    txhash: result.txhash,
                });
            }
            if let Some(err) = envelope.error {
                return Err(map_envelope_error(err, retry_after_header));
            }
            return Err(LedgerError::transient(
                "ledger.internal",
                "response missing result and error",
            ));
        }

        // Non-2xx: try to decode the error envelope, otherwise
        // synthesize one from the HTTP status.
        let envelope: Option<ResponseEnvelope> = serde_json::from_str(&body_text).ok();
        if let Some(err) = envelope.and_then(|e| e.error) {
            return Err(map_envelope_error(err, retry_after_header));
        }
        let code = status.as_u16();
        match code {
            400 => Err(LedgerError::hard(
                "ledger.bad_request",
                format!("HTTP {code}"),
            )),
            401 => Err(LedgerError::hard(
                "ledger.signature_invalid",
                format!("HTTP {code}"),
            )),
            409 => Err(LedgerError::hard(
                "ledger.token_already_spent",
                format!("HTTP {code}"),
            )),
            429 => {
                let mut e = LedgerError::transient("ledger.rate_limited", format!("HTTP {code}"));
                if let Some(s) = retry_after_header {
                    e = e.with_retry_after(s);
                }
                Err(e)
            }
            502..=504 => {
                let mut e = LedgerError::transient("ledger.unavailable", format!("HTTP {code}"));
                if let Some(s) = retry_after_header {
                    e = e.with_retry_after(s);
                }
                Err(e)
            }
            _ if (500..600).contains(&code) => Err(LedgerError::transient(
                "ledger.internal",
                format!("HTTP {code}"),
            )),
            _ => Err(LedgerError::hard(
                "ledger.bad_request",
                format!("HTTP {code}"),
            )),
        }
    }
}

fn map_envelope_error(err: ErrorPart, retry_after_header: Option<u32>) -> LedgerError {
    let mut out = LedgerError {
        code: err.code,
        message: err.message,
        retryable: err.retryable,
        retry_after_seconds: err.retry_after_seconds,
    };
    if out.retry_after_seconds.is_none() {
        out.retry_after_seconds = retry_after_header;
    }
    out
}

// --- Wire types ---

#[derive(Debug, Serialize)]
struct RedeemEnvelope {
    v: u32,
    request_id: String,
    timestamp: String,
    nonce: String,
    agent_id: String,
    agent_vendor: String,
    workspace_id: String,
    payload: RedeemPayload,
}

#[derive(Debug, Serialize)]
struct RedeemPayload {
    token: String,
    host: String,
    path: String,
    amount_micros: u64,
    currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_shape: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResponseEnvelope {
    #[serde(default)]
    result: Option<ResultPart>,
    #[serde(default)]
    error: Option<ErrorPart>,
}

#[derive(Debug, Deserialize)]
struct ResultPart {
    #[serde(default)]
    redeemed: Option<bool>,
    #[serde(default)]
    redemption_id: Option<String>,
    #[serde(default)]
    amount_micros: Option<u64>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    txhash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorPart {
    code: String,
    message: String,
    #[serde(default)]
    retryable: bool,
    #[serde(default)]
    retry_after_seconds: Option<u32>,
}

// --- Helpers ---

#[allow(clippy::too_many_arguments)] // canonical signing string is 8 fields by spec.
fn canonical_signing_string(
    v: u32,
    request_id: &str,
    timestamp: &str,
    nonce: &str,
    workspace_id: &str,
    method: &str,
    path: &str,
    body_hash_hex: &str,
) -> String {
    // Eight lines, \n separated, no trailing newline (per ADR).
    format!(
            "{v}\n{request_id}\n{timestamp}\n{nonce}\n{workspace_id}\n{method}\n{path}\n{body_hash_hex}"
        )
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| e.to_string())?;
    mac.update(data);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn random_nonce_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn rfc3339_millis_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    // Manual format avoids pulling chrono::Utc::now() which is
    // already in the dep tree but not used elsewhere on this hot
    // path. RFC 3339 / ISO 8601 form.
    let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, millis * 1_000_000)
        .unwrap_or_default();
    datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
